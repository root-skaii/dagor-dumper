#include "../include/rtti_dump.h"
#include "../include/scanner.h"
#include "../include/logger.h"
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <unordered_map>
#include <map>
#include <vector>

namespace {

uintptr_t g_base = 0;
size_t    g_size = 0;

inline bool in_image(uintptr_t v)      { return v >= g_base && v < g_base + g_size; }
inline bool rva_ok(uint32_t r)         { return r != 0 && r < g_size; }
inline uint32_t r32(uintptr_t a)       { return *(const uint32_t*)a; }
inline uint64_t r64(uintptr_t a)       { return *(const uint64_t*)a; }

// ".?AVMyClass@ns@@" -> "ns::MyClass". Qualifiers are stored innermost-first.
std::string demangle(const char* raw) {
    if (!raw || raw[0] != '.') return raw ? raw : "";
    const char* p = raw + 1;
    if (*p == '?') p++;
    if (*p == 'A') p++;
    if (*p == 'V' || *p == 'U' || *p == 'T') p++;
    else if (*p == 'W' && p[1] == '4') p += 2;

    std::vector<std::string> parts;
    std::string cur;
    for (; *p; p++) {
        if (*p == '@') {
            if (cur.empty()) break;      // "@@" terminator
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(*p);
        }
    }
    if (!cur.empty()) parts.push_back(cur);
    if (parts.empty()) return raw;

    std::string out;
    for (size_t i = parts.size(); i-- > 0; ) {
        if (!out.empty()) out += "::";
        out += parts[i];
    }
    return out;
}

// Sorted executable section ranges; avoids a VirtualQuery per candidate pointer.
std::vector<std::pair<uintptr_t, uintptr_t>> g_exec;

void build_exec_ranges() {
    g_exec.clear();
    auto* dos = (IMAGE_DOS_HEADER*)g_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    auto* nt = (IMAGE_NT_HEADERS*)(g_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        size_t vsz = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (!vsz) continue;
        g_exec.emplace_back(g_base + sec->VirtualAddress, g_base + sec->VirtualAddress + vsz);
    }
    std::sort(g_exec.begin(), g_exec.end());
}

bool is_code_ptr(uintptr_t v) {
    if (!in_image(v)) return false;
    size_t lo = 0, hi = g_exec.size();
    while (lo < hi) { size_t m = (lo + hi) / 2; if (g_exec[m].first <= v) lo = m + 1; else hi = m; }
    return lo != 0 && v < g_exec[lo - 1].second;
}

} // namespace

static void rtti_impl(RttiResult& res) {
    LOG_SECTION("MSVC RTTI: class names and vtables");

    HMODULE h = GetModuleHandleA(nullptr);
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) return;
    g_base = (uintptr_t)mi.lpBaseOfDll;
    g_size = mi.SizeOfImage;
    res.moduleBase = g_base;
    {
        char nm[MAX_PATH] = {};
        GetModuleBaseNameA(GetCurrentProcess(), h, nm, MAX_PATH);
        res.moduleName = nm;
    }

    build_exec_ranges();
    LOG_INFO("RTTI: %zu executable range(s) in %s", g_exec.size(), res.moduleName.c_str());

    // Find COLs: a 24-byte record whose last dword (pSelf) is its own RVA.
    std::vector<uintptr_t> cols;
    for (const auto& sec : enumerate_data_sections(g_base)) {
        uintptr_t s = (sec.base + 3) & ~3ull;
        uintptr_t e = sec.base + sec.size;
        if (e < s + 24) continue;
        e -= 24;
        for (uintptr_t a = s; a <= e; a += 4) {
            if (r32(a) != 1) continue;                       // signature, x64
            uint32_t pSelf = r32(a + 20);
            if (g_base + pSelf != a) continue;               // self-check
            uint32_t pType = r32(a + 12), pChd = r32(a + 16);
            if (!rva_ok(pType) || !rva_ok(pChd)) continue;
            cols.push_back(a);
        }
    }
    res.colCandidates = (uint32_t)cols.size();
    LOG_INFO("RTTI: %zu CompleteObjectLocator record(s)", cols.size());
    if (cols.empty()) {
        LOG_WARN("no RTTI found — the binary was probably built with /GR-");
        return;
    }

    // COL -> vtable: a vtable's slot -1 holds its COL pointer.
    std::unordered_map<uintptr_t, uintptr_t> colToVtable;
    for (const auto& sec : enumerate_data_sections(g_base)) {
        uintptr_t s = (sec.base + 7) & ~7ull;
        uintptr_t e = sec.base + sec.size;
        if (e < s + 16) continue;
        e -= 16;
        for (uintptr_t a = s; a <= e; a += 8) {
            uintptr_t v = (uintptr_t)r64(a);
            if (!in_image(v)) continue;
            if (!colToVtable.count(v)) {
                if (is_code_ptr((uintptr_t)r64(a + 8))) colToVtable[v] = a + 8;
            }
        }
    }

    std::map<std::string, RttiClass> uniq;
    for (uintptr_t col : cols) {
        uint32_t pType = r32(col + 12), pChd = r32(col + 16);
        uintptr_t td = g_base + pType;
        const char* raw = (const char*)(td + 16);            // past vfptr+spare

        if (!in_image((uintptr_t)raw)) continue;
        if (raw[0] != '.') continue;
        size_t n = 0;
        while (n < 512 && raw[n] && (uint8_t)raw[n] >= 0x20 && (uint8_t)raw[n] < 0x7F) n++;
        if (n == 0 || n >= 512 || raw[n] != 0) continue;

        RttiClass rc;
        rc.rawName    = raw;
        rc.name       = demangle(raw);
        rc.colAddr    = col;
        rc.thisOffset = r32(col + 4);
        // ClassHierarchyDescriptor: {signature, attributes, numBaseClasses, pBaseClassArray}
        rc.numBases   = r32(g_base + pChd + 8);
        if (rc.numBases > 4096) rc.numBases = 0;

        auto it = colToVtable.find(col);
        if (it != colToVtable.end()) {
            rc.vtable    = it->second;
            rc.vtableRva = (uint32_t)(it->second - g_base);
            while (rc.numMethods < 4096 &&
                   is_code_ptr((uintptr_t)r64(rc.vtable + 8ull * rc.numMethods)))
                rc.numMethods++;
        }

        // A class has one COL per base subobject; prefer the primary (thisOffset 0).
        auto ex = uniq.find(rc.name);
        if (ex == uniq.end() || (rc.thisOffset == 0 && ex->second.thisOffset != 0) ||
            rc.numMethods > ex->second.numMethods)
            uniq[rc.name] = rc;
    }

    res.classes.reserve(uniq.size());
    for (auto& kv : uniq) res.classes.push_back(kv.second);
    std::sort(res.classes.begin(), res.classes.end(),
              [](const RttiClass& a, const RttiClass& b) { return a.name < b.name; });

    size_t withVt = 0;
    for (const auto& c : res.classes) if (c.vtable) withVt++;
    LOG_INFO("RTTI: %zu unique class(es), %zu with a vtable located",
             res.classes.size(), withVt);
}

// __try cannot share a frame with C++ unwinding, hence the split.
static void rtti_trampoline(RttiResult& r) { rtti_impl(r); }

static bool rtti_guarded(RttiResult* r, DWORD* code) {
    __try { rtti_trampoline(*r); return true; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { return false; }
}

RttiResult dump_msvc_rtti() {
    RttiResult res;
    DWORD code = 0;
    if (!rtti_guarded(&res, &code))
        LOG_ERR("RTTI scan faulted (0x%08X) — returning what was collected", code);
    return res;
}
