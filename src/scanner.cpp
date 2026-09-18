#include "../include/scanner.h"
#include <unordered_set>
#include <psapi.h>
#include <algorithm>
#pragma comment(lib, "psapi.lib")

static HMODULE   s_module     = nullptr;
static uintptr_t s_image_base = 0;
static size_t    s_image_size = 0;

static void init_module_info() {
    if (s_module) return;
    s_module = GetModuleHandleA(nullptr);
    MODULEINFO mi{};
    if (GetModuleInformation(GetCurrentProcess(), s_module, &mi, sizeof(mi))) {
        s_image_base = (uintptr_t)mi.lpBaseOfDll;
        s_image_size = mi.SizeOfImage;
    }
}

SectionRange get_section(const char* name) {
    init_module_info();
    if (!s_image_base) return {};

    auto* dos = (IMAGE_DOS_HEADER*)s_image_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return {};

    auto* nt = (IMAGE_NT_HEADERS*)(s_image_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return {};

    auto* sec = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;
    for (WORD i = 0; i < count; i++, sec++) {
        if (strncmp((const char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            return {
                s_image_base + sec->VirtualAddress,
                sec->Misc.VirtualSize
            };
        }
    }
    return {};
}

bool is_valid_ptr(const void* p) {
    if (!p) return false;
    uintptr_t addr = (uintptr_t)p;
    if (addr < 0x10000 || addr > 0x00007FFFFFFFFFFEull) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    constexpr DWORD readable = PAGE_READONLY | PAGE_READWRITE |
                               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                               PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
    return (mbi.Protect & readable) && !(mbi.Protect & PAGE_NOACCESS);
}

bool is_valid_string(const char* s, size_t max_len) {
    if (!is_valid_ptr(s)) return false;
    for (size_t i = 0; i < max_len; i++) {
        if ((i % 4096 == 0) && !is_valid_ptr(s + i)) return false;
        char c = s[i];
        if (c == '\0') return i > 0;
        if ((uint8_t)c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
    }
    return false;
}

uintptr_t find_string(const char* str) {
    SectionRange rdata = get_section(".rdata");
    if (!rdata.valid()) return 0;

    size_t len = strlen(str);
    if (len == 0) return 0;

    const uint8_t* base = (const uint8_t*)rdata.base;
    const uint8_t* end  = base + rdata.size - len;
    const uint8_t* tgt  = (const uint8_t*)str;

    for (const uint8_t* p = base; p < end; p++) {
        if (*p == tgt[0] && memcmp(p, tgt, len) == 0 && p[len] == '\0') {
            return (uintptr_t)p;
        }
    }
    return 0;
}

std::vector<uintptr_t> find_all_strings(const char* str) {
    std::vector<uintptr_t> results;
    SectionRange rdata = get_section(".rdata");
    if (!rdata.valid()) return results;

    size_t len = strlen(str);
    if (len == 0) return results;

    const uint8_t* base = (const uint8_t*)rdata.base;
    const uint8_t* end  = base + rdata.size - len;
    const uint8_t* tgt  = (const uint8_t*)str;

    for (const uint8_t* p = base; p < end; p++) {
        if (*p == tgt[0] && memcmp(p, tgt, len) == 0 && p[len] == '\0') {
            results.push_back((uintptr_t)p);
        }
    }
    return results;
}

std::vector<uintptr_t> find_ptr_to(uintptr_t target,
                                    uintptr_t range_start,
                                    size_t    range_size) {
    std::vector<uintptr_t> results;
    uintptr_t start = (range_start + 7) & ~7ull;
    uintptr_t end   = range_start + range_size - sizeof(uintptr_t);

    for (uintptr_t addr = start; addr <= end; addr += 8) {
        if (*reinterpret_cast<uintptr_t*>(addr) == target) {
            results.push_back(addr);
        }
    }
    return results;
}

uintptr_t scan_pattern(uintptr_t base, size_t size,
                        const uint8_t* pattern, const char* mask, size_t pat_len) {
    const uint8_t* b = (const uint8_t*)base;
    const uint8_t* e = b + size - pat_len;
    for (const uint8_t* p = b; p < e; p++) {
        bool match = true;
        for (size_t j = 0; j < pat_len && match; j++) {
            match = (mask[j] == '?') || (p[j] == pattern[j]);
        }
        if (match) return (uintptr_t)p;
    }
    return 0;
}

uintptr_t scan_ida_pattern(const char* pattern_str) {
    std::vector<uint8_t> bytes;
    std::vector<char> mask;

    const char* p = pattern_str;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            bytes.push_back(0x00);
            mask.push_back('?');
            p++;
            if (*p == '?') p++;
        } else {
            char hex[3] = {p[0], p[1], '\0'};
            bytes.push_back((uint8_t)strtoul(hex, nullptr, 16));
            mask.push_back('x');
            p += 2;
        }
    }
    if (bytes.empty()) return 0;

    init_module_info();
    return scan_pattern(s_image_base, s_image_size,
                        bytes.data(), mask.data(), bytes.size());
}

uintptr_t resolve_rip_rel(uintptr_t instruction_addr, int instr_size) {
    if (!is_valid_ptr((void*)(instruction_addr + 3))) return 0;
    int32_t disp = *reinterpret_cast<int32_t*>(instruction_addr + 3);
    return instruction_addr + instr_size + disp;
}

uintptr_t find_chain_entry(const char* anchor_str,
                            size_t name_field_offset,
                            size_t next_field_offset) {
    uintptr_t str_addr = find_string(anchor_str);
    if (!str_addr) return 0;

    SectionRange data = get_section(".data");
    if (!data.valid()) return 0;

    auto ptrs = find_ptr_to(str_addr, data.base, data.size);
    for (uintptr_t name_ptr_addr : ptrs) {
        uintptr_t node_addr = name_ptr_addr - name_field_offset;
        if (!is_valid_ptr((void*)node_addr)) continue;

        uintptr_t next = *reinterpret_cast<uintptr_t*>(node_addr + next_field_offset);
        if (next != 0 && !is_valid_ptr((void*)next)) continue;

        uintptr_t name_val = *reinterpret_cast<uintptr_t*>(node_addr + name_field_offset);
        if (name_val != str_addr) continue;

        return node_addr;
    }

    // Some compilers place const statics in .rdata.
    SectionRange rdata = get_section(".rdata");
    if (rdata.valid()) {
        auto rdata_ptrs = find_ptr_to(str_addr, rdata.base, rdata.size);
        for (uintptr_t name_ptr_addr : rdata_ptrs) {
            uintptr_t node_addr = name_ptr_addr - name_field_offset;
            if (!is_valid_ptr((void*)node_addr)) continue;
            uintptr_t next = *reinterpret_cast<uintptr_t*>(node_addr + next_field_offset);
            if (next != 0 && !is_valid_ptr((void*)next)) continue;
            uintptr_t name_val = *reinterpret_cast<uintptr_t*>(node_addr + name_field_offset);
            if (name_val != str_addr) continue;
            return node_addr;
        }
    }

    return 0;
}

std::vector<ModuleRange> enumerate_modules() {
    std::vector<ModuleRange> out;
    HMODULE mods[1024];
    DWORD   needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
        return out;
    size_t count = needed / sizeof(HMODULE);
    for (size_t i = 0; i < count; i++) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        char name[MAX_PATH] = {};
        GetModuleBaseNameA(GetCurrentProcess(), mods[i], name, MAX_PATH);
        out.push_back({ (uintptr_t)mi.lpBaseOfDll, (size_t)mi.SizeOfImage, name });
    }
    return out;
}

// SEH can't share a frame with C++ unwinding, hence the plain-array helper.
struct RawSec { uintptr_t base; size_t size; };

static int collect_data_sections_raw(uintptr_t module_base, RawSec* out, int max_out) {
    int n = 0;
    __try {
        auto* dos = (IMAGE_DOS_HEADER*)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt = (IMAGE_NT_HEADERS*)(module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections && n < max_out; i++, sec++) {
            const DWORD ch = sec->Characteristics;
            if (ch & IMAGE_SCN_MEM_EXECUTE)     continue;
            if (ch & IMAGE_SCN_MEM_DISCARDABLE) continue;
            if (!(ch & IMAGE_SCN_MEM_READ))     continue;

            char nm[9] = {};
            memcpy(nm, sec->Name, 8);
            if (!strncmp(nm, ".reloc", 6) || !strncmp(nm, ".rsrc",  5) ||
                !strncmp(nm, ".pdata", 6) || !strncmp(nm, ".idata", 6))
                continue;

            // VirtualSize so the .bss tail merged into .data is covered.
            size_t vsz = sec->Misc.VirtualSize;
            if (!vsz) vsz = sec->SizeOfRawData;
            if (!vsz) continue;

            out[n].base = module_base + sec->VirtualAddress;
            out[n].size = vsz;
            n++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return n;
}

std::vector<SectionRange> enumerate_data_sections(uintptr_t module_base) {
    std::vector<SectionRange> out;
    if (!module_base) return out;
    RawSec raw[96];
    int n = collect_data_sections_raw(module_base, raw, 96);
    for (int i = 0; i < n; i++) out.push_back({ raw[i].base, raw[i].size });
    return out;
}

std::vector<SectionRange> enumerate_all_data_sections() {
    std::vector<SectionRange> out;
    for (const auto& m : enumerate_modules()) {
        auto secs = enumerate_data_sections(m.base);
        out.insert(out.end(), secs.begin(), secs.end());
    }
    return out;
}

std::vector<SectionRange> enumerate_private_regions(size_t max_region) {
    std::vector<SectionRange> out;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
        uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;

        constexpr DWORD RW = PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY;
        const bool guarded = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;

        if (mbi.State == MEM_COMMIT && !guarded && (mbi.Protect & RW) &&
            mbi.Type == MEM_PRIVATE && mbi.RegionSize <= max_region) {
            out.push_back({ (uintptr_t)mbi.BaseAddress, (size_t)mbi.RegionSize });
        }
        addr = next;
    }
    return out;
}

// Called per 8-byte slot in the structural scans, hence sorted + binary search.
struct SortedMod { uintptr_t lo, hi; };
static std::vector<SortedMod> s_sorted_mods;

static void build_sorted_mods() {
    if (!s_sorted_mods.empty()) return;
    for (const auto& m : enumerate_modules())
        s_sorted_mods.push_back({ m.base, m.base + m.size });
    std::sort(s_sorted_mods.begin(), s_sorted_mods.end(),
              [](const SortedMod& a, const SortedMod& b) { return a.lo < b.lo; });
}

bool is_in_any_module(const void* p) {
    uintptr_t v = (uintptr_t)p;
    build_sorted_mods();
    size_t lo = 0, hi = s_sorted_mods.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (s_sorted_mods[mid].lo <= v) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return false;
    const SortedMod& m = s_sorted_mods[lo - 1];
    return v < m.hi;
}

bool in_main_image(uintptr_t v) {
    init_module_info();
    return v >= s_image_base && v < s_image_base + s_image_size;
}

uint32_t fnv1a_str(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) h = (h ^ (uint8_t)*s++) * 16777619u;
    return h;
}

static bool probe_cstring_noexcept(const char* s, int max_len) {
    __try {
        if ((uint8_t)*s < 0x20 || (uint8_t)*s > 0x7E) return false;
        for (int i = 0; i < max_len; i++, s++) {
            if (*s == 0) return i > 0;
            if ((uint8_t)*s < 0x20 || (uint8_t)*s > 0x7E) return false;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
}

bool fast_module_string(uintptr_t ptr) {
    if (!ptr || (ptr & 0xFFFF000000000000ull)) return false;
    if (!is_in_any_module((const void*)ptr)) return false;
    return probe_cstring_noexcept((const char*)ptr, 256);
}

// VirtualSize can extend past committed memory, so sections are clipped to
// committed ranges instead of using SEH (std::string can't live in a __try frame).
void harvest_all_string_hashes(std::unordered_map<uint32_t, std::string>& out) {
    for (const auto& sec : enumerate_all_data_sections()) {
        uintptr_t cur = sec.base, secEnd = sec.base + sec.size;
        while (cur < secEnd) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery((void*)cur, &mbi, sizeof(mbi))) break;
            uintptr_t regEnd = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (regEnd <= cur) break;

            constexpr DWORD R = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            bool usable = mbi.State == MEM_COMMIT && (mbi.Protect & R) &&
                          !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));

            if (usable) {
                const uint8_t* p = (const uint8_t*)cur;
                const uint8_t* e = (const uint8_t*)(regEnd < secEnd ? regEnd : secEnd);
                while (p < e) {
                    if (*p < 0x20 || *p > 0x7E) { p++; continue; }
                    const uint8_t* s = p;
                    while (p < e && *p >= 0x20 && *p <= 0x7E) p++;
                    size_t len = (size_t)(p - s);
                    if (p >= e) break;
                    bool terminated = (*p == 0);
                    p++;

                    if (!terminated || len < 2 || len > 96) continue;

                    // Identifier-like only, to keep false names near zero.
                    uint8_t c0 = s[0];
                    if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_'))
                        continue;
                    bool ok = true;
                    for (size_t i = 0; i < len; i++) {
                        uint8_t c = s[i];
                        bool good = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                    (c >= '0' && c <= '9') || c == '_' || c == ':' || c == '.';
                        if (!good) { ok = false; break; }
                    }
                    if (!ok) continue;

                    std::string str((const char*)s, len);
                    out.emplace(fnv1a_str(str.c_str()), str);
                }
            }
            cur = regEnd;
        }
    }
}

void derive_shadow_component_names(std::unordered_map<uint32_t, std::string>& out,
                                   const std::vector<uint32_t>* wanted) {
    std::unordered_set<uint32_t> want;
    if (wanted) want.insert(wanted->begin(), wanted->end());

    std::vector<std::string> bases;
    bases.reserve(out.size());
    for (const auto& kv : out)
        if (!kv.second.empty() && kv.second.back() != '$') bases.push_back(kv.second);

    for (const std::string& b : bases) {
        std::string s = b + "$";
        uint32_t h = fnv1a_str(s.c_str());
        if (!want.empty() && !want.count(h)) continue;
        out.emplace(h, s);
    }
}
