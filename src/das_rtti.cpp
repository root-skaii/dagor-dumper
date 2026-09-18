#include "../include/das_rtti.h"
#include "../include/scanner.h"
#include "../include/logger.h"
#include <windows.h>
#include <psapi.h>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#include <map>

namespace {

// Sorted committed-readable ranges, so hot loops skip VirtualQuery.
struct Ranges {
    std::vector<std::pair<uintptr_t, uintptr_t>> r;
    void build() {
        r.clear();
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
        uintptr_t e = (uintptr_t)si.lpMaximumApplicationAddress;
        while (a < e) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery((void*)a, &mbi, sizeof(mbi))) break;
            uintptr_t nxt = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (nxt <= a) break;
            constexpr DWORD R = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & R) &&
                !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                if (!r.empty() && r.back().second == (uintptr_t)mbi.BaseAddress)
                    r.back().second = nxt;
                else
                    r.emplace_back((uintptr_t)mbi.BaseAddress, nxt);
            }
            a = nxt;
        }
        std::sort(r.begin(), r.end());
    }
    bool has(uintptr_t lo, size_t len) const {
        if (!lo || !len) return false;
        uintptr_t hi = lo + len;
        if (hi < lo) return false;
        size_t a = 0, b = r.size();
        while (a < b) { size_t m = (a + b) / 2; if (r[m].first <= lo) a = m + 1; else b = m; }
        if (!a) return false;
        return lo >= r[a - 1].first && hi <= r[a - 1].second;
    }
};

Ranges g_rd;
uintptr_t g_modLo = 0, g_modHi = 0;   // bounding box of all loaded images

inline uint64_t r64(uintptr_t a) { return *(const uint64_t*)a; }
inline uint32_t r32(uintptr_t a) { return *(const uint32_t*)a; }

bool looks_like_identifier(uintptr_t p, size_t maxLen = 128) {
    if (p < g_modLo || p >= g_modHi) return false;
    if (!fast_module_string(p)) return false;
    const char* s = (const char*)p;
    char c0 = s[0];
    if (!(isalpha((unsigned char)c0) || c0 == '_')) return false;
    size_t n = 0;
    while (s[n] && n < maxLen) n++;
    return s[n] == 0 && n >= 1;
}

constexpr size_t SI_NAME = 0x00, SI_MODULE = 0x08, SI_FIELDS = 0x10;
constexpr size_t SI_HEADER_SPAN = 0x50;

struct Candidate {
    uintptr_t addr;
    uintptr_t fieldsArr;
    uint32_t  fieldCount;   // derived by walking the array
};

uint32_t count_ptr_run(uintptr_t arr, uint32_t cap = 1024) {
    uint32_t n = 0;
    while (n < cap) {
        uintptr_t slot = arr + 8ull * n;
        if (!g_rd.has(slot, 8)) break;
        uint64_t v = r64(slot);
        if (!v || (v & 7) || !g_rd.has((uintptr_t)v, 0x80)) break;
        n++;
    }
    return n;
}

// SEH per region: the game frees heap constantly, so a region can vanish
// mid-scan. Catching here loses only that region, not the whole scan.
static int scan_region_for_structinfo(uintptr_t s, uintptr_t e,
                                      Candidate* out, int maxOut) {
    int n = 0;
    __try {
        for (uintptr_t a = s; a <= e && n < maxOut; a += 8) {
            uintptr_t nameP = (uintptr_t)r64(a + SI_NAME);
            if (!looks_like_identifier(nameP)) continue;

            // module_name is "" for the builtin module, so no identifier check.
            uintptr_t modP = (uintptr_t)r64(a + SI_MODULE);
            if (modP < g_modLo || modP >= g_modHi) continue;
            if (!g_rd.has(modP, 1)) continue;

            uintptr_t fieldsP = (uintptr_t)r64(a + SI_FIELDS);
            if (!fieldsP || (fieldsP & 7) || !g_rd.has(fieldsP, 8)) continue;

            uint32_t cnt = count_ptr_run(fieldsP);
            if (cnt < 1 || cnt > 1024) continue;

            out[n].addr       = a;
            out[n].fieldsArr  = fieldsP;
            out[n].fieldCount = cnt;
            n++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return n;
}

std::vector<Candidate> find_struct_info_candidates(bool moduleOnly) {
    std::vector<Candidate> out;

    // AOT debug info is baked into the image; the heap sweep is a slow fallback.
    std::vector<SectionRange> raw = enumerate_all_data_sections();
    if (moduleOnly == false)
        for (const auto& r : enumerate_private_regions()) raw.push_back(r);

    // Clip to committed memory up front so the inner loop needs no per-slot checks.
    std::vector<SectionRange> spaces;
    for (const auto& r : raw) {
        uintptr_t lo = r.base, hi = r.base + r.size;
        for (const auto& g : g_rd.r) {
            if (g.second <= lo) continue;
            if (g.first  >= hi) break;
            uintptr_t a = lo > g.first  ? lo : g.first;
            uintptr_t b = hi < g.second ? hi : g.second;
            if (b > a + SI_HEADER_SPAN) spaces.push_back({ a, (size_t)(b - a) });
        }
    }

    static const int kBatch = 4096;
    std::vector<Candidate> batch(kBatch);

    size_t scanned = 0, faulted = 0;
    for (const auto& sec : spaces) {
        uintptr_t s = (sec.base + 7) & ~7ull;
        uintptr_t e = sec.base + sec.size;
        if (e < s + SI_HEADER_SPAN) continue;
        e -= SI_HEADER_SPAN;
        scanned += (size_t)(e - s);

        int n = scan_region_for_structinfo(s, e, batch.data(), kBatch);
        for (int i = 0; i < n; i++) out.push_back(batch[i]);
    }

    LOG_INFO("das RTTI: scanned %.1f MB → %zu StructInfo candidate(s)",
             scanned / (1024.0 * 1024.0), out.size());
    (void)faulted;
    return out;
}

// EnumValueInfo has a name string at +0x00; VarInfo has a pointer or null.
// Anything matching neither (e.g. signature tables) is dropped.
enum class EntryKind { Unknown, EnumValue, VarInfo };

EntryKind classify_entries(const Candidate& c) {
    if (c.fieldCount < 1) return EntryKind::Unknown;

    uint32_t stringAt0 = 0, ptrAt0 = 0, saneValues = 0;
    uint32_t n = c.fieldCount < 32 ? c.fieldCount : 32;

    for (uint32_t i = 0; i < n; i++) {
        uintptr_t e = (uintptr_t)r64(c.fieldsArr + 8ull * i);
        if (!g_rd.has(e, 0x10)) return EntryKind::Unknown;

        uintptr_t first = (uintptr_t)r64(e);
        if (looks_like_identifier(first)) {
            stringAt0++;
            long long v = (long long)r64(e + 8);
            if (v >= -0x7FFFFFFFll && v <= 0x7FFFFFFFll) saneValues++;
        } else if (first == 0 || g_rd.has(first, 8)) {
            ptrAt0++;
        }
    }

    if (stringAt0 == n && saneValues == n) return EntryKind::EnumValue;
    if (ptrAt0 == n)                        return EntryKind::VarInfo;
    return EntryKind::Unknown;
}

constexpr size_t VI_SEARCH_SPAN = 0x100;

struct LayoutVote {
    std::unordered_map<size_t, uint32_t> nameVotes, offsetVotes, sizeVotes, typeVotes;
};

void vote_layout(const Candidate& c, LayoutVote& v) {
    if (c.fieldCount < 2) return;   // a single field can't show a trend

    std::vector<uintptr_t> vis;
    vis.reserve(c.fieldCount);
    for (uint32_t i = 0; i < c.fieldCount; i++) {
        uintptr_t p = (uintptr_t)r64(c.fieldsArr + 8ull * i);
        if (!g_rd.has(p, VI_SEARCH_SPAN)) return;
        vis.push_back(p);
    }

    for (size_t o = 0; o + 8 <= VI_SEARCH_SPAN; o += 8) {
        bool all = true;
        std::unordered_set<uintptr_t> distinct;
        for (uintptr_t vi : vis) {
            uintptr_t sp = (uintptr_t)r64(vi + o);
            if (!looks_like_identifier(sp)) { all = false; break; }
            distinct.insert(sp);
        }
        // Field names within a struct are unique, so the pointers must differ.
        if (all && distinct.size() == vis.size()) v.nameVotes[o]++;
    }

    // Offset column: first == 0, strictly increasing, and small enough that the
    // high half of a pointer (0x7FF7...) can't pass.
    for (size_t o = 0; o + 4 <= VI_SEARCH_SPAN; o += 4) {
        uint32_t prev = 0;
        bool ok = (r32(vis[0] + o) == 0);
        for (size_t i = 1; ok && i < vis.size(); i++) {
            uint32_t val = r32(vis[i] + o);
            if (val <= prev || val > 0x4000) ok = false;
            prev = val;
        }
        if (ok && prev > 0) v.offsetVotes[o]++;
    }
}

size_t best_vote(const std::unordered_map<size_t, uint32_t>& m, uint32_t minVotes = 3) {
    size_t best = SIZE_MAX; uint32_t bestN = 0;
    for (const auto& kv : m)
        if (kv.second > bestN || (kv.second == bestN && kv.first < best)) { bestN = kv.second; best = kv.first; }
    return bestN >= minVotes ? best : SIZE_MAX;
}

// The size column is the one where offset[i] + size[i] <= offset[i+1] for all i.
size_t discover_size_offset(const std::vector<Candidate>& cands, size_t offsetOfs) {
    std::unordered_map<size_t, uint32_t> votes;
    uint32_t used = 0;
    for (const auto& c : cands) {
        if (c.fieldCount < 3) continue;
        std::vector<uintptr_t> vis;
        bool ok = true;
        for (uint32_t i = 0; i < c.fieldCount && ok; i++) {
            uintptr_t p = (uintptr_t)r64(c.fieldsArr + 8ull * i);
            if (!g_rd.has(p, VI_SEARCH_SPAN)) ok = false; else vis.push_back(p);
        }
        if (!ok) continue;

        for (size_t o = 0; o + 4 <= VI_SEARCH_SPAN; o += 4) {
            if (o == offsetOfs) continue;
            bool good = true;
            for (size_t i = 0; good && i + 1 < vis.size(); i++) {
                uint32_t sz  = r32(vis[i] + o);
                uint32_t cur = r32(vis[i] + offsetOfs);
                uint32_t nxt = r32(vis[i + 1] + offsetOfs);
                if (sz == 0 || sz > 0x10000) good = false;
                else if (cur + sz > nxt)      good = false;
            }
            if (good) votes[o]++;
        }
        if (++used >= 64) break;
    }
    return best_vote(votes, 3);
}

} // namespace

static void das_rtti_impl(DasRttiResult& res) {
    LOG_SECTION("daScript RTTI: native struct field offsets");

    g_rd.build();
    g_modLo = ~(uintptr_t)0; g_modHi = 0;
    for (const auto& m : enumerate_modules()) {
        if (m.base < g_modLo) g_modLo = m.base;
        if (m.base + m.size > g_modHi) g_modHi = m.base + m.size;
    }
    if (g_modLo > g_modHi) { LOG_WARN("no modules?"); return; }

    auto cands = find_struct_info_candidates(/*moduleOnly=*/true);
    if (cands.empty()) {
        LOG_INFO("nothing in module data — retrying over private memory (slow)");
        cands = find_struct_info_candidates(/*moduleOnly=*/false);
    }
    res.candidatesSeen = (uint32_t)cands.size();
    if (cands.empty()) {
        LOG_WARN("no daScript type-info records found — this build may not ship "
                 "daScript bindings, or type info has not been materialised yet");
        return;
    }

    std::vector<Candidate> structCands, enumCands;
    for (const auto& c : cands) {
        switch (classify_entries(c)) {
            case EntryKind::VarInfo:   structCands.push_back(c); break;
            case EntryKind::EnumValue: enumCands.push_back(c);   break;
            default: break;
        }
    }
    LOG_INFO("das RTTI: %zu candidate(s) → %zu struct-like, %zu enum-like, %zu other",
             cands.size(), structCands.size(), enumCands.size(),
             cands.size() - structCands.size() - enumCands.size());

    // EnumValueInfo { const char* name; int64_t value; }
    {
        std::map<std::string, DasEnum> uniq;
        for (const auto& c : enumCands) {
            DasEnum de;
            de.addr       = c.addr;
            de.name       = (const char*)r64(c.addr + SI_NAME);
            uintptr_t mp  = (uintptr_t)r64(c.addr + SI_MODULE);
            de.moduleName = g_rd.has(mp, 1) ? (const char*)mp : "";
            for (uint32_t i = 0; i < c.fieldCount; i++) {
                uintptr_t e = (uintptr_t)r64(c.fieldsArr + 8ull * i);
                if (!g_rd.has(e, 0x10)) break;
                uintptr_t np = (uintptr_t)r64(e);
                if (!looks_like_identifier(np)) break;
                DasEnumValue v;
                v.name  = (const char*)np;
                v.value = (long long)r64(e + 8);
                de.values.push_back(v);
            }
            if (de.values.empty()) continue;
            std::string key = de.moduleName.empty() ? de.name : de.moduleName + "::" + de.name;
            auto it = uniq.find(key);
            if (it == uniq.end() || it->second.values.size() < de.values.size())
                uniq[key] = de;
        }
        for (auto& kv : uniq) res.enums.push_back(kv.second);
        std::sort(res.enums.begin(), res.enums.end(),
                  [](const DasEnum& a, const DasEnum& b) {
                      if (a.moduleName != b.moduleName) return a.moduleName < b.moduleName;
                      return a.name < b.name;
                  });
    }

    if (structCands.empty()) {
        LOG_WARN("no struct-like records: every candidate decoded as an enum or was "
                 "rejected. %zu enum(s) still recovered.", res.enums.size());
        return;
    }

    LayoutVote votes;
    uint32_t sampled = 0;
    for (const auto& c : structCands) {
        vote_layout(c, votes);
        if (++sampled >= 512) break;
    }
    res.varInfoNameOfs   = best_vote(votes.nameVotes);
    res.varInfoOffsetOfs = best_vote(votes.offsetVotes);
    if (res.varInfoNameOfs == SIZE_MAX || res.varInfoOffsetOfs == SIZE_MAX) {
        LOG_WARN("could not agree on a VarInfo layout across %u struct candidate(s) "
                 "(name=%s offset=%s) — no field offsets emitted",
                 sampled,
                 res.varInfoNameOfs   == SIZE_MAX ? "?" : "ok",
                 res.varInfoOffsetOfs == SIZE_MAX ? "?" : "ok");
        return;
    }
    res.varInfoSizeOfs = discover_size_offset(structCands, res.varInfoOffsetOfs);

    LOG_INFO("VarInfo layout discovered: name=+0x%02zX offset=+0x%02zX size=%s "
             "(from %u sampled struct(s))",
             res.varInfoNameOfs, res.varInfoOffsetOfs,
             res.varInfoSizeOfs == SIZE_MAX ? "?" : "found", sampled);

    std::map<std::string, DasStruct> uniq;
    for (const auto& c : structCands) {
        DasStruct ds;
        ds.addr       = c.addr;
        ds.name       = (const char*)r64(c.addr + SI_NAME);
        uintptr_t mp  = (uintptr_t)r64(c.addr + SI_MODULE);
        ds.moduleName = g_rd.has(mp, 1) ? (const char*)mp : "";

        // Block/function signature tables pass the VarInfo test; drop them by name.
        if (ds.name.rfind("invoke block<", 0) == 0 ||
            ds.name.rfind("block<", 0) == 0 ||
            ds.name.rfind("lambda<", 0) == 0 ||
            ds.name.rfind("function<", 0) == 0) continue;

        bool ok = true;
        uint32_t maxEnd = 0, prevOfs = 0;
        for (uint32_t i = 0; i < c.fieldCount; i++) {
            uintptr_t vi = (uintptr_t)r64(c.fieldsArr + 8ull * i);
            if (!g_rd.has(vi, VI_SEARCH_SPAN)) { ok = false; break; }
            uintptr_t np = (uintptr_t)r64(vi + res.varInfoNameOfs);
            if (!looks_like_identifier(np)) { ok = false; break; }

            DasField fld;
            fld.name   = (const char*)np;
            fld.offset = r32(vi + res.varInfoOffsetOfs);
            if (res.varInfoSizeOfs != SIZE_MAX) fld.size = r32(vi + res.varInfoSizeOfs);
            // Re-check per record so one bad struct can't pass on the majority vote.
            if (fld.offset > 0x4000) { ok = false; break; }
            if (i && fld.offset <= prevOfs) { ok = false; break; }
            prevOfs = fld.offset;
            maxEnd = (std::max)(maxEnd, fld.offset + fld.size);
            ds.fields.push_back(fld);
        }
        if (!ok || ds.fields.empty()) continue;
        ds.size = maxEnd;

        std::string key = ds.moduleName.empty() ? ds.name : ds.moduleName + "::" + ds.name;
        auto it = uniq.find(key);
        if (it == uniq.end() || it->second.fields.size() < ds.fields.size())
            uniq[key] = ds;
    }

    res.structs.reserve(uniq.size());
    for (auto& kv : uniq) res.structs.push_back(kv.second);
    std::sort(res.structs.begin(), res.structs.end(),
              [](const DasStruct& a, const DasStruct& b) {
                  if (a.moduleName != b.moduleName) return a.moduleName < b.moduleName;
                  return a.name < b.name;
              });

    size_t totalFields = 0;
    for (const auto& st : res.structs) totalFields += st.fields.size();
    LOG_INFO("das RTTI: %zu struct(s) with %zu field offset(s), %zu enum(s)",
             res.structs.size(), totalFields, res.enums.size());
}

// __try cannot share a frame with C++ unwinding, hence the split.
static void das_trampoline(DasRttiResult& res) { das_rtti_impl(res); }

static bool das_guarded(DasRttiResult* res, DWORD* code) {
    __try { das_trampoline(*res); return true; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) { return false; }
}

DasRttiResult dump_das_rtti() {
    DasRttiResult res;
    DWORD code = 0;
    if (!das_guarded(&res, &code))
        LOG_ERR("das RTTI scan faulted (0x%08X) — a region was freed mid-scan; "
                "returning what was collected", code);
    return res;
}
