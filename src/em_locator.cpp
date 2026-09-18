// Structural discovery of DagorEngine ECS runtime objects. Each step matches a
// signature of the structure's *shape* (which survives a fork), then rejects
// the candidate unless an independent invariant also holds.
//
//   entDescs   two SmallTabs with equal counts: EntityDesc[] with a dense
//              archetype-id distribution, and a near-all-zero u8 SoA array.
//
//   archetypes a record table whose totalEntitiesUsed reproduces, per
//              archetype, the entity histogram counted from entDescs.
//
//   archComps  a u16 array that, for every archetype slice, is a running
//              offset from 0 ending within entitySize (DATA_OFFSET); INDEX
//              is strictly ascending cidx per slice.
//
//   cidx table a heap array of known component-name hashes with "eid" at
//              index 0, whose "transform" cidx appears in archComps INDEX.
#include "../include/ecs_runtime.h"
#include "../include/logger.h"
#include <psapi.h>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <set>

// Readable-region cache so the hot loops skip VirtualQuery.
namespace {

struct RegionCache {
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges; // [lo, hi)
    void build() {
        ranges.clear();
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
        uintptr_t end  = (uintptr_t)si.lpMaximumApplicationAddress;
        while (addr < end) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;
            uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            constexpr DWORD R = PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY;
            if (mbi.State == MEM_COMMIT && (mbi.Protect & R) &&
                !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
                if (!ranges.empty() && ranges.back().second == (uintptr_t)mbi.BaseAddress)
                    ranges.back().second = next;
                else
                    ranges.emplace_back((uintptr_t)mbi.BaseAddress, next);
            }
            addr = next;
        }
        std::sort(ranges.begin(), ranges.end());
    }
    bool contains(uintptr_t lo, size_t len) const {
        if (!lo || len == 0) return false;
        uintptr_t hi = lo + len;
        if (hi < lo) return false;
        size_t a = 0, b = ranges.size();
        while (a < b) { size_t m = (a + b) / 2; if (ranges[m].first <= lo) a = m + 1; else b = m; }
        if (a == 0) return false;
        return hi <= ranges[a - 1].second && lo >= ranges[a - 1].first;
    }
};

RegionCache g_regions;

// Sections can have uncommitted holes inside VirtualSize, so clip before scanning.
std::vector<SectionRange> clip_to_readable(const std::vector<SectionRange>& in) {
    std::vector<SectionRange> out;
    for (const auto& r : in) {
        uintptr_t lo = r.base, hi = r.base + r.size;
        for (const auto& g : g_regions.ranges) {
            if (g.second <= lo) continue;
            if (g.first  >= hi) break;
            uintptr_t a = lo > g.first ? lo : g.first;
            uintptr_t b = hi < g.second ? hi : g.second;
            if (b > a + 0x40) out.push_back({ a, (size_t)(b - a) });
        }
    }
    return out;
}

// 2^24-bit prefilter so the common non-matching case is one bit test, not a set lookup.
struct HashFilter {
    static constexpr uint32_t BITS = 1u << 24;
    std::vector<uint64_t> bits;
    void build(const std::vector<uint32_t>& v) {
        bits.assign(BITS / 64, 0);
        for (uint32_t h : v) { uint32_t i = h & (BITS - 1); bits[i >> 6] |= 1ull << (i & 63); }
    }
    inline bool maybe(uint32_t h) const {
        uint32_t i = h & (BITS - 1);
        return (bits[i >> 6] >> (i & 63)) & 1;
    }
};

inline bool rd_ok(uintptr_t a, size_t n)  { return g_regions.contains(a, n); }
inline uint64_t rd64(uintptr_t a) { return *(const uint64_t*)a; }
inline uint32_t rd32(uintptr_t a) { return *(const uint32_t*)a; }
inline uint16_t rd16(uintptr_t a) { return *(const uint16_t*)a; }
inline uint8_t  rd8 (uintptr_t a) { return *(const uint8_t*) a; }

} // namespace

TupleVecInfo decode_tuple_vector_at(uintptr_t obj_addr, uint32_t max_leaves) {
    TupleVecInfo info;
    if (!rd_ok(obj_addr, 8 * (size_t)max_leaves + 0x20)) return info;

    const uint64_t leaf0 = rd64(obj_addr);
    if (!leaf0) return info;

    for (uint32_t n = 1; n <= max_leaves; n++) {
        uintptr_t mp = obj_addr + 8ull * n;
        if (!rd_ok(mp, 0x18)) break;
        if (rd64(mp) != leaf0) continue;

        uint32_t cnt = rd32(mp + 0x08);
        uint32_t cap = rd32(mp + 0x0C);
        uint32_t dsz = rd32(mp + 0x10);
        if (cnt > cap || cap == 0 || cap > (1u << 26)) continue;
        if (dsz == 0 || dsz > (1u << 30)) continue;

        // All leaves lie inside the single allocation, ascending.
        bool ok = true;
        uint64_t prev = 0;
        for (uint32_t i = 0; i < n && ok; i++) {
            uint64_t li = rd64(obj_addr + 8ull * i);
            if (li < leaf0 || li >= leaf0 + dsz) ok = false;
            else if (li < prev)                  ok = false;
            prev = li;
        }
        if (!ok) continue;

        info.addr = obj_addr;
        info.leafCount = n;
        for (uint32_t i = 0; i < n && i < 16; i++) info.leaf[i] = (uintptr_t)rd64(obj_addr + 8ull * i);
        info.mpData = (uintptr_t)leaf0;
        info.numElements = cnt;
        info.numCapacity = cap;
        info.dataSize = dsz;
        return info;
    }
    return info;
}

namespace {

struct EntDescCandidate {
    uintptr_t structAddr;
    uintptr_t arrayAddr;
    uint32_t  count;
    uint32_t  capacity;
    uint32_t  live;
    uint32_t  distinctArch;
    uint32_t  maxArch;
    uint32_t  score;
};

// EntityDesc[] test. Density of archetype ids is what rejects random data.
bool score_entdesc_array(uintptr_t arr, uint32_t n,
                         uint32_t& live, uint32_t& distinct, uint32_t& maxArch) {
    live = distinct = maxArch = 0;
    uint32_t check = n < 4096 ? n : 4096;
    if (check < 16) return false;
    if (!rd_ok(arr, (size_t)check * 8)) return false;

    std::set<uint32_t> archs;
    uint32_t freeSlots = 0, bad = 0;
    for (uint32_t i = 0; i < check; i++) {
        uint32_t lo = rd32(arr + 8ull * i);
        uint32_t hi = rd32(arr + 8ull * i + 4);
        uint16_t archetype = (uint16_t)(lo & 0xFFFF);
        uint32_t idInChunk = hi >> 18;

        if (archetype == INVALID_ARCHETYPE) { freeSlots++; continue; }
        if (idInChunk >= (1u << 14)) { bad++; continue; }
        live++;
        archs.insert(archetype);
        if (archetype > maxArch) maxArch = archetype;
    }
    distinct = (uint32_t)archs.size();
    if (live == 0) return false;
    if (bad * 4 > check) return false;
    if (distinct * 2 > live && live > 32) return false;

    // Ids are allocated sequentially from 0, so in-use ids cluster at the bottom.
    if (maxArch > distinct * 8 + 64) return false;
    (void)freeSlots;
    return true;
}

// g_entity_mgr is InitOnDemandValidateThread<EntityManager, false>, which stores
// the object inline, so it normally lives in module .bss. The heap sweep is only
// for DAGOR_PREFER_HEAP_ALLOCATION builds and is slow.
enum class ScanSpace { ModuleData, PrivateHeap };

std::vector<EntDescCandidate> find_entity_descriptors(ScanSpace where) {
    std::vector<EntDescCandidate> out;

    std::vector<SectionRange> raw = (where == ScanSpace::ModuleData)
                                  ? enumerate_all_data_sections()
                                  : enumerate_private_regions();
    std::vector<SectionRange> ranges = clip_to_readable(raw);

    size_t scanned = 0;
    for (const auto& r : ranges) {
        uintptr_t s = (r.base + 7) & ~7ull;
        uintptr_t e = r.base + r.size;
        if (e < s + 0x30) continue;
        e -= 0x30;
        scanned += (size_t)(e - s);

        for (uintptr_t a = s; a < e; a += 8) {
            uint64_t p0 = rd64(a);
            if (!p0 || (p0 & 7)) continue;
            uint32_t n0 = rd32(a + 0x08);
            uint32_t c0 = rd32(a + 0x0C);
            if (n0 < 16 || n0 > (1u << 22) || c0 < n0) continue;
            // entDescs is resized exactly, so capacity tracks count closely.
            if (c0 > n0 * 2 + 4096) continue;

            // currentlyCreatingEntitiesCnt: SoA, same count
            uint64_t p1 = rd64(a + 0x10);
            if (!p1) continue;
            uint32_t n1 = rd32(a + 0x18);
            uint32_t c1 = rd32(a + 0x1C);
            if (n1 != n0 || c1 < n1 || c1 > n1 * 2 + 4096) continue;

            // totalSize includes entities scheduled for creation.
            uint32_t totalSize = rd32(a + 0x20);
            if (totalSize < n0 || totalSize > n0 + 65536) continue;

            if (!rd_ok((uintptr_t)p0, (size_t)n0 * 8)) continue;
            if (!rd_ok((uintptr_t)p1, n1)) continue;

            uint32_t live = 0, distinct = 0, maxArch = 0;
            if (!score_entdesc_array((uintptr_t)p0, n0, live, distinct, maxArch)) continue;

            // The creating-counter array is almost all zeros in a settled game.
            uint32_t sample = n1 < 1024 ? n1 : 1024, nonzero = 0;
            for (uint32_t i = 0; i < sample; i++) if (rd8((uintptr_t)p1 + i)) nonzero++;
            if (nonzero * 8 > sample) continue;

            EntDescCandidate cand{};
            cand.structAddr = a;
            cand.arrayAddr  = (uintptr_t)p0;
            cand.count      = n0;
            cand.capacity   = c0;
            cand.live       = live;
            cand.distinctArch = distinct;
            cand.maxArch    = maxArch;
            // The downstream histogram match is only as strong as its bucket
            // count, so archetype diversity dominates the score.
            cand.score      = distinct * 64 + live * 2;
            out.push_back(cand);
        }
    }

    LOG_INFO("entDescs: scanned %.1f MB of %s, %zu candidate(s)",
             scanned / (1024.0 * 1024.0),
             where == ScanSpace::ModuleData ? "module data" : "private heap",
             out.size());
    std::sort(out.begin(), out.end(),
              [](const EntDescCandidate& x, const EntDescCandidate& y) { return x.score > y.score; });
    for (size_t i = 0; i < out.size() && i < 8; i++)
        LOG_INFO("  cand[%zu] struct=0x%016llX arr=0x%016llX slots=%u cap=%u live=%u archs=%u maxArch=%u score=%u",
                 i, (unsigned long long)out[i].structAddr, (unsigned long long)out[i].arrayAddr,
                 out[i].count, out[i].capacity, out[i].live, out[i].distinctArch,
                 out[i].maxArch, out[i].score);
    return out;
}

// `rec` must already be known readable.
bool archetype_record_plausible(uintptr_t rec) {
    const ArchetypeView* a = (const ArchetypeView*)rec;
    if (a->entitySize == 0 || a->componentsCnt == 0) return false;
    if (a->componentsCnt > 4096) return false;
    if (a->totalEntitiesUsed > a->totalEntitiesCapacity) return false;
    if (a->totalEntitiesCapacity > (1u << 24)) return false;
    // <= 14, or 32 for the empty-chunk sentinel.
    if (a->chunk0_capBits > 14 && a->chunk0_capBits != 32) return false;
    if (a->currentCapacityBits > 14) return false;
    if (a->initialBits > 14) return false;
    if (a->chunk0_data && (a->chunk0_data & 3)) return false;
    return true;
}

// Archetypes: entDescs gives the exact entity count per archetype, so look for
// a table where totalEntitiesUsed[a] == histogram[a] for every a <= maxArch.
// Only the real table reproduces that.
struct ArchCandidate {
    uintptr_t tupleVec;     // 0 when only the array was located
    uintptr_t base;
    uint32_t  count;
    uint32_t  sumEntities;
    uint32_t  stride;
    size_t    usedOfs;
};

constexpr size_t kEmWindow = 0x100000;   // +/- 1 MB

// Readable sub-ranges of anchor +/- kEmWindow.
std::vector<std::pair<uintptr_t, uintptr_t>> windows_around(uintptr_t anchor) {
    std::vector<std::pair<uintptr_t, uintptr_t>> out;
    uintptr_t lo = anchor > kEmWindow ? anchor - kEmWindow : 0;
    uintptr_t hi = anchor + kEmWindow;
    for (const auto& g : g_regions.ranges) {
        if (g.second <= lo) continue;
        if (g.first  >= hi) break;
        uintptr_t a = lo > g.first  ? lo : g.first;
        uintptr_t b = hi < g.second ? hi : g.second;
        if (b > a + 0x40) out.emplace_back(a, b);
    }
    return out;
}

bool window_around(uintptr_t anchor, uintptr_t& lo, uintptr_t& hi) {
    auto w = windows_around(anchor);
    if (w.empty()) return false;
    lo = w.front().first;
    hi = w.back().second;
    return true;
}

// First entry is the engine-source layout; the rest cover a fork that added a
// member, and are logged loudly if they win since every offset shifts.
struct ArchShape { uint32_t stride; size_t usedOfs; size_t entitySizeOfs; size_t compCntOfs; };
const ArchShape kArchShapes[] = {
    { 32, 0x10, 0x1C, 0x1E },   // engine source
    { 40, 0x10, 0x24, 0x26 },
    { 48, 0x10, 0x2C, 0x2E },
    { 40, 0x18, 0x24, 0x26 },
    { 48, 0x18, 0x2C, 0x2E },
};
ArchShape g_archShape = kArchShapes[0];

std::vector<ArchCandidate> find_archetypes_near(uintptr_t entDescsAddr,
                                                uintptr_t entDescsArray,
                                                uint32_t entDescsSlots,
                                                uint32_t liveEntities,
                                                uint32_t maxArchSeen) {
    std::vector<ArchCandidate> out;

    std::vector<uint32_t> histo(maxArchSeen + 1, 0);
    for (uint32_t i = 0; i < entDescsSlots; i++) {
        uint16_t a = (uint16_t)(rd32(entDescsArray + 8ull * i) & 0xFFFF);
        if (a == INVALID_ARCHETYPE || a > maxArchSeen) continue;
        histo[a]++;
    }

    auto wins = windows_around(entDescsAddr);
    size_t bytes = 0;
    for (const auto& w : wins) bytes += (size_t)(w.second - w.first);

    for (const auto& shape : kArchShapes) {
        for (const auto& w : wins) {
            for (uintptr_t p = (w.first + 7) & ~7ull; p + 8 <= w.second; p += 8) {
                uint64_t arr = rd64(p);
                if (!arr || (arr & 3)) continue;
                if (!rd_ok((uintptr_t)arr, (size_t)shape.stride * (maxArchSeen + 1))) continue;

                // Histogram match plus a per-record sanity check; with few
                // buckets the histogram alone matches almost anything.
                bool match = true;
                for (uint32_t a = 0; a <= maxArchSeen && match; a++) {
                    uintptr_t rec = (uintptr_t)arr + (size_t)shape.stride * a;
                    if (rd32(rec + shape.usedOfs) != histo[a]) { match = false; break; }
                    if (shape.stride == 32 && !archetype_record_plausible(rec)) match = false;
                }
                if (!match) continue;

                // Extend past maxArch: empty archetypes are invisible to the histogram.
                uint32_t n = maxArchSeen + 1;
                uint64_t sum = liveEntities;
                while (n < 65535) {
                    uintptr_t rec = (uintptr_t)arr + (size_t)shape.stride * n;
                    if (!rd_ok(rec, shape.stride)) break;
                    uint16_t esz = rd16(rec + shape.entitySizeOfs);
                    uint16_t cnt = rd16(rec + shape.compCntOfs);
                    uint32_t used = rd32(rec + shape.usedOfs);
                    if (esz == 0 || cnt == 0 || cnt > 4096 || used > (1u << 24)) break;
                    sum += used;
                    n++;
                }

                g_archShape = shape;
                out.push_back({ 0, (uintptr_t)arr, n, (uint32_t)sum, shape.stride, shape.usedOfs });
                if (out.size() >= 8) break;
            }
            if (out.size() >= 8) break;
        }
        if (!out.empty()) {
            if (shape.stride != 32 || shape.usedOfs != 0x10)
                LOG_WARN("Archetype record shape is NOT the engine-source one: "
                         "stride=%u used=+0x%02zX entitySize=+0x%02zX componentsCnt=+0x%02zX "
                         "— this fork changed DataComponentManager",
                         shape.stride, shape.usedOfs, shape.entitySizeOfs, shape.compCntOfs);
            break;
        }
    }

    LOG_INFO("archetypes: searched %.2f MB around entDescs (%zu window(s)) for a table "
             "reproducing the %u-bucket entity histogram → %zu hit(s)",
             bytes / (1024.0 * 1024.0), wins.size(), maxArchSeen + 1, out.size());

    // Best effort: locate the owning tuple_vector.
    if (!out.empty()) {
        for (const auto& w : wins) {
            bool done = false;
            for (uintptr_t p = (w.first + 7) & ~7ull; p + 0x60 <= w.second; p += 8) {
                if (rd64(p) != (uint64_t)out.front().base) continue;
                TupleVecInfo tv = decode_tuple_vector_at(p);
                // The container's element count beats the walk-derived estimate.
                if (tv.valid() && tv.numElements >= maxArchSeen + 1 &&
                    tv.numElements <= 65535) {
                    out.front().count = tv.numElements;
                    out.front().tupleVec = p;
                    LOG_INFO("archetypes tuple_vector at 0x%016llX (%u leaves, %u elems)",
                             (unsigned long long)p, tv.leafCount, tv.numElements);
                    done = true;
                    break;
                }
            }
            if (done) break;
        }
        if (!out.front().tupleVec)
            LOG_INFO("archetypes array found at 0x%016llX; owning tuple_vector not "
                     "identified (harmless — the array is what matters)",
                     (unsigned long long)out.front().base);
    }
    return out;
}

// Confirm a (DATA_OFFSET, DATA_SIZE) pair by replaying addArchetype's layout:
// per slice, DATA_OFFSET starts at 0, steps by DATA_SIZE, and sums to entitySize.
bool validate_arch_comp_pair(uintptr_t offArr, uintptr_t sizeArr,
                             uintptr_t archArr, uint32_t archCount,
                             const std::vector<uint32_t>& compOfs) {
    uint32_t checked = 0;
    for (uint32_t a = 0; a < archCount; a++) {
        uintptr_t rec = archArr + (size_t)g_archShape.stride * a;
        uint32_t cnt  = rd16(rec + g_archShape.compCntOfs);
        uint32_t esz  = rd16(rec + g_archShape.entitySizeOfs);
        uint32_t ofs  = compOfs[a];
        if (!cnt) continue;
        if (!rd_ok(offArr  + 2ull * ofs, 2ull * cnt)) return false;
        if (!rd_ok(sizeArr + 2ull * ofs, 2ull * cnt)) return false;

        uint32_t running = 0;
        for (uint32_t i = 0; i < cnt; i++) {
            if (rd16(offArr + 2ull * (ofs + i)) != (uint16_t)running) return false;
            running += rd16(sizeArr + 2ull * (ofs + i));
        }
        if (running != esz) return false;
        if (++checked >= 64) break;
    }
    return checked > 0;
}

} // namespace

static void discover_ecs_runtime_impl(const std::vector<uint32_t>& known_component_hashes,
                                      EcsRuntimeOffsets& o) {
    LOG_SECTION("ECS runtime discovery");
    g_regions.build();
    LOG_INFO("region cache: %zu readable ranges", g_regions.ranges.size());

    LOG_SECTION("discover: EntitiesDescriptors");
    auto entCands = find_entity_descriptors(ScanSpace::ModuleData);
    bool fromModule = !entCands.empty();
    if (entCands.empty()) {
        LOG_WARN("nothing in module data — this build probably heap-allocates the "
                 "EntityManager (DAGOR_PREFER_HEAP_ALLOCATION); falling back to a "
                 "private-memory sweep, which is slow");
        entCands = find_entity_descriptors(ScanSpace::PrivateHeap);
    }
    if (entCands.empty()) {
        LOG_ERR("entDescs not found — nothing else can be anchored; aborting discovery");
        return;
    }
    for (size_t i = 0; i < entCands.size() && i < 8; i++)
        LOG_INFO("  cand[%zu] struct=0x%016llX arr=0x%016llX slots=%u cap=%u "
                 "live=%u archs=%u maxArch=%u score=%u",
                 i, (unsigned long long)entCands[i].structAddr,
                 (unsigned long long)entCands[i].arrayAddr,
                 entCands[i].count, entCands[i].capacity, entCands[i].live,
                 entCands[i].distinctArch, entCands[i].maxArch, entCands[i].score);

    // Best-first, confirmed only when an archetype table agrees. Pass 0 skips
    // low-diversity candidates so a degenerate buffer can't win.
    LOG_SECTION("discover: Archetypes");
    constexpr uint32_t kMinBuckets = 3;
    for (int pass = 0; pass < 2 && !o.archetypesValidated; pass++) {
    if (pass == 1)
        LOG_WARN("no candidate had >= %u distinct archetypes; retrying with the "
                 "weak ones (a 1-bucket histogram is barely evidence)", kMinBuckets);
    for (size_t ci = 0; ci < entCands.size() && ci < 16; ci++) {
        const auto& c = entCands[ci];
        if (pass == 0 && c.distinctArch < kMinBuckets) continue;
        if (pass == 1 && c.distinctArch >= kMinBuckets) continue;
        o.entDescsStruct = c.structAddr;
        o.entDescsArray  = c.arrayAddr;
        o.entitySlots    = c.count;
        o.entitySlotsCap = c.capacity;

        // Full recount; scoring only sampled 4096 rows.
        uint32_t live = 0, maxArch = 0;
        for (uint32_t i = 0; i < c.count; i++) {
            uint16_t arch = (uint16_t)(rd32(c.arrayAddr + 8ull * i) & 0xFFFF);
            if (arch == INVALID_ARCHETYPE) continue;
            live++;
            if (arch > maxArch) maxArch = arch;
        }
        o.liveEntities = live;

        auto archCands = find_archetypes_near(c.structAddr, c.arrayAddr,
                                             c.count, live, maxArch);
        LOG_INFO("  cand[%zu] struct=0x%016llX live=%u maxArch=%u → %zu archetype table(s)",
                 ci, (unsigned long long)c.structAddr, live, maxArch, archCands.size());
        if (archCands.empty()) continue;

        std::sort(archCands.begin(), archCands.end(),
                  [live](const ArchCandidate& x, const ArchCandidate& y) {
                      uint32_t dx = x.sumEntities > live ? x.sumEntities - live : live - x.sumEntities;
                      uint32_t dy = y.sumEntities > live ? y.sumEntities - live : live - y.sumEntities;
                      return dx < dy;
                  });

        const auto& ac = archCands.front();
        // ArchetypeView only matches the 32-byte layout; for any other shape,
        // report the table but don't read fields through it.
        if (ac.stride != 32 || ac.usedOfs != 0x10) {
            o.archetypeArray  = ac.base;
            o.archetypeCount  = ac.count;
            o.archetypeStride = ac.stride;
            o.sumArchEntities = ac.sumEntities;
            LOG_ERR("archetype table found at 0x%016llX with a NON-STANDARD record "
                    "shape (stride=%u used=+0x%02zX). Per-component reads are disabled: "
                    "update ArchetypeView in ecs_runtime.h to match this fork.",
                    (unsigned long long)ac.base, ac.stride, ac.usedOfs);
            break;
        }
        o.archetypeStride     = ac.stride;
        o.maxArchetypeSeen    = maxArch;
        o.archetypesTupleVec  = ac.tupleVec;
        o.archetypeArray      = ac.base;
        o.archetypeCount      = ac.count;
        o.sumArchEntities     = ac.sumEntities;
        o.archetypesValidated = true;

        // Holds even after Archetypes::remap, which compacts in order.
        o.componentOfs.resize(ac.count);
        uint32_t running = 0;
        for (uint32_t a = 0; a < ac.count; a++) {
            o.componentOfs[a] = running;
            running += rd16(ac.base + (size_t)g_archShape.stride * a + g_archShape.compCntOfs);
        }
        o.archCompCount = running;

        LOG_INFO("archetypes CONFIRMED: tupleVec=0x%016llX array=0x%016llX "
                 "count=%u sumEntities=%u (live=%u) componentSlots=%u",
                 (unsigned long long)ac.tupleVec, (unsigned long long)ac.base,
                 ac.count, ac.sumEntities, live, running);
        break;
    }
    }

    if (!o.archetypesValidated) {
        LOG_WARN("archetype table not confirmed — entity enumeration still usable, "
                 "component reads are not");
    }

    // archetypeComponents. DATA_OFFSET alone suffices: sizes are its successive
    // differences, the last one being entitySize - DATA_OFFSET[last].
    if (o.archetypesValidated && o.archCompCount) {
        LOG_SECTION("discover: archetypeComponents");

        // Candidate pointers: near entDescs, and near wherever the archetype
        // array pointer is held (Archetypes may be far from entDescs).
        std::vector<uintptr_t> ptrs;
        auto harvest = [&](uintptr_t anchor) {
            for (const auto& w : windows_around(anchor)) {
                for (uintptr_t p = (w.first + 7) & ~7ull; p + 8 <= w.second; p += 8) {
                    uint64_t v = rd64(p);
                    if (!v || (v & 1)) continue;
                    if (!rd_ok((uintptr_t)v, 0x40)) continue;
                    ptrs.push_back((uintptr_t)v);
                }
            }
        };
        harvest(o.entDescsStruct);

        uint32_t holders = 0;
        for (const auto& sec : clip_to_readable(enumerate_all_data_sections())) {
            uintptr_t s2 = (sec.base + 7) & ~7ull, e2 = sec.base + sec.size;
            if (e2 < s2 + 8) continue;
            e2 -= 8;
            for (uintptr_t p = s2; p <= e2; p += 8) {
                if (rd64(p) != (uint64_t)o.archetypeArray) continue;
                holders++;
                if (holders <= 4) harvest(p);
            }
        }

        std::sort(ptrs.begin(), ptrs.end());
        ptrs.erase(std::unique(ptrs.begin(), ptrs.end()), ptrs.end());

        // Only archetypes referenced by entities are proven; the walked count
        // can over-reach into heap residue past the end of the table.
        const uint32_t provenArch  = o.maxArchetypeSeen + 1;
        const uint32_t archProbe   = provenArch;
        const uint32_t provenSlots = o.componentOfs[provenArch - 1] +
            rd16(o.archetypeArray + (size_t)g_archShape.stride * (provenArch - 1)
                 + g_archShape.compCntOfs);

        // DATA_OFFSET per slice: starts at 0, non-decreasing (zero-size tag
        // components leave it flat), never past entitySize, and has >= 2
        // distinct values when the archetype stores bytes (rejects zero-filled buffers).
        uintptr_t bestOff = 0;
        uint32_t  bestDepth = 0, offCands = 0;
        for (uintptr_t P : ptrs) {
            if (!rd_ok(P, 2ull * provenSlots)) continue;
            uint32_t depth = 0;
            for (uint32_t a = 0; a < archProbe; a++) {
                uintptr_t rec = o.archetypeArray + (size_t)g_archShape.stride * a;
                uint32_t cnt = rd16(rec + g_archShape.compCntOfs);
                uint32_t esz = rd16(rec + g_archShape.entitySizeOfs);
                if (!cnt) break;
                uint32_t base = o.componentOfs[a];
                if (rd16(P + 2ull * base) != 0) break;

                bool ok = true;
                uint32_t prev = 0, distinct = 1;
                for (uint32_t i = 1; i < cnt; i++) {
                    uint16_t v = rd16(P + 2ull * (base + i));
                    if (v < prev || v > esz) { ok = false; break; }
                    if (v != prev) distinct++;
                    prev = v;
                }
                if (!ok) break;
                if (esz - prev > 8192) break;
                if (esz > 0 && cnt > 1 && distinct < 2) break;
                depth++;
            }
            if (depth) offCands++;
            if (depth > bestDepth) { bestDepth = depth; bestOff = P; }
        }

        // Log the winner's first slice so a near miss is diagnosable.
        if (bestOff) {
            uint32_t cnt0 = rd16(o.archetypeArray + g_archShape.compCntOfs);
            uint32_t esz0 = rd16(o.archetypeArray + g_archShape.entitySizeOfs);
            char buf[256]; int n = 0;
            for (uint32_t i = 0; i < cnt0 && i < 16 && n < 200; i++)
                n += snprintf(buf + n, sizeof(buf) - n, "%s%u",
                              i ? "," : "", rd16(bestOff + 2ull * i));
            LOG_INFO("archComps: best candidate 0x%016llX arch0 slice [%s] "
                     "(entitySize=%u, %u components)",
                     (unsigned long long)bestOff, buf, esz0, cnt0);
        }

        LOG_INFO("archComps: %zu pointer(s) harvested (%u slot(s) hold the archetype "
                 "array) → %u DATA_OFFSET candidate(s), best matches %u/%u archetype(s)",
                 ptrs.size(), holders, offCands, bestDepth, archProbe);

        if (bestOff && bestDepth == archProbe) {
            o.archCompDataOffset = bestOff;
            o.archCompsValidated = true;

            // With DATA_OFFSET trusted, extend while slices still parse to get
            // the real archetype count.
            {
                uint32_t realCount = provenArch;
                uint32_t running   = provenSlots;
                while (realCount < o.archetypeCount) {
                    uintptr_t rec = o.archetypeArray +
                                    (size_t)g_archShape.stride * realCount;
                    uint32_t cnt = rd16(rec + g_archShape.compCntOfs);
                    uint32_t esz = rd16(rec + g_archShape.entitySizeOfs);
                    if (!cnt || cnt > 4096) break;
                    if (!rd_ok(bestOff + 2ull * running, 2ull * cnt)) break;
                    if (rd16(bestOff + 2ull * running) != 0) break;

                    bool ok = true;
                    uint32_t prev = 0, distinct = 1;
                    for (uint32_t i = 1; i < cnt; i++) {
                        uint16_t v = rd16(bestOff + 2ull * (running + i));
                        if (v < prev || v > esz) { ok = false; break; }
                        if (v != prev) distinct++;
                        prev = v;
                    }
                    if (!ok) break;
                    if (esz - prev > 8192) break;
                    if (esz > 0 && cnt > 1 && distinct < 2) break;

                    running += cnt;
                    realCount++;
                }
                if (realCount != o.archetypeCount) {
                    LOG_INFO("archetype count corrected: %u -> %u "
                             "(component slots %u -> %u); the walk had over-reached "
                             "past the end of the table",
                             o.archetypeCount, realCount, o.archCompCount, running);
                    o.archetypeCount = realCount;
                    o.componentOfs.resize(realCount);
                    o.archCompCount = running;
                }
            }

            // Optional: a real DATA_SIZE array agreeing with the derived sizes.
            for (uintptr_t P : ptrs) {
                if (P == bestOff || !rd_ok(P, 2ull * o.archCompCount)) continue;
                if (validate_arch_comp_pair(bestOff, P, o.archetypeArray,
                                            o.archetypeCount, o.componentOfs)) {
                    o.archCompDataSize = P;
                    break;
                }
            }

            // INDEX: cidx, strictly ascending per slice (addArchetype gets a sorted list).
            uintptr_t bestIdx = 0;
            uint32_t bestIdxDepth = 0;
            for (uintptr_t P : ptrs) {
                if (P == o.archCompDataOffset || P == o.archCompDataSize) continue;
                if (!rd_ok(P, 2ull * provenSlots)) continue;
                uint32_t depth = 0;
                for (uint32_t a = 0; a < archProbe; a++) {
                    uintptr_t rec = o.archetypeArray + (size_t)g_archShape.stride * a;
                    uint32_t cnt = rd16(rec + g_archShape.compCntOfs);
                    uint32_t base = o.componentOfs[a];
                    bool ok = true;
                    uint32_t prev = 0;
                    for (uint32_t i = 0; i < cnt; i++) {
                        uint16_t v = rd16(P + 2ull * (base + i));
                        if (v == 0xFFFF) { ok = false; break; }
                        if (i && v <= prev) { ok = false; break; }
                        prev = v;
                    }
                    if (!ok) break;
                    depth++;
                }
                if (depth > bestIdxDepth) { bestIdxDepth = depth; bestIdx = P; }
            }
            if (bestIdxDepth == archProbe) o.archCompIndex = bestIdx;

            if (o.archCompIndex) {
                uint32_t maxCidx = 0;
                for (uint32_t i = 0; i < o.archCompCount; i++) {
                    uint16_t v = rd16(o.archCompIndex + 2ull * i);
                    if (v != 0xFFFF && v > maxCidx) maxCidx = v;
                }
                o.componentCount = maxCidx + 1;
            }

            LOG_INFO("archetypeComponents CONFIRMED: DATA_OFFSET=0x%016llX "
                     "DATA_SIZE=0x%016llX%s INDEX=0x%016llX%s slots=%u maxCidx=%u",
                     (unsigned long long)o.archCompDataOffset,
                     (unsigned long long)o.archCompDataSize,
                     o.archCompDataSize ? "" : " (derived from DATA_OFFSET)",
                     (unsigned long long)o.archCompIndex,
                     o.archCompIndex ? "" : " (not found)",
                     o.archCompCount, o.componentCount ? o.componentCount - 1 : 0);
        } else {
            LOG_WARN("archetypeComponents not found — best candidate satisfied only "
                     "%u of %u archetype slices", bestDepth, archProbe);
        }
    }

    // cidx -> name hash table (DataComponents::components). Searching only near
    // the EntityManager also keeps it off this DLL's own hash vector.
    if (!known_component_hashes.empty() && o.entDescsStruct) {
        LOG_SECTION("discover: DataComponents cidx table");
        // "eid" is created internally, so it's never in the harvested dictionary.
        const uint32_t kEidHash = fnv1a_str("eid");
        HashFilter filter;
        filter.build(known_component_hashes);
        std::unordered_set<uint32_t> known(known_component_hashes.begin(),
                                           known_component_hashes.end());

        const uint32_t probe = o.componentCount ? (std::min)(o.componentCount, 512u) : 512u;
        uint32_t bestHits = 0;
        for (const auto& w : windows_around(o.entDescsStruct)) {
            for (uintptr_t p = (w.first + 7) & ~7ull; p + 8 <= w.second; p += 8) {
                uint64_t v = rd64(p);
                if (!v || (v & 3)) continue;
                uintptr_t arr = (uintptr_t)v;
                if (!rd_ok(arr, 4ull * probe)) continue;

                // The real table is a heap allocation; the image also holds a
                // static hash array starting with "eid" that passes every other test.
                if (is_in_any_module((const void*)arr)) continue;

                // cidx 0 is always "eid". This is what separates it from
                // EventsDB's table, which is also dense known hashes.
                if (rd32(arr) != kEidHash) continue;

                uint32_t hits = 0;
                for (uint32_t i = 0; i < probe; i++) {
                    uint32_t h = rd32(arr + 4ull * i);
                    if (filter.maybe(h) && known.count(h)) hits++;
                }
                // The dictionary doesn't cover every component, so a real table
                // can score well below half; junk scores ~zero.
                if (hits < 16 || hits * 8 < probe) continue;

                // End-to-end: the cidx for "transform" must actually appear in
                // archCompIndex, or this table uses a different numbering.
                if (o.archCompIndex && o.archCompCount) {
                    uint32_t want = fnv1a_str("transform");
                    uint32_t tcidx = 0xFFFFFFFF;
                    for (uint32_t i = 0; i < o.componentCount; i++)
                        if (rd32(arr + 4ull * i) == want) { tcidx = i; break; }
                    if (tcidx == 0xFFFFFFFF) continue;
                    bool used = false;
                    for (uint32_t i = 0; i < o.archCompCount && !used; i++)
                        if (rd16(o.archCompIndex + 2ull * i) == tcidx) used = true;
                    if (!used) {
                        LOG_INFO("  rejected 0x%016llX: transform -> cidx %u, "
                                 "which no archetype uses",
                                 (unsigned long long)arr, tcidx);
                        continue;
                    }
                }

                if (hits > bestHits) { bestHits = hits; o.componentHashArray = arr; }
            }
        }
        if (o.componentHashArray) {
            if (!o.componentCount) o.componentCount = probe;
            LOG_INFO("cidx table CONFIRMED: array=0x%016llX count=%u "
                     "(%u/%u sampled entries are known names)",
                     (unsigned long long)o.componentHashArray, o.componentCount,
                     bestHits, probe);
        } else {
            LOG_WARN("cidx table not found — components will be reported by index only");
        }
    }

    // cidx -> type: DCOMP leaf, 8 bytes per cidx, +0x04 = FNV-1a of the C++ type.
    // Anchored by cidx 0 being ecs::EntityId, and by the column's low cardinality.
    if (o.componentHashArray && o.componentCount && o.entDescsStruct) {
        LOG_SECTION("discover: cidx -> type table");
        const uint32_t kEidTypeHash = fnv1a_str("ecs::EntityId");
        const uint32_t probe = (std::min)(o.componentCount, 512u);

        for (const auto& w : windows_around(o.entDescsStruct)) {
            for (uintptr_t p = (w.first + 7) & ~7ull; p + 8 <= w.second; p += 8) {
                uint64_t v = rd64(p);
                if (!v || (v & 3)) continue;
                uintptr_t arr = (uintptr_t)v;
                if (!rd_ok(arr, 8ull * o.componentCount)) continue;
                if (is_in_any_module((const void*)arr)) continue;
                if (rd32(arr + 4) != kEidTypeHash) continue;

                std::set<uint32_t> distinct;
                bool ok = true;
                for (uint32_t i = 0; i < probe; i++) {
                    uint32_t th = rd32(arr + 8ull * i + 4);
                    if (!th) { ok = false; break; }
                    distinct.insert(th);
                }
                if (!ok || distinct.size() > 512) continue;
                o.componentTypeArray = arr;
                LOG_INFO("cidx->type table CONFIRMED: array=0x%016llX "
                         "(%zu distinct type(s) over %u components)",
                         (unsigned long long)arr, distinct.size(), probe);
                break;
            }
            if (o.componentTypeArray) break;
        }
        if (!o.componentTypeArray)
            LOG_WARN("cidx->type table not found — list elements stay undecoded");
    }

    // As a module static, EntityManager members have restart-stable RVAs.
    if (o.entDescsStruct) {
        for (const auto& m : enumerate_modules()) {
            if (o.entDescsStruct < m.base || o.entDescsStruct >= m.base + m.size) continue;
            o.moduleBase = m.base;
            strncpy_s(o.moduleName, sizeof(o.moduleName), m.name.c_str(), _TRUNCATE);
            LOG_INFO("EntityManager lives in %s at base 0x%016llX — "
                     "entDescs RVA = 0x%08llX (stable across runs)",
                     o.moduleName, (unsigned long long)m.base,
                     (unsigned long long)(o.entDescsStruct - m.base));
            break;
        }
        if (!o.moduleBase)
            LOG_INFO("EntityManager is heap-allocated; addresses are valid for this run only");
    }

    if (o.entityManager) {
        auto rel = [&](uintptr_t a) { return a ? (size_t)(a - o.entityManager) : SIZE_MAX; };
        o.ofsEntDescs       = rel(o.entDescsStruct);
        o.ofsArchetypes     = rel(o.archetypesTupleVec);
        o.ofsArchComps      = rel(o.archCompsTupleVec);
        o.ofsDataComponents = rel(o.dataComponentsTupleVec);
    }

    LOG_INFO("discovery summary: entDescs=%s archetypes=%s archComps=%s cidx=%s",
             o.haveEntities()   ? "OK" : "--",
             o.haveArchetypes() ? "OK" : "--",
             o.haveArchComps()  ? "OK" : "--",
             o.componentHashArray ? "OK" : "--");
}

// A region can be decommitted between VirtualQuery and the read; that fault is
// in the game's process and must not crash it. __try can't share a frame with
// C++ unwinding, hence the trampoline. The impl writes into `out` as it goes,
// so a fault still keeps partial results.
static void discover_trampoline(const std::vector<uint32_t>& h, EcsRuntimeOffsets& out) {
    discover_ecs_runtime_impl(h, out);
}

static bool discover_guarded(const std::vector<uint32_t>* h, EcsRuntimeOffsets* out, DWORD* code) {
    *code = 0;
    __try {
        discover_trampoline(*h, *out);
        return true;
    } __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

EcsRuntimeOffsets discover_ecs_runtime(const std::vector<uint32_t>& known_component_hashes) {
    EcsRuntimeOffsets out;
    DWORD code = 0;
    if (!discover_guarded(&known_component_hashes, &out, &code))
        LOG_ERR("discovery faulted (0x%08lX) — a scanned region was freed mid-scan; "
                "returning partial results", code);
    return out;
}

uint32_t ecs_find_arch_component(const EcsRuntimeOffsets& o, uint32_t archetype, uint16_t cidx) {
    if (!o.haveArchetypes() || !o.archCompIndex) return UINT32_MAX;
    if (archetype >= o.archetypeCount) return UINT32_MAX;
    const ArchetypeView* av = (const ArchetypeView*)(o.archetypeArray + (size_t)o.archetypeStride * archetype);
    uint32_t ofs = o.componentOfs[archetype], cnt = av->componentsCnt;
    if (!rd_ok(o.archCompIndex + 2ull * ofs, 2ull * cnt)) return UINT32_MAX;
    for (uint32_t i = 0; i < cnt; i++)
        if (rd16(o.archCompIndex + 2ull * (ofs + i)) == cidx) return i;
    return UINT32_MAX;
}

uint16_t ecs_cidx_for_hash(const EcsRuntimeOffsets& o, uint32_t name_hash) {
    if (!o.componentHashArray || !o.componentCount) return 0xFFFF;
    for (uint32_t i = 0; i < o.componentCount; i++)
        if (rd32(o.componentHashArray + 4ull * i) == name_hash) return (uint16_t)i;
    return 0xFFFF;
}

uintptr_t ecs_component_data_ptr(const EcsRuntimeOffsets& o,
                                 uint32_t archetype, uint32_t chunkId, uint32_t idInChunk,
                                 uint32_t archLocalComponent, uint16_t* out_size) {
    if (!o.haveArchetypes() || !o.haveArchComps()) return 0;
    if (archetype >= o.archetypeCount) return 0;

    const ArchetypeView* av = (const ArchetypeView*)(o.archetypeArray + (size_t)o.archetypeStride * archetype);
    if (archLocalComponent >= av->componentsCnt) return 0;

    uint32_t slot = o.componentOfs[archetype] + archLocalComponent;
    if (!rd_ok(o.archCompDataOffset + 2ull * slot, 2)) return 0;
    uint16_t dataOfs = rd16(o.archCompDataOffset + 2ull * slot);

    // Without DATA_SIZE: size = step to the next offset, or rest of entitySize.
    uint16_t dataSz;
    if (o.archCompDataSize && rd_ok(o.archCompDataSize + 2ull * slot, 2)) {
        dataSz = rd16(o.archCompDataSize + 2ull * slot);
    } else {
        uint16_t esz = ((const ArchetypeView*)(o.archetypeArray +
                        (size_t)o.archetypeStride * archetype))->entitySize;
        if (archLocalComponent + 1 < av->componentsCnt) {
            if (!rd_ok(o.archCompDataOffset + 2ull * (slot + 1), 2)) return 0;
            uint16_t next = rd16(o.archCompDataOffset + 2ull * (slot + 1));
            if (next < dataOfs) return 0;
            dataSz = (uint16_t)(next - dataOfs);
        } else {
            if (esz < dataOfs) return 0;
            dataSz = (uint16_t)(esz - dataOfs);
        }
    }
    if (out_size) *out_size = dataSz;
    if (!dataSz) return 0;   // tag component, no storage

    uintptr_t chunkRec;
    if (av->isChunkArray) {
        const ChunksArrayView* ca = (const ChunksArrayView*)(o.archetypeArray + (size_t)o.archetypeStride * archetype);
        if (chunkId >= ca->count) return 0;
        if (!rd_ok(ca->ptr + 16ull * chunkId, 16)) return 0;
        chunkRec = ca->ptr + 16ull * chunkId;
    } else {
        if (chunkId != 0) return 0;
        chunkRec = o.archetypeArray + (size_t)o.archetypeStride * archetype;
    }

    const ChunkView* ch = (const ChunkView*)chunkRec;
    if (!ch->data || ch->capacityBits > 14) return 0;
    if (idInChunk >= ch->entitiesUsed) return 0;

    uintptr_t p = ch->data + ((size_t)dataOfs << ch->capacityBits) + (size_t)idInChunk * dataSz;
    if (!rd_ok(p, dataSz)) return 0;
    return p;
}

namespace {

bool looks_like_string_blob(uintptr_t p, uint32_t bytes) {
    if (!rd_ok(p, bytes < 64 ? 64 : bytes)) return false;
    const uint8_t* s = (const uint8_t*)p;
    uint32_t strings = 0, i = 0;
    uint32_t limit = bytes < 256 ? bytes : 256;
    while (i < limit) {
        if (s[i] == 0) { i++; continue; }
        uint8_t c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')) return false;
        uint32_t start = i;
        while (i < limit && s[i] >= 0x20 && s[i] <= 0x7E) i++;
        if (i >= limit) break;
        if (s[i] != 0) return false;
        if (i - start >= 2) strings++;
        i++;
    }
    return strings >= 3;
}

uint32_t reap_blob(uintptr_t p, uint32_t bytes,
                   const std::unordered_set<uint32_t>& wanted,
                   std::unordered_map<uint32_t, std::string>& out) {
    if (!rd_ok(p, bytes)) return 0;
    const char* s = (const char*)p;
    uint32_t found = 0, i = 0;
    while (i < bytes) {
        if (!s[i]) { i++; continue; }
        uint32_t start = i;
        while (i < bytes && (uint8_t)s[i] >= 0x20 && (uint8_t)s[i] <= 0x7E) i++;
        if (i >= bytes) break;
        if (s[i] == 0 && i > start) {
            std::string str(s + start, i - start);
            uint32_t h = fnv1a_str(str.c_str());
            if (wanted.count(h) && out.emplace(h, str).second) found++;
        }
        i++;
    }
    return found;
}

} // namespace

void ecs_harvest_component_names(const EcsRuntimeOffsets& o,
                                 std::unordered_map<uint32_t, std::string>& out) {
    if (!o.componentHashArray || !o.componentCount || !o.entDescsStruct) return;
    LOG_SECTION("discover: runtime component names");

    g_regions.build();

    std::unordered_set<uint32_t> wanted;
    for (uint32_t i = 0; i < o.componentCount; i++) {
        uint32_t h = rd32(o.componentHashArray + 4ull * i);
        if (h && !out.count(h)) wanted.insert(h);
    }
    if (wanted.empty()) {
        LOG_INFO("every component already has a name");
        return;
    }

    uint32_t blobs = 0, named = 0;
    auto take_blob = [&](uintptr_t data, uint32_t len) {
        if (len < 8 || len > (1u << 20)) return;
        if (!looks_like_string_blob(data, len)) return;
        blobs++;
        named += reap_blob(data, len, wanted, out);
    };

    for (const auto& w : windows_around(o.entDescsStruct)) {
        for (uintptr_t p = (w.first + 7) & ~7ull; p + 16 <= w.second; p += 8) {
            uint64_t v = rd64(p);
            if (!v || (v & 7)) continue;
            uintptr_t t = (uintptr_t)v;

            // StringTableAllocator::head, or any bare page pointer.
            if (rd_ok(t, 64) && looks_like_string_blob(t, 256)) {
                uint32_t len = rd32(p + 8) + rd32(p + 12);   // left + used
                take_blob(t, (len >= 8 && len <= 65536) ? len : 8192);
                continue;
            }

            // dag::Vector<StringPage>: 16-byte {char* data, u32 left, u32 used}.
            uint32_t pages = 0;
            for (uint32_t i = 0; i < 4096; i++) {
                uintptr_t e = t + 16ull * i;
                if (!rd_ok(e, 16)) break;
                uintptr_t d = (uintptr_t)rd64(e);
                uint32_t left = rd32(e + 8), used = rd32(e + 12);
                uint32_t total = left + used;
                if (!d || total < 8 || total > 65536) break;
                if (!looks_like_string_blob(d, 256)) break;
                pages++;
            }
            if (pages >= 2) {
                for (uint32_t i = 0; i < pages; i++) {
                    uintptr_t e = t + 16ull * i;
                    take_blob((uintptr_t)rd64(e), rd32(e + 8) + rd32(e + 12));
                }
            }
        }
    }

    LOG_INFO("runtime names: %u string page(s) walked, %u of %zu missing "
             "component name(s) recovered",
             blobs, named, wanted.size());
}

namespace {

struct TemplateArray {
    uintptr_t base = 0;
    uint32_t  count = 0;
    uint32_t  stride = 0;
    uint32_t  nameOfs = 0;
};

uint32_t count_named_records(uintptr_t base, uint32_t stride, uint32_t nameOfs,
                             uint32_t cap) {
    uint32_t n = 0;
    while (n < cap) {
        uintptr_t rec = base + (size_t)stride * n;
        if (!rd_ok(rec + nameOfs, 8)) break;
        uintptr_t sp = (uintptr_t)rd64(rec + nameOfs);
        if (!sp || !rd_ok(sp, 2)) break;
        const char* s = (const char*)sp;
        char c0 = s[0];
        if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_')) break;
        uint32_t len = 0;
        while (len < 128 && rd_ok(sp + len, 1) && s[len]) {
            char c = s[len];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '+' || c == '-';
            if (!ok) return n;
            len++;
        }
        if (len < 2 || len >= 128) break;
        n++;
    }
    return n;
}

} // namespace

void ecs_harvest_template_names(const EcsRuntimeOffsets& o,
                                uint32_t max_template_id,
                                std::unordered_map<uint32_t, std::string>& out) {
    if (!o.entDescsStruct) return;
    LOG_SECTION("discover: template names");
    g_regions.build();

    // TemplateDB records: the longest run of name pointers at a fixed stride.
    TemplateArray best;
    uint32_t bestRun = 0;

    for (const auto& w : windows_around(o.entDescsStruct)) {
        for (uintptr_t p = (w.first + 7) & ~7ull; p + 16 <= w.second; p += 8) {
            uint64_t ptr = rd64(p);
            uint32_t cnt = rd32(p + 8), cap = rd32(p + 12);
            if (!ptr || (ptr & 7)) continue;
            if (cnt < 64 || cnt > 262144 || cap < cnt || cap > cnt * 2 + 4096) continue;
            if (!rd_ok((uintptr_t)ptr, 64)) continue;

            for (uint32_t stride = 0x40; stride <= 0x200; stride += 8) {
                if (!rd_ok((uintptr_t)ptr, (size_t)stride * 4)) break;
                for (uint32_t nofs = 0; nofs + 8 <= stride; nofs += 8) {
                    if (count_named_records((uintptr_t)ptr, stride, nofs, 2) < 2) continue;
                    uint32_t run = count_named_records((uintptr_t)ptr, stride, nofs,
                                                       cnt < 4096 ? cnt : 4096);
                    if (run > bestRun) {
                        bestRun = run;
                        best.base = (uintptr_t)ptr;
                        best.count = cnt;
                        best.stride = stride;
                        best.nameOfs = nofs;
                    }
                }
            }
        }
    }

    if (bestRun < 64 || !best.base) {
        LOG_WARN("template record array not found (longest named run = %u)", bestRun);
        return;
    }
    LOG_INFO("template records: base=0x%016llX count=%u stride=0x%X name=+0x%X "
             "(%u consecutive named)",
             (unsigned long long)best.base, best.count, best.stride, best.nameOfs, bestRun);

    auto name_at = [&](uint32_t dbId) -> const char* {
        if (dbId >= best.count) return nullptr;
        uintptr_t rec = best.base + (size_t)best.stride * dbId;
        if (!rd_ok(rec + best.nameOfs, 8)) return nullptr;
        uintptr_t sp = (uintptr_t)rd64(rec + best.nameOfs);
        return (sp && rd_ok(sp, 2)) ? (const char*)sp : nullptr;
    };

    // templateDbId: u32[] parallel to instantiated templates; every entry indexes
    // the record array, and it covers the highest live template id.
    const uint32_t need = max_template_id + 1;
    uintptr_t dbIdArr = 0;
    uint32_t dbIdCount = 0;

    for (const auto& w : windows_around(o.entDescsStruct)) {
        for (uintptr_t p = (w.first + 7) & ~7ull; p + 16 <= w.second; p += 8) {
            uint64_t ptr = rd64(p);
            uint32_t cnt = rd32(p + 8), cap = rd32(p + 12);
            if (!ptr || (ptr & 3)) continue;
            if (cnt < need || cnt > 262144 || cap < cnt) continue;
            if (!rd_ok((uintptr_t)ptr, 4ull * cnt)) continue;

            bool ok = true;
            uint32_t distinct = 0, prev = 0xFFFFFFFF;
            for (uint32_t i = 0; i < cnt && ok; i++) {
                uint32_t v = rd32((uintptr_t)ptr + 4ull * i);
                if (v >= best.count) ok = false;
                else if (v != prev) { distinct++; prev = v; }
            }
            // A constant array would satisfy the range test trivially.
            if (!ok || distinct < need / 4) continue;
            dbIdArr = (uintptr_t)ptr;
            dbIdCount = cnt;
            break;
        }
        if (dbIdArr) break;
    }

    uint32_t named = 0;
    if (dbIdArr) {
        for (uint32_t t = 0; t < dbIdCount && t <= max_template_id; t++) {
            const char* nm = name_at(rd32(dbIdArr + 4ull * t));
            if (nm) { out[t] = nm; named++; }
        }
        LOG_INFO("templateDbId at 0x%016llX (%u entries) -> %u template name(s)",
                 (unsigned long long)dbIdArr, dbIdCount, named);
    } else {
        // Fallback: treat template_t as a direct index, and say so.
        for (uint32_t t = 0; t <= max_template_id && t < best.count; t++) {
            const char* nm = name_at(t);
            if (nm) { out[t] = nm; named++; }
        }
        LOG_WARN("templateDbId not found; treating template_t as a direct index "
                 "into the record array — %u name(s), VERIFY these against a "
                 "vehicle you recognise", named);
    }
}

void ecs_dump_all_templates(const EcsRuntimeOffsets& o,
                            std::vector<std::pair<uint32_t, std::string>>& out) {
    if (!o.entDescsStruct) return;
    LOG_SECTION("discover: full template catalogue");
    g_regions.build();

    uintptr_t base = 0;
    uint32_t count = 0, stride = 0, nameOfs = 0, bestRun = 0;

    for (const auto& w : windows_around(o.entDescsStruct)) {
        for (uintptr_t p = (w.first + 7) & ~7ull; p + 16 <= w.second; p += 8) {
            uint64_t ptr = rd64(p);
            uint32_t cnt = rd32(p + 8), cap = rd32(p + 12);
            if (!ptr || (ptr & 7)) continue;
            if (cnt < 64 || cnt > 262144 || cap < cnt || cap > cnt * 2 + 4096) continue;
            if (!rd_ok((uintptr_t)ptr, 64)) continue;

            for (uint32_t st = 0x40; st <= 0x200; st += 8) {
                if (!rd_ok((uintptr_t)ptr, (size_t)st * 4)) break;
                for (uint32_t nofs = 0; nofs + 8 <= st; nofs += 8) {
                    if (count_named_records((uintptr_t)ptr, st, nofs, 2) < 2) continue;
                    uint32_t run = count_named_records((uintptr_t)ptr, st, nofs,
                                                       cnt < 4096 ? cnt : 4096);
                    if (run > bestRun) {
                        bestRun = run; base = (uintptr_t)ptr;
                        count = cnt; stride = st; nameOfs = nofs;
                    }
                }
            }
        }
    }

    if (bestRun < 64 || !base) {
        LOG_WARN("template catalogue: record array not found");
        return;
    }

    uint32_t emitted = 0;
    for (uint32_t i = 0; i < count; i++) {
        uintptr_t rec = base + (size_t)stride * i;
        if (!rd_ok(rec + nameOfs, 8)) break;
        uintptr_t sp = (uintptr_t)rd64(rec + nameOfs);
        if (!sp || !rd_ok(sp, 2)) continue;
        const char* s = (const char*)sp;
        char c0 = s[0];
        if (!((c0 >= 'A' && c0 <= 'Z') || (c0 >= 'a' && c0 <= 'z') || c0 == '_')) continue;
        uint32_t len = 0;
        bool ok = true;
        while (len < 128 && rd_ok(sp + len, 1) && s[len]) {
            char c = s[len];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '+' || c == '-')) {
                ok = false; break;
            }
            len++;
        }
        if (!ok || len < 2 || len >= 128) continue;
        out.emplace_back(i, std::string(s, len));
        emitted++;
    }
    LOG_INFO("template catalogue: %u of %u record(s) named (stride=0x%X name=+0x%X)",
             emitted, count, stride, nameOfs);
}

uint32_t ecs_component_type_hash(const EcsRuntimeOffsets& o, uint16_t cidx) {
    if (!o.componentTypeArray || cidx >= o.componentCount) return 0;
    return rd32(o.componentTypeArray + 8ull * cidx + 4);
}
