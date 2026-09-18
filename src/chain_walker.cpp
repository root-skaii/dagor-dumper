#include "../include/ecs_structs.h"
#include "../include/ecs_runtime.h"
#include "../include/das_rtti.h"
#include "../include/rtti_dump.h"
#include "../include/scanner.h"
#include "../include/logger.h"
#include <psapi.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <thread>
#include <unordered_set>

struct TypeRecord {
    uint32_t    index;
    uintptr_t   node_addr;
    uint32_t    hash;
    uint32_t    size;
    uint16_t    flags;
    std::string name;
};

static const char* type_flags_str(uint16_t f, char* buf, size_t buf_sz) {
    buf[0] = '\0';
    struct { uint16_t bit; const char* label; } kF[] = {
        {CTF_NON_TRIVIAL_CREATE,"CTOR"   }, {CTF_NON_TRIVIAL_MOVE,"NO_MOVE"},
        {CTF_BOXED,             "BOXED"  }, {CTF_CREATE_ON_TEMPL,  "TEMPL" },
        {CTF_NEED_RESOURCES,    "RES"    }, {CTF_HAS_IO,           "IO"    },
        {CTF_IS_POD,            "POD"    }, {CTF_REPLICATION,      "NET"   },
    };
    bool first = true;
    for (auto& kf : kF) {
        if (!(f & kf.bit)) continue;
        if (!first) strncat_s(buf, buf_sz, "|", 1);
        strncat_s(buf, buf_sz, kf.label, _TRUNCATE);
        first = false;
    }
    if (first) strncat_s(buf, buf_sz, "-", 1);
    return buf;
}

// Nodes are enumerated structurally rather than by walking from an anchor:
// the lists are LIFO (`next = tail; tail = this`), so a walk from any node only
// reaches a suffix, and EventsDB::validateInternal() moves event nodes to a
// second list (registered_tail) before injection. fnv1a(name) == stored_hash
// is a 32-bit self-check random memory doesn't pass, so scanning every data
// section for it finds every node regardless of which list holds it.

namespace {

// A node candidate: `name` at +name_ofs, matching FNV-1a hash at +hash_ofs.
template <typename Fn>
static std::vector<uintptr_t> scan_hash_named_nodes(size_t name_ofs, size_t hash_ofs,
                                                    size_t node_span, const char* label,
                                                    Fn&& extra_check) {
    std::vector<uintptr_t> found;
    auto sections = enumerate_all_data_sections();

    size_t bytes = 0;
    for (const auto& sec : sections) {
        uintptr_t s = (sec.base + 7) & ~7ull;
        uintptr_t e = sec.base + sec.size;
        if (e < s + node_span) continue;
        e -= node_span;
        bytes += (size_t)(e - s);

        for (uintptr_t a = s; a <= e; a += 8) {
            uintptr_t str_ptr = *(uintptr_t*)(a + name_ofs);
            if (!fast_module_string(str_ptr)) continue;
            uint32_t stored = *(uint32_t*)(a + hash_ofs);
            if (!stored) continue;
            if (fnv1a_str((const char*)str_ptr) != stored) continue;
            if (!extra_check(a)) continue;
            found.push_back(a);
        }
    }
    LOG_INFO("%s: structural scan over %.1f MB of module data → %zu node(s)",
             label, bytes / (1024.0 * 1024.0), found.size());
    return found;
}

// Union the structural result with everything reachable by following `next`
// from each node — cheap, and covers nodes in unscanned regions.
static void absorb_chain_reachable(std::vector<uintptr_t>& nodes, size_t next_ofs,
                                    size_t node_span, const char* label) {
    std::set<uintptr_t> known(nodes.begin(), nodes.end());
    size_t added = 0;
    for (size_t i = 0; i < nodes.size(); i++) {          // grows while iterating
        uintptr_t cur = *(uintptr_t*)(nodes[i] + next_ofs);
        size_t guard = 0;
        while (cur && guard++ < 65536) {
            if (known.count(cur)) break;
            if (!is_valid_ptr((void*)cur) || !is_valid_ptr((void*)(cur + node_span - 1))) break;
            known.insert(cur);
            nodes.push_back(cur);
            added++;
            cur = *(uintptr_t*)(cur + next_ofs);
        }
    }
    if (added) LOG_INFO("%s: +%zu node(s) reached by walking `next`", label, added);
}

} // namespace

std::vector<TypeRecord> dump_type_chain() {
    LOG_SECTION("Chain 1: CompileComponentTypeRegister");

    auto nodes = scan_hash_named_nodes(
        offsetof(CompileComponentTypeRegister, name),
        offsetof(CompileComponentTypeRegister, name_hash),
        sizeof(CompileComponentTypeRegister),
        "Chain1",
        [](uintptr_t a) {
            auto* n = (const CompileComponentTypeRegister*)a;
            if (n->flags >= 0x0200) return false;                       // flags are 8 bits worth
            if (n->size > (1u << 20)) return false;                     // sizeof(T) sanity
            if (n->next && !is_valid_ptr(n->next)) return false;
            // ctm/dtm are either both null (POD types) or both code pointers.
            if ((n->ctm != nullptr) != (n->dtm != nullptr)) return false;
            return true;
        });

    absorb_chain_reachable(nodes, offsetof(CompileComponentTypeRegister, next),
                           sizeof(CompileComponentTypeRegister), "Chain1");

    std::set<uint32_t>      seen;
    std::vector<TypeRecord> records;
    for (uintptr_t addr : nodes) {
        auto* n = (const CompileComponentTypeRegister*)addr;
        if (!is_valid_string(n->name)) continue;
        if (fnv1a_str(n->name) != n->name_hash) continue;
        if (seen.count(n->name_hash)) continue;
        seen.insert(n->name_hash);
        records.push_back({ 0, addr, n->name_hash, n->size, n->flags, n->name });
    }

    std::sort(records.begin(), records.end(),
              [](const TypeRecord& a, const TypeRecord& b) { return a.name < b.name; });
    for (uint32_t i = 0; i < (uint32_t)records.size(); i++) records[i].index = i;

    LOG_INFO("Chain1: total unique component types: %zu", records.size());
    return records;
}

struct ComponentRecord {
    uint32_t    index;
    uintptr_t   node_addr;
    uint32_t    name_hash;
    uint32_t    type_hash;
    uint16_t    flags;
    std::string name;
    std::string type_name;
};

std::vector<ComponentRecord> dump_component_chain() {
    LOG_SECTION("Chain 2: CompileComponentRegister");

    // Every ECS_HASH() literal has the same (str, hash) head, so the
    // discriminator is the second self-check: type == fnv1a(type_name).
    auto nodes = scan_hash_named_nodes(
        offsetof(CompileComponentRegister, name),
        offsetof(CompileComponentRegister, name) + offsetof(HashedConstString, hash),
        sizeof(CompileComponentRegister),
        "Chain2",
        [](uintptr_t a) {
            auto* n = (const CompileComponentRegister*)a;
            if (!fast_module_string((uintptr_t)n->type_name)) return false;
            if (n->type != fnv1a_str(n->type_name)) return false;   // decisive
            if (n->flags >= 0x0100) return false;
            if (n->next && !is_valid_ptr(n->next)) return false;
            if (n->deps.count > 4096) return false;
            return true;
        });

    absorb_chain_reachable(nodes, offsetof(CompileComponentRegister, next),
                           sizeof(CompileComponentRegister), "Chain2");

    std::set<uint32_t>           seen;
    std::vector<ComponentRecord> records;
    for (uintptr_t addr : nodes) {
        auto* n = (const CompileComponentRegister*)addr;
        if (!is_valid_string(n->name.str)) continue;
        if (fnv1a_str(n->name.str) != n->name.hash) continue;
        if (seen.count(n->name.hash)) continue;
        seen.insert(n->name.hash);
        std::string tn = (n->type_name && is_valid_string(n->type_name)) ? n->type_name : "<unknown>";
        records.push_back({ 0, addr, n->name.hash, n->type, n->flags, n->name.str, tn });
    }

    std::sort(records.begin(), records.end(),
              [](const ComponentRecord& a, const ComponentRecord& b) { return a.name < b.name; });
    for (uint32_t i = 0; i < (uint32_t)records.size(); i++) records[i].index = i;

    LOG_INFO("Chain2: total unique component slots: %zu", records.size());
    return records;
}

struct EventRecord {
    uintptr_t   node_addr;
    uint32_t    type_hash;
    uint16_t    size;
    uint16_t    flags;
    std::string name;
};

std::vector<EventRecord> dump_event_chain() {
    LOG_SECTION("Chain 6: EventInfoLinkedList");

    auto nodes = scan_hash_named_nodes(
        offsetof(EventInfoLinkedList, name),
        offsetof(EventInfoLinkedList, eventType),
        sizeof(EventInfoLinkedList),
        "Chain6",
        [](uintptr_t a) {
            auto* n = (const EventInfoLinkedList*)a;
            // Loose size bound; fnv1a(name) == eventType is the real filter.
            if (n->eventSize < sizeof(Event) || n->eventSize > 4096) return false;
            if ((n->eventFlags & (EV_UNICAST | EV_BROADCAST)) == 0) return false;    // must be uni or broadcast
            if (n->eventFlags >= 0x0100) return false;
            // destroy/move_out come as a pair, and only when EVFLG_DESTROY is set.
            const bool hasDtor = (n->eventFlags & EV_DESTROY) != 0;
            if (!hasDtor && (n->destroy || n->move_out)) return false;
            if (n->destroy && !is_valid_ptr(n->destroy)) return false;
            if (n->move_out && !is_valid_ptr(n->move_out)) return false;
            if (n->next && !is_valid_ptr(n->next)) return false;
            return true;
        });

    absorb_chain_reachable(nodes, offsetof(EventInfoLinkedList, next),
                           sizeof(EventInfoLinkedList), "Chain6");

    std::set<uint32_t>       seen;
    std::vector<EventRecord> records;
    for (uintptr_t addr : nodes) {
        auto* n = (const EventInfoLinkedList*)addr;
        if (!is_valid_string(n->name)) continue;
        if (fnv1a_str(n->name) != n->eventType) continue;
        if (seen.count(n->eventType)) continue;
        seen.insert(n->eventType);
        records.push_back({ addr, n->eventType, n->eventSize, n->eventFlags, n->name });
    }

    std::sort(records.begin(), records.end(),
              [](const EventRecord& a, const EventRecord& b) { return a.name < b.name; });

    LOG_INFO("Chain6: total unique events: %zu", records.size());
    return records;
}

// Every ECS_HASH("x") leaves a {const char*, fnv1a} pair in the image; scanning
// for them yields the game's name<->hash dictionary, registered or not.
struct HashedString {
    uint32_t    hash;
    std::string name;
};

std::vector<HashedString> dump_hashed_strings() {
    LOG_SECTION("ECS_HASH literal dictionary");

    std::unordered_map<uint32_t, std::string> uniq;
    auto sections = enumerate_all_data_sections();
    size_t bytes = 0;

    for (const auto& sec : sections) {
        uintptr_t s = (sec.base + 7) & ~7ull;
        uintptr_t e = sec.base + sec.size;
        if (e < s + 16) continue;
        e -= 16;
        bytes += (size_t)(e - s);

        for (uintptr_t a = s; a <= e; a += 8) {
            uintptr_t str_ptr = *(uintptr_t*)a;
            if (!fast_module_string(str_ptr)) continue;
            uint32_t stored = *(uint32_t*)(a + 8);
            if (!stored) continue;
            const char* str = (const char*)str_ptr;
            if (fnv1a_str(str) != stored) continue;
            uniq.emplace(stored, str);
        }
    }

    std::vector<HashedString> out;
    out.reserve(uniq.size());
    for (auto& kv : uniq) out.push_back({ kv.first, kv.second });
    std::sort(out.begin(), out.end(),
              [](const HashedString& a, const HashedString& b) { return a.name < b.name; });

    LOG_INFO("hashed strings: %.1f MB scanned → %zu unique name↔hash pairs",
             bytes / (1024.0 * 1024.0), out.size());
    return out;
}

static void write_offsets_header(const char* header_path,
                                  uintptr_t   module_base,
                                  uint32_t    pid,
                                  const std::vector<TypeRecord>&      types,
                                  const std::vector<ComponentRecord>& comps,
                                  const std::vector<EventRecord>&     events,
                                  const EcsRuntimeOffsets&            rt) {
    FILE* f = nullptr;
    if (fopen_s(&f, header_path, "w") != 0 || !f) {
        LOG_ERR("write_offsets_header: cannot open '%s'", header_path);
        return;
    }

    std::unordered_map<uint32_t, uint32_t> type_sz;
    std::unordered_map<uint32_t, std::string> type_nm;
    for (auto& t : types) { type_sz[t.hash] = t.size; type_nm[t.hash] = t.name; }

    SYSTEMTIME st{};
    GetLocalTime(&st);

    // SIZE_MAX prints as SIZE_MAX so a consumer can spot "not discovered".
    auto sz = [](size_t v) {
        char b[32];
        if (v == SIZE_MAX) snprintf(b, sizeof(b), "SIZE_MAX");
        else               snprintf(b, sizeof(b), "0x%04zX", (size_t)v);
        return std::string(b);
    };

    fprintf(f,
        "// ================================================================\n"
        "// dagor_ecs_offsets.hpp  —  AUTO-GENERATED by dagor_dumper\n"
        "// DO NOT EDIT — regenerate by re-injecting dagor_dumper.dll\n"
        "//\n"
        "// Target PID : %u\n"
        "// Module base: 0x%016llX\n"
        "// Generated  : %04u-%02u-%02u %02u:%02u:%02u\n"
        "//\n"
        "// Include in dagor_test or any tool to use typed ECS hashes:\n"
        "//   #include \"dagor_ecs_offsets.hpp\"\n"
        "//   component_t hash = dagor::slot_hash::transform;\n"
        "// ================================================================\n"
        "#pragma once\n"
        "#include <cstdint>\n\n"
        "namespace dagor {\n\n",
        pid, (unsigned long long)module_base,
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Some component types are named after C++ types (e.g. uint32_t). A
    // constant with that name would shadow the type used by every later
    // declaration in the header, so reserved names get a trailing underscore.
    auto ident = [](const std::string& s) {
        static const char* kReserved[] = {
            "component_t", "archetype_t", "entity_id_t",
            "uint8_t", "uint16_t", "uint32_t", "uint64_t",
            "int8_t", "int16_t", "int32_t", "int64_t", "size_t", "intptr_t",
            "int", "float", "double", "bool", "char", "short", "long", "void",
            "signed", "unsigned", "class", "struct", "union", "enum", "const",
            "static", "inline", "template", "typename", "namespace", "using",
            "operator", "public", "private", "protected", "virtual", "friend",
            "explicit", "mutable", "volatile", "extern", "typedef", "sizeof",
            "new", "delete", "this", "true", "false", "nullptr", "auto",
            "return", "if", "else", "for", "while", "do", "switch", "case",
            "default", "break", "continue", "goto", "try", "catch", "throw",
            "and", "or", "not", "xor",
        };
        std::string r = s;
        for (char& c : r) if (!isalnum((unsigned char)c) && c != '_') c = '_';
        if (!r.empty() && isdigit((unsigned char)r[0])) r = "_" + r;
        for (const char* k : kReserved)
            if (r == k) { r += "_"; break; }
        return r;
    };

    fprintf(f, "/// Component type hashes  (Chain 1: CompileComponentTypeRegister)\n"
               "/// Usage: if (slot_type_hash::transform == type_hash::TMatrix) { ... }\n"
               "namespace type_hash {\n");
    for (auto& t : types) {
        const char* flag = (t.flags & CTF_IS_POD) ? "POD" :
                           (t.flags & CTF_BOXED)  ? "BOXED" :
                           (t.flags & CTF_NEED_RESOURCES) ? "RES" : "";
        fprintf(f, "    constexpr uint32_t %-52s = 0x%08Xu; // sz=%-5u %s\n",
                ident(t.name).c_str(), t.hash, t.size, flag);
    }
    fprintf(f, "} // namespace type_hash\n\n");

    fprintf(f, "/// Component slot name hashes  (Chain 2: CompileComponentRegister)\n"
               "/// Usage: component_t h = dagor::slot_hash::transform;\n"
               "namespace slot_hash {\n");
    for (auto& c : comps)
        fprintf(f, "    constexpr uint32_t %-52s = 0x%08Xu;\n",
                ident(c.name).c_str(), c.name_hash);
    fprintf(f, "} // namespace slot_hash\n\n");

    fprintf(f, "/// What type each slot stores (type_hash of the stored component type)\n"
               "namespace slot_type_hash {\n");
    for (auto& c : comps) {
        auto it = type_nm.find(c.type_hash);
        std::string tn = (it != type_nm.end()) ? it->second : "?";
        fprintf(f, "    constexpr uint32_t %-52s = 0x%08Xu; // %s\n",
                ident(c.name).c_str(), c.type_hash, tn.c_str());
    }
    fprintf(f, "} // namespace slot_type_hash\n\n");

    fprintf(f, "/// sizeof(T) for the type stored in each slot  (0 = type not in dump)\n"
               "namespace slot_elem_size {\n");
    for (auto& c : comps) {
        uint32_t sz = type_sz.count(c.type_hash) ? type_sz[c.type_hash] : 0;
        fprintf(f, "    constexpr uint32_t %-52s = %u;\n",
                ident(c.name).c_str(), sz);
    }
    fprintf(f, "} // namespace slot_elem_size\n\n");

    fprintf(f, "/// Event type hashes  (Chain 6: EventInfoLinkedList)\n"
               "namespace event_hash {\n");
    for (auto& e : events) {
        const char* cast = (e.flags & EV_UNICAST) ? "UNICAST" : "BROADCAST";
        fprintf(f, "    constexpr uint32_t %-52s = 0x%08Xu; // sz=%-4u %s\n",
                ident(e.name).c_str(), e.type_hash, e.size, cast);
    }
    fprintf(f, "} // namespace event_hash\n\n");

    fprintf(f,
        "/// Engine-wide constants (do not change per binary)\n"
        "namespace ecs_const {\n"
        "    constexpr uint16_t INVALID_ARCHETYPE         = 0xFFFFu;\n"
        "    constexpr uint16_t INVALID_TEMPLATE_ID       = 0xFFFFu;\n"
        "    constexpr uint16_t INVALID_COMPONENT_INDEX   = 0xFFFFu;\n"
        "    constexpr uint32_t FNV1A_BASIS               = 0x811C9DC5u;\n"
        "    constexpr uint32_t FNV1A_PRIME               = 0x01000193u;\n"
        "    constexpr uint32_t MAX_CHUNK_ID_BITS         = 14u;\n"
        "    constexpr uint32_t MAX_ENTITIES_PER_CHUNK    = 1u << 14u;\n"
        "    constexpr uint32_t MAX_CHUNKS_PER_ARCHETYPE  = 255u;\n"
        "    constexpr uint32_t BOXED_THRESHOLD_SIZE      = 4095u;\n"
        "    constexpr uint64_t MODULE_BASE               = 0x%016llXull;\n"
        "} // namespace ecs_const\n\n",
        (unsigned long long)module_base);

    // Discovered, not from engine source — consumers should re-validate them.
    fprintf(f,
        "/// EntityManager layout discovered at runtime by dagor_dumper.\n"
        "/// SIZE_MAX / 0 means \"not discovered\" — the consumer must fall back to a\n"
        "/// structural search. Never trust these across a game patch.\n"
        "namespace em_layout {\n"
        "    constexpr bool     DISCOVERED           = %s;\n"
        "    constexpr uint64_t ENTITY_MANAGER_ADDR  = 0x%016llXull; // this run only\n"
        "    constexpr size_t   OFS_ENTDESCS         = %s;\n"
        "    constexpr size_t   OFS_ARCHETYPES       = %s;\n"
        "    constexpr size_t   OFS_ARCH_COMPONENTS  = %s;\n"
        "    constexpr size_t   OFS_DATA_COMPONENTS  = %s;\n"
        "\n"
        "    // Field offsets below come from the engine's own container templates\n"
        "    // and struct definitions, so they are stable across builds.\n"
        "    constexpr size_t   SMALLTAB_PTR         = 0x00; // dag::Vector::mpBegin\n"
        "    constexpr size_t   SMALLTAB_COUNT       = 0x08; // mCount     <- size()\n"
        "    constexpr size_t   SMALLTAB_CAPACITY    = 0x0C; // mAllocated <- capacity()\n"
        "    constexpr size_t   ENTDESCS_CREATING    = 0x10; // SoA counter tab, same count\n"
        "    constexpr size_t   ENTDESCS_TOTALSIZE   = 0x20;\n"
        "    constexpr size_t   ARCHETYPE_STRIDE     = 0x20; // sizeof(ecs::Archetype)\n"
        "    constexpr size_t   ARCH_CHUNK0          = 0x00; // AliasedChunk buffer\n"
        "    constexpr size_t   ARCH_IS_CHUNK_ARRAY  = 0x0F; // last byte of the buffer\n"
        "    constexpr size_t   ARCH_TOTAL_USED      = 0x10;\n"
        "    constexpr size_t   ARCH_TOTAL_CAPACITY  = 0x14;\n"
        "    constexpr size_t   ARCH_ENTITY_SIZE     = 0x1C;\n"
        "    constexpr size_t   ARCH_COMPONENTS_CNT  = 0x1E;\n"
        "    constexpr size_t   CHUNK_STRIDE         = 0x10; // DataComponentManager::Chunk\n"
        "    constexpr size_t   CHUNK_DATA           = 0x00;\n"
        "    constexpr size_t   CHUNK_USED           = 0x08;\n"
        "    constexpr size_t   CHUNK_CAP_BITS       = 0x0C;\n"
        "\n"
        "    // Counts observed during the dump — a sanity reference, not offsets.\n"
        "    constexpr uint32_t ENTITY_SLOTS         = %u;\n"
        "    constexpr uint32_t LIVE_ENTITIES        = %u;\n"
        "    constexpr uint32_t ARCHETYPE_COUNT      = %u;\n"
        "    constexpr uint32_t ARCH_COMPONENT_SLOTS = %u;\n"
        "    constexpr uint32_t COMPONENT_COUNT      = %u;\n"
        "} // namespace em_layout\n\n"
        "} // namespace dagor\n",
        rt.archetypesValidated ? "true" : "false",
        (unsigned long long)rt.entityManager,
        sz(rt.ofsEntDescs).c_str(), sz(rt.ofsArchetypes).c_str(),
        sz(rt.ofsArchComps).c_str(), sz(rt.ofsDataComponents).c_str(),
        rt.entitySlots, rt.liveEntities, rt.archetypeCount,
        rt.archCompCount, rt.componentCount);

    fclose(f);
    LOG_INFO("Offsets header written: %s", header_path);
}

// RVAs survive restarts; absolute addresses are only valid for this process.
static void write_offsets_json(const char* path,
                               const std::vector<TypeRecord>& types,
                               const std::vector<ComponentRecord>& comps,
                               const std::vector<EventRecord>& events,
                               const EcsRuntimeOffsets& rt,
                               const std::unordered_map<uint32_t, std::string>& hash_to_name) {
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") != 0 || !f) {
        LOG_ERR("write_offsets_json: cannot open '%s'", path);
        return;
    }

    auto esc = [](const std::string& in) {
        std::string o;
        for (char c : in) {
            if (c == '"' || c == '\\') { o += '\\'; o += c; }
            else if ((unsigned char)c < 0x20) continue;
            else o += c;
        }
        return o;
    };

    SYSTEMTIME st{}; GetLocalTime(&st);
    fprintf(f, "{\n");
    fprintf(f, "  \"generated\": \"%04u-%02u-%02uT%02u:%02u:%02u\",\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fprintf(f, "  \"module\": \"%s\",\n", rt.moduleName[0] ? rt.moduleName : "?");
    fprintf(f, "  \"module_base\": \"0x%016llX\",\n", (unsigned long long)rt.moduleBase);
    fprintf(f, "  \"note\": \"rva fields are stable across restarts; addr fields are this run only\",\n");

    fprintf(f, "  \"entity_manager\": {\n");
    if (rt.moduleBase && rt.entDescsStruct)
        fprintf(f, "    \"ent_descs_rva\": \"0x%08llX\",\n",
                (unsigned long long)(rt.entDescsStruct - rt.moduleBase));
    fprintf(f, "    \"ent_descs_addr\": \"0x%016llX\",\n", (unsigned long long)rt.entDescsStruct);
    fprintf(f, "    \"ent_descs_array\": \"0x%016llX\",\n", (unsigned long long)rt.entDescsArray);
    fprintf(f, "    \"entity_slots\": %u,\n", rt.entitySlots);
    fprintf(f, "    \"live_entities\": %u,\n", rt.liveEntities);
    fprintf(f, "    \"archetype_array\": \"0x%016llX\",\n", (unsigned long long)rt.archetypeArray);
    fprintf(f, "    \"archetype_count\": %u,\n", rt.archetypeCount);
    fprintf(f, "    \"archetype_stride\": %u,\n", rt.archetypeStride);
    fprintf(f, "    \"arch_comp_index\": \"0x%016llX\",\n", (unsigned long long)rt.archCompIndex);
    fprintf(f, "    \"arch_comp_data_offset\": \"0x%016llX\",\n", (unsigned long long)rt.archCompDataOffset);
    fprintf(f, "    \"arch_comp_data_size\": \"0x%016llX\",\n", (unsigned long long)rt.archCompDataSize);
    fprintf(f, "    \"component_hash_array\": \"0x%016llX\",\n", (unsigned long long)rt.componentHashArray);
    fprintf(f, "    \"component_count\": %u\n", rt.componentCount);
    fprintf(f, "  },\n");

    fprintf(f, "  \"struct_layout\": {\n");
    fprintf(f, "    \"entity_desc\": {\"size\": 8, \"archetype\": \"u16@0\", \"template_id\": \"u16@2\","
               " \"chunk_id\": \"u32@4:0..7\", \"generation\": \"u32@4:8..17\", \"id_in_chunk\": \"u32@4:18..31\"},\n");
    fprintf(f, "    \"small_tab\": {\"ptr\": 0, \"count\": 8, \"capacity\": 12},\n");
    fprintf(f, "    \"archetype\": {\"size\": 32, \"chunk0\": 0, \"is_chunk_array\": 15,"
               " \"total_used\": 16, \"total_capacity\": 20, \"entity_size\": 28, \"components_cnt\": 30},\n");
    fprintf(f, "    \"chunk\": {\"size\": 16, \"data\": 0, \"used\": 8, \"capacity_bits\": 12},\n");
    fprintf(f, "    \"component_addr\": \"chunk.data + (DATA_OFFSET << chunk.capacity_bits) + row * DATA_SIZE\"\n");
    fprintf(f, "  },\n");

    fprintf(f, "  \"components\": {\n");
    bool firstC = true;
    if (rt.componentHashArray && rt.componentCount) {
        for (uint32_t cidx = 0; cidx < rt.componentCount; cidx++) {
            uint32_t h = *(const uint32_t*)(rt.componentHashArray + 4ull * cidx);
            auto it = hash_to_name.find(h);
            if (it == hash_to_name.end()) continue;
            if (!firstC) fprintf(f, ",\n");
            firstC = false;
            fprintf(f, "    \"%s\": {\"cidx\": %u, \"hash\": \"0x%08X\"}",
                    esc(it->second).c_str(), cidx, h);
        }
    }
    fprintf(f, "\n  },\n");

    fprintf(f, "  \"archetypes\": [\n");
    bool firstA = true;
    for (uint32_t a = 0; a < rt.archetypeCount; a++) {
        const ArchetypeView* av =
            (const ArchetypeView*)(rt.archetypeArray + (size_t)rt.archetypeStride * a);
        if (!av->totalEntitiesUsed) continue;
        if (!firstA) fprintf(f, ",\n");
        firstA = false;
        uint32_t nchunks = av->isChunkArray ? ((const ChunksArrayView*)av)->count : 1u;
        fprintf(f, "    {\"id\": %u, \"entities\": %u, \"entity_size\": %u, \"chunks\": %u,"
                   " \"components\": [",
                a, av->totalEntitiesUsed, av->entitySize, nchunks);
        if (rt.haveArchComps() && rt.archCompIndex) {
            uint32_t cofs = rt.componentOfs[a];
            for (uint32_t i = 0; i < av->componentsCnt; i++) {
                uint32_t slot = cofs + i;
                uint16_t cidx = *(const uint16_t*)(rt.archCompIndex + 2ull * slot);
                uint16_t off  = *(const uint16_t*)(rt.archCompDataOffset + 2ull * slot);
                uint16_t sz;
                if (rt.archCompDataSize)
                    sz = *(const uint16_t*)(rt.archCompDataSize + 2ull * slot);
                else if (i + 1 < av->componentsCnt)
                    sz = (uint16_t)(*(const uint16_t*)(rt.archCompDataOffset + 2ull * (slot + 1)) - off);
                else
                    sz = (uint16_t)(av->entitySize - off);
                const char* nm = "";
                if (rt.componentHashArray && cidx < rt.componentCount) {
                    uint32_t h = *(const uint32_t*)(rt.componentHashArray + 4ull * cidx);
                    auto it = hash_to_name.find(h);
                    if (it != hash_to_name.end()) nm = it->second.c_str();
                }
                fprintf(f, "%s{\"name\": \"%s\", \"cidx\": %u, \"offset\": %u, \"size\": %u}",
                        i ? ", " : "", esc(nm).c_str(), cidx, off, sz);
            }
        }
        fprintf(f, "]}");
    }
    fprintf(f, "\n  ],\n");

    fprintf(f, "  \"events\": {\n");
    for (size_t i = 0; i < events.size(); i++)
        fprintf(f, "    \"%s\": {\"hash\": \"0x%08X\", \"size\": %u}%s\n",
                esc(events[i].name).c_str(), events[i].type_hash, events[i].size,
                i + 1 < events.size() ? "," : "");
    fprintf(f, "  },\n");

    fprintf(f, "  \"component_types\": {\n");
    for (size_t i = 0; i < types.size(); i++)
        fprintf(f, "    \"%s\": {\"hash\": \"0x%08X\", \"size\": %u}%s\n",
                esc(types[i].name).c_str(), types[i].hash, types[i].size,
                i + 1 < types.size() ? "," : "");
    fprintf(f, "  }\n}\n");

    fclose(f);
    LOG_INFO("offsets JSON written: %s", path);
}

void write_dump(const char* output_path) {
    LOG_SECTION("Writing dump file");
    LOG_INFO("Output path: %s", output_path);

    ULONGLONG t_total = GetTickCount64();

    auto types      = dump_type_chain();
    auto components = dump_component_chain();
    auto events     = dump_event_chain();
    auto hashed     = dump_hashed_strings();

    LOG_INFO("Summary — Types: %zu  Components: %zu  Events: %zu  HashedStrings: %zu",
             types.size(), components.size(), events.size(), hashed.size());

    // Slot-name hashes let runtime discovery recognise the cidx table.
    std::vector<uint32_t> known_hashes;
    known_hashes.reserve(components.size() + hashed.size());
    for (const auto& c : components) known_hashes.push_back(c.name_hash);
    for (const auto& h : hashed)     known_hashes.push_back(h.hash);

    EcsRuntimeOffsets rt = discover_ecs_runtime(known_hashes);

    DasRttiResult das = dump_das_rtti();

    RttiResult rtti = dump_msvc_rtti();

    std::unordered_map<uint32_t, std::string> hash_to_name;
    for (const auto& h : hashed)     hash_to_name.emplace(h.hash, h.name);
    for (const auto& c : components) hash_to_name[c.name_hash] = c.name;
    {
        size_t before = hash_to_name.size();
        harvest_all_string_hashes(hash_to_name);
        LOG_INFO("name dictionary: %zu -> %zu after hashing every identifier string",
                 before, hash_to_name.size());
    }
    ecs_harvest_component_names(rt, hash_to_name);

    // Must run last: shadows are derived from every name recovered above.
    if (rt.componentHashArray && rt.componentCount) {
        std::vector<uint32_t> wanted;
        wanted.reserve(rt.componentCount);
        for (uint32_t i = 0; i < rt.componentCount; i++)
            wanted.push_back(*(const uint32_t*)(rt.componentHashArray + 4ull * i));
        size_t before = hash_to_name.size();
        derive_shadow_component_names(hash_to_name, &wanted);
        LOG_INFO("shadow components: %zu \"name$\" entries recovered",
                 hash_to_name.size() - before);
    }

    FILE* f = nullptr;
    if (fopen_s(&f, output_path, "w") != 0 || !f) {
        LOG_ERR("Failed to open output file '%s'", output_path);
        return;
    }

    fprintf(f, "// ════════════════════════════════════════════════════════\n");
    fprintf(f, "// DAGORENGINE ECS DUMP (runtime injected DLL)\n");
    fprintf(f, "// Analogous to Il2CppDumper output for Unity IL2CPP\n");
    fprintf(f, "// ════════════════════════════════════════════════════════\n");
    fprintf(f, "// Module base: 0x%016llX\n",
            (unsigned long long)(uintptr_t)GetModuleHandleA(nullptr));
    fprintf(f, "// PID: %u\n\n", GetCurrentProcessId());

    fprintf(f, "// --- COMPONENT TYPES [Chain 1: CompileComponentTypeRegister] ---\n");
    fprintf(f, "// Total: %zu\n", types.size());
    fprintf(f, "//  IDX   HASH        SIZE    FLAGS                NAME\n");
    char fbuf[128];
    for (auto& t : types) {
        type_flags_str(t.flags, fbuf, sizeof(fbuf));
        fprintf(f, "  [%04u] 0x%08X  %-6u  %-22s  %s\n",
                t.index, t.hash, t.size, fbuf, t.name.c_str());
    }
    fprintf(f, "\n");

    fprintf(f, "// --- COMPONENT SLOTS [Chain 2: CompileComponentRegister] ---\n");
    fprintf(f, "// Total: %zu\n", components.size());
    fprintf(f, "// NAME_HASH   TYPE_HASH   REP    TYPE_NAME : SLOT_NAME\n");
    for (auto& c : components) {
        const char* rep = (c.flags & CF_DONT_REPLICATE) ? "LOCAL" : "NET  ";
        fprintf(f, "  0x%08X  0x%08X  [%s]  %s : %s\n",
                c.name_hash, c.type_hash, rep,
                c.type_name.c_str(), c.name.c_str());
    }
    fprintf(f, "\n");

    fprintf(f, "// --- EVENTS [Chain 6: EventInfoLinkedList] ---\n");
    fprintf(f, "// Total: %zu\n", events.size());
    fprintf(f, "// HASH        SIZE   CAST       FLAGS_EXTRA              NAME\n");
    for (auto& e : events) {
        const char* cast = (e.flags & EV_UNICAST)   ? "UNICAST   "
                         : (e.flags & EV_BROADCAST) ? "BROADCAST "
                                                     : "UNKNOWN   ";
        char ef[64] = "";
        if (e.flags & EV_SERIALIZE)  strncat_s(ef, "SERIALIZE|",  _TRUNCATE);
        if (e.flags & EV_DESTROY)    strncat_s(ef, "DTOR|",       _TRUNCATE);
        if (e.flags & EV_SCHEMELESS) strncat_s(ef, "SCHEMELESS|", _TRUNCATE);
        if (e.flags & EV_CORE)       strncat_s(ef, "CORE|",       _TRUNCATE);
        if (strlen(ef)) ef[strlen(ef)-1] = '\0';
        fprintf(f, "  0x%08X  %-5u  %s  %-24s  %s\n",
                e.type_hash, e.size, cast, ef, e.name.c_str());
    }
    fprintf(f, "\n");

    fprintf(f, "// --- RUNTIME LAYOUT (discovered this run, nothing hardcoded) ---\n");
    if (rt.entityManager)
        fprintf(f, "//   EntityManager            : 0x%016llX\n", (unsigned long long)rt.entityManager);
    else
        fprintf(f, "//   EntityManager            : <not pinned — module static, reached via LEA>\n");
    if (rt.moduleBase) {
        fprintf(f, "//   host module              : %s @ 0x%016llX\n",
                rt.moduleName, (unsigned long long)rt.moduleBase);
        fprintf(f, "//   entDescs RVA             : %s+0x%08llX  <- stable across restarts\n",
                rt.moduleName, (unsigned long long)(rt.entDescsStruct - rt.moduleBase));
        if (rt.archetypesTupleVec)
            fprintf(f, "//   archetypes RVA           : %s+0x%08llX\n",
                    rt.moduleName, (unsigned long long)(rt.archetypesTupleVec - rt.moduleBase));
        if (rt.archCompsTupleVec)
            fprintf(f, "//   archetypeComponents RVA  : %s+0x%08llX\n",
                    rt.moduleName, (unsigned long long)(rt.archCompsTupleVec - rt.moduleBase));
        if (rt.dataComponentsTupleVec)
            fprintf(f, "//   dataComponents RVA       : %s+0x%08llX\n",
                    rt.moduleName, (unsigned long long)(rt.dataComponentsTupleVec - rt.moduleBase));
    } else {
        fprintf(f, "//   host module              : <heap-allocated, addresses valid this run only>\n");
    }

    auto ofs_str = [](size_t v, char* buf, size_t n) -> const char* {
        if (v == SIZE_MAX) snprintf(buf, n, "   n/a ");
        else               snprintf(buf, n, "+0x%04zX", (size_t)v);
        return buf;
    };
    char ob[32];
    fprintf(f, "//   entDescs   struct        : 0x%016llX  EM%s\n",
            (unsigned long long)rt.entDescsStruct, ofs_str(rt.ofsEntDescs, ob, sizeof(ob)));
    fprintf(f, "//   entDescs   array         : 0x%016llX  slots=%u cap=%u live=%u\n",
            (unsigned long long)rt.entDescsArray, rt.entitySlots, rt.entitySlotsCap, rt.liveEntities);
    fprintf(f, "//   archetypes tuple_vector  : 0x%016llX  EM%s\n",
            (unsigned long long)rt.archetypesTupleVec, ofs_str(rt.ofsArchetypes, ob, sizeof(ob)));
    fprintf(f, "//   archetypes array         : 0x%016llX  count=%u sumEntities=%u %s\n",
            (unsigned long long)rt.archetypeArray, rt.archetypeCount, rt.sumArchEntities,
            rt.archetypesValidated ? "[VALIDATED against entDescs]" : "[UNVALIDATED]");
    fprintf(f, "//   archComps  tuple_vector  : 0x%016llX  EM%s slots=%u %s\n",
            (unsigned long long)rt.archCompsTupleVec, ofs_str(rt.ofsArchComps, ob, sizeof(ob)),
            rt.archCompCount, rt.archCompsValidated ? "[VALIDATED against entitySize]" : "[UNVALIDATED]");
    fprintf(f, "//     INDEX       (cidx[])   : 0x%016llX\n", (unsigned long long)rt.archCompIndex);
    fprintf(f, "//     DATA_OFFSET (uint16[]) : 0x%016llX\n", (unsigned long long)rt.archCompDataOffset);
    fprintf(f, "//     DATA_SIZE   (uint16[]) : 0x%016llX\n", (unsigned long long)rt.archCompDataSize);
    fprintf(f, "//   dataComponents tuple_vec : 0x%016llX  EM%s\n",
            (unsigned long long)rt.dataComponentsTupleVec, ofs_str(rt.ofsDataComponents, ob, sizeof(ob)));
    fprintf(f, "//   cidx -> name hash array  : 0x%016llX  count=%u\n\n",
            (unsigned long long)rt.componentHashArray, rt.componentCount);

    if (rt.componentHashArray && rt.componentCount) {
        fprintf(f, "// --- COMPONENT INDEX TABLE (cidx -> slot name) ---\n");
        fprintf(f, "// Total: %u\n", rt.componentCount);
        fprintf(f, "//  CIDX   HASH        NAME\n");
        for (uint32_t i = 0; i < rt.componentCount; i++) {
            uint32_t h = *(const uint32_t*)(rt.componentHashArray + 4ull * i);
            auto it = hash_to_name.find(h);
            fprintf(f, "  [%04u] 0x%08X  %s\n", i, h,
                    it != hash_to_name.end() ? it->second.c_str() : "<unknown>");
        }
        fprintf(f, "\n");
    }

    if (rt.haveArchetypes()) {
        fprintf(f, "// --- ARCHETYPES ---\n");
        fprintf(f, "// Total: %u archetype(s).\n", rt.archetypeCount);
        fprintf(f, "//\n");
        fprintf(f, "// This is the chunk layout: where every component of every entity\n");
        fprintf(f, "// physically lives. To read component C of the entity whose entDescs row\n");
        fprintf(f, "// says (archetype A, chunkId K, idInChunk R):\n");
        fprintf(f, "//\n");
        fprintf(f, "//     addr = chunk[K].data + (OFFSET << chunk[K].capacityBits) + R * SIZE\n");
        fprintf(f, "//\n");
        fprintf(f, "// OFFSET and SIZE are the per-component columns below. Storage is SoA:\n");
        fprintf(f, "// a component's column is contiguous across all entities in the chunk,\n");
        fprintf(f, "// which is why OFFSET is shifted by capacityBits rather than added.\n");
        fprintf(f, "//\n");
        fprintf(f, "// A SIZE of 0 is a tag (ecs::Tag and friends): presence carries the\n");
        fprintf(f, "// meaning, there are no bytes to read.\n\n");

        for (uint32_t a = 0; a < rt.archetypeCount; a++) {
            const ArchetypeView* av = (const ArchetypeView*)(rt.archetypeArray + (size_t)rt.archetypeStride * a);
            if (!av->totalEntitiesUsed) continue;   // only archetypes with live entities

            uint32_t nchunks = av->isChunkArray ? ((const ChunksArrayView*)av)->count : 1u;
            fprintf(f, "archetype[%u]  entities=%u/%u  entitySize=%u  components=%u  chunks=%u\n",
                    a, av->totalEntitiesUsed, av->totalEntitiesCapacity,
                    av->entitySize, av->componentsCnt, nchunks);

            for (uint32_t k = 0; k < nchunks && k < 8; k++) {
                const ChunkView* ch;
                if (av->isChunkArray) {
                    const ChunksArrayView* ca = (const ChunksArrayView*)av;
                    ch = (const ChunkView*)(ca->ptr + 16ull * k);
                } else {
                    ch = (const ChunkView*)av;
                }
                fprintf(f, "    chunk[%u] data=0x%016llX used=%u capacityBits=%u (capacity=%u)\n",
                        k, (unsigned long long)ch->data, ch->entitiesUsed,
                        ch->capacityBits,
                        ch->capacityBits <= 14 ? (1u << ch->capacityBits) : 0u);
            }

            if (rt.haveArchComps() && rt.archCompIndex) {
                fprintf(f, "    %-8s %-6s %-6s %s\n", "OFFSET", "SIZE", "CIDX", "COMPONENT");
                uint32_t cofs = rt.componentOfs[a];
                for (uint32_t i = 0; i < av->componentsCnt; i++) {
                    uint32_t slot = cofs + i;
                    uint16_t cidx = *(const uint16_t*)(rt.archCompIndex + 2ull * slot);
                    uint16_t off  = *(const uint16_t*)(rt.archCompDataOffset + 2ull * slot);

                    // Size = step to the next DATA_OFFSET; the last takes the rest of entitySize.
                    uint16_t sz;
                    if (rt.archCompDataSize)
                        sz = *(const uint16_t*)(rt.archCompDataSize + 2ull * slot);
                    else if (i + 1 < av->componentsCnt)
                        sz = (uint16_t)(*(const uint16_t*)(rt.archCompDataOffset + 2ull * (slot + 1)) - off);
                    else
                        sz = (uint16_t)(av->entitySize - off);

                    const char* nm = "<unnamed>";
                    if (rt.componentHashArray && cidx < rt.componentCount) {
                        uint32_t h = *(const uint32_t*)(rt.componentHashArray + 4ull * cidx);
                        auto it = hash_to_name.find(h);
                        if (it != hash_to_name.end()) nm = it->second.c_str();
                    }
                    fprintf(f, "    +0x%04X   %-6u %-6u %s\n", off, sz, cidx, nm);
                }
            } else {
                fprintf(f, "    (component layout unavailable — archetypeComponents not located)\n");
            }
            fprintf(f, "\n");
        }
    }

    fprintf(f, "// --- NATIVE STRUCT FIELD OFFSETS (daScript RTTI) ---\n");
    fprintf(f, "// C++ structs bound to script with DAS_BIND_MANAGED_FIELD keep their real\n");
    fprintf(f, "// offsetof() at runtime. This is the layout INSIDE a component type; the ECS\n");
    fprintf(f, "// chains only ever tell you a type's name and its total size.\n");
    if (das.ok()) {
        fprintf(f, "// VarInfo layout used: name=+0x%02zX offset=+0x%02zX size=%s\n",
                das.varInfoNameOfs, das.varInfoOffsetOfs,
                das.varInfoSizeOfs == SIZE_MAX ? "<not found>" : "found");
        size_t nf = 0;
        for (const auto& st : das.structs) nf += st.fields.size();
        fprintf(f, "// Total: %zu struct(s), %zu field(s)\n\n", das.structs.size(), nf);
        for (const auto& st : das.structs) {
            fprintf(f, "struct %s%s%s {   // size 0x%X (%u bytes), %zu field(s)  @0x%016llX\n",
                    st.moduleName.empty() ? "" : st.moduleName.c_str(),
                    st.moduleName.empty() ? "" : "::",
                    st.name.c_str(), st.size, st.size, st.fields.size(),
                    (unsigned long long)st.addr);
            for (const auto& fl : st.fields)
                fprintf(f, "    +0x%04X  %-6u  %s\n", fl.offset, fl.size, fl.name.c_str());
            fprintf(f, "};\n\n");
        }
    } else {
        fprintf(f, "// None recovered (%u candidate record(s) examined).\n",
                das.candidatesSeen);
        fprintf(f, "// Either this build ships no daScript bindings, or script type info had\n");
        fprintf(f, "// not been materialised yet when the DLL was injected.\n\n");
    }

    if (!das.enums.empty()) {
        size_t nv = 0;
        for (const auto& en : das.enums) nv += en.values.size();
        fprintf(f, "// --- daScript ENUMS ---\n");
        fprintf(f, "// Total: %zu enum(s), %zu value(s)\n\n", das.enums.size(), nv);
        for (const auto& en : das.enums) {
            fprintf(f, "enum %s%s%s {   // %zu value(s)  @0x%016llX\n",
                    en.moduleName.empty() ? "" : en.moduleName.c_str(),
                    en.moduleName.empty() ? "" : "::",
                    en.name.c_str(), en.values.size(), (unsigned long long)en.addr);
            for (const auto& v : en.values)
                fprintf(f, "    %-40s = %lld,\n", v.name.c_str(), v.value);
            fprintf(f, "};\n\n");
        }
    }

    fprintf(f, "// --- C++ CLASSES (MSVC RTTI) ---\n");
    fprintf(f, "// Every class with a virtual function. VTABLE_RVA is stable across\n");
    fprintf(f, "// restarts: add it to the module base to get the live vtable. METHODS is\n");
    fprintf(f, "// how many consecutive slots hold code, i.e. the virtual count, so slot N\n");
    fprintf(f, "// is at VTABLE + 8*N if you want to hook one.\n");
    fprintf(f, "// RTTI describes the type graph, NOT field layout - there are no field\n");
    fprintf(f, "// offsets to be had here.\n");
    if (rtti.ok()) {
        fprintf(f, "// Module: %s @ 0x%016llX\n",
                rtti.moduleName.c_str(), (unsigned long long)rtti.moduleBase);
        fprintf(f, "// Total: %zu class(es) from %u locator(s)\n\n",
                rtti.classes.size(), rtti.colCandidates);
        fprintf(f, "//  VTABLE_RVA  VTABLE             METHODS BASES THISOFS  CLASS\n");
        for (const auto& c : rtti.classes) {
            if (c.vtable)
                fprintf(f, "  0x%08X  0x%016llX %-7u %-5u +0x%04X  %s\n",
                        c.vtableRva, (unsigned long long)c.vtable,
                        c.numMethods, c.numBases, c.thisOffset, c.name.c_str());
            else
                fprintf(f, "  %-11s %-18s %-7s %-5u %-8s %s\n",
                        "-", "-", "-", c.numBases, "-", c.name.c_str());
        }
        fprintf(f, "\n");
    } else {
        fprintf(f, "// None recovered (%u locator candidate(s)) - the binary was likely\n",
                rtti.colCandidates);
        fprintf(f, "// built with /GR- so no RTTI was emitted.\n\n");
    }

    {
        std::vector<std::pair<uint32_t, std::string>> tmpl;
        ecs_dump_all_templates(rt, tmpl);
        if (!tmpl.empty()) {
            fprintf(f, "// --- ENTITY TEMPLATES ---\n");
            fprintf(f, "// Every entity type the game can spawn. entDescs gives each entity a\n");
            fprintf(f, "// template id; this is what those ids mean.\n");
            fprintf(f, "// Total: %zu\n\n", tmpl.size());
            for (const auto& t : tmpl)
                fprintf(f, "  [%05u] %s\n", t.first, t.second.c_str());
            fprintf(f, "\n");
        }
    }

    fprintf(f, "// --- ECS_HASH DICTIONARY (FNV-1a basis=0x811C9DC5 prime=0x01000193) ---\n");
    fprintf(f, "// Every {const char*, fnv1a(str)} literal found in module data —\n");
    fprintf(f, "// use it to reverse any hash you meet elsewhere in the engine.\n");
    fprintf(f, "// Total: %zu\n", hashed.size());
    for (const auto& h : hashed)
        fprintf(f, "  0x%08X  %s\n", h.hash, h.name.c_str());
    fprintf(f, "\n");

    fclose(f);
    LOG_INFO("Dump file written successfully");

    std::string hdr_path = output_path;
    auto ext = hdr_path.rfind(".txt");
    if (ext != std::string::npos) hdr_path.erase(ext);
    hdr_path += "_offsets.hpp";
    {
        std::string json_path = output_path;
        auto e2 = json_path.rfind(".txt");
        if (e2 != std::string::npos) json_path.erase(e2);
        json_path += "_offsets.json";
        write_offsets_json(json_path.c_str(), types, components, events, rt, hash_to_name);
    }

    write_offsets_header(hdr_path.c_str(),
                         (uintptr_t)GetModuleHandleA(nullptr),
                         GetCurrentProcessId(),
                         types, components, events, rt);

    ULONGLONG elapsed = GetTickCount64() - t_total;
    LOG_INFO("Total dump time: %llums", (unsigned long long)elapsed);
}
