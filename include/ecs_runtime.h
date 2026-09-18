// Runtime DagorEngine ECS structures and the offset-discovery engine.
//
// The public DagorEngine tree gives the *shape* of each structure, not the
// offsets in a shipped (forked) build. Nothing here is hardcoded: each address
// is found by a structural signature, then accepted only if an independent
// invariant holds (e.g. sum of per-archetype entity counts == live entities
// counted from entDescs).
//
// Layouts (per DagorEngine/prog/dagorInclude/daECS):
//
// dag::Vector<T, EmptyAlloc, false, uint32_t> (= SmallTab<T>), 16 bytes
//   +0x00 T* mpBegin; +0x08 u32 mCount; +0x0C u32 mAllocated
//
// eastl::tuple_vector<T0..Tn-1> (SoA)
//   +0x00..        Ti* leaf[i]          leaf[0] == mpData
//   +0x08*n        void* mpData
//   +0x08*n+0x08   u32 mNumElements
//   +0x08*n+0x0C   u32 mNumCapacity
//   +0x08*n+0x10   u32 dataSize
//
// EntitiesDescriptors
//   +0x00 SmallTab<EntityDesc> entDescs
//   +0x10 SmallTab<u8> currentlyCreatingEntitiesCnt   (SoA, same count)
//   +0x20 u32 totalSize; +0x24 u32 delayedAdded; +0x28 u32 globalGen
//
// Component address:
//   chunk.data + (DATA_OFFSET[COMPONENT_OFS+comp] << chunk.capacityBits)
//              + idInChunk * DATA_SIZE[COMPONENT_OFS+comp]
//
// DATA_OFFSET is an unaligned prefix sum of DATA_SIZE (SoA per chunk), and
// COMPONENT_OFS[a] == sum(componentsCnt[0..a-1]) because archetypes are
// append-only — so it's computed, not read.

#pragma once
#include "ecs_structs.h"
#include "scanner.h"
#include <vector>
#include <string>
#include <unordered_map>

#pragma pack(push, 8)
struct DagVectorView {
    uintptr_t ptr;
    uint32_t  count;
    uint32_t  capacity;
};
static_assert(sizeof(DagVectorView) == 16, "DagVectorView must be 16 bytes");

struct EntitiesDescriptorsView {
    DagVectorView entDescs;                     // +0x00
    DagVectorView currentlyCreatingEntitiesCnt; // +0x10
    uint32_t      totalSize;                    // +0x20
    uint32_t      delayedAdded;                 // +0x24
    uint32_t      globalGen;                    // +0x28
};

// ecs::Archetype. DataComponentManager is #pragma pack(4).
struct ArchetypeView {
    uintptr_t chunk0_data;      // +0x00 ┐ AliasedChunk: one inline Chunk, or a
    uint32_t  chunk0_used;      // +0x08 │ SmallTab<Chunk,_,u16> in the same
    uint8_t   chunk0_capBits;   // +0x0C │ 16 bytes. Last byte != 0 means array.
    uint8_t   _pad0[2];         // +0x0D │
    uint8_t   isChunkArray;     // +0x0F ┘
    uint32_t  totalEntitiesUsed;     // +0x10
    uint32_t  totalEntitiesCapacity; // +0x14
    uint8_t   workingChunk;          // +0x18
    uint8_t   initialBits;           // +0x19
    uint8_t   currentCapacityBits;   // +0x1A
    uint8_t   lockedOnRecreateCount; // +0x1B
    uint16_t  entitySize;            // +0x1C
    uint16_t  componentsCnt;         // +0x1E
};
static_assert(sizeof(ArchetypeView) == 32, "ArchetypeView must be 32 bytes");

struct ChunkView {
    uintptr_t data;             // +0x00
    uint32_t  entitiesUsed;     // +0x08
    uint8_t   capacityBits;     // +0x0C
    uint8_t   _pad[3];
};
static_assert(sizeof(ChunkView) == 16, "ChunkView must be 16 bytes");
#pragma pack(pop)

struct ChunksArrayView {
    uintptr_t ptr;
    uint16_t  count;
    uint16_t  capacity;
};

struct TupleVecInfo {
    uintptr_t addr        = 0;
    uint32_t  leafCount   = 0;
    uintptr_t leaf[16]    = {};
    uintptr_t mpData      = 0;
    uint32_t  numElements = 0;
    uint32_t  numCapacity = 0;
    uint32_t  dataSize    = 0;
    bool      valid() const { return addr != 0 && leafCount != 0; }
};

// Layout is [leaf0][leaf1]..[leafN-1][mpData==leaf0][count][cap], so the
// second occurrence of leaf0's value marks mpData and fixes N.
TupleVecInfo decode_tuple_vector_at(uintptr_t obj_addr, uint32_t max_leaves = 16);

struct EcsRuntimeOffsets {
    // Absolute addresses, valid for this run only.
    uintptr_t entityManager        = 0;   // 0 if the base couldn't be pinned
    uintptr_t entDescsStruct       = 0;
    uintptr_t entDescsArray        = 0;
    uintptr_t archetypesTupleVec   = 0;
    uintptr_t archetypeArray       = 0;
    uintptr_t archCompsTupleVec    = 0;
    uintptr_t archCompIndex        = 0;   // leaf INDEX       (component_index_t[])
    uintptr_t archCompDataOffset   = 0;   // leaf DATA_OFFSET (uint16_t[])
    uintptr_t archCompDataSize     = 0;   // leaf DATA_SIZE   (uint16_t[])
    uintptr_t dataComponentsTupleVec = 0;
    uintptr_t componentHashArray   = 0;   // component_t[] by cidx
    uintptr_t componentTypeArray   = 0;   // DataComponent[] by cidx (gives the C++ type)

    // Set when EntityManager is a static; used to emit restart-stable RVAs.
    uintptr_t moduleBase = 0;
    char      moduleName[64] = {};

    // Relative to entityManager.
    size_t ofsEntDescs        = SIZE_MAX;
    size_t ofsArchetypes      = SIZE_MAX;
    size_t ofsArchComps       = SIZE_MAX;
    size_t ofsDataComponents  = SIZE_MAX;

    uint32_t entitySlots       = 0;   // used slots, not capacity
    uint32_t entitySlotsCap    = 0;
    uint32_t liveEntities      = 0;
    uint32_t archetypeCount    = 0;
    uint32_t maxArchetypeSeen  = 0;   // ids up to here are proven; past it is inference
    uint32_t archetypeStride   = 32;  // discovered; a fork can grow ecs::Archetype
    uint32_t archCompCount     = 0;
    uint32_t componentCount    = 0;

    std::vector<uint32_t> componentOfs;

    uint32_t sumArchEntities   = 0;
    bool     archetypesValidated = false;
    bool     archCompsValidated  = false;

    bool haveEntities()   const { return entDescsArray != 0 && entitySlots > 0; }
    bool haveArchetypes() const { return archetypeArray != 0 && archetypeCount > 0; }
    // DATA_SIZE is optional: it can be derived from DATA_OFFSET differences.
    bool haveArchComps()  const { return archCompDataOffset != 0; }
};

// known_component_hashes: slot-name hashes from the registration chains, used to
// identify the cidx table. May be empty (weaker validation on that step only).
EcsRuntimeOffsets discover_ecs_runtime(const std::vector<uint32_t>& known_component_hashes);

uintptr_t ecs_component_data_ptr(const EcsRuntimeOffsets& o,
                                 uint32_t archetype, uint32_t chunkId, uint32_t idInChunk,
                                 uint32_t archLocalComponent, uint16_t* out_size = nullptr);

// UINT32_MAX if absent.
uint32_t ecs_find_arch_component(const EcsRuntimeOffsets& o,
                                 uint32_t archetype, uint16_t cidx);

// 0 when the type table is absent.
uint32_t ecs_component_type_hash(const EcsRuntimeOffsets& o, uint16_t cidx);

// 0xFFFF if not found.
uint16_t ecs_cidx_for_hash(const EcsRuntimeOffsets& o, uint32_t name_hash);

// Names of components declared only in .blk templates live solely in
// DataComponents::names, a StringTableAllocator of heap pages:
//
//   StringTableAllocator { +0x00 StringPage head; +0x10 dag::Vector<StringPage> pages; }
//   StringPage           { +0x00 char* data; +0x08 u32 left; +0x0C u32 used; }  // pack(4)
//
// A string is accepted only if its hash is already in the cidx table, so no
// names are invented. Never overwrites existing entries.
void ecs_harvest_component_names(const EcsRuntimeOffsets& o,
                                 std::unordered_map<uint32_t, std::string>& out);

// template_t -> name, two hops away:
//   Templates::templates / templateDbId (SoA)  ->  TemplateDB::templates[dbId].name
// ecs::Template's stride and name offset aren't derivable from public headers,
// so both are discovered by consensus.
void ecs_harvest_template_names(const EcsRuntimeOffsets& o,
                                uint32_t max_template_id,
                                std::unordered_map<uint32_t, std::string>& out);

// Every template in TemplateDB (thousands), not just instantiated ones. dbId -> name.
void ecs_dump_all_templates(const EcsRuntimeOffsets& o,
                            std::vector<std::pair<uint32_t, std::string>>& out);
