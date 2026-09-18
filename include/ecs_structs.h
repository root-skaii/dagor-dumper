// POD mirrors of DagorEngine ECS registration structures (x64 MSVC ABI).
#pragma once
#include <stdint.h>

using entity_id_t        = uint32_t;
using component_type_t   = uint32_t;   // FNV-1a of C++ type name
using component_t        = uint32_t;   // FNV-1a of component slot name
using event_type_t       = uint32_t;
using event_size_t       = uint16_t;
using event_flags_t      = uint16_t;
using component_index_t  = uint16_t;
using archetype_t        = uint16_t;
using template_t         = uint16_t;
using type_index_t       = uint16_t;
using ComponentTypeFlags = uint16_t;
using component_flags_t  = uint16_t;

static constexpr archetype_t       INVALID_ARCHETYPE        = 0xFFFF;
static constexpr component_index_t INVALID_COMPONENT_INDEX  = 0xFFFF;

inline constexpr uint32_t fnv1a(const char* s, uint32_t h = 2166136261u) {
    return *s ? fnv1a(s + 1, (h ^ (uint8_t)*s) * 16777619u) : h;
}

struct EntityId {
    uint32_t handle = 0;
    uint32_t index()      const { return handle >> 10; }       // 22-bit index
    uint32_t generation() const { return handle & 0x3FF; }     // 10-bit gen
    bool     valid()      const { return handle != 0; }
    static EntityId make(uint32_t idx, uint32_t gen) {
        return { (idx << 10) | (gen & 0x3FF) };
    }
};
static_assert(sizeof(EntityId) == 4, "EntityId must be 4 bytes");

// archetype == 0xFFFF means the slot is free.
struct EntityDesc {
    archetype_t archetype   = 0xFFFF;   // +0x00
    template_t  template_id = 0xFFFF;   // +0x02
    uint32_t    chunkId    : 8;         // +0x04 bits [7:0]
    uint32_t    generation : 10;        //       bits [17:8]  must match EntityId::generation()
    uint32_t    idInChunk  : 14;        //       bits [31:18]
};
static_assert(sizeof(EntityDesc) == 8, "EntityDesc must be 8 bytes (G_STATIC_ASSERT)");

// Chain 1. Each ctor does `next = tail; tail = this;` — `tail` is a separate static.
#pragma pack(push, 8)
struct CompileComponentTypeRegister {
    const char*                   name;       // +0x00
    CompileComponentTypeRegister* next;       // +0x08
    void*                         ctm;        // +0x10
    void*                         dtm;        // +0x18
    void*                         io;         // +0x20
    uint32_t                      name_hash;  // +0x28 FNV-1a(name)
    uint32_t                      size;       // +0x2C 0 for tag types
    ComponentTypeFlags            flags;      // +0x30 CTF_*
    uint16_t                      _pad;
};
#pragma pack(pop)
static_assert(sizeof(CompileComponentTypeRegister) == 0x38, "size mismatch");

static constexpr ComponentTypeFlags CTF_NON_TRIVIAL_CREATE  = 0x0001;
static constexpr ComponentTypeFlags CTF_NON_TRIVIAL_MOVE    = 0x0002;
static constexpr ComponentTypeFlags CTF_BOXED               = 0x0004; // heap-allocated; chunk holds a pointer
static constexpr ComponentTypeFlags CTF_CREATE_ON_TEMPL     = 0x0008;
static constexpr ComponentTypeFlags CTF_NEED_RESOURCES      = 0x0010;
static constexpr ComponentTypeFlags CTF_HAS_IO              = 0x0020;
static constexpr ComponentTypeFlags CTF_IS_POD              = 0x0040;
static constexpr ComponentTypeFlags CTF_REPLICATION         = 0x0080;

// Chain 2: one named component slot.
#pragma pack(push, 8)
struct HashedConstString {
    const char* str;     // +0x00
    uint32_t    hash;    // +0x08 FNV-1a(str)
    uint32_t    _pad;
};

struct ConstSpanCStr {
    const char** data;
    uintptr_t    count;
};

struct CompileComponentRegister {
    HashedConstString          name;       // +0x00
    const char*                type_name;  // +0x10
    void*                      io;         // +0x18
    ConstSpanCStr              deps;       // +0x20
    CompileComponentRegister*  next;       // +0x30
    component_type_t           type;       // +0x38 FNV-1a(type_name)
    component_flags_t          flags;      // +0x3C CF_*
    uint16_t                   _pad;
};
#pragma pack(pop)
static_assert(sizeof(CompileComponentRegister) == 0x40, "size mismatch");

static constexpr component_flags_t CF_DONT_REPLICATE  = 0x0001;
static constexpr component_flags_t CF_IS_COPY         = 0x0002;
static constexpr component_flags_t CF_HAS_SERIALIZER  = 0x0004;

// Chain 6: one node per registered event type.
#pragma pack(push, 8)
struct EventInfoLinkedList {
    const char*          name;       // +0x00
    uint32_t             eventType;  // +0x08 ECS_HASH(name)
    uint16_t             eventSize;  // +0x0C max 1024
    uint16_t             eventFlags; // +0x0E EV_*
    void*                destroy;    // +0x10
    void*                move_out;   // +0x18
    EventInfoLinkedList* next;       // +0x20
};
#pragma pack(pop)
static_assert(sizeof(EventInfoLinkedList) == 0x28, "size mismatch");

static constexpr event_flags_t EV_UNICAST    = 0x0001;
static constexpr event_flags_t EV_BROADCAST  = 0x0002;
static constexpr event_flags_t EV_SERIALIZE  = 0x0004;
static constexpr event_flags_t EV_DESTROY    = 0x0008;
static constexpr event_flags_t EV_SCHEMELESS = 0x0010;
static constexpr event_flags_t EV_CORE       = 0x0020;
static constexpr event_flags_t EV_PROFILE    = 0x0040;

struct alignas(4) Event {
    event_type_t  type;    // +0x00
    event_size_t  length;  // +0x04
    event_flags_t flags;   // +0x06
    static constexpr size_t max_event_size = 1024;
};
static_assert(sizeof(Event) == 8, "Event must be 8 bytes (alignas(4))");

// Component at row R with DATA_OFFSET O:
//   chunk.data + (O << entitiesCapacityBits) + R * component_size
struct Chunk {
    uint8_t* data;
    uint32_t entitiesUsed;
    uint8_t  entitiesCapacityBits;   // capacity = 1 << bits (max 14)
    uint8_t  _pad[3];
};

#pragma pack(push, 1)
struct ChildComponent {
    union {
        void*   data;         // when > 8 bytes or non-trivial
        uint8_t buffer[8];    // inline small POD
    } value;                  // +0x00
    component_type_t componentType      = 0;      // +0x08
    type_index_t     componentTypeIndex = 0xFFFF; // +0x0C
    uint16_t         componentTypeSize  = 0;      // +0x0E
};
#pragma pack(pop)
static_assert(sizeof(ChildComponent) == 16, "ChildComponent must be 16 bytes");

struct DataComponent {
    type_index_t      componentType;      // +0x00 index into ComponentTypes::types
    component_flags_t flags;              // +0x02 CF_*
    component_type_t  componentTypeName;  // +0x04 type hash
};
static_assert(sizeof(DataComponent) == 8, "DataComponent must be 8 bytes");
