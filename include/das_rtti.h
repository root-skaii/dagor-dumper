// Recover native struct field offsets from daScript runtime type info.
//
// Structs bound with ManagedStructureAnnotation + DAS_BIND_MANAGED_FIELD keep
// the real offsetof() of every field at runtime:
//
//   StructInfo {
//       const char* name;          // +0x00
//       const char* module_name;   // +0x08
//       VarInfo**   fields;        // +0x10
//       AnnotationInfo* annotations;
//       u64 hash, init_mnh;
//       u32 flags, count, size, ...
//   }
//   VarInfo : TypeInfo { ...; const char* name; ...; u32 offset; ... }
//
// The shipped daScript is a fork, so VarInfo::name / ::offset positions are
// discovered by consensus across all candidates rather than hardcoded: every
// field has a readable name at the same offset, and offsets start at 0, are
// non-decreasing, and stay below the struct size. Only the StructInfo header
// shape is assumed.
#pragma once
#include <stdint.h>
#include <string>
#include <vector>

struct DasField {
    std::string name;
    uint32_t    offset = 0;
    uint32_t    size   = 0;
    uint32_t    typeCode = 0;   // raw daScript Type enum
};

struct DasStruct {
    uintptr_t   addr = 0;
    std::string name;
    std::string moduleName;
    uint32_t    size  = 0;
    uint32_t    flags = 0;
    std::vector<DasField> fields;
};

// EnumInfo shares StructInfo's first three members, so the signature scan
// can't tell them apart. The entry discriminates: EnumValueInfo has a string
// at +0x00, VarInfo has a pointer (or null) there.
struct DasEnumValue {
    std::string name;
    long long   value = 0;
};

struct DasEnum {
    uintptr_t   addr = 0;
    std::string name;
    std::string moduleName;
    std::vector<DasEnumValue> values;
};

struct DasRttiResult {
    std::vector<DasStruct> structs;
    std::vector<DasEnum>   enums;
    size_t varInfoNameOfs   = SIZE_MAX;
    size_t varInfoOffsetOfs = SIZE_MAX;
    size_t varInfoSizeOfs   = SIZE_MAX;
    size_t varInfoTypeOfs   = SIZE_MAX;
    size_t structCountOfs   = SIZE_MAX;
    size_t structSizeOfs    = SIZE_MAX;
    uint32_t candidatesSeen = 0;
    bool ok()       const { return !structs.empty(); }
    bool anything() const { return !structs.empty() || !enums.empty(); }
};

// Returns an empty result if the process has no daScript.
DasRttiResult dump_das_rtti();
