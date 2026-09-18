// Recover class names and vtables from MSVC RTTI (x64, all fields are RVAs):
//
//   vtable[-1] -> RTTICompleteObjectLocator {
//       u32 signature;             // 1 on x64
//       u32 offset;                // this-adjustment
//       u32 cdOffset;
//       u32 pTypeDescriptor;       // -> { void* vft; void* spare; char name[]; }
//       u32 pClassHierarchyDesc;
//       u32 pSelf;                 // own RVA — used as the scan signature
//   }
//
// Gives names and vtables only, not field offsets.
#pragma once
#include <stdint.h>
#include <string>
#include <vector>

struct RttiClass {
    std::string name;        // "ns::MyClass"
    std::string rawName;     // ".?AVMyClass@ns@@"
    uintptr_t   colAddr = 0;
    uintptr_t   vtable  = 0; // 0 when no vtable references this COL
    uint32_t    vtableRva = 0;
    uint32_t    numBases  = 0;
    uint32_t    thisOffset = 0;
    uint32_t    numMethods = 0;  // counted until a slot stops pointing at code
};

struct RttiResult {
    std::vector<RttiClass> classes;
    uintptr_t moduleBase = 0;
    std::string moduleName;
    uint32_t colCandidates = 0;
    bool ok() const { return !classes.empty(); }
};

RttiResult dump_msvc_rtti();
