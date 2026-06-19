// Non-Windows shim for <rttidata.h>: MSVC RTTI on-disk structures.
//
// These describe the MSVC C++ RTTI graph as it is laid out inside a PE image.
// On x86-64 the cross-references are image-relative 32-bit offsets (added to the
// module base), which is exactly how kananlib's RTTI.cpp consumes them. Field
// names match the MSVC <rttidata.h> definitions the source refers to.
#pragma once

#include <cstdint>

// {mdisp, pdisp, vdisp} member displacement record.
typedef struct _PMD {
    int32_t mdisp;
    int32_t pdisp;
    int32_t vdisp;
} _PMD;

typedef struct _s_RTTIBaseClassDescriptor {
    uint32_t pTypeDescriptor;        // image-relative TypeDescriptor*
    uint32_t numContainedBases;
    _PMD     where;
    uint32_t attributes;
    uint32_t pClassDescriptor;       // image-relative ClassHierarchyDescriptor*
} _s_RTTIBaseClassDescriptor;

typedef struct _s_RTTIBaseClassArray {
    uint32_t arrayOfBaseClassDescriptors[1]; // image-relative offsets (variable length)
} _s_RTTIBaseClassArray;

typedef struct _s_RTTIClassHierarchyDescriptor {
    uint32_t signature;
    uint32_t attributes;
    uint32_t numBaseClasses;
    uint32_t pBaseClassArray;        // image-relative BaseClassArray*
} _s_RTTIClassHierarchyDescriptor;

typedef struct _s_RTTICompleteObjectLocator {
    uint32_t signature;              // 0 = x86, 1 = x64
    uint32_t offset;                 // offset of vtable within the class
    uint32_t cdOffset;
    uint32_t pTypeDescriptor;        // image-relative TypeDescriptor*
    uint32_t pClassDescriptor;       // image-relative ClassHierarchyDescriptor*
    uint32_t pSelf;                  // image-relative self pointer (x64)
} _s_RTTICompleteObjectLocator;
