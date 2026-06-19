// Non-Windows shim for <winternl.h>: PEB / loader structures.
//
// On Linux there is no PEB and no loader module list, so the functions that walk
// these (foreach_module, unlink, ...) are no-ops. The types still need to exist
// because they appear in public signatures (e.g. the foreach_module callback).
#pragma once

#if defined(_WIN32)
#error "compat/winternl.h is a non-Windows shim and must not be used on Windows"
#endif

#include "windows.h"

typedef struct _LIST_ENTRY {
    struct _LIST_ENTRY* Flink;
    struct _LIST_ENTRY* Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID          Reserved1[2];
    LIST_ENTRY     InMemoryOrderLinks;
    PVOID          Reserved2[2];
    PVOID          DllBase;
    PVOID          EntryPoint;
    PVOID          Reserved3[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    PVOID          Reserved4[8];
    PVOID          Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG          TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    BYTE          Reserved1[2];
    BYTE          BeingDebugged;
    BYTE          Reserved2[1];
    PVOID         Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;
