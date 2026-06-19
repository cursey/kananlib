// kananlib Linux/non-Windows compatibility shim.
//
// Provides the subset of <windows.h> / <winnt.h> types, PE/COFF structures and
// constants that kananlib relies on so the library can be built on Linux with
// clang. Only pulled in when the platform's real headers are absent; on Windows
// the compat include directory is not on the search path.
//
// Layouts here mirror the x86-64 Windows ABI exactly because the library reads
// real PE images byte-for-byte. Integer widths use fixed-size types so the
// structures are correct under LP64 (where `long` is 64-bit, unlike Windows).
#pragma once

#if defined(_WIN32)
#error "winnt_compat.h is a non-Windows shim and must not be used on Windows"
#endif

#include <cstdint>
#include <cstddef>

// ---------------------------------------------------------------------------
// Fundamental Windows integer/handle typedefs (LP64-safe).
// ---------------------------------------------------------------------------
typedef uint8_t  BYTE;
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t QWORD;
typedef int32_t  LONG;
typedef uint32_t ULONG;
typedef int16_t  SHORT;
typedef uint16_t USHORT;
typedef char     CHAR;
typedef uint8_t  UCHAR;
typedef int64_t  LONGLONG;
typedef uint64_t ULONGLONG;
typedef int      INT;
typedef unsigned int UINT;
typedef int      BOOL;
typedef uint8_t  BOOLEAN;
typedef wchar_t  WCHAR;
typedef float    FLOAT;

typedef intptr_t  LONG_PTR;
typedef uintptr_t ULONG_PTR;
typedef uintptr_t DWORD_PTR;
typedef intptr_t  INT_PTR;
typedef uintptr_t UINT_PTR;
typedef size_t    SIZE_T;
typedef intptr_t  SSIZE_T;

typedef void           VOID;
typedef void*          PVOID;
typedef void*          LPVOID;
typedef const void*    LPCVOID;
typedef void*          HANDLE;
typedef void*          HMODULE;
typedef void*          HINSTANCE;
typedef void*          HKEY;
typedef void*          HLOCAL;
typedef void*          HWND;
typedef int32_t        NTSTATUS;

typedef char*          PSTR;
typedef char*          LPSTR;
typedef const char*    PCSTR;
typedef const char*    LPCSTR;
typedef wchar_t*       PWSTR;
typedef wchar_t*       LPWSTR;
typedef const wchar_t* PCWSTR;
typedef const wchar_t* LPCWSTR;
typedef wchar_t*       PWCHAR;

typedef BYTE*      PBYTE;
typedef BYTE*      LPBYTE;
typedef WORD*      PWORD;
typedef DWORD*     PDWORD;
typedef DWORD*     LPDWORD;
typedef ULONG*     PULONG;
typedef ULONG_PTR* PULONG_PTR;
typedef BOOL*      PBOOL;
typedef HANDLE*    PHANDLE;
typedef HKEY*      PHKEY;

typedef void (*FARPROC)(void);
typedef void (*PROC)(void);

// Calling-convention / annotation macros are no-ops on the SysV x86-64 ABI.
#ifndef WINAPI
#define WINAPI
#endif
#ifndef NTAPI
#define NTAPI
#endif
#ifndef CALLBACK
#define CALLBACK
#endif
#ifndef APIENTRY
#define APIENTRY
#endif
#ifndef WINBASEAPI
#define WINBASEAPI
#endif
#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
#ifndef CONST
#define CONST const
#endif

// ---------------------------------------------------------------------------
// PE / COFF structures (x86-64). Field order and widths match winnt.h.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
#pragma pack(pop)

typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD      Magic;
    BYTE      MajorLinkerVersion;
    BYTE      MinorLinkerVersion;
    DWORD     SizeOfCode;
    DWORD     SizeOfInitializedData;
    DWORD     SizeOfUninitializedData;
    DWORD     AddressOfEntryPoint;
    DWORD     BaseOfCode;
    ULONGLONG ImageBase;
    DWORD     SectionAlignment;
    DWORD     FileAlignment;
    WORD      MajorOperatingSystemVersion;
    WORD      MinorOperatingSystemVersion;
    WORD      MajorImageVersion;
    WORD      MinorImageVersion;
    WORD      MajorSubsystemVersion;
    WORD      MinorSubsystemVersion;
    DWORD     Win32VersionValue;
    DWORD     SizeOfImage;
    DWORD     SizeOfHeaders;
    DWORD     CheckSum;
    WORD      Subsystem;
    WORD      DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD     LoaderFlags;
    DWORD     NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

// kananlib is x86-64 only, so the unsuffixed names map to the 64-bit variants.
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;
        DWORD OriginalFirstThunk;
    };
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;
        ULONGLONG Function;
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;
    } u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA64 PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD Hint;
    CHAR Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    union {
        DWORD UnwindInfoAddress;
        DWORD UnwindData;
    };
} IMAGE_RUNTIME_FUNCTION_ENTRY, *PIMAGE_RUNTIME_FUNCTION_ENTRY;
typedef IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION;
typedef PIMAGE_RUNTIME_FUNCTION_ENTRY PRUNTIME_FUNCTION;

// PE signatures / magics.
#define IMAGE_DOS_SIGNATURE              0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE               0x00004550  // PE00
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC    0x20b

// Data directory indices.
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE   2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION  3
#define IMAGE_DIRECTORY_ENTRY_SECURITY   4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
#define IMAGE_DIRECTORY_ENTRY_DEBUG      6
#define IMAGE_DIRECTORY_ENTRY_TLS        9
#define IMAGE_DIRECTORY_ENTRY_IAT        12

// Section characteristics.
#define IMAGE_SCN_CNT_CODE               0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA   0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_MEM_DISCARDABLE        0x02000000
#define IMAGE_SCN_MEM_EXECUTE            0x20000000
#define IMAGE_SCN_MEM_READ               0x40000000
#define IMAGE_SCN_MEM_WRITE              0x80000000

// Ordinal helpers (x86-64).
#define IMAGE_ORDINAL_FLAG64             0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG               IMAGE_ORDINAL_FLAG64
#define IMAGE_SNAP_BY_ORDINAL64(o)       (((o) & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL(o)         IMAGE_SNAP_BY_ORDINAL64(o)
#define IMAGE_ORDINAL64(o)               ((o) & 0xffff)
#define IMAGE_ORDINAL(o)                 IMAGE_ORDINAL64(o)

// First section header follows the optional header.
#define IMAGE_FIRST_SECTION(nth) ((PIMAGE_SECTION_HEADER)( \
    (ULONG_PTR)(nth) + \
    offsetof(IMAGE_NT_HEADERS, OptionalHeader) + \
    ((PIMAGE_NT_HEADERS)(nth))->FileHeader.SizeOfOptionalHeader))

// x64 unwind handler flags.
#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

// ---------------------------------------------------------------------------
// Memory protection / allocation constants.
// ---------------------------------------------------------------------------
#define PAGE_NOACCESS          0x01
#define PAGE_READONLY          0x02
#define PAGE_READWRITE         0x04
#define PAGE_WRITECOPY         0x08
#define PAGE_EXECUTE           0x10
#define PAGE_EXECUTE_READ      0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80
#define PAGE_GUARD             0x100
#define PAGE_NOCACHE           0x200
#define PAGE_WRITECOMBINE      0x400

#define MEM_COMMIT             0x00001000
#define MEM_RESERVE            0x00002000
#define MEM_DECOMMIT           0x00004000
#define MEM_RELEASE            0x00008000
#define MEM_FREE               0x00010000
#define MEM_PRIVATE            0x00020000
#define MEM_MAPPED             0x00040000
#define MEM_IMAGE              0x01000000

#define SEC_IMAGE              0x1000000
#define SEC_COMMIT             0x8000000

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID     BaseAddress;
    PVOID     AllocationBase;
    DWORD     AllocationProtect;
    SIZE_T    RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

// ---------------------------------------------------------------------------
// File / handle constants (only referenced by Windows-only code paths, but
// defined so those translation units still compile cleanly).
// ---------------------------------------------------------------------------
#define INVALID_HANDLE_VALUE   ((HANDLE)(LONG_PTR)-1)
#define GENERIC_READ           0x80000000
#define GENERIC_WRITE          0x40000000
#define FILE_SHARE_READ        0x00000001
#define FILE_SHARE_WRITE       0x00000002
#define OPEN_EXISTING          3
#define FILE_ATTRIBUTE_NORMAL  0x80
#define FILE_MAP_READ          0x0004
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)

// ---------------------------------------------------------------------------
// Registry constants.
// ---------------------------------------------------------------------------
#define ERROR_SUCCESS          0L
#define ERROR_FILE_NOT_FOUND   2L
#define KEY_QUERY_VALUE        0x0001
#define REG_NONE               0
#define REG_SZ                 1
#define REG_DWORD              4
#define HKEY_CLASSES_ROOT      ((HKEY)(ULONG_PTR)0x80000000)
#define HKEY_CURRENT_USER      ((HKEY)(ULONG_PTR)0x80000001)
#define HKEY_LOCAL_MACHINE     ((HKEY)(ULONG_PTR)0x80000002)
#define HKEY_USERS             ((HKEY)(ULONG_PTR)0x80000003)

// Module-handle resolution flags.
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS       0x00000004
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 0x00000002
#define DONT_RESOLVE_DLL_REFERENCES                  0x00000001

// ---------------------------------------------------------------------------
// MSVC defines the DUMMYUNIONNAME/DUMMYSTRUCTNAME placeholders to nothing so the
// winnt.h-style unions/structs that use them are anonymous. Match that so member
// access through those (e.g. RUNTIME_FUNCTION.UnwindData) compiles.
// ---------------------------------------------------------------------------
#define DUMMYUNIONNAME
#define DUMMYUNIONNAME2
#define DUMMYUNIONNAME3
#define DUMMYUNIONNAME4
#define DUMMYUNIONNAME5
#define DUMMYSTRUCTNAME
#define DUMMYSTRUCTNAME2

// Thread access right used by OpenThread (thread suspension path).
#define THREAD_SUSPEND_RESUME 0x0002

// MSVC byte-swap intrinsics. Defined here (rather than in <intrin.h>) so they
// have a single definition in TUs that include both headers.
static inline unsigned short     _byteswap_ushort(unsigned short v)     { return __builtin_bswap16(v); }
static inline unsigned long      _byteswap_ulong(unsigned long v)       { return __builtin_bswap32((uint32_t)v); }
static inline unsigned long long _byteswap_uint64(unsigned long long v) { return __builtin_bswap64(v); }

// Base relocations (applied by the non-Windows loader to rebase absolute
// pointers when the image is not mapped at its preferred ImageBase).
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
} IMAGE_BASE_RELOCATION, *PIMAGE_BASE_RELOCATION;

#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_HIGHLOW  3
#define IMAGE_REL_BASED_DIR64    10
