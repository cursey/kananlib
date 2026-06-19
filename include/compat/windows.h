// Non-Windows shim for <windows.h>. See winnt_compat.h for the rationale.
//
// Declares the Win32 entry points kananlib actually calls; implementations live
// in src/compat/WinCompat.cpp. Everything is C++-linkage (the library is C++).
//
// SCOPE POLICY: this shim implements ONLY the Win32 surface needed for
// file-mapped binary analysis. Do not grow it casually. Live-process / OS
// features (loader walk, real thread suspension, registry, input, PDB/DIA) stay
// deliberately unsupported -- they return failure or warn, never fake success.
// Anything that cannot be emulated faithfully should be made loud (SPDLOG_WARN
// or an honest failure), not papered over with a permissive guess.
//
// Note: kananlib sources include this as lowercase <windows.h>. On a
// case-sensitive filesystem there is intentionally no <Windows.h>; the few
// sources that used the capital spelling were normalized to lowercase so a
// single shim file serves both Windows (case-insensitive) and Linux builds.
#pragma once

#if defined(_WIN32)
#error "compat/windows.h is a non-Windows shim and must not be used on Windows"
#endif

#include "winnt_compat.h"
#include "seh_compat.h"

extern "C" {

// --- Virtual memory -------------------------------------------------------
BOOL   VirtualProtect(LPVOID address, SIZE_T size, DWORD new_protect, PDWORD old_protect);
SIZE_T VirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length);
LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD allocation_type, DWORD protect);
BOOL   VirtualFree(LPVOID address, SIZE_T size, DWORD free_type);

// --- Pointer validation ---------------------------------------------------
BOOL IsBadReadPtr(LPCVOID ptr, UINT_PTR size);
BOOL IsBadWritePtr(LPVOID ptr, UINT_PTR size);
BOOL IsBadCodePtr(FARPROC ptr);

// --- Modules / process ----------------------------------------------------
HMODULE GetModuleHandleA(LPCSTR module_name);
HMODULE GetModuleHandleW(LPCWSTR module_name);
BOOL    GetModuleHandleExA(DWORD flags, LPCSTR module_name, HMODULE* module);
DWORD   GetModuleFileNameA(HMODULE module, LPSTR filename, DWORD size);
DWORD   GetModuleFileNameW(HMODULE module, LPWSTR filename, DWORD size);
FARPROC GetProcAddress(HMODULE module, LPCSTR proc_name);
HMODULE LoadLibraryA(LPCSTR filename);
HMODULE LoadLibraryW(LPCWSTR filename);
HMODULE LoadLibraryExA(LPCSTR filename, HANDLE file, DWORD flags);
UINT    GetSystemDirectoryW(LPWSTR buffer, UINT size);

HANDLE GetCurrentProcess(void);
DWORD  GetCurrentProcessId(void);
DWORD  GetCurrentThreadId(void);
BOOL   FlushInstructionCache(HANDLE process, LPCVOID base, SIZE_T size);

// --- Handles / files (referenced by Windows-only code paths) --------------
BOOL   CloseHandle(HANDLE object);
HANDLE CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPVOID sa, DWORD disp, DWORD flags, HANDLE templ);
HANDLE CreateFileMappingW(HANDLE file, LPVOID sa, DWORD protect, DWORD high, DWORD low, LPCWSTR name);
LPVOID MapViewOfFile(HANDLE mapping, DWORD access, DWORD high, DWORD low, SIZE_T bytes);
BOOL   UnmapViewOfFile(LPCVOID base);
DWORD  GetTempPathA(DWORD len, LPSTR buffer);
BOOL   DeleteFileA(LPCSTR filename);

// --- Interlocked ----------------------------------------------------------
LONG    InterlockedCompareExchange(volatile LONG* dest, LONG exchange, LONG comparand);
PVOID   InterlockedCompareExchangePointer(PVOID volatile* dest, PVOID exchange, PVOID comparand);

// --- Input ----------------------------------------------------------------
SHORT GetAsyncKeyState(int vkey);

// --- Registry -------------------------------------------------------------
LONG RegOpenKeyExA(HKEY key, LPCSTR subkey, DWORD options, DWORD desired, PHKEY result);
LONG RegQueryValueExA(HKEY key, LPCSTR value, LPDWORD reserved, LPDWORD type, LPBYTE data, LPDWORD size);
LONG RegCloseKey(HKEY key);

} // extern "C"

// ANSI-default macros mirroring <windows.h> (no UNICODE on Linux builds).
#define GetModuleHandle  GetModuleHandleA
#define GetModuleFileName GetModuleFileNameA
#define LoadLibrary      LoadLibraryA

// Allocation-type flag accepted (and ignored) by the VirtualAlloc shim.
#ifndef MEM_TOP_DOWN
#define MEM_TOP_DOWN 0x00100000
#endif
