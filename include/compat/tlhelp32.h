// Non-Windows shim for <tlhelp32.h>: thread enumeration.
//
// Linux has no toolhelp snapshot API; CreateToolhelp32Snapshot returns
// INVALID_HANDLE_VALUE so the thread-suspension code degrades to a no-op.
// Included as lowercase <tlhelp32.h> (the one source that used <TlHelp32.h> was
// normalized to lowercase for case-sensitive filesystems).
#pragma once

#if defined(_WIN32)
#error "compat/tlhelp32.h is a non-Windows shim and must not be used on Windows"
#endif

#include "windows.h"

#define TH32CS_SNAPTHREAD 0x00000004

typedef struct tagTHREADENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
    LONG  tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, *PTHREADENTRY32, *LPTHREADENTRY32;

extern "C" {
HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD process_id);
BOOL   Thread32First(HANDLE snapshot, LPTHREADENTRY32 entry);
BOOL   Thread32Next(HANDLE snapshot, LPTHREADENTRY32 entry);
HANDLE OpenThread(DWORD desired, BOOL inherit, DWORD thread_id);
DWORD  SuspendThread(HANDLE thread);
DWORD  ResumeThread(HANDLE thread);
}
