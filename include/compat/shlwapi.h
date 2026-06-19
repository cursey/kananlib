// Non-Windows shim for <shlwapi.h>: only PathRemoveFileSpecW is used.
#pragma once

#if defined(_WIN32)
#error "compat/shlwapi.h is a non-Windows shim and must not be used on Windows"
#endif

#include "windows.h"

extern "C" {
BOOL PathRemoveFileSpecW(LPWSTR path);
}
