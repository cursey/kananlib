// Runtime backing for the non-Windows Win32 shim (see include/compat/).
//
// Implements the handful of Win32 entry points kananlib calls in terms of POSIX:
//   * VirtualAlloc/Free/Protect/Query   -> mmap/munmap/mprotect + /proc/self/maps
//   * IsBad{Read,Write,Code}Ptr         -> /proc/self/maps readability checks
//   * structured-exception emulation    -> SIGSEGV/SIGBUS + sigsetjmp/siglongjmp
// Module/registry/input/toolhelp entry points become inert (Linux has no Win32
// loader, registry, async key state or toolhelp snapshots), which makes the
// live-process features no-ops while the file-mapping + scanning core works.
#if !defined(_WIN32)

#include <compat/windows.h>
#include <compat/winternl.h>
#include <compat/shlwapi.h>
#include <compat/tlhelp32.h>

#include <utility/Logging.hpp>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <algorithm>

#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/mman.h>

namespace {
// --------------------------------------------------------------------------
// /proc/self/maps snapshot, cached per-thread and invalidated by a global
// generation counter that bumps whenever we change the address space.
// --------------------------------------------------------------------------
struct Region {
    uintptr_t start;
    uintptr_t end;
    int       prot;   // PROT_READ | PROT_WRITE | PROT_EXEC
};

std::atomic<uint64_t> g_maps_generation{1};

struct MapsCache {
    uint64_t generation{0};
    std::vector<Region> regions; // sorted by start
};

thread_local MapsCache t_cache;

void rebuild_cache() {
    t_cache.regions.clear();

    FILE* f = std::fopen("/proc/self/maps", "r");
    if (f == nullptr) {
        t_cache.generation = g_maps_generation.load();
        return;
    }

    char line[512];
    while (std::fgets(line, sizeof(line), f) != nullptr) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        // Format: start-end perms offset dev inode path
        if (std::sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) {
            continue;
        }

        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;

        t_cache.regions.push_back({start, end, prot});
    }
    std::fclose(f);

    std::sort(t_cache.regions.begin(), t_cache.regions.end(),
              [](const Region& a, const Region& b) { return a.start < b.start; });

    t_cache.generation = g_maps_generation.load();
}

void ensure_cache() {
    if (t_cache.generation != g_maps_generation.load()) {
        rebuild_cache();
    }
}

// Region containing addr, or nullptr if addr falls in a gap.
const Region* region_of(uintptr_t addr) {
    ensure_cache();
    const auto& regs = t_cache.regions;
    // upper_bound by start, then step back one.
    size_t lo = 0, hi = regs.size();
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (regs[mid].start <= addr) lo = mid + 1; else hi = mid;
    }
    if (lo == 0) return nullptr;
    const Region& r = regs[lo - 1];
    return (addr >= r.start && addr < r.end) ? &r : nullptr;
}

// Is [addr, addr+len) entirely covered by mapped regions whose protection
// includes every bit in `need`? Adjacent regions are treated as contiguous.
bool range_has_access(uintptr_t addr, size_t len, int need) {
    if (len == 0) return true;
    ensure_cache();

    uintptr_t cur = addr;
    const uintptr_t end = addr + len;
    if (end < addr) return false; // overflow

    while (cur < end) {
        const Region* r = region_of(cur);
        if (r == nullptr || (r->prot & need) != need) {
            return false;
        }
        cur = r->end;
    }
    return true;
}

int page_size() {
    static int ps = (int)sysconf(_SC_PAGESIZE);
    return ps;
}

int win_to_posix_prot(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return PROT_NONE;
        case PAGE_READONLY:          return PROT_READ;
        case PAGE_READWRITE:         return PROT_READ | PROT_WRITE;
        case PAGE_WRITECOPY:         return PROT_READ | PROT_WRITE;
        case PAGE_EXECUTE:           return PROT_EXEC;
        case PAGE_EXECUTE_READ:      return PROT_READ | PROT_EXEC;
        case PAGE_EXECUTE_READWRITE: return PROT_READ | PROT_WRITE | PROT_EXEC;
        case PAGE_EXECUTE_WRITECOPY: return PROT_READ | PROT_WRITE | PROT_EXEC;
        default:
            // A page protection we do not model. Be loud and deny rather than
            // silently guessing a permissive mapping.
            SPDLOG_WARN("[compat] unsupported Win32 page protection 0x{:x}; treating as PAGE_NOACCESS", protect);
            return PROT_NONE;
    }
}

DWORD posix_to_win_prot(int prot) {
    const bool r = prot & PROT_READ, w = prot & PROT_WRITE, x = prot & PROT_EXEC;
    if (x) {
        if (w) return PAGE_EXECUTE_READWRITE;
        if (r) return PAGE_EXECUTE_READ;
        return PAGE_EXECUTE;
    }
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// Tracks VirtualAlloc'd bases so VirtualFree(MEM_RELEASE) can munmap them.
std::mutex g_alloc_mutex;
std::unordered_map<void*, size_t>& alloc_table() {
    static std::unordered_map<void*, size_t> t;
    return t;
}
} // namespace

// ==========================================================================
// Virtual memory
// ==========================================================================
extern "C" LPVOID VirtualAlloc(LPVOID address, SIZE_T size, DWORD /*allocation_type*/, DWORD protect) {
    if (size == 0) return nullptr;

    // Honor the requested protection faithfully. PAGE_NOACCESS -> PROT_NONE
    // reserves the range (a caller commits it later via VirtualProtect); we do
    // NOT silently upgrade it to RW, which would make VirtualQuery / IsBadReadPtr
    // report a reservation as accessible when Windows would not.
    const int prot = win_to_posix_prot(protect);

    void* p = mmap(address, size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return nullptr;
    }

    {
        std::scoped_lock _{g_alloc_mutex};
        alloc_table()[p] = size;
    }
    g_maps_generation.fetch_add(1);
    return p;
}

extern "C" BOOL VirtualFree(LPVOID address, SIZE_T size, DWORD free_type) {
    size_t len = 0;
    {
        std::scoped_lock _{g_alloc_mutex};
        auto& t = alloc_table();
        auto it = t.find(address);
        if (it != t.end()) {
            len = it->second;
            if (free_type & MEM_RELEASE) {
                t.erase(it);
            }
        }
    }

    if (len == 0) {
        len = (size != 0) ? size : (size_t)page_size();
    }

    const int rc = munmap(address, len);
    g_maps_generation.fetch_add(1);
    return rc == 0 ? TRUE : FALSE;
}

extern "C" BOOL VirtualProtect(LPVOID address, SIZE_T size, DWORD new_protect, PDWORD old_protect) {
    const uintptr_t addr = (uintptr_t)address;
    const int ps = page_size();
    const uintptr_t aligned = addr & ~((uintptr_t)ps - 1);
    const size_t span = (addr + size) - aligned;
    const size_t rounded = (span + ps - 1) & ~((size_t)ps - 1);

    if (old_protect != nullptr) {
        const Region* r = region_of(addr);
        *old_protect = (r != nullptr) ? posix_to_win_prot(r->prot) : PAGE_NOACCESS;
    }

    const int rc = mprotect((void*)aligned, rounded, win_to_posix_prot(new_protect));
    g_maps_generation.fetch_add(1);
    return rc == 0 ? TRUE : FALSE;
}

extern "C" SIZE_T VirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length) {
    if (buffer == nullptr || length < sizeof(MEMORY_BASIC_INFORMATION)) {
        return 0;
    }

    ensure_cache();
    std::memset(buffer, 0, sizeof(MEMORY_BASIC_INFORMATION));

    const uintptr_t addr = (uintptr_t)address;
    const Region* r = region_of(addr);

    if (r != nullptr) {
        buffer->BaseAddress     = (PVOID)r->start;
        buffer->AllocationBase  = (PVOID)r->start;
        buffer->RegionSize      = (SIZE_T)(r->end - r->start);
        buffer->State           = MEM_COMMIT;
        buffer->Protect         = posix_to_win_prot(r->prot);
        buffer->AllocationProtect = buffer->Protect;
        buffer->Type            = MEM_PRIVATE;
        return sizeof(MEMORY_BASIC_INFORMATION);
    }

    // Address is in a gap: report a free region up to the next mapping so callers
    // skipping by RegionSize advance past the hole.
    uintptr_t next_start = 0;
    for (const auto& reg : t_cache.regions) {
        if (reg.start > addr) { next_start = reg.start; break; }
    }
    buffer->BaseAddress = (PVOID)addr;
    // When there is no later mapping, report a single page rather than a
    // near-SIZE_MAX span, so callers that advance by BaseAddress + RegionSize
    // cannot overflow/wrap.
    buffer->RegionSize  = (next_start > addr) ? (SIZE_T)(next_start - addr) : (SIZE_T)page_size();
    buffer->State       = MEM_FREE;
    buffer->Protect     = PAGE_NOACCESS;
    buffer->Type        = 0;
    return sizeof(MEMORY_BASIC_INFORMATION);
}

// ==========================================================================
// Pointer validation
// ==========================================================================
extern "C" BOOL IsBadReadPtr(LPCVOID ptr, UINT_PTR size) {
    if (size == 0) return FALSE;
    if (ptr == nullptr) return TRUE;
    return range_has_access((uintptr_t)ptr, size, PROT_READ) ? FALSE : TRUE;
}

extern "C" BOOL IsBadWritePtr(LPVOID ptr, UINT_PTR size) {
    if (size == 0) return FALSE;
    if (ptr == nullptr) return TRUE;
    return range_has_access((uintptr_t)ptr, size, PROT_WRITE) ? FALSE : TRUE;
}

extern "C" BOOL IsBadCodePtr(FARPROC ptr) {
    if (ptr == nullptr) return TRUE;
    return range_has_access((uintptr_t)ptr, 1, PROT_EXEC) ? FALSE : TRUE;
}

// ==========================================================================
// Modules / process (no Win32 loader on Linux -> inert)
// ==========================================================================
extern "C" HMODULE GetModuleHandleA(LPCSTR) { return nullptr; }
extern "C" HMODULE GetModuleHandleW(LPCWSTR) { return nullptr; }
extern "C" BOOL GetModuleHandleExA(DWORD, LPCSTR, HMODULE* module) {
    if (module) *module = nullptr;
    return FALSE;
}
extern "C" DWORD GetModuleFileNameA(HMODULE, LPSTR, DWORD) { return 0; }
extern "C" DWORD GetModuleFileNameW(HMODULE, LPWSTR, DWORD) { return 0; }
extern "C" FARPROC GetProcAddress(HMODULE, LPCSTR) { return nullptr; }
extern "C" HMODULE LoadLibraryA(LPCSTR) { return nullptr; }
extern "C" HMODULE LoadLibraryW(LPCWSTR) { return nullptr; }
extern "C" HMODULE LoadLibraryExA(LPCSTR, HANDLE, DWORD) { return nullptr; }
extern "C" UINT GetSystemDirectoryW(LPWSTR, UINT) { return 0; }

extern "C" HANDLE GetCurrentProcess(void) { return (HANDLE)(LONG_PTR)-1; }
extern "C" DWORD GetCurrentProcessId(void) { return (DWORD)getpid(); }
extern "C" DWORD GetCurrentThreadId(void) { return (DWORD)::syscall(SYS_gettid); }

extern "C" BOOL FlushInstructionCache(HANDLE, LPCVOID base, SIZE_T size) {
    if (base != nullptr && size != 0) {
        __builtin___clear_cache((char*)base, (char*)base + size);
    }
    return TRUE;
}

// ==========================================================================
// Handles / file mapping (only the Linux-guarded paths reference these; stubs
// keep the symbols defined so nothing fails to link).
// ==========================================================================
extern "C" BOOL CloseHandle(HANDLE) { return TRUE; }
extern "C" HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE) { return INVALID_HANDLE_VALUE; }
extern "C" HANDLE CreateFileMappingW(HANDLE, LPVOID, DWORD, DWORD, DWORD, LPCWSTR) { return nullptr; }
extern "C" LPVOID MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T) { return nullptr; }
extern "C" BOOL UnmapViewOfFile(LPCVOID) { return TRUE; }

extern "C" DWORD GetTempPathA(DWORD len, LPSTR buffer) {
    const char* dir = std::getenv("TMPDIR");
    if (dir == nullptr || *dir == '\0') {
        dir = "/tmp";
    }
    std::string path = dir;
    if (path.empty() || path.back() != '/') {
        path.push_back('/'); // Windows returns a trailing separator.
    }
    if (buffer != nullptr && len > path.size()) {
        std::memcpy(buffer, path.c_str(), path.size() + 1);
        return (DWORD)path.size();
    }
    return (DWORD)(path.size() + 1); // required buffer size, per Win32
}

extern "C" BOOL DeleteFileA(LPCSTR filename) {
    if (filename == nullptr) {
        return FALSE;
    }
    return unlink(filename) == 0 ? TRUE : FALSE;
}

// ==========================================================================
// Interlocked
// ==========================================================================
extern "C" LONG InterlockedCompareExchange(volatile LONG* dest, LONG exchange, LONG comparand) {
    return __sync_val_compare_and_swap(dest, comparand, exchange);
}
extern "C" PVOID InterlockedCompareExchangePointer(PVOID volatile* dest, PVOID exchange, PVOID comparand) {
    return __sync_val_compare_and_swap(dest, comparand, exchange);
}

// ==========================================================================
// Input / registry / path / toolhelp (inert on Linux)
// ==========================================================================
extern "C" SHORT GetAsyncKeyState(int) { return 0; }

extern "C" LONG RegOpenKeyExA(HKEY, LPCSTR, DWORD, DWORD, PHKEY result) {
    if (result) *result = nullptr;
    return ERROR_FILE_NOT_FOUND;
}
extern "C" LONG RegQueryValueExA(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD) {
    return ERROR_FILE_NOT_FOUND;
}
extern "C" LONG RegCloseKey(HKEY) { return ERROR_SUCCESS; }

extern "C" BOOL PathRemoveFileSpecW(LPWSTR path) {
    if (path == nullptr) return FALSE;
    wchar_t* last_sep = nullptr;
    for (wchar_t* p = path; *p; ++p) {
        if (*p == L'\\' || *p == L'/') last_sep = p;
    }
    if (last_sep != nullptr) {
        *last_sep = L'\0';
        return TRUE;
    }
    return FALSE;
}

extern "C" HANDLE CreateToolhelp32Snapshot(DWORD, DWORD) { return INVALID_HANDLE_VALUE; }
extern "C" BOOL Thread32First(HANDLE, LPTHREADENTRY32) { return FALSE; }
extern "C" BOOL Thread32Next(HANDLE, LPTHREADENTRY32) { return FALSE; }
extern "C" HANDLE OpenThread(DWORD, BOOL, DWORD) { return nullptr; }
extern "C" DWORD SuspendThread(HANDLE) { return (DWORD)-1; }
extern "C" DWORD ResumeThread(HANDLE) { return (DWORD)-1; }

// ==========================================================================
// Structured-exception emulation
// ==========================================================================
#include <utility/Seh.hpp>

namespace kananlib::seh {
Frame*& current() noexcept {
    static thread_local Frame* top = nullptr;
    return top;
}

namespace {
void fault_handler(int sig) {
    Frame* f = current();
    if (f != nullptr) {
        siglongjmp(f->buf, 1);
    }
    // No active __try frame: fall back to the default disposition and let the
    // faulting instruction re-run, terminating the process as it normally would.
    ::signal(sig, SIG_DFL);
}
} // namespace

void ensure_installed() noexcept {
    static std::once_flag once;
    std::call_once(once, [] {
        struct sigaction sa{};
        sa.sa_handler = fault_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_NODEFER;
        ::sigaction(SIGSEGV, &sa, nullptr);
        ::sigaction(SIGBUS, &sa, nullptr);
    });
}
} // namespace kananlib::seh

#endif // !_WIN32
