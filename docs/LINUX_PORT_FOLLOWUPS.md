# Linux port: follow-ups and known limitations

This file tracks work that is intentionally **out of scope** for the initial
Linux-support PR (which covers *file-mapped binary analysis*: map a PE/Mach-O
from disk and run the scanners/RTTI/disassembly on it). None of these block that
use case; they are things to keep an eye on or address in future feature/bug
branches. Each item lists where it lives and a suggested direction.

The guiding rule for the compat layer (see `include/compat/windows.h`): implement
only the Win32 surface needed for file-mapped analysis; anything live-process or
OS-specific stays deliberately unsupported and fails or warns loudly rather than
faking success.

## 1. Future feature branches

- **ELF support.** New module format (program headers, `.dynsym`/`.symtab`,
  GNU/SysV hashes, `.eh_frame` instead of `.pdata`, Itanium RTTI instead of MSVC
  `.?AV...`). Reuses this branch's `mmap`+section-layout and scan infrastructure,
  but the parsing and the function/RTTI discovery are separate code with their
  own tests. Orthogonal to the Win32-on-Linux work.
- **Linux-native live-process primitives.** Replace the deliberate no-ops with
  real implementations (each is independently testable, likely its own branch):
  - Module enumeration of a live process via `dl_iterate_phdr` /
    `/proc/self/maps` (or `/proc/<pid>/maps`), replacing the `get_executable` /
    `GetModuleHandle*` / `foreach_module` stubs (`src/compat/WinCompat.cpp`,
    `src/Module.cpp`).
  - Real thread suspension via `tgkill` + a stop signal (intra-process) or
    `ptrace` (cross-process), replacing the `ThreadSuspender` / toolhelp no-op
    (`src/Thread.cpp`, `include/compat/tlhelp32.h`).
- **Symbol resolution without DIA.** `src/PDB.cpp` is compiled Windows-only (DIA
  SDK + urlmon). A portable CodeView/PDB reader would be a separate effort.

## 2. Embedding & live-process robustness

These only matter once kananlib is embedded in a larger Linux app or pointed at a
live process; the file-mapped path never exercises them.

- **Chain the previous signal handler.** `kananlib::seh::ensure_installed`
  (`src/compat/WinCompat.cpp`) installs process-global SIGSEGV/SIGBUS handlers and
  does not save/forward any pre-existing handler; when no SEH frame is active it
  resets to `SIG_DFL`. An embedding host that owns signal handling would be
  clobbered. Fix: store the previous `sigaction` and chain to it when no frame is
  active.
- **Refresh the maps cache on miss.** `IsBadReadPtr`/`VirtualQuery` use a
  thread-local `/proc/self/maps` snapshot invalidated by a generation counter
  that is only bumped by allocations made *through the shim*
  (`src/compat/WinCompat.cpp`). External `mmap`/`dlopen`/glibc-arena allocations
  do not bump it, so a live process can get a stale "bad pointer" answer. Fix:
  re-read maps before returning "bad" (the miss path is the rare one).

## 3. RTTI / API cleanups

- **`get_type_info` cross-platform return type.** `utility::rtti::get_type_info`
  returns `std::type_info*` that, off Windows, aliases the in-image MSVC
  `TypeDescriptor` (documented in `include/utility/RTTI.hpp`). It is safe for
  pointer-identity comparison but calling `std::type_info` members on it off
  Windows is UB. A cleaner shape: expose a distinct `msvc_type_descriptor_view`
  (or `std::string_view` of the decorated name) and make the `std::type_info*`
  overloads Windows-only. Public-API break, so a separate PR. Note
  `for_each_uncached` uses an internal `KANANLIB_RTTI_TI` accessor, so any gating
  must keep that internal path.
- **MSVC name undecoration on Linux.** RTTI `name()` returns the *decorated* name
  (`.?AV...`) off Windows (no MSVC undecorator), so undecorated-name lookups
  (`find_vtable(m, "class Foo")`) do not work there; only decorated names match.
  A vendored MSVC demangler (e.g. `llvm::microsoftDemangle`) would close this.

## 4. Performance (Linux)

- **`concurrency::parallel_for` is a serial shim** (`include/compat/ppl.h`), so
  RTTI `find_all_vtables` / `find_object_*` and any parallel scans run
  single-threaded on Linux. Correct, just slower than Windows PPL. A real
  thread-pool `parallel_for` (or the bundled `parallel-util`) would restore
  parallelism.
- **Per-iteration `sigsetjmp` in guarded hot loops.** `KANANLIB_SEH_TRY` /
  `KANANLIB_AV_TRY` do a `sigsetjmp` per iteration in the AVX scan and RTTI loops
  (`savesigs=0`, no syscall, cheap) but it inhibits some optimization versus
  Windows table-based SEH. Unmeasured; revisit only if Linux scan throughput
  becomes a concern.

## 5. Pre-existing / latent (watch, fix in a bug branch)

- **`get_valid_regions` unsigned overflow.** `src/Memory.cpp`: `end = start +
  length` has no overflow guard. Pre-existing (shared with Windows), not a Linux
  regression; safe-by-accident today (a wrapped `end` makes the loop early-exit,
  no overrun) because all callers pass in-bounds `(base, size)`. Add a guard in a
  hardening PR.
- **VirtualQuery span for a far later mapping.** The gap path
  (`src/compat/WinCompat.cpp`) reports the real free-region size up to the next
  mapping, which can be multi-TiB. This is correct and non-wrapping
  (`BaseAddress + RegionSize == next_start`), and every current caller bounds the
  walk by a module/scan window, so the huge span just lands past the end and the
  loop terminates. A *future* caller that walks the whole address space without an
  upper bound would iterate a lot. Revisit only if such a caller is added; do not
  clamp it otherwise (that would mis-report legitimate large reserved gaps).

## 6. Documented fidelity gaps (by design)

These are intentional and noted in code; listed here so they are not mistaken for
bugs.

- **SEH emulation does not unwind C++ destructors.** Off Windows, fault recovery
  is `siglongjmp`, which does not run destructors (Windows `/EHa` does). Bodies of
  `KANANLIB_SEH_TRY` / `KANANLIB_AV_TRY` must hold only trivially destructible
  locals (`include/utility/Seh.hpp`).
- **`map_view_of_pe` applies base relocations; Windows `SEC_IMAGE` does not.**
  Needed so absolute pointers (vtable -> RTTI locator) are valid at the mmap
  address, but mapped bytes at relocated sites differ from the on-disk file.
- **`map_view_of_pe` does not resolve imports** (same as `SEC_IMAGE`): the IAT
  holds RVAs/thunks, not resolved function pointers.
- **`VirtualFree` does not model `MEM_DECOMMIT` or sub-range `MEM_RELEASE`**
  (`src/compat/WinCompat.cpp`): it releases the whole tracked allocation. No
  caller uses either.
- **`VirtualQuery` no-later-mapping gap reports one page** rather than the size to
  the top of the user address space, to avoid a near-`SIZE_MAX` span. Safe;
  slightly less faithful than Windows for that one case.
