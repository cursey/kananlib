# kananlib Test Coverage Improvement

## Repository
- **Path:** `I:/Programming/projects/kananlib-fresh`
- **Branch:** `tests`
- **Latest test commit:** `8324df8` (clang-coverage segfault fix in kananlib-test) + coverage push (this section)

## Build System
- **OS:** Windows 10/11, MSVC (Visual Studio 17 2022), x64 only
- **Config source:** `test/cmake.toml` (auto-generates `test/CMakeLists.txt`)
- **Build:**
  ```
  cd test
  cmake -B build -G "Visual Studio 17 2022" -A x64
  cmake --build build --config Release
  ```
- **Executables:**
  - `test/build/Release/kananlib-test.exe`
  - `test/build/Release/kananlib-stress-test.exe`
  - `test/build/Release/kananlib-utils-test.exe`
  - `test/build/Release/kananlib-advanced-test.exe`
  - `test/build/Release/kananlib-vtablehook-test.exe`
  - `test/build/Release/kananlib-input-test.exe`
  - `test/build/Release/kananlib-registry-test.exe`
  - `test/build/Release/kananlib-module-test.exe`
  - `test/build/Release/kananlib-scan-test.exe`
  - `test/build/Release/kananlib-pdb-rtti-test.exe`
  - `test/build/Release/kananlib-emulation-test.exe`
  - `test/build/Release/kananlib-bug-regression-test.exe`
  - `test/build/Release/kananlib-scan-bug-regression-test.exe`
  - `test/build/Release/kananlib-behavior-test.exe`
- **Note:** LSP/clangd will show errors (wrong compiler version). MSVC builds cleanly.
## What Was Done (8 coverage commits + bug fixes)

### Commit 1: `b6360e9` — Fix structural weaknesses in test suite
- Created `test/TestHelpers.hpp` — shared test infrastructure:
  - `TEST_ASSERT(expr)` — hard fail (returns 1)
  - `TEST_EXPECT(expr)` — soft fail (continues)
  - `RUN_TEST(fn)` — run zero-arg test function with timing
  - `RUN_TEST_NAMED(name, expr)` — run expression with tracking
  - `test_summary()` — prints totals, returns 0 or 1
- Rewrote `test/Main.cpp` — split monolithic main() into 9 independent test functions with proper assertions, PDB validation, resolve_instruction check, negative/edge-case tests, OOM guards for 1GB allocations
- Rewrote `test/StressTest.cpp` — replaced sequential `STRESS_ASSERT`-abort pattern with `RUN_TEST_NAMED` so all tests execute on failure; aliased `STRESS_ASSERT` to `TEST_ASSERT`; used `test_summary()` for exit code

### Commit 2: `195c4e8` — Add Pattern, String, Address, Config tests
- Created `test/TestUtils.cpp` — 31 tests across 4 modules
- **Pattern:** `buildPattern()` parsing, exact/wildcard/multi-segment/custom-gap/no-match/empty/all-wildcards/too-short matching
- **String:** `narrow`/`widen` roundtrips (ASCII + Unicode + empty), FNV-1a `hash` determinism/uniqueness/wide/bytes, `_fnv` consteval literal
- **Address:** constructors (default/void*/uintptr_t), get/add/sub arithmetic, as/to/deref, operators (==/!= with uintptr_t to avoid ambiguity), set
- **Config:** get/set for string/bool/int/float, save/load file roundtrip, empty key/value rejection, overwrite, nonexistent file load
- Added `kananlib-utils-test` target to `cmake.toml` and `CMakeLists.txt`

### Commit 3: `7be9fe4` — Add ScopeGuard, Benchmark, Memory, Patch, PointerHook tests
- Created `test/TestAdvanced.cpp` — 16 tests across 5 modules
- **ScopeGuard:** fire-on-destroy, nested scoping
- **Benchmark:** construct/destroy no-crash, explicit `print_elapsed_time()`
- **Memory:** `isGoodReadPtr` (valid/nullptr/huge-addr), `isGoodWritePtr` (valid/code-section), `isGoodCodePtr` (fn-ptr/stack), `is_stub_code` (known-stubs/random/nullptr), `get_valid_regions` on own code
- **Patch:** enable/disable byte patching, toggle, NOP patch, wildcard patching (`int16_t` -1 = skip byte), auto-restore on destruction (VirtualAlloc RWX buffer with ScopeGuard cleanup)
- **PointerHook:** hook/unhook/restore function pointer with atomic swap, verify `get_original<T>()`
- Added `kananlib-advanced-test` target to `cmake.toml` and `CMakeLists.txt`

### Commit 4: `2e21db2` — Add VtableHook, Input, Registry tests
- Created `test/TestVtableHook.cpp` — 8 tests across VtableHook module
  - **VtableHook:** create/remove lifecycle, hook method dispatch, get_method<T>, multiple methods, remove/restore, recreate after remove, out-of-bounds handling, default constructor
  - Key technique: volatile pointer helper to prevent MSVC devirtualization of virtual calls on stack objects in Release mode
  - Key technique: brace initialization to avoid most-vexing-parse (`VtableHook hook{Address{&obj}};`)
- Created `test/TestInput.cpp` — 3 tests across Input module
  - **Input:** was_key_down with unpressed keys, key state tracking, various virtual key codes (VK_F20-F24, VK_OEM_CLEAR, 0xFF)
- Created `test/TestRegistry.cpp` — 3 tests across Registry module
  - **Registry:** nonexistent key/value returning nullopt, type mismatch handling
- Added 3 new targets to `cmake.toml` and `CMakeLists.txt`: kananlib-vtablehook-test, kananlib-input-test, kananlib-registry-test

### Commit 5: <done> — Add Scan function tests
- Created `test/TestScan.cpp` — 8 tests across Scan module
  - **scan_reverse:** reverse direction pattern scan in controlled buffer
  - **scan_data:** raw byte scan (start/length + HMODULE overloads, scan_data_t typed version, negative case)
  - **scan_ptr:** pointer value scan (aligned + noalign overloads, negative case)
  - **scan_opcode:** find instruction by opcode byte (RET, MOV, negative case)
  - **scan_mnemonic:** find instruction by mnemonic string (NOP, XOR, RETN, negative case)
  - **get_insn_size:** instruction length for NOP/XOR/MOV/RET/PUSH/REX-prefixed MOV
  - **calculate_absolute:** resolve relative offset to absolute (positive, custom offset, negative/backwards)
  - **decode_one:** decode single instruction (NOP/MOV/RET/XOR, zero-length edge case)
- Added `kananlib-scan-test` target to `cmake.toml` and `CMakeLists.txt`

### Commit 6: <done> — Add PDB + RTTI deep coverage tests + CTest integration
- Created `test/TestPDBRTTI.cpp` — 11 tests across PDB and RTTI modules
  - **PDB (4 tests, require DIA SDK):**
    - `test_pdb_get_symbol_name` — resolve RVA back to symbol name (roundtrip with get_symbol_address)
    - `test_pdb_get_symbol_map` — get full symbol map, verify non-empty and contains known symbols
    - `test_pdb_enumerate_symbols` — list symbols from PDB, verify non-empty and non-null names
    - `test_pdb_negative` — null module handling for get_symbol_address, get_symbol_name, get_symbol_map, enumerate_symbols
  - **RTTI (7 tests):**
    - `test_rtti_is_vtable` — verify known vtable detected, null/stack addresses rejected
    - `test_rtti_get_locator` — get CompleteObjectLocator from polymorphic objects
    - `test_rtti_get_type_info` — get type_info, verify name matches expected class
    - `test_rtti_derives_from` — inheritance check (base/derived self-match, derived-from-base, negative reverse)
    - `test_rtti_find_vtable_partial` — partial name match search
    - `test_rtti_find_vtable_regex` — regex name match search
    - `test_rtti_find_all_vtables` — enumerate all vtables in executable, verify test classes present
  - Key technique: `#ifdef KANANLIB_USE_DIA_SDK` guards around PDB tests (DIA SDK is PRIVATE on kananlib target)
  - Key technique: compile-definition `KANANLIB_USE_DIA_SDK` passed to test target in cmake.toml
- Added `kananlib-pdb-rtti-test` target to `cmake.toml` and `CMakeLists.txt`

### Commit 7: <done> — CTest integration + template refactoring
- Added `enable_testing()` to project-level `cmake-after` in `test/cmake.toml`
- Added `cmake-after` with `add_test(NAME ${CMKR_TARGET} COMMAND ${CMKR_TARGET})` to template `kananlib-test-template`
- All 9 non-template targets inherit from `kananlib-test-template` — each is just 2-3 lines (type + sources)
- `ctest -C Release` runs all 10 test executables in one shot (10/10 pass)
- **Template source merge fix:** cmkr merges template sources with target sources (not replaces). Template has no `sources` to avoid duplicate `main()` symbols
- Template includes shared: `include-directories`, `compile-features`, `compile-options`, `link-libraries`, `cmake-before`, `cmake-after`
- `kananlib-pdb-rtti-test` overrides with `compile-definitions = ["KANANLIB_USE_DIA_SDK"]`

### Commit 8: <done> — Add Emulation tests
- Created `test/TestEmulation.cpp` — 7 tests across Emulation module
  - **ShemuContext construction:** VirtualAlloc RWX buffer, verify internal state (ctx, stack, internal_buffer, Shellcode/ShellcodeBase/ShellcodeSize)
  - **NOP emulation:** 10 NOPs with NOP sled detection disabled, verify RIP advances by 10
  - **mov eax, imm32:** verify register update (RAX = 1 after `mov eax, 1`)
  - **Multi-instruction:** `mov eax, 1; add eax, 5` → verify RAX = 6
  - **Free function:** `utility::emulate(base, size, ip, n)` convenience wrapper, verify RAX = 0xBEEF
  - **Single-step:** `emulate()` no-args, verify monotonic RIP/instruction-count progression across 3 steps
  - **HMODULE construction:** kernel32.dll always loaded, verify Shellcode/ShellcodeSize/stack
  - Key quirk: bdshemu single-step executes 2 NOPs per call (off-by-one in internal counting); test verifies progression not exact counts
  - Key technique: `RWXBuffer` RAII helper for VirtualAlloc/VirtualFree with copy-delete prevention
- Pre-existing in cmake.toml — target `kananlib-emulation-test` was already defined, fixed missing function header and return statement in TestEmulation.cpp
- `ctest -C Release` runs all 11 test executables (11/11 pass)

### Bug Fixes (branch `tests`) — found via API audit, demonstrated with failing tests, then fixed

These follow the workflow in `test/TESTING.md`: write a failing regression test
against the buggy code, cite the failure, then apply the minimal fix.

- **Address const-correctness** (`include/utility/Address.hpp`): comparison operators
  were non-const, so `const Address&` silently fell back to `operator uintptr_t()` and
  changed `a == true` semantics. Fix: add `const` to all comparison operators.
  Regression: `kananlib-bug-regression-test` (`test_address_const_operators`).
- **Patch::disable() state corruption** (`src/Patch.cpp`): `disable()` on a
  never-enabled patch called `patch()` with empty `m_original_bytes`, corrupting
  `m_enabled`. Fix: early-return `true` when `!m_enabled`. Regression:
  `kananlib-bug-regression-test` (3 patch tests).
- **scan_reverse / scan_data_reverse unsigned wraparound** (`src/Scan.cpp`, commit
  `a346a05`): loop bound `i >= start - length` never terminates when `length == start`
  (`start - length == 0`, and `i >= 0` is always true for unsigned `i`, which wraps to
  `SIZE_MAX` past 0). The pre-existing `length > start` guard did not cover the
  `length == start` boundary. Fix: hoist `lo = start - length` and `break` after
  processing `i == lo` — cannot wrap. Behavior is identical for all `length < start`
  inputs (same address set, same descending order, same closest-to-start match).
  Regression: `kananlib-scan-bug-regression-test` (`test_scan_reverse_length_equals_start`)
  runs the scan on a worker thread with a 5s timeout so it FAILS (instead of hanging the
  whole suite) if the wraparound regresses.

## Current Test Coverage

| Executable | Tests | Modules Covered |
|---|---|---|
| `kananlib-test` | 9 | Scan, PDB, RTTI, Module, String-refs |
| `kananlib-stress-test` | 19 | Scan (collect_basic_blocks, exhaustive_decode) |
| `kananlib-utils-test` | 31 | Pattern, String, Address, Config |
| `kananlib-advanced-test` | 16 | ScopeGuard, Benchmark, Memory, Patch, PointerHook |
| `kananlib-vtablehook-test` | 8 | VtableHook |
| `kananlib-input-test` | 3 | Input |
| `kananlib-registry-test` | 3 | Registry |
| `kananlib-module-test` | 30 | Module (all functions) |
| `kananlib-scan-test` | 8 | Scan (reverse, data, ptr, opcode, mnemonic, insn_size, calculate_absolute, decode_one) |
| `kananlib-pdb-rtti-test` | 11 | PDB (symbol_name, symbol_map, enumerate_symbols, negative), RTTI (is_vtable, get_locator, get_type_info, derives_from, find_vtable_partial, find_vtable_regex, find_all_vtables) |
| `kananlib-emulation-test` | 7 | Emulation (ShemuContext construction, NOP/mov/multi-instruction emulation, free function, single-step, HMODULE construction) |
| `kananlib-bug-regression-test` | 5 | Address (const operators), Patch (disable/toggle on never-enabled) — regression guards |
| `kananlib-scan-bug-regression-test` | 8 | Scan (nonexistent-module, scan_reverse/scan_data_reverse basics + not-found, scan_strings short-length, scan_reverse length==start wraparound) |
| `kananlib-behavior-test` | 13 | Scan (scan_strings HMODULE/uintptr), Thread (ThreadSuspender lifecycle/freeze/balance), RTTI (find_all_vtables) |
| `kananlib-scan-coverage-test` | 29 | Scan (scan_string all overloads, scan_ptr_noalign, scan_relative_reference[_scalar/_byte_by_byte/_strict], scan_relative_references, scan_reference, scan_displacement_reference[s], resolve_displacement, scan_disasm, exhaustive/linear_decode, collect_basic_blocks, scan_data_reverse, scan_data_t) |
| `kananlib-module-coverage-test` | 26 | Module (ptr_from_rva, get_imagebase_va_from_ptr, find_partial_module, foreach_module, deeper imports/exports/sections, get_original_bytes, map_view edge cases, path/dir edges) |
| `kananlib-module-macho-test` | 15 | Module (map_view_of_macho thin/fat success, malformed Mach-O/fat branches, map_view_of_file auto-detect, safe null edges for unlink/safe_unlink, missing load_module_from_current_directory) |
| `kananlib-pdb-edge-test` | 7 | PDB (synthetic PE/CodeView get_pdb_path null/bad-header/no-debug/non-CodeView/invalid-signature/local-PDB/cache branches, generate_c_struct pointer/array/bitfield/padding formatting) |
| `kananlib-rtti-coverage-test` | 18 | RTTI (derives_from both overloads + multi-level hierarchy, get_type_info, get_locator, find_vtable[s], find_vtables_derived_from, find_vtable_partial/regex, find_object_inline, find_objects_ptr, is_vtable) |
| `kananlib-misc-coverage-test` | 16 | String (format_string all paths), Emulation (free emulate overloads, callback CONTINUE/BREAK/STEP_OVER, HMODULE ctor, status field) |
| `kananlib-scan-bounds-test` | 24 | Scan (populate_function_buckets_heuristic, find_function_entry, find_all_function_bounds, determine_function_bounds, find_function_start[_unwind/_with_call], find_virtual_function_start, resolve_scope_table_owner, resolve_instruction) |
| `kananlib-scan-path-test` | 32 | Scan (find_next_displacement, find_{string_reference,pointer,displacement,mnemonic,register_usage,pattern}_in_path, find_encapsulating_function[_disp], find_encapsulating_virtual_function[_disp]) |
| `kananlib-scan-resolve-test` | 20 | Scan (scan_ptr HMODULE, find_function_from_string_ref ascii/wide, find_function_with_string_refs/refs, find_virtual_function_*, get_disassembly_behind, collect_linear_blocks, collect_{ascii,unicode}_string_references, scan_displacement_references) |
| **Total** | **358** | **20 of 20 modules** |

## Measured Line Coverage

Measured with LLVM source-based coverage via `test/coverage.sh` (clang-cl 20 from
the VS18 bundle + `llvm-cov`; see `test/TESTING.md` for why clang and the exact
toolchain pairing). Scope = library only (`src/` + `include/utility/`); third-party
deps, the test sources, and the CLI are filtered out. Run:

```
"C:/Program Files/Git/usr/bin/bash.exe" test/coverage.sh            # reuse build
"C:/Program Files/Git/usr/bin/bash.exe" test/coverage.sh --rebuild  # clean
```

HTML report: `test/build-cov/coverage-html/index.html`.

### Totals (library, all 23 test executables)

| Metric | Initial (post-segfault-fix) | After API-surface push | After Scan-deep push | After Module Mach-O push | After PDB edge push |
|---|---|---|---|---|---|
| **Lines** | 47.65% | 53.77% | 74.98% | 77.37% | **78.24%** (1474 / 6775 missed) |
| Regions | 44.56% | 49.29% | 66.63% | 69.51% | **70.84%** |
| Functions | 66.47% | 73.99% | 91.33% | 92.49% | **92.49%** |
| Branches | 38.01% | 42.78% | 60.35% | 62.40% | **63.33%** |

(The "initial" baseline already includes `kananlib-test` running to completion after
the `8324df8` segfault fix; the prior crashing-run baseline was only ~34% lines.
The Scan-deep push added 76 tests across `kananlib-scan-{bounds,path,resolve}-test`,
taking Scan.cpp from 37% to 84%. The Module Mach-O push added 15 tests for the
cross-platform mapper and safe edge paths, taking Module.cpp from 45.7% to 62.2%.
The PDB edge push added synthetic PE/CodeView fixtures, taking PDB.cpp from 53.1% to 58.7%.)

### Per-file line coverage (after)

| File | Lines % | Missed | Notes |
|---|---|---|---|
| `include/utility/Address.hpp` | 100% | 0 | |
| `include/utility/String.hpp` | 80% | 6 | `hash` overloads + literals fully hit |
| `include/utility/Scan.hpp` | 76.6% | 75 | inline templates (`exhaustive_decode`, `scan_data_t`) |
| `include/utility/Module.hpp` | 64.5% | 11 | inline accessors |
| `src/Address.cpp` | 100% | 0 | |
| `src/String.cpp` | **100%** | 0 | `format_string` now covered (was 50%) |
| `src/Memory.cpp` | 95.2% | 4 | |
| `src/Patch.cpp` | 95.5% | 3 | |
| `src/Pattern.cpp` | 92.8% | 12 | |
| `src/Config.cpp` | 91.3% | 4 | |
| `src/Thread.cpp` | 91.5% | 7 | |
| `src/RTTI.cpp` | **88.3%** | 58 | was 59.5% |
| `src/Registry.cpp` | 86.2% | 4 | |
| `src/Emulation.cpp` | **85.6%** | 18 | was 51.2% |
| `src/VtableHook.cpp` | 77.9% | 15 | |
| `src/PDB.cpp` | **58.7%** | 430 | was 53.1% — synthetic PE/CodeView edge branches now covered |
| `src/Module.cpp` | **62.2%** | 372 | was 45.7% — Mach-O mapper now covered; loader-mutating APIs still skipped |
| `src/Scan.cpp` | **84.0%** | 476 | was 37.3% — function-analysis/disassembly APIs now covered (Scan-deep push) |

### Remaining high-value gaps (diminishing returns per test)

- **Scan.cpp (476 missed, down from 1866):** remaining are AVX2/SIMD fast-path variants of
  scans already covered by their scalar paths, deep `scan_disasm`/branch-exhaustion corners,
  and a few error branches in the function-bucket heuristics. Lower ROI per test now.
- **PDB.cpp (430 missed, down from 489):** remaining are DIA error/diagnostic branches and
  symbol/struct traversal branches that need unusual or malformed PDBs.
- **Module.cpp (372 missed, down from 534):** remaining are mostly loader-mutating APIs
  (`unlink`, `safe_unlink`, `unlink_duplicate_modules`, `spoof_module_paths_in_exe_dir`,
  `load_module_from_current_directory`) and rare error branches. Mach-O thin/fat success and
  malformed-input branches are now covered by `kananlib-module-macho-test`.

## Gap Analysis — Untested and Partially Tested Modules

### Modules with 0 direct test coverage (Logging only — config glue, nothing to test)

1. ~~**Emulation**~~ — **NOW TESTED** (7 tests, `kananlib-emulation-test`)
   - ShemuContext construction (VirtualAlloc'd buffer + HMODULE), NOP/mov/multi-instruction emulation, free function wrapper, single-step, bdshemu counting quirk documented

2. ~~**Thread**~~ — **NOW TESTED** (6 tests in `kananlib-behavior-test`)
   - `suspend_threads()` / `resume_threads(ThreadStates)` capture ALL threads except the
     calling one; ThreadSuspender lifecycle (double-construct, suspend/resume, destruct
     without double-unlock), actual thread freeze, suspended-flag accuracy, balanced
     suspend/resume are all exercised against real worker threads.

3. **Logging** (`include/utility/Logging.hpp`)
   - Just `#if __has_include` + `#define` wrappers around spdlog macros — nothing to test

### Modules with significant untested surface area

4. **Module** (`include/utility/Module.hpp`, `src/Module.cpp`) — TESTED (30 tests, `kananlib-module-test`)
   - All major functions now covered: get_executable, get_module, get_module_size (3 overloads), get_module_within, get_dll_imagebase, get_module_path/w, get_module_directory/w, get_loaded_module_names, get_module_count, read_module_from_disk, get_original_bytes, get_module_imports, get_module_exports, get_module_sections, LoaderLockGuard, FakeModule move/detach, map_view_of_pe, map_view_of_file
   - Negative cases: nullptr for imports/exports/sections, nonexistent module name

5. **Scan** (`include/utility/Scan.hpp`, `src/Scan.cpp`) — TESTED (8 new tests, `kananlib-scan-test`)
   - Tested: `scan`, `scan_string`, `scan_strings`, `scan_displacement_reference`, `scan_relative_reference`, `resolve_instruction`, `collect_basic_blocks`, `exhaustive_decode`
   - Now also tested (Phase 8): `scan_reverse`, `scan_data` (start/length + HMODULE), `scan_data_t`, `scan_ptr` (aligned + noalign), `scan_opcode`, `scan_mnemonic`, `get_insn_size`, `calculate_absolute`, `decode_one`
   - Edge cases (regression-tested in `kananlib-scan-bug-regression-test`): `scan_reverse`/`scan_data_reverse` no longer hang on `length == start` (unsigned wraparound, fixed in `a346a05`); `scan(nonexistent_module, ...)` and `scan_strings` with short length return empty instead of scanning the address space.
   - Remaining untested:
     - `scan_disasm` — find instruction by pattern
     - `resolve_displacement` — resolve RIP-relative target (used internally, tested indirectly)
6. **PDB** (`include/utility/PDB.hpp`, `src/PDB.cpp`) — TESTED (4 tests, `kananlib-pdb-rtti-test`, requires DIA SDK)
   - Tested: `get_symbol_name` (RVA roundtrip), `get_symbol_map` (full map, known symbol lookup), `enumerate_symbols` (list, non-null names), null-module negative cases
   - Previously tested: `get_pdb_path`, `get_symbol_address`, `get_struct_info`, `enumerate_structs`, `generate_c_struct` (in `kananlib-test`)
   - Remaining untested: `scan_disasm`, `resolve_displacement` (internal, tested indirectly)

7. **RTTI** (`include/utility/RTTI.hpp`, `src/RTTI.cpp`) — TESTED (7 tests, `kananlib-pdb-rtti-test`)
   - Tested: `is_vtable` (known vtable + negative), `get_locator`, `get_type_info`, `derives_from` (self/inheritance/negative), `find_vtable_partial`, `find_vtable_regex`, `find_all_vtables`
   - Previously tested: `find_vtable`, `find_object_ptr` (in `kananlib-test`)
   - Remaining untested:
     - `find_vtables_derived_from(name)` — all derived vtables
     - `find_object_inline(name)` / `find_objects_ptr(name)` — find static instances

### Well-tested (no major gaps)
String, Pattern, Address, Config, ScopeGuard, Benchmark, Memory, Patch, PointerHook, VtableHook, Input, Registry, Module, Scan, PDB, RTTI, Emulation

## Key Implementation Notes for Next Session
### Adding a new test target
1. Create `test/TestXxx.cpp` with `#include "TestHelpers.hpp"` and test functions
2. Add target section to `test/cmake.toml` (inherit from `kananlib-test-template`, just 2-3 lines):
   ```toml
   [target.kananlib-xxx-test]
   type = "kananlib-test-template"
   sources = ["TestXxx.cpp"]
   ```
3. Regenerate `test/CMakeLists.txt` from `cmake.toml` (cmkr gen, or manual sync)
4. Re-run cmake, build, run `ctest -C Release` to verify all tests pass

**Note:** Template inherits all shared settings (include dirs, compile flags, link libs, `add_test()`).
Only add `compile-definitions` or other overrides if the target needs something extra (e.g. `kananlib-pdb-rtti-test` adds `KANANLIB_USE_DIA_SDK`).

### CTest integration
All test targets automatically get `add_test(NAME ${CMKR_TARGET} COMMAND ${CMKR_TARGET})` via the template's `cmake-after`.
Run `ctest -C Release` from the build directory to execute all tests.
### Most vexing parse
`VtableHook hook(Address(&obj));` is parsed as a function declaration by MSVC.
Use brace initialization: `VtableHook hook{Address{&obj}};`

### MSVC devirtualization
MSVC `/O2` resolves virtual calls on known-type stack objects at compile time.
To test vtable hooks, call through a volatile pointer (see VtableHook test setup below).

### Address::operator== ambiguity
When comparing two `Address` objects, use `(uintptr_t)a == (uintptr_t)b` — there is no `operator==(Address, Address)`, only `operator==(uintptr_t)`, `operator==(void*)`, `operator==(bool)`. Comparing two `Address` objects directly causes MSVC ambiguity error C2593.

### Patch::patch() wildcard semantics
`Patch::patch()` takes `vector<int16_t>` where values 0-255 are written and negative/ >255 values are skipped (wildcard). This matches the pattern scanner's convention.

### VtableHook test setup pattern
```cpp
class TestBase {
public:
    virtual int get_value() { return 42; }
    virtual int get_other() { return 99; }
    virtual ~TestBase() = default;
};
static int replacement_get_value(TestBase*) { return 100; }

// CRITICAL: Use brace init to avoid most-vexing-parse:
VtableHook hook{Address{&obj}};   // OK
VtableHook hook(Address(&obj));   // WRONG — parsed as function decl

// CRITICAL: Call through volatile pointer to prevent devirtualization:
static TestBase* get_volatile_ptr(TestBase* p) {
    TestBase* volatile vp = p;
    return vp;
}
auto* p = get_volatile_ptr(&obj);
p->get_value();  // goes through vtable
obj.get_value(); // may be devirtualized by MSVC in Release
```

### VirtualAlloc for Patch tests
```cpp
auto* page = (uint8_t*)VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
auto guard = utility::ScopeGuard([&]() { VirtualFree(page, 0, MEM_RELEASE); });
```

### Global function pointer for PointerHook tests
```cpp
static void* g_hook_target = nullptr;  // must be global/static for VirtualProtect
```

## Todo: To-Do List of Action Items

- [x] Phase 1: Fix structural weaknesses in existing tests (commit b6360e9)
- [x] Phase 2: Write tests for Pattern, String, Address, Config (commit 195c4e8)
- [x] Phase 3: Write tests for ScopeGuard, Benchmark, Memory, Patch, PointerHook (commit 7be9fe4)
- [x] Phase 4: Write tests for VtableHook (8 tests, `kananlib-vtablehook-test`)
- [x] Phase 5: Write tests for Input (3 tests, `kananlib-input-test`)
- [x] Phase 6: Write tests for Registry (3 tests, `kananlib-registry-test`)
- [x] Phase 7: Write tests for Module utilities (30 tests, `kananlib-module-test`)
  - All functions tested: get_executable, get_module, get_module_size (3 overloads), get_module_within, get_dll_imagebase, get_module_path/w, get_module_directory/w, get_loaded_module_names, get_module_count, read_module_from_disk, get_original_bytes, get_module_imports, get_module_exports, get_module_sections, LoaderLockGuard, FakeModule move/detach, map_view_of_pe, map_view_of_file
- [x] Phase 8: Write tests for additional Scan functions (8 tests, `kananlib-scan-test`)
  - All functions tested: scan_reverse, scan_data (start/length + HMODULE), scan_ptr (aligned + noalign), scan_opcode, scan_mnemonic, get_insn_size, calculate_absolute (positive/custom/negative), decode_one
  - Uses VirtualAlloc RWX buffer with known x86-64 instruction bytes
- [x] Phase 9: Write tests for PDB + RTTI deep coverage (11 tests, `kananlib-pdb-rtti-test`)
  - PDB: `get_symbol_name`, `get_symbol_map`, `enumerate_symbols`, negative cases (null module)
  - RTTI: `is_vtable`, `get_locator`, `get_type_info`, `derives_from`, `find_vtable_partial`, `find_vtable_regex`, `find_all_vtables`
  - PDB tests guarded by `#ifdef KANANLIB_USE_DIA_SDK` (define passed to test target)
- [x] CTest integration + template refactoring (`enable_testing()`, `add_test()` via template, `ctest -C Release` runs all 10 tests)
- [x] Phase 10: Write tests for Emulation (7 tests, `kananlib-emulation-test`)
  - ShemuContext construction with VirtualAlloc'd buffer (verify internal state)
  - NOP emulation (10 NOPs, verify RIP advances)
  - mov eax, imm32 emulation (verify register update)
  - Multi-instruction emulation (mov + add, verify arithmetic)
  - Free function emulate(base, size, ip, n) convenience wrapper
  - Single-step emulation (emulate() no-args, verify RIP advances per step)
  - HMODULE construction (kernel32.dll always loaded, verify Shellcode/Size)
  - Key quirk: bdshemu single-step executes 2 NOPs per step (off-by-one in counting); test verifies monotonic RIP/instruction-count progression instead of exact counts
- [x] Phase 11: Thread tests — DONE (6 tests in `kananlib-behavior-test`, real worker threads, no deadlock because the suspender excludes the calling thread)
- [x] Phase 12: Bug-hunt pass (branch `tests`) — Address const operators, Patch disable/toggle, scan_reverse/scan_data_reverse `length == start` wraparound (commit `a346a05`). Each demonstrated with a failing test before the fix; see `test/TESTING.md`.
- [ ] Phase 13 (open): remaining Scan surface — `scan_disasm`, and a graceful-failure (not crash) audit of `scan_data_reverse` over unmapped memory (it uses raw `memcmp` with no SEH, unlike `Pattern::find_single`).
- [x] Phase 14: clang coverage tooling — `test/coverage.sh` (LLVM source-based coverage via VS18-bundled clang 20). Fixed `kananlib-test` crashing under the instrumented build (commit `8324df8`): the string-ref→function raw call is gated `#ifndef __clang__` (resolver misresolves under clang's instrumented layout; MSVC path unchanged).
- [x] Phase 15: coverage push — 4 new test executables (`kananlib-{scan,module,rtti,misc}-coverage-test`, +89 tests) for uncovered public API. Library line coverage 47.65% → **53.77%**; String.cpp 50→100%, RTTI 59.5→88.3%, Emulation 51→85.6%. All 18 executables green (260 tests). See "Measured Line Coverage" above.
- [x] Phase 16: Scan-deep coverage — 3 new executables (`kananlib-scan-{bounds,path,resolve}-test`, +76 tests) for the function-analysis/disassembly APIs (function bounds, function-start/unwind, find_*_in_path, find_encapsulating_*, find_function_*_refs, linear blocks, string-ref collection). Scan.cpp 37.3% → **84.0%**; library line coverage 53.77% → **74.98%** (functions 91%, regions 67%, branches 60%). All 21 executables green (336 tests).
- [x] Phase 17: Module Mach-O coverage — `kananlib-module-macho-test` (+15 tests) generates minimal thin/fat Mach-O fixtures at runtime and covers `map_view_of_macho` success plus malformed/fat error branches, `map_view_of_file` auto-detect, null `unlink`/`safe_unlink`, and missing `load_module_from_current_directory`. Module.cpp 45.7% → **62.2%**; library line coverage 74.98% → **77.37%**. All 22 executables green (351 tests).
- [x] Phase 18: PDB edge coverage — `kananlib-pdb-edge-test` (+7 tests) builds synthetic PE/CodeView buffers to cover `get_pdb_path` null/bad DOS/bad NT/no debug/non-CodeView/invalid signature/local absolute PDB/local base PDB/cache branches, plus `generate_c_struct` pointer/array/bitfield/padding formatting. PDB.cpp 53.1% → **58.7%**; library line coverage 77.37% → **78.24%**. All 23 executables green (358 tests).
- [ ] Phase 19 (open): remaining Scan SIMD/branch-exhaustion corners, PDB DIA traversal branches requiring unusual PDBs, and only-safe Module loader branches. Avoid live loader mutation unless isolated in a sacrificial process/harness.
