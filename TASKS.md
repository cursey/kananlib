# kananlib Test Coverage Improvement

## Repository
- **Path:** `I:/Programming/projects/kananlib-fresh`
- **Branch:** `main`
- **Latest test commit:** `2e21db2` (4 total test commits)

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
- **Note:** LSP/clangd will show errors (wrong compiler version). MSVC builds cleanly.
  - `test/build/Release/kananlib-module-test.exe`

## What Was Done (4 commits)

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
| **Total** | **119** | **17 of 19 modules** |

## Gap Analysis — Untested and Partially Tested Modules

### Modules with 0 direct test coverage (2 of 19)

1. **Emulation** (`include/utility/Emulation.hpp`, `src/Emulation.cpp`)
   - `ShemuContext(base, buffer_size, stack_size)` — construct with VirtualAlloc'd buffer
   - `ShemuContext(HMODULE, stack_size)` — construct with loaded module
   - `emulate(ip, num_instructions)` — run multi-step emulation
   - `emulate()` — single-step emulation
   - Free-function `emulate(base, size, ip, num_instructions)`
   - Testable by VirtualAlloc-ing a buffer, copying known x86-64 bytes (e.g. `mov eax, 1; ret`), checking returned status code

2. **Thread** (`include/utility/Thread.hpp`, `src/Thread.cpp`)
   - `suspend_threads()` / `resume_threads(ThreadStates)` capture ALL threads, including the calling one = deadlock
   - `ThreadSuspender` default ctor is safe (doesn't suspend until `.suspend()`), but testing `.suspend()` has the same problem
   - **Decision: skip unless child process isolation is added**

3. **Logging** (`include/utility/Logging.hpp`)
   - Just `#if __has_include` + `#define` wrappers around spdlog macros — nothing to test

### Modules with significant untested surface area

4. **Module** (`include/utility/Module.hpp`, `src/Module.cpp`) — TESTED (30 tests, `kananlib-module-test`)
   - All major functions now covered: get_executable, get_module, get_module_size (3 overloads), get_module_within, get_dll_imagebase, get_module_path/w, get_module_directory/w, get_loaded_module_names, get_module_count, read_module_from_disk, get_original_bytes, get_module_imports, get_module_exports, get_module_sections, LoaderLockGuard, FakeModule move/detach, map_view_of_pe, map_view_of_file
   - Negative cases: nullptr for imports/exports/sections, nonexistent module name

5. **Scan** (`include/utility/Scan.hpp`, `src/Scan.cpp`) — partially covered, many functions untested
   - Tested: `scan`, `scan_string`, `scan_strings`, `scan_displacement_reference`, `scan_relative_reference`, `resolve_instruction`, `collect_basic_blocks`, `exhaustive_decode`
   - NOT tested:
     - `scan_reverse` — reverse direction scan
     - `scan_data(HMODULE, data, size)` / `scan_data_t` — raw byte scan
     - `scan_ptr` / `scan_ptr_noalign` — pointer value scan
     - `scan_opcode` — find opcode by byte
     - `scan_mnemonic` — find instruction by mnemonic
     - `scan_disasm` — find instruction by pattern
     - `get_insn_size` — get instruction size at address
     - `calculate_absolute` — resolve relative offset to absolute
     - `decode_one` — decode single instruction
     - `resolve_displacement` — resolve RIP-relative target

6. **PDB** (`include/utility/PDB.hpp`, `src/PDB.cpp`) — only `get_pdb_path` + type functions tested
   - NOT tested:
     - `get_symbol_address(module, name)` — resolve symbol name to address
     - `get_symbol_name(module, rva)` — resolve address to symbol name
     - `get_symbol_map(module)` — full symbol map
     - `enumerate_symbols(module, max)` — list symbols
     - `get_struct_info(module, name)` — struct layout via DIA SDK
     - `enumerate_structs(module)` — list structs via DIA SDK
     - `generate_c_struct(info)` — C header generation

7. **RTTI** (`include/utility/RTTI.hpp`, `src/RTTI.cpp`) — only COL/find_vtable tested
   - NOT tested:
     - `is_vtable(ptr)` — check if pointer is a vtable
     - `get_locator(obj)` / `get_type_info(obj)` — get COL/TI from object
     - `derives_from(obj, name)` — inheritance check
     - `find_vtable_partial(name)` — partial name match
     - `find_vtable_regex(name)` — regex match
     - `find_vtables_derived_from(name)` — all derived vtables
     - `find_all_vtables(module)` — enumerate all vtables
     - `find_object_inline(name)` / `find_object_ptr(name)` / `find_objects_ptr(name)` — find static instances

### Well-tested (no major gaps)
String, Pattern, Address, Config, ScopeGuard, Benchmark, Memory, Patch, PointerHook, VtableHook, Input, Registry, Module

## Key Implementation Notes for Next Session

### Adding a new test target
1. Create `test/TestXxx.cpp` with `#include "TestHelpers.hpp"` and test functions
2. Add target section to `test/cmake.toml` (copy from existing, change name and source)
3. Add matching section to `test/CMakeLists.txt` (cmake.toml is source of truth, but CMakeLists.txt is what actually builds)
4. Re-run cmake, build, run

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
- [ ] Phase 8: Write tests for additional Scan functions (~8 tests, add to `kananlib-utils-test` or new target)
  - `scan_reverse`, `scan_data`, `scan_ptr`, `scan_opcode`, `scan_mnemonic`
  - `get_insn_size`, `calculate_absolute`, `decode_one`
  - Use VirtualAlloc'd buffer with known code or scan own module
- [ ] Phase 9: Write tests for PDB + RTTI deep coverage (~10 tests, add to `kananlib-test` or new target)
  - PDB: `get_symbol_address`, `get_symbol_name`, `get_symbol_map`, `enumerate_symbols`
  - RTTI: `is_vtable`, `get_locator`, `get_type_info`, `derives_from`, `find_all_vtables`
  - Test on loaded modules (ntdll, kernel32) and existing RTTITest classes
- [ ] Phase 10: Write tests for Emulation (~4 tests, `kananlib-emulation-test`)
  - ShemuContext construction with VirtualAlloc'd buffer
  - Simple instruction emulation (`mov eax, 1; ret`)
  - Multi-step emulation and status checking
- [ ] Phase 11: Thread tests — SKIP (deadlock risk unless child process isolation is added)
