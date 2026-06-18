# Bug Hunting & Regression Testing Guide

How to find real bugs in kananlib, demonstrate them with failing tests, then fix them.

## Core Principle

**Demonstrate before you fix.** Never claim a bug exists without showing it failing
at runtime or compile time. Speculation is not evidence.

## Step 1: Read the API, then read how tests use it

Start by reading the public headers in `include/utility/`. These are the contracts.
Then read the test files in `test/`. Look for:

### Pattern A: Semantics change under different calling contexts

The Address bug is a textbook example. The class had:
```cpp
// In the header — operators were non-const:
bool operator ==(bool val) {       // NOT const
    return ((m_ptr && val) || (!m_ptr && !val));  // checks truthiness
}
operator uintptr_t() const {       // const
    return (uintptr_t)m_ptr;
}
```

The existing tests only used non-const `Address` objects, so the dedicated `operator==`
always won the overload. No test ever passed a `const Address&` — which forced MSVC to
use the implicit conversion operator instead, silently changing the semantics:

| Context | `a == true` for `a = 0x1000` | Reason |
|---|---|---|
| Non-const `Address` | `true` (correct) | Uses `operator==(bool)` — checks truthiness |
| `const Address&` | `false` (wrong) | Converts to `uintptr_t` → `0x1000 == 1` |

The fix: add `const` to all comparison operators so the dedicated operator always wins.

### Pattern B: State corruption on edge-case call sequences

The Patch bug is an example. `Patch::disable()` unconditionally called `patch()`:
```cpp
bool Patch::disable() {
    return !(m_enabled = !patch(m_address, m_original_bytes));
}
```

When called on a patch created with `should_enable = false` (so `m_original_bytes` is
empty), `patch()` calls `VirtualProtect(addr, 0, ...)` which fails, then:
- `patch()` returns `false`
- `m_enabled = !false = true`  — **corrupted**
- `disable()` returns `false`

After this, `toggle()` sees `m_enabled = true` and takes the wrong branch. The existing
tests all created patches with `should_enable = true`, so this path was never exercised.

### Pattern C: Unsigned arithmetic on boundary conditions

Look for `uintptr_t` loops with subtraction (`i >= start - length`) — if `length > start`,
the subtraction wraps and the loop either never executes or never terminates.

### Pattern D: Missing error-path checks

Functions that call OS APIs (`VirtualProtect`, `VirtualAlloc`, `IsBadReadPtr`) and assume
success. Check what happens on size=0, nullptr, or already-committed pages.

## Step 2: Write a regression test that fails

Write the test FIRST, against the buggy code. The test must:

1. **Compile** (or fail to compile if the bug is a compile-time issue — that IS the demonstration)
2. **Fail at runtime** with a clear assertion message when the bug is present

Use the existing test infrastructure:
```cpp
#include "TestHelpers.hpp"

int test_my_bug() {
    // Set up the scenario that triggers the bug
    auto result = function_under_test(bad_input);
    TEST_ASSERT(result == expected_value);  // This should fail with buggy code
    return 0;
}
```

### Adding the test target

1. Create `test/TestXxx.cpp`
2. Add to `test/cmake.toml`:
   ```toml
   [target.kananlib-xxx-test]
   type = "kananlib-test-template"
   sources = ["TestXxx.cpp"]
   ```
3. Add the corresponding block to `test/CMakeLists.txt` (copy the pattern from any
   existing target — the template provides all shared settings)
4. Re-run cmake: `cmake -B build -G "Visual Studio 17 2022" -A x64`

## Step 3: Build and run to demonstrate the failure

```bash
cd test
cmake --build build --config Release --target kananlib-xxx-test
build\Release\kananlib-xxx-test.exe
```

You MUST see the test fail. If it doesn't fail, either:
- The bug doesn't exist (your hypothesis was wrong)
- The test doesn't exercise the right code path
- MSVC is silently papering over the issue (like the Address implicit conversion case)

For the Address bug, the test compiled but produced wrong results:
```
[RUN ] test_address_const_operators
  FAIL: exercise_const_address(a)  (TestBugRegression.cpp:42)
[FAIL] test_address_const_operators (0.0 ms)
```

For the Patch bug, three tests failed:
```
[RUN ] test_patch_disable_before_enable
  FAIL: p->disable()  (TestBugRegression.cpp:117)
[FAIL] test_patch_disable_before_enable (0.0 ms)
```

**Paste or cite this output in your commit message.**

## Step 4: Fix the bug

Now — and only now — apply the minimal fix. For the Address bug:
```cpp
// Before:
bool operator ==(bool val) {
// After:
bool operator ==(bool val) const {
```

For the Patch bug:
```cpp
bool Patch::disable() {
    if (!m_enabled) {
        return true;  // Already disabled — don't call patch() with empty m_original_bytes
    }
    return !(m_enabled = !patch(m_address, m_original_bytes));
}
```

## Step 5: Rebuild and verify

```bash
cmake --build build --config Release --target kananlib-xxx-test
build\Release\kananlib-xxx-test.exe
```

Expected output:
```
===== Results: 5 passed, 0 failed (5 total) =====
```

Then verify no existing tests regressed:
```bash
cmake --build build --config Release
cd build && ctest -C Release --output-on-failure
```

All 14 test executables should pass.

## Checklist for a Bug Fix Commit

- [ ] Regression test written and committed alongside the fix
- [ ] Test demonstrates failure on the unfixed code (cite output)
- [ ] Fix is minimal — changes only what's necessary
- [ ] All existing tests still pass (`ctest -C Release`)
- [ ] Commit message names the bug, the root cause, and the fix

## Common Pitfalls

**"It compiles so it's fine."** The Address bug compiled — MSVC silently used a different
operator. Always test with `const` references and edge-case inputs.

**"The existing tests pass."** The Patch bug had no test for `disable()` on a never-enabled
patch. Existing tests only prove existing coverage, not correctness.

**"It works on my machine."** Run the full `ctest` suite. Some tests (PDB, RTTI) depend
on the executable having debug info; the emulation test depends on bddisasm. Run them all.

**"I'll fix the bug and the test in one commit."** Separate commits: one for the test
(demonstrating the bug), one for the fix. This makes `git bisect` useful and lets reviewers
see the before/after.

## Friction Points Encountered

These are real issues hit during the bug-finding process. They're not theoretical.

### Test file includes are minimal — you must bring your own

`TestHelpers.hpp` only pulls in `<chrono>` and `<cstdio>`. Every test file must
manually include `<iostream>` (for `std::cout`), and every library header it touches
(`Patch.hpp`, `ScopeGuard.hpp`, etc.). Forgetting `<iostream>` gives you a cascade
of `std::cout is not a member` errors that look like a toolchain problem but aren't.

The build system does NOT auto-include the kananlib headers for you — you need them
all explicitly in each test file.

### MSVC doesn't reject const-correctness bugs — it papers over them

The Address bug is the canonical example. The hypothesis was: "the non-const operators
won't compile on `const Address`". That was **wrong** — MSVC compiled it by falling
back to `operator uintptr_t() const`. The test compiled, linked, and ran. The bug
manifested as silent wrong results at runtime, not a compiler error.

The technique that worked: write a `static` helper that takes `const Address&` and
exercises every comparison operator. If the semantics are wrong, the runtime assertions
catch it. Don't rely on compilation failure as your evidence.

```cpp
static bool exercise_const_address(const Address& a) {
    // If operator== is non-const, MSVC uses operator uintptr_t() const instead,
    // which changes semantics: a == true becomes (uintptr_t)a == true (i.e. addr == 1).
    return a == (uintptr_t)0x1000
        && a != (uintptr_t)0x2000
        && a == (void*)0x1000
        && a == true    // <-- this one fails silently without the fix
        && a != false;
}
```

### ctest output truncates without -V — tests appear missing

Running `ctest -C Release` on this project produces a summary that only shows the
first ~9 of 14 tests. The rest do run and pass, but their lines are truncated in the
summary. This is a display issue, not a test failure.

If you see fewer tests than expected, don't assume they failed. Check with:
```bash
ctest -C Release -N          # lists all registered tests
ctest -C Release -V          # verbose: shows every test's output
ctest -C Release -R "name" -V  # verbose for a specific test
```

### Running test executables: use absolute Windows paths

When running test executables directly (not through ctest), use the full path:
```bash
"I:\Programming\projects\kananlib-fresh\test\build\Release\kananlib-bug-regression-test.exe"
```
Relative paths with backslashes get mangled by some shells. Forward slashes work too
but quoting the full path is safest.

### Both cmake.toml AND CMakeLists.txt must be updated

`cmake.toml` is the source of truth for cmkr, but the actual CMake build uses
`CMakeLists.txt`. When adding a new test target:
1. Add the `[target.xxx]` section to `cmake.toml`
2. Add the corresponding `set(CMKR_TARGET ...)` / `add_executable(...)` block to
   `CMakeLists.txt` — copy the pattern from any existing target
3. Re-run `cmake -B build -G "Visual Studio 17 2022" -A x64` to pick up changes

If you only update `cmake.toml`, the build won't see your new target. The `[cmkr] Skipping
automatic cmkr generation` message during cmake configure confirms that cmkr is NOT
auto-generating CMakeLists.txt.

### TEST_ASSERT vs TEST_EXPECT — know the difference

- `TEST_ASSERT(expr)` — **hard fail**: prints location and `return 1` from the function.
  First failure stops the test function.
- `TEST_EXPECT(expr)` — **soft fail**: prints location but continues. Use for checking
  multiple properties where you want to see all failures, not just the first.

If you use `TEST_ASSERT` for the first check and it fails, you'll never see whether
later checks pass or fail. For diagnostic tests, prefer `TEST_EXPECT` so you get
maximum information from a single run.

### The test framework doesn't catch exceptions — you must

`TestHelpers.hpp` has no exception catching. The test `main()` functions wrap everything
in `try { ... } catch (const std::exception& e) { ... }`. If you forget this and your
test code throws, you'll get an unhelpful abort with no message. Always use the pattern:
```cpp
int main() try {
    RUN_TEST(test_foo);
    return test_summary();
} catch (const std::exception& e) {
    std::cout << "Exception: " << e.what() << std::endl;
    return 1;
} catch (...) {
    std::cout << "Unknown exception" << std::endl;
    return 1;
}
```

### Scoping test execution: revert fixes first, then demonstrate, then re-apply

When you've already applied a fix and need to demonstrate the bug existed:
1. Revert the source fix (keep the test file)
2. Build and run — the test should fail (this is your evidence)
3. Re-apply the fix
4. Build and run — the test should pass

Don't skip step 2. The failure output is your proof.

### A test for a HANG must time out and FAIL — never let it hang the suite

The scan_reverse `length == start` bug is an infinite loop, not a wrong value. The
naive test (`auto r = scan_reverse(start, start, pat); TEST_ASSERT(!r);`) does not
"fail" against the buggy code — it **hangs forever**, taking the entire executable
(and CI) down with it. That is useless as a regression guard.

Run the suspect call on a worker thread and poll an `std::atomic<bool> done` flag with
a deadline. If the deadline passes, the scan is hanging: print a clear message, detach
the thread (you cannot safely cancel a hung native call), and `TEST_ASSERT(false)`.
The test then FAILS in N seconds instead of hanging. See
`TestScanBugRegression.cpp::test_scan_reverse_length_equals_start`.

```cpp
std::atomic<bool> done{false};
std::optional<uintptr_t> result;
std::thread worker([&]{ result = scan_reverse(p, p, "DE AD"); done.store(true); });
auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
while (!done.load()) {
    if (std::chrono::steady_clock::now() >= deadline) {
        worker.detach();                         // leak the hung thread on purpose
        TEST_ASSERT(false && "scan hung — regression");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}
worker.join();
```

`TestHelpers.hpp` does not pull in `<thread>`, `<chrono>`, or `<atomic>` — add them.

### Demonstrate the ACTUAL bug condition, not a lookalike that passes anyway

The most common wasted effort in this codebase: writing a "boundary" test that looks
like it exercises the bug but doesn't. For the reverse-scan wraparound, three separate
attempts placed the pattern at a small offset inside a buffer and passed a small
`length` — those passed against the buggy code because the wraparound only happens when
`start - length == 0`, i.e. when `length` equals the **absolute address** `start`, not
some offset. A test that passes against the unfixed code proves nothing.

Before claiming a demonstration: revert the fix, run the test, and confirm it FAILS
(or hangs, then times out and fails). If it passes without the fix, you are testing the
wrong condition. This is step 2 in "Scoping test execution" — it is not optional.

### `VirtualAlloc(addr, ..., MEM_TOP_DOWN, ...)` does not allocate AT `addr`

To make `length == start` cheap (scan ~64KB instead of the whole 64-bit space) the
reverse-scan test needs the buffer at a known LOW address. `MEM_TOP_DOWN` treats the
address argument as a hint/maximum and normally hands back a high address. On this
machine `VirtualAlloc((void*)0x10000, 0x1000, MEM_COMMIT|MEM_RESERVE|MEM_TOP_DOWN, ...)`
does land at `0x10000`, but it is not guaranteed — the test `SKIP`s (returns 0) if the
low allocation fails rather than scanning billions of bytes. Don't assume a specific
address; check the returned pointer.

### `scan_data_reverse` has no SEH — keep its tests inside mapped memory

`Pattern::find_single` wraps its inner scan in `try { ... } catch(...)` to swallow
access violations and skip to the next page, so `scan_reverse` survives scanning across
unmapped memory (slowly). `scan_data_reverse` does NOT — it calls raw `memcmp((void*)i,
...)` with no guard. A reverse-data scan that walks into an unmapped page throws an
uncaught SEH/`Unknown exception` and aborts the test. Keep `scan_data_reverse` tests
within a single committed page; do not reuse the `length == start` low-address trick for
it. (This asymmetry is itself a candidate bug — see TASKS.md Phase 13.)

### Auditing a load-bearing change: diff the original, then check every caller

kananlib is consumed by other projects, so a "fix" to a public function in `Scan.cpp` /
`Module.cpp` / `RTTI.cpp` can break downstream silently. Before trusting a change:
1. `git show HEAD:src/Scan.cpp` (or `git diff`) and read the ORIGINAL loop/guards — do
   not assume what was there. The reverse-scan guards (`start==0||length==0`,
   `length>start`) were already present; only the loop body changed.
2. Prove behavioral equivalence for the non-buggy domain: same address set, same
   iteration order, same early-return point. The fix must be a strict superset
   (identical where it worked, correct where it hung).
3. `search` for every caller in `src/`, `include/`, `src/cli/`, `test/`. These scan
   functions have no internal callers — they are public API, so existing behavioral
   tests (`test_scan_reverse`, `*_basic`, `*_not_found`) are the contract you must not
   break. Run them.

### `git commit -m` with backticks or `$()` in the message spawns junk files

Writing a rich multi-line commit message inline that contains backticks (`` `code` ``)
or `$(...)` makes the shell try to execute them. The commit still lands (git already
has the message), but you get `command not found` noise AND stray files named after the
mangled fragments (e.g. files literally called `=` and `start`) appear untracked. After
such a commit, check `git status` and delete the junk: `rm -f -- "=" "start"`. To avoid
it entirely, keep inline commit messages free of backticks/`$()`, or write the message
to a file and use `git commit -F`.
