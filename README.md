# kananlib

*C++ binary analysis library with AVX2-accelerated scanning, exhaustive disassembly, emulation, control flow analysis, and function discovery.*

Built for runtime modding projects (UEVR, REFramework) that need to discover hook targets in stripped game binaries at injection time. A typical lookup chains three primitives:

```cpp
// Find UE's InitNullRHI by a string it logs.
const auto str = utility::scan_string(rhi_module, L"NullDrvFailure");
const auto ref = utility::scan_displacement_reference(rhi_module, *str);
const auto fn  = utility::find_function_start(*ref);
```

That shape, repeated against different anchor strings, survives game patches without manual address updates. When one string is ambiguous, `find_function_with_string_refs(A, B)` filters to functions referencing both. When strings don't anchor anything, `find_landmark_sequence` chains patterns across the CFG. `exhaustive_decode` walks any function's CFG and hands each instruction to a callback for deeper work.

For the methodology behind this approach, see [UEVR: An Exploration of Advanced Game Hacking Techniques](https://praydog.com/reverse-engineering/2023/07/03/uevr.html).

The library is C++20, Windows-only, x86-64. See `include/utility/` for the full API.

## CLI

`kananlib-cli` exposes the library's scanners as one-shot argv commands. It maps a PE or x86-64 Mach-O binary into the host Windows process's address space using `utility::map_view_of_file` and runs queries against the live bytes. There is no analysis database and no cache. Every command starts from raw memory, finishes, and exits.

### When it's useful

- Iterating on pattern signatures during mod development: type a pattern, get an RVA, sub-second on multi-megabyte binaries.
- CI verification that signatures still resolve uniquely after a game patch (`find_pattern --all`, fail the build if `> 1`).
- Quick triage on an unknown binary before deciding whether to open IDA/r2.
- Scripting around game updates: run the same query against three game versions in a shell loop.

### When it isn't

- Interactive exploration: use IDA / r2 / Binja.
- Repeated xref queries against the same binary. Analysis databases amortize cost; we re-scan every time.
- Anything needing types, decompilation, symbol-aware queries, or persistent comments / flags.

### Build

```bash
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --target kananlib-cli
# build/Release/kananlib-cli.exe
```

### Conventions

- `<rva>` arguments accept hex (`0x1286ee`) or decimal. They're interpreted relative to the module base, not absolute, so they're stable across runs even though Windows hands the mapping a different base every time.
- Results print as `0x<absolute> (RVA 0x<rva>)`. The RVA is the one you'd typically paste into another tool or save in a signature file.
- Pattern syntax is IDA-style with **one `?` per wildcard byte** (not `??`). `*` between segments means "skip up to N bytes" (default 256); `*[N]` overrides the gap.
- The library's spdlog output (`[info]`/`[error]` lines) interleaves with command output. `2>&1 | grep -v info` if you want it gone.

---

### find_string

```
find_string <text> [--wide] [--all]
```

Find ASCII (default) or UTF-16 (`--wide`) string occurrences. `--all` returns every hit; without it, just the first.

```
$ kananlib-cli game.exe find_string "is_act_boss" --all
Found 1 occurrence(s):
  0x7ff68a88c068 (RVA 0x2dfc068)
```

### find_pattern

```
find_pattern <pattern> [--all]
```

IDA-style hex pattern search with single-`?` wildcards and `*` / `*[N]` gap globs. `--all` enumerates every hit.

```
$ kananlib-cli binary.exe find_pattern "48 89 5C 24 ? 48 89 74 24 ? 57"
0x7ff687b96c10 (RVA 0x106c10)
```

### find_displacement_reference

```
find_displacement_reference <rva>
```

Find every RIP-relative displacement reference (LEA, `MOV [rip+disp]`, etc.) whose decoded target equals the given RVA. Each candidate is decoded with bddisasm to confirm it's a real instruction with that exact displacement, so random rel32-shaped bytes don't produce false positives.

```
$ kananlib-cli binary.exe find_displacement_reference 0x2dfc068
Found 1 reference(s):
  0x7ff687bb86ee (RVA 0x1286ee)
```

### find_relative_reference

```
find_relative_reference <rva>
```

Find every raw 32-bit relative reference (`CALL rel32`, `JMP rel32`) whose `ip + 4 + rel32 == base + rva`. Cheaper than `find_displacement_reference`, but matches both code and data interpretations of the rel32 bytes. Useful for finding callers of a function.

```
$ kananlib-cli binary.exe find_relative_reference 0x1282d0
Found 1 reference(s):
  0x7ff687bb94fa (RVA 0x1294fa)
```

### find_string_reference

```
find_string_reference <text> [--wide]
```

Composition: find the string, then list every displacement reference to it. Dedupes if the string appears more than once. Single command instead of two.

```
$ kananlib-cli binary.exe find_string_reference "is_act_boss"
String found at 1 location(s):
  0x7ff687... (RVA 0x2dfc068)

Found 1 reference(s):
  0x7ff687... (RVA 0x1286ee)
```

### find_function_with_string_reference

```
find_function_with_string_reference <text> [--wide]
```

Composition: find the string, find every displacement reference, walk each reference back to its enclosing function start, deduplicate. Multiple references inside the same function collapse to one entry.

```
$ kananlib-cli binary.exe find_function_with_string_reference \
    "Audio/Sound Effects/UI/click_01_down.ogg" --wide
Found 9 function(s):
  0x7ff687bfedd0 (RVA 0x16edd0)
  0x7ff688723d30 (RVA 0xc93d30)
  ...
```

### find_function_start

```
find_function_start <rva>
```

Walk backward from `rva` to the enclosing function start using `.pdata` on Windows PE images (plus heuristics where `.pdata` doesn't reach).

```
$ kananlib-cli binary.exe find_function_start 0x1286ee
0x7ff687bb82d0 (RVA 0x1282d0)
```

### function_bounds

```
function_bounds <rva>
```

Walk backward to the function start, then determine its end via CFG walk + linear extension. Reports `start`, `end`, `size`, instruction count.

```
$ kananlib-cli binary.exe function_bounds 0x1286ee
start:        0x7ff687bb82d0 (RVA 0x1282d0)
end:          0x7ff687bb8b44 (RVA 0x128b44)
size:         0x874 bytes
instructions: 1
```

### list_functions

```
list_functions [--count N]
```

Enumerate every function discovered via `.pdata` + heuristics. `--count N` truncates.

```
$ kananlib-cli binary.exe list_functions --count 3
Discovered 150688 function(s) (showing first 3):
  0x7ff687a91000 (RVA 0x1000)  size=0x68 insns=0
  0x7ff687a91080 (RVA 0x1080)  size=0x211 insns=0
  0x7ff687a91360 (RVA 0x1360)  size=0x23a insns=0
```

### disasm

```
disasm <rva> [count]
```

Linearly disassemble `count` instructions (default 10) from `rva` via bddisasm. Doesn't follow branches; `collect_string_references` is the CFG-aware option.

```
$ kananlib-cli binary.exe disasm 0x1282d0 5
0x7ff687bb82d0 (RVA 0x1282d0): MOV       qword ptr [rsp+0x8], rbx
0x7ff687bb82d5 (RVA 0x1282d5): MOV       qword ptr [rsp+0x10], rsi
0x7ff687bb82da (RVA 0x1282da): MOV       qword ptr [rsp+0x18], rdi
0x7ff687bb82df (RVA 0x1282df): PUSH      rbp
0x7ff687bb82e0 (RVA 0x1282e0): PUSH      r12
```

### hexdump

```
hexdump <rva> [count]
```

Raw bytes (default 64) with ASCII gutter.

```
$ kananlib-cli binary.exe hexdump 0x2dfc068 16
0x00007ff68a88c068  69 73 5f 61 63 74 5f 62 6f 73 73 00 00 00 00 00  is_act_boss.....
```

### resolve_displacement

```
resolve_displacement <rva>
```

Decode the instruction containing `rva`. Handles the mid-instruction case: `find_displacement_reference` returns the offset of the rel32 operand, not the instruction start, so this command finds the instruction first. Reports the decoded instruction text and the resolved RIP-relative target.

```
$ kananlib-cli binary.exe resolve_displacement 0x1286ee
insn:   0x7ff687bb86eb (RVA 0x1286eb): LEA       rcx, [rel 0x7ff68a88c068]
target: 0x7ff68a88c068 (RVA 0x2dfc068)
```

### collect_string_references

```
collect_string_references <rva> [--wide] [--follow-calls]
                          [--max-instructions N] [--min-length N] [--max-length N]
```

Point this at a function start and it walks the CFG, stepping over `CALL` by default to stay inside the function, emitting every printable string the function references. Filters: `--wide` for UTF-16, `--min-length` to drop single-char noise, `--max-instructions` (default 4096) caps the CFG walk.

The output bundles both the originating `LEA` and the resolved string content, so you get a one-shot answer to "what does this function care about":

```
$ kananlib-cli binary.exe collect_string_references 0x1282d0
Found 11 ascii string reference(s):
  0x7ff687bb845d (RVA 0x12845d): LEA       rax, [rel 0x7ff68add4ca0]
      -> 0x7ff68add4ca0 (RVA 0x3344ca0) "Monster"
  0x7ff687bb84a0 (RVA 0x1284a0): LEA       rbx, [rel 0x7ff68a88c100]
      -> 0x7ff68a88c100 (RVA 0x2dfc100) "K"
  0x7ff687bb86eb (RVA 0x1286eb): LEA       rcx, [rel 0x7ff68a88c068]
      -> 0x7ff68a88c068 (RVA 0x2dfc068) "is_act_boss"
  ...
```

### imports / exports

```
imports [filter]
exports [filter]
```

Enumerate the PE IAT (imports) or export table (exports). Optional substring filter matches against the raw entry name. For MSVC-mangled exports that's the mangled form (`@AK@@` for namespace `AK::`, etc.).

```
$ kananlib-cli kernel32.dll exports "GetModuleHandle"
Found 4 export(s):
  0x... (RVA 0x1f3f0)  GetModuleHandleA
  0x... (RVA 0x212d0)  GetModuleHandleExA
  0x... (RVA 0x1f970)  GetModuleHandleExW
  0x... (RVA 0x1d470)  GetModuleHandleW

$ kananlib-cli eldenring.exe imports "kernel32"
Found 204 import(s):
  ...
```

Forwarded and ordinal-only exports are skipped (no local VA to report).

---

### Composing commands

The CLI is designed so output of one command flows into the next:

```bash
# What functions does this string land in?
RVA=$(kananlib-cli game.exe find_string "MyFeatureName" \
      | awk -F'RVA 0x' '/RVA/ {print $2}' | tr -d ')')

kananlib-cli game.exe find_function_with_string_reference "MyFeatureName"

# What strings does each of those functions touch?
for fn_rva in $(kananlib-cli game.exe find_function_with_string_reference "MyFeatureName" \
                 | awk -F'RVA 0x' '/RVA/ {print $2}' | tr -d ')'); do
  echo "=== Function 0x$fn_rva ==="
  kananlib-cli game.exe collect_string_references "0x$fn_rva" --min-length 4
done
```

This is the workflow the CLI was built for: chained queries against a fresh binary, no setup, scriptable.
