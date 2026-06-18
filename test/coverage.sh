#!/usr/bin/env bash
# Measure kananlib test coverage with clang source-based coverage (LLVM).
#
# Why clang and not MSVC: MSVC has no built-in line-coverage tool. clang's
# -fprofile-instr-generate/-fcoverage-mapping + llvm-cov is self-contained and
# already on disk via the VS-bundled LLVM (no extra install).
#
# CRITICAL — toolchain pairing: the VS18 MSVC STL static_asserts "Clang 20 or
# newer". Use the clang-cl that VS18 BUNDLES (clang 20.x), NOT a standalone
# LLVM on PATH (e.g. LLVM 17), or every STL include fails. We also pin
# CMAKE_RC_COMPILER to the same bundle so the manifest/resource link pass uses
# a matching llvm-rc (a mismatched one fails with "no such file or directory").
#
# Usage:  bash test/coverage.sh            # build (if needed), run, report
#         bash test/coverage.sh --rebuild  # wipe build-cov and reconfigure
#
# Output: text summary on stdout + browsable HTML at
#         test/build-cov/coverage-html/index.html
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# --- Locate the VS18 bundled LLVM toolchain (clang 20, matches VS18 STL) ---
VS_LLVM="C:/Program Files/Microsoft Visual Studio/18/Community/VC/Tools/Llvm/x64/bin"
CLANG_CL="$VS_LLVM/clang-cl.exe"
LLVM_RC="$VS_LLVM/llvm-rc.exe"
PROFDATA="$VS_LLVM/llvm-profdata.exe"
COV="$VS_LLVM/llvm-cov.exe"

for tool in "$CLANG_CL" "$LLVM_RC" "$PROFDATA" "$COV"; do
    [ -f "$tool" ] || { echo "ERROR: missing toolchain component: $tool" >&2; exit 1; }
done

BUILD="build-cov"
SRC_ROOT="$(cd .. && pwd)"

# Files to EXCLUDE from the coverage report: third-party deps, the test
# sources themselves, vendored headers, and the CLI front-end. We only want
# the library under src/ and include/utility/.
IGNORE='(_deps|TestHelpers|Test.*\.cpp|Main\.cpp|StressTest\.cpp|thirdparty|cli)'

# All instrumented test executables (one .profraw each).
EXES=(
    kananlib-test kananlib-stress-test kananlib-utils-test kananlib-advanced-test
    kananlib-vtablehook-test kananlib-input-test kananlib-registry-test
    kananlib-module-test kananlib-scan-test kananlib-pdb-rtti-test
    kananlib-emulation-test kananlib-bug-regression-test
    kananlib-scan-bug-regression-test kananlib-behavior-test
    kananlib-scan-coverage-test kananlib-module-coverage-test
    kananlib-rtti-coverage-test kananlib-misc-coverage-test
    kananlib-scan-bounds-test kananlib-scan-path-test kananlib-scan-resolve-test
)

# --- Configure (instrumented) ---
if [ "${1:-}" = "--rebuild" ] || [ ! -d "$BUILD" ]; then
    rm -rf "$BUILD"
    cmake -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        "-DCMAKE_C_COMPILER=$CLANG_CL" \
        "-DCMAKE_CXX_COMPILER=$CLANG_CL" \
        "-DCMAKE_RC_COMPILER=$LLVM_RC" \
        "-DCMAKE_C_FLAGS=-fprofile-instr-generate -fcoverage-mapping /EHsc" \
        "-DCMAKE_CXX_FLAGS=-fprofile-instr-generate -fcoverage-mapping /EHsc" \
        "-DCMAKE_EXE_LINKER_FLAGS=-fprofile-instr-generate"
fi

# --- Build ---
cmake --build "$BUILD"

# --- Run each test exe, emitting a per-exe .profraw ---
cd "$BUILD"
rm -f ./*.profraw
for exe in "${EXES[@]}"; do
    # Full path: this shell can't exec ./foo.exe directly.
    LLVM_PROFILE_FILE="$exe.profraw" "$(pwd)/$exe.exe" >/dev/null 2>&1 || \
        echo "  note: $exe exited non-zero (its profile still counts)" >&2
done

# --- Merge + report ---
"$PROFDATA" merge -sparse ./*.profraw -o merged.profdata

OBJS=()
for e in "${EXES[@]:1}"; do OBJS+=(-object "$(pwd)/$e.exe"); done

echo
echo "================ kananlib coverage (library only) ================"
"$COV" report "$(pwd)/${EXES[0]}.exe" "${OBJS[@]}" \
    -instr-profile=merged.profdata -ignore-filename-regex="$IGNORE" \
    "$SRC_ROOT/src" "$SRC_ROOT/include" 2>/dev/null

# --- HTML ---
"$COV" show "$(pwd)/${EXES[0]}.exe" "${OBJS[@]}" \
    -instr-profile=merged.profdata -ignore-filename-regex="$IGNORE" \
    -format=html -output-dir=coverage-html \
    -show-line-counts-or-regions -show-branches=count \
    "$SRC_ROOT/src" "$SRC_ROOT/include" 2>/dev/null

echo
echo "HTML report: test/$BUILD/coverage-html/index.html"
