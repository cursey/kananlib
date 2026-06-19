// Contrived sample target for kananlib's cross-platform tests.
//
// Compiled with the MSVC ABI (clang-cl) into an x86-64 PE/DLL and committed as
// kananlib_sample.dll. kananlib's Linux test (TestLinuxPE.cpp) maps this DLL
// with utility::map_view_of_file and runs the scan / module / RTTI utilities
// against its known, deterministic content:
//
//   * exported functions       -> get_module_exports
//   * a kernel32 import        -> get_module_imports
//   * a marker string in .rdata-> scan_string + scan_displacement_reference
//   * a polymorphic class      -> rtti::find_vtable (TypeDescriptor ".?AV...")
//   * real .pdata              -> find_function_start / function bounds
//
// Rebuild (from a Windows shell with clang-cl on PATH):
//   clang-cl /LD /O2 /GR /EHsc kananlib_sample.cpp /Fe:kananlib_sample.dll
#include <windows.h>

extern "C" {

// "kananlib_sample_marker" ends up in .rdata and is referenced (RIP-relative
// LEA) by this function, giving the displacement-reference scanner a target.
__declspec(dllexport) int kananlib_sample_compute(int x) {
    volatile const char* marker = "kananlib_sample_marker";
    int acc = x;
    for (int i = 0; marker[i] != '\0'; ++i) {
        acc += marker[i];
    }
    // Reference a kernel32 import so the import directory is non-trivial.
    acc ^= (int)GetCurrentProcessId();
    return acc;
}

__declspec(dllexport) int kananlib_sample_add(int a, int b) {
    return a + b;
}

} // extern "C"

// A polymorphic type makes MSVC emit a vtable plus complete RTTI graph
// (TypeDescriptor with decorated name ".?AVSampleVtableClass@@").
class SampleVtableClass {
public:
    virtual ~SampleVtableClass() = default;
    virtual int magic() const { return 0x4B414E41; } // 'KANA'
    virtual int compute(int x) const { return x * 2 + 1; }
};

// Keep the vtable/RTTI alive by exporting factory/dispatch helpers.
extern "C" __declspec(dllexport) SampleVtableClass* kananlib_sample_make() {
    return new SampleVtableClass();
}

extern "C" __declspec(dllexport) int kananlib_sample_call(SampleVtableClass* p, int x) {
    return p != nullptr ? p->compute(x) : -1;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
