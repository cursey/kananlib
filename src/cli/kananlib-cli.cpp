#define NOMINMAX

#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <bddisasm.h>

#include <utility/Module.hpp>
#include <utility/Scan.hpp>
#include <utility/String.hpp>

using namespace std;

static void print_usage(const char* prog) {
    cerr << "Usage: " << prog << " <binary_path> <command> [options]\n"
         << "\n"
         << "Commands:\n"
         << "  find_string <text> [--wide] [--all]\n"
         << "      Find string occurrences in the mapped binary.\n"
         << "      --wide   Search as UTF-16 (wide) string.\n"
         << "      --all    Find all occurrences, not just the first.\n"
         << "\n"
         << "  find_displacement_reference <rva>\n"
         << "      Find all RIP-relative displacement references to the given RVA.\n"
         << "      <rva> is interpreted as hex if it starts with 0x, otherwise decimal.\n"
         << "\n"
         << "  find_string_reference <text> [--wide]\n"
         << "      Convenience: find the string then list displacement references to it.\n"
         << "      --wide   Search as UTF-16 (wide) string.\n"
         << "\n"
         << "  find_pattern <pattern> [--all]\n"
         << "      Find IDA-style hex pattern (e.g. \"48 8B ? ? 90\"; one '?' per wildcard byte).\n"
         << "      --all    Find all occurrences, not just the first.\n"
         << "\n"
         << "  find_function_start <rva>\n"
         << "      Walk backward from <rva> to the enclosing function start.\n"
         << "\n"
         << "  find_function_with_string_reference <text> [--wide]\n"
         << "      Find functions that contain a displacement reference to the string.\n"
         << "      --wide   Search as UTF-16 (wide) string.\n"
         << "\n"
         << "  find_relative_reference <rva>\n"
         << "      Find raw 32-bit relative references (e.g. call/jmp targets) to <rva>.\n"
         << "\n"
         << "  disasm <rva> [count]\n"
         << "      Linearly disassemble <count> instructions from <rva> (default 10).\n"
         << "\n"
         << "  hexdump <rva> [count]\n"
         << "      Hexdump <count> bytes from <rva> (default 64).\n"
         << "\n"
         << "  function_bounds <rva>\n"
         << "      Report start, end, size, and instruction count for the enclosing function.\n"
         << "\n"
         << "  resolve_displacement <rva>\n"
         << "      Decode the instruction at <rva> and print the RIP-relative target it resolves to.\n"
         << "\n"
         << "  imports [filter]\n"
         << "      List IAT entries (PE only). Optional substring filter (e.g. \"kernel32!\").\n"
         << "\n"
         << "  exports [filter]\n"
         << "      List export table entries (PE only). Optional substring filter.\n"
         << "\n"
         << "  list_functions [--count N]\n"
         << "      Enumerate functions discovered by .pdata + heuristics.\n"
         << "\n"
         << "  collect_string_references <rva> [--wide] [--follow-calls]\n"
         << "                          [--max-instructions N] [--min-length N] [--max-length N]\n"
         << "      Walk the function CFG starting at <rva> and list every printable string referenced.\n"
         << "      Steps over CALL by default (stays inside the function). --wide for UTF-16.\n"
         << "\n"
         << "Examples:\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_string \"MessageBoxA\" --all\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_displacement_reference 0x1000\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_string_reference \"some_string\" --wide\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_pattern \"48 8B ? ? 90\"\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_function_start 0x1286ee\n"
         << "  " << prog << " C:\\path\\to\\binary.dll find_function_with_string_reference \"is_act_boss\"\n";
}

static uintptr_t parse_address(const string& s) {
    try {
        bool hex = s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0;
        if (hex) {
            return static_cast<uintptr_t>(stoull(s, nullptr, 16));
        }
        return static_cast<uintptr_t>(stoull(s, nullptr, 10));
    } catch (...) {
        cerr << "Error: invalid address: " << s << "\n";
        exit(1);
    }
}

static int cmd_find_string(const char* argv0, HMODULE module, size_t size, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_string requires a text argument\n";
        print_usage(argv0);
        return 1;
    }

    string text{ argv[3] };
    bool wide = false;
    bool all = false;

    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--wide") == 0) {
            wide = true;
        } else if (strcmp(argv[i], "--all") == 0) {
            all = true;
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    auto base = (uintptr_t)module;

    if (wide) {
        auto wide_text = utility::widen(text);
        if (all) {
            auto results = utility::scan_strings(base, size, wide_text, false);
            cout << "Found " << std::dec << results.size() << " occurrence(s):\n";
            for (auto addr : results) {
                cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
            }
        } else {
            auto result = utility::scan_string(base, size, wide_text, false);
            if (result) {
                cout << "0x" << std::hex << *result << " (RVA 0x" << (*result - base) << ")\n";
            } else {
                cout << "Not found.\n";
            }
        }
    } else {
        if (all) {
            auto results = utility::scan_strings(base, size, text, false);
            cout << "Found " << std::dec << results.size() << " occurrence(s):\n";
            for (auto addr : results) {
                cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
            }
        } else {
            auto result = utility::scan_string(base, size, text, false);
            if (result) {
                cout << "0x" << std::hex << *result << " (RVA 0x" << (*result - base) << ")\n";
            } else {
                cout << "Not found.\n";
            }
        }
    }

    return 0;
}

static int cmd_find_displacement_reference(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_displacement_reference requires an address argument\n";
        print_usage(argv0);
        return 1;
    }
    
    auto rva = parse_address(argv[3]);
    auto target = base + rva;
    
    auto results = utility::scan_displacement_references(base, size, target);

    if (results.empty()) {
        cout << "No displacement references found.\n";
    } else {
        cout << "Found " << std::dec << results.size() << " reference(s):\n";
        for (auto addr : results) {
            cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
        }
    }

    return 0;
}

static int cmd_find_string_reference(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_string_reference requires a text argument\n";
        print_usage(argv0);
        return 1;
    }

    string text{ argv[3] };
    bool wide = false;

    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--wide") == 0) {
            wide = true;
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    vector<uintptr_t> string_hits;
    if (wide) {
        string_hits = utility::scan_strings(base, size, utility::widen(text), false);
    } else {
        string_hits = utility::scan_strings(base, size, text, false);
    }

    if (string_hits.empty()) {
        cout << "String not found.\n";
        return 0;
    }

    cout << "String found at " << std::dec << string_hits.size() << " location(s):\n";
    for (auto addr : string_hits) {
        cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
    }
    cout << "\n";

    vector<uintptr_t> refs;
    for (auto str_addr : string_hits) {
        auto hits = utility::scan_displacement_references(base, size, str_addr);
        refs.insert(refs.end(), hits.begin(), hits.end());
    }
    std::sort(refs.begin(), refs.end());
    refs.erase(std::unique(refs.begin(), refs.end()), refs.end());

    if (refs.empty()) {
        cout << "No displacement references found.\n";
    } else {
        cout << "Found " << std::dec << refs.size() << " reference(s):\n";
        for (auto addr : refs) {
            cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
        }
    }

    return 0;
}

static int cmd_find_function_start(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_function_start requires an address argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    auto target = base + rva;

    auto result = utility::find_function_start(target);
    if (!result) {
        cout << "Function start not found.\n";
        return 1;
    }

    cout << "0x" << std::hex << *result << " (RVA 0x" << (*result - base) << ")\n";
    return 0;
}

static int cmd_find_function_with_string_reference(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_function_with_string_reference requires a text argument\n";
        print_usage(argv0);
        return 1;
    }

    string text{ argv[3] };
    bool wide = false;

    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--wide") == 0) {
            wide = true;
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    vector<uintptr_t> string_hits;
    if (wide) {
        string_hits = utility::scan_strings(base, size, utility::widen(text), false);
    } else {
        string_hits = utility::scan_strings(base, size, text, false);
    }

    if (string_hits.empty()) {
        cout << "String not found.\n";
        return 0;
    }

    vector<uintptr_t> funcs;
    for (auto str_addr : string_hits) {
        auto refs = utility::scan_displacement_references(base, size, str_addr);
        for (auto ref : refs) {
            auto fn = utility::find_function_start(ref);
            if (fn) {
                funcs.push_back(*fn);
            }
        }
    }
    std::sort(funcs.begin(), funcs.end());
    funcs.erase(std::unique(funcs.begin(), funcs.end()), funcs.end());

    if (funcs.empty()) {
        cout << "No referencing functions found.\n";
    } else {
        cout << "Found " << std::dec << funcs.size() << " function(s):\n";
        for (auto addr : funcs) {
            cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
        }
    }

    return 0;
}

static int cmd_find_pattern(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_pattern requires a pattern argument\n";
        print_usage(argv0);
        return 1;
    }

    string pattern{ argv[3] };
    bool all = false;

    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--all") == 0) {
            all = true;
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    if (!all) {
        auto result = utility::scan(base, size, pattern);
        if (result) {
            cout << "0x" << std::hex << *result << " (RVA 0x" << (*result - base) << ")\n";
        } else {
            cout << "Not found.\n";
        }
        return 0;
    }

    // --all: iterate from result+1 until exhausted.
    vector<uintptr_t> results;
    uintptr_t cursor = base;
    size_t remaining = size;
    while (true) {
        auto hit = utility::scan(cursor, remaining, pattern);
        if (!hit) break;
        results.push_back(*hit);
        auto advance = (*hit + 1) - cursor;
        if (advance >= remaining) break;
        cursor = *hit + 1;
        remaining -= advance;
    }

    if (results.empty()) {
        cout << "Not found.\n";
    } else {
        cout << "Found " << std::dec << results.size() << " occurrence(s):\n";
        for (auto addr : results) {
            cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
        }
    }
    return 0;
}

static int cmd_disasm(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: disasm requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    size_t count = (argc >= 5) ? (size_t)parse_address(argv[4]) : 10;
    auto target = base + rva;

    const auto end = base + size;
    if (target >= end) {
        cerr << "Error: RVA out of range\n";
        return 1;
    }
    const auto max_size = end - target;

    size_t emitted = 0;
    utility::linear_decode((uint8_t*)target, max_size, [&](utility::ExhaustionContext& ctx) -> bool {
        char buf[ND_MIN_BUF_SIZE]{};
        NdToText(&ctx.instrux, ctx.addr, sizeof(buf), buf);
        cout << "0x" << std::hex << ctx.addr
             << " (RVA 0x" << (ctx.addr - base) << "): "
             << buf << "\n";
        ++emitted;
        return emitted < count;
    });
    return 0;
}

static int cmd_hexdump(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: hexdump requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    size_t count = (argc >= 5) ? (size_t)parse_address(argv[4]) : 64;
    auto target = base + rva;

    const auto end = base + size;
    if (target >= end) {
        cerr << "Error: RVA out of range\n";
        return 1;
    }
    if (target + count > end) {
        count = end - target;
    }

    const auto* p = (const uint8_t*)target;
    for (size_t i = 0; i < count; i += 16) {
        cout << "0x" << std::hex << std::setw(sizeof(uintptr_t) * 2) << std::setfill('0')
             << (target + i) << std::setfill(' ') << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < count) {
                cout << std::hex << std::setw(2) << std::setfill('0') << (unsigned)p[i + j] << ' ';
            } else {
                cout << "   ";
            }
        }
        cout << " ";
        for (size_t j = 0; j < 16 && (i + j) < count; ++j) {
            unsigned char c = p[i + j];
            cout << (char)(std::isprint(c) ? c : '.');
        }
        cout << std::setfill(' ') << "\n";
    }
    cout << std::dec;
    return 0;
}

static int cmd_function_bounds(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: function_bounds requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    auto target = base + rva;

    auto start = utility::find_function_start(target);
    if (!start) {
        cout << "Function start not found.\n";
        return 1;
    }

    auto bounds = utility::determine_function_bounds(*start);
    if (!bounds) {
        cout << "Could not determine bounds for function 0x" << std::hex << *start << "\n";
        return 1;
    }

    cout << "start:        0x" << std::hex << bounds->start
         << " (RVA 0x" << (bounds->start - base) << ")\n"
         << "end:          0x" << bounds->end
         << " (RVA 0x" << (bounds->end - base) << ")\n"
         << "size:         0x" << (bounds->end - bounds->start) << " bytes\n"
         << "instructions: " << std::dec << bounds->instruction_count << "\n";
    return 0;
}

static int cmd_resolve_displacement(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: resolve_displacement requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    auto target = base + rva;

    auto insn = utility::resolve_instruction(target);
    if (!insn) {
        cout << "Failed to resolve instruction at 0x" << std::hex << target << "\n";
        return 1;
    }

    auto resolved = utility::resolve_displacement(insn->addr, &insn->instrux);
    if (!resolved) {
        cout << "No RIP-relative displacement on the instruction at 0x" << std::hex << insn->addr << "\n";
        return 1;
    }

    char buf[ND_MIN_BUF_SIZE]{};
    NdToText(&insn->instrux, insn->addr, sizeof(buf), buf);
    cout << "insn:   0x" << std::hex << insn->addr
         << " (RVA 0x" << (insn->addr - base) << "): "
         << buf << "\n"
         << "target: 0x" << *resolved
         << " (RVA 0x" << (*resolved - base) << ")\n";
    return 0;
}

static int cmd_exports(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    string filter;
    for (int i = 3; i < argc; ++i) {
        if (filter.empty()) {
            filter = argv[i];
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    auto exports = utility::get_module_exports(module);
    if (!exports) {
        cerr << "Error: failed to read export table (not a PE, or no exports?)\n";
        return 1;
    }

    vector<pair<string, uintptr_t>> entries;
    entries.reserve(exports->name_to_addr.size());
    for (auto& [name, addr] : exports->name_to_addr) {
        if (!filter.empty() && name.find(filter) == string::npos) continue;
        entries.emplace_back(name, addr);
    }
    std::sort(entries.begin(), entries.end());

    cout << "Found " << std::dec << entries.size() << " export(s):\n";
    for (auto& [name, addr] : entries) {
        cout << "  0x" << std::hex << addr
             << " (RVA 0x" << (addr - base) << ")  "
             << name << "\n";
    }
    return 0;
}

static int cmd_imports(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    string filter;
    for (int i = 3; i < argc; ++i) {
        if (filter.empty()) {
            filter = argv[i];
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    auto imports = utility::get_module_imports(module);
    if (!imports) {
        cerr << "Error: failed to read import table (not a PE?)\n";
        return 1;
    }

    vector<pair<string, uintptr_t>> entries;
    entries.reserve(imports->name_to_addr.size());
    for (auto& [name, addr] : imports->name_to_addr) {
        if (!filter.empty() && name.find(filter) == string::npos) continue;
        entries.emplace_back(name, addr);
    }
    std::sort(entries.begin(), entries.end());

    cout << "Found " << std::dec << entries.size() << " import(s):\n";
    for (auto& [name, addr] : entries) {
        cout << "  0x" << std::hex << addr
             << " (RVA 0x" << (addr - base) << ")  "
             << name << "\n";
    }
    return 0;
}

static int cmd_find_relative_reference(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: find_relative_reference requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    auto target = base + rva;

    auto results = utility::scan_relative_references(base, size, target, nullptr);
    if (results.empty()) {
        cout << "No relative references found.\n";
    } else {
        cout << "Found " << std::dec << results.size() << " reference(s):\n";
        for (auto addr : results) {
            cout << "  0x" << std::hex << addr << " (RVA 0x" << (addr - base) << ")\n";
        }
    }
    return 0;
}

static int cmd_collect_string_references(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    if (argc < 4) {
        cerr << "Error: collect_string_references requires an RVA argument\n";
        print_usage(argv0);
        return 1;
    }

    auto rva = parse_address(argv[3]);
    auto target = base + rva;

    bool wide = false;
    bool follow_calls = false;
    size_t max_instructions = 4096;
    size_t min_length = 1;
    size_t max_length = 256;

    for (int i = 4; i < argc; ++i) {
        if (strcmp(argv[i], "--wide") == 0) {
            wide = true;
        } else if (strcmp(argv[i], "--follow-calls") == 0) {
            follow_calls = true;
        } else if (strcmp(argv[i], "--max-instructions") == 0 && i + 1 < argc) {
            max_instructions = (size_t)parse_address(argv[++i]);
        } else if (strcmp(argv[i], "--min-length") == 0 && i + 1 < argc) {
            min_length = (size_t)parse_address(argv[++i]);
        } else if (strcmp(argv[i], "--max-length") == 0 && i + 1 < argc) {
            max_length = (size_t)parse_address(argv[++i]);
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    utility::StringReferenceOptions options{};
    options.follow_calls = follow_calls;
    options.min_length = min_length;
    options.max_length = max_length;

    auto print_ref = [&](uintptr_t insn_addr, const INSTRUX& ix, uintptr_t str_addr, const string& text) {
        char buf[ND_MIN_BUF_SIZE]{};
        NdToText(&ix, insn_addr, sizeof(buf), buf);
        cout << "  0x" << std::hex << insn_addr
             << " (RVA 0x" << (insn_addr - base) << "): "
             << buf << "\n"
             << "      -> 0x" << str_addr
             << " (RVA 0x" << (str_addr - base) << ") \""
             << text << "\"\n";
    };

    if (wide) {
        auto refs = utility::collect_unicode_string_references(target, max_instructions, options);
        cout << "Found " << std::dec << refs.size() << " unicode string reference(s):\n";
        for (auto& r : refs) {
            print_ref(r.resolved.addr, r.resolved.instrux, (uintptr_t)r.unicode, utility::narrow(r.unicode));
        }
    } else {
        auto refs = utility::collect_ascii_string_references(target, max_instructions, options);
        cout << "Found " << std::dec << refs.size() << " ascii string reference(s):\n";
        for (auto& r : refs) {
            print_ref(r.resolved.addr, r.resolved.instrux, (uintptr_t)r.ascii, string{r.ascii});
        }
    }
    return 0;
}

static int cmd_list_functions(const char* argv0, HMODULE module, size_t size, uintptr_t base, int argc, const char* argv[]) {
    size_t max_count = (size_t)-1;
    for (int i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            max_count = (size_t)parse_address(argv[++i]);
        } else {
            cerr << "Error: unknown option: " << argv[i] << "\n";
            print_usage(argv0);
            return 1;
        }
    }

    auto bounds = utility::find_all_function_bounds(module);
    cout << "Discovered " << std::dec << bounds.size() << " function(s)";
    if (max_count < bounds.size()) {
        cout << " (showing first " << max_count << ")";
    }
    cout << ":\n";

    size_t shown = 0;
    for (auto& fb : bounds) {
        if (shown++ >= max_count) break;
        cout << "  0x" << std::hex << fb.start
             << " (RVA 0x" << (fb.start - base) << ")  size=0x"
             << (fb.end - fb.start)
             << " insns=" << std::dec << fb.instruction_count << "\n";
    }
    return 0;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    string binary_path{ argv[1] };
    string command{ argv[2] };

    auto module = utility::map_view_of_file(binary_path);
    if (!module) {
        cerr << "Error: failed to map binary: " << binary_path << "\n";
        return 1;
    }

    auto handle = module->module;
    auto module_size = utility::get_module_size(handle);
    if (!module_size) {
        cerr << "Error: failed to determine module size\n";
        return 1;
    }

    auto base = (uintptr_t)handle;
    cout << "Mapped " << binary_path << "\n";
    cout << "  Base: 0x" << std::hex << base << "\n";
    cout << "  Size: 0x" << *module_size << "\n\n";

    if (command == "find_string") {
        return cmd_find_string(argv[0], handle, *module_size, argc, argv);
    } else if (command == "find_displacement_reference") {
        return cmd_find_displacement_reference(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "find_string_reference") {
        return cmd_find_string_reference(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "find_pattern") {
        return cmd_find_pattern(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "find_function_start") {
        return cmd_find_function_start(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "find_function_with_string_reference") {
        return cmd_find_function_with_string_reference(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "find_relative_reference") {
        return cmd_find_relative_reference(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "disasm") {
        return cmd_disasm(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "hexdump") {
        return cmd_hexdump(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "function_bounds") {
        return cmd_function_bounds(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "resolve_displacement") {
        return cmd_resolve_displacement(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "exports") {
        return cmd_exports(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "imports") {
        return cmd_imports(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "collect_string_references") {
        return cmd_collect_string_references(argv[0], handle, *module_size, base, argc, argv);
    } else if (command == "list_functions") {
        return cmd_list_functions(argv[0], handle, *module_size, base, argc, argv);
    } else {
        cerr << "Error: unknown command: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }
}
