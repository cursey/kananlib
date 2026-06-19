#pragma once

#include <windows.h>

#include <vector>
#include <string_view>
#include <typeinfo>
#include <optional>

struct _s_RTTICompleteObjectLocator;

namespace utility {
namespace rtti {
    bool is_vtable(const void* vtable);
    _s_RTTICompleteObjectLocator* get_locator(const void* obj);
    // NOTE: off Windows the returned pointer aliases the MSVC TypeDescriptor
    // embedded in the mapped image, NOT a host std::type_info. It is valid for
    // pointer-identity comparison (e.g. derives_from(obj, ti)), but you MUST NOT
    // call std::type_info members (name()/raw_name()) on it on non-Windows: that
    // dispatches the host RTTI vtable over foreign bytes. For name-based queries
    // use find_vtable / find_vtables / derives_from(obj, type_name) instead,
    // which work on every platform (matching the decorated ".?AV..." name).
    std::type_info* get_type_info(const void* obj);
    std::type_info* get_type_info(HMODULE m, std::string_view type_name);
    bool derives_from(const void* obj, std::string_view type_name);
    bool derives_from(const void* obj, std::type_info* ti);
    std::optional<uintptr_t> find_vtable(HMODULE m, std::string_view type_name);
    std::vector<uintptr_t> find_vtables(HMODULE m, std::string_view type_name); // sometimes vtables can be duplicated
    std::optional<uintptr_t> find_vtable_partial(HMODULE m, std::string_view type_name);
    std::optional<uintptr_t> find_vtable_regex(HMODULE m, std::string_view reg_str);

    std::vector<uintptr_t*> find_vtables_derived_from(HMODULE m, std::string_view friendly_type_name);
    std::vector<uintptr_t> find_all_vtables(HMODULE m);

    std::optional<uintptr_t> find_object_inline(HMODULE m, std::string_view type_name); // level 0 only
    std::optional<uintptr_t*> find_object_ptr(HMODULE m, std::string_view type_name); // level 1 pointers (Obj*)
    std::optional<uintptr_t*> find_object_ptr(HMODULE vtable_module, uintptr_t start, uintptr_t end, std::string_view type_name); // level 1 pointers (Obj*)

    std::vector<uintptr_t*> find_objects_ptr(HMODULE m, std::string_view type_name); // level 1 pointers (Obj*)
}
}