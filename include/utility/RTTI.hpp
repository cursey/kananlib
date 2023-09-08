#pragma once

#include <Windows.h>

#include <string_view>
#include <typeinfo>
#include <optional>

struct _s_RTTICompleteObjectLocator;

namespace utility {
namespace rtti {
    _s_RTTICompleteObjectLocator* get_locator(const void* obj);
    std::type_info* get_type_info(const void* obj);
    bool derives_from(const void* obj, std::string_view type_name);
    std::optional<uintptr_t> find_vtable(HMODULE m, std::string_view type_name);
    std::optional<uintptr_t> find_vtable_partial(HMODULE m, std::string_view type_name);
    std::optional<uintptr_t> find_vtable_regex(HMODULE m, std::string_view reg_str);
}
}