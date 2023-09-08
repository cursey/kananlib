// Include MSVC internal RTTI headers
#include <vcruntime.h>
#include <rttidata.h>

#include <regex>

#include <spdlog/spdlog.h>

#include <utility/Module.hpp>
#include <utility/RTTI.hpp>
#include <utility/Scan.hpp>

namespace utility {
namespace rtti {
_s_RTTICompleteObjectLocator* get_locator(const void* obj) {
    if (obj == nullptr || *(void**)obj == nullptr) {
        return nullptr;
    }

    return *(_s_RTTICompleteObjectLocator**)(*(uintptr_t*)obj - sizeof(void*));
}

std::type_info* get_type_info(const void* obj) {
    const auto locator = get_locator(obj);

    if (locator == nullptr) {
        return nullptr;
    }

    const auto module_within = ::utility::get_module_within(locator);

    if (!module_within) {
        return nullptr;
    }

    const auto module = (uintptr_t)*module_within;
    const auto ti = (std::type_info*)(module + locator->pTypeDescriptor);

    return ti;
}

bool derives_from(const void* obj, std::string_view type_name) {
    if (obj == nullptr) {
        return false;
    }

    const auto locator = *(_s_RTTICompleteObjectLocator**)(*(uintptr_t*)obj - sizeof(void*));

    if (locator == nullptr) {
        return false;
    }

    const auto module_within = ::utility::get_module_within(locator);

    if (!module_within) {
        return false;
    }

    const auto module = (uintptr_t)*module_within;
    const auto class_hierarchy = (_s_RTTIClassHierarchyDescriptor*)(module + locator->pClassDescriptor);

    if (class_hierarchy == nullptr) {
        return false;
    }

    const auto base_classes = (_s_RTTIBaseClassArray*)(module + class_hierarchy->pBaseClassArray);

    if (base_classes == nullptr) {
        return false;
    }

    for (auto i = 0; i < class_hierarchy->numBaseClasses; ++i) {
        const auto desc_offset = base_classes->arrayOfBaseClassDescriptors[i];

        if (desc_offset == 0) {
            continue;
        }

        const auto desc = (_s_RTTIBaseClassDescriptor*)(module + desc_offset);

        if (desc == nullptr) {
            continue;
        }

        const auto ti = (std::type_info*)(module + desc->pTypeDescriptor);

        if (ti == nullptr) {
            continue;
        }

        if (ti->name() == type_name) {
            return true;
        }
    }

    return false;
}

std::optional<uintptr_t> find_vtable(HMODULE m, std::string_view type_name) try {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    for (auto i = begin; i < end - sizeof(void*); i += sizeof(void*)) try {
        const auto fake_obj = (void*)i;
        const auto ti = get_type_info(&fake_obj);

        if (ti == nullptr) {
            continue;
        }

        const auto rn = ti->raw_name();

        if (rn[0] != '.' || rn[1] != '?') {
            continue;
        }

        if (std::string_view{rn}.find("@") == std::string_view::npos) {
            continue;
        }

        if (ti->name() == type_name || ti->raw_name() == type_name) {
            return i;
        }
    } catch(...) {
        continue;
    }

    return std::nullopt;
} catch(...) {
    spdlog::error("rtti::find_vtable - exception");
    return std::nullopt;
}

std::optional<uintptr_t> find_vtable_partial(HMODULE m, std::string_view type_name) try {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    for (auto i = begin; i < end - sizeof(void*); i += sizeof(void*)) try {
        const auto fake_obj = (void*)i;
        const auto ti = get_type_info(&fake_obj);

        if (ti == nullptr) {
            continue;
        }

        const auto rn = ti->raw_name();

        if (rn[0] != '.' || rn[1] != '?') {
            continue;
        }

        if (std::string_view{rn}.find("@") == std::string_view::npos) {
            continue;
        }

        if (std::string_view{ti->name()}.find(type_name) != std::string_view::npos) {
            return i;
        }
    } catch(...) {
        continue;
    }

    return std::nullopt;
} catch(...) {
    spdlog::error("rtti::find_vtable_partial - exception");
    return std::nullopt;
}

std::optional<uintptr_t> find_vtable_regex(HMODULE m, std::string_view reg_str) {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    std::regex reg{reg_str.data()};

    for (auto i = begin; i < end - sizeof(void*); i += sizeof(void*)) try {
        const auto fake_obj = (void*)i;
        const auto ti = get_type_info(&fake_obj);

        if (ti == nullptr) {
            continue;
        }

        const auto rn = ti->raw_name();

        if (rn[0] != '.' || rn[1] != '?') {
            continue;
        }

        if (std::string_view{rn}.find("@") == std::string_view::npos) {
            continue;
        }

        if (std::regex_match(ti->name(), reg)) {
            return i;
        }
    } catch(...) {
        continue;
    }

    return std::nullopt;
}
}
}