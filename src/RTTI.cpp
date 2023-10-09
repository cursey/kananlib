#include <ppl.h>

// Include MSVC internal RTTI headers
#include <vcruntime.h>
#include <rttidata.h>

#include <regex>
#include <mutex>
#include <unordered_map>

#include <spdlog/spdlog.h>

#include <utility/Module.hpp>
#include <utility/RTTI.hpp>
#include <utility/Scan.hpp>

#include <utility/thirdparty/parallel-util.hpp>

namespace utility {
namespace rtti {
namespace detail {
struct Vtable {
    std::type_info* ti{nullptr};
    uintptr_t vtable{};
};

std::recursive_mutex s_vtable_cache_mutex{};
std::unordered_map<HMODULE, std::vector<Vtable>> s_vtable_cache{};

void for_each_uncached(HMODULE m, std::function<void(const Vtable&)> predicate) {
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

        predicate(Vtable{ti, i});
    } catch(...) {
        continue;
    }
}

void populate(HMODULE m) {
    std::scoped_lock _{s_vtable_cache_mutex};

    if (!s_vtable_cache[m].empty()) {
        return;
    }

    s_vtable_cache[m].reserve(4192);

    for_each_uncached(m, [&](const Vtable& vtable) {
        s_vtable_cache[m].push_back(vtable);
    });
}

void for_each(HMODULE m, std::function<void(const Vtable&)> predicate) {
    populate(m);

    // makes it easier for the caller to thread this
    std::vector<Vtable> entries{};
    {
        std::scoped_lock _{s_vtable_cache_mutex};
        //entries = s_vtable_cache[m];
        entries.insert(entries.end(), s_vtable_cache[m].begin(), s_vtable_cache[m].end());
    }

    for (const auto& vtable : entries) {
        predicate(vtable);
    }
}

std::optional<Vtable> find(HMODULE m, std::function<bool(const Vtable&)> predicate) {
    populate(m);

    std::optional<Vtable> result{};

    // makes it easier for the caller to thread this
    std::vector<Vtable> entries{};
    {
        std::scoped_lock _{s_vtable_cache_mutex};
        //entries = s_vtable_cache[m];
        entries.insert(entries.end(), s_vtable_cache[m].begin(), s_vtable_cache[m].end());
    }

    for (const auto& vtable : entries) {
        if (predicate(vtable)) {
            return vtable;
        }
    }

    return std::nullopt;
}
}

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

std::type_info* get_type_info(HMODULE m, std::string_view type_name) {
    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return vtable.ti->name() == type_name;
    });

    if (result) {
        return result->ti;
    }

    return nullptr;
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

        const auto rn = ti->raw_name();

        if (rn[0] != '.' || rn[1] != '?') {
            return false; // we ran into a bad one
        }

        if (std::string_view{rn}.find("@") == std::string_view::npos) {
            return false; // we ran into a bad one
        }

        if (ti->name() == type_name) {
            return true;
        }
    }

    return false;
}

bool derives_from(const void* obj, std::type_info* ti_compare) {
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

        if (ti == ti_compare) {
            return true;
        }
    }

    return false;
}

std::optional<uintptr_t> find_vtable(HMODULE m, std::string_view type_name) try {
    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return vtable.ti->name() == type_name || vtable.ti->raw_name() == type_name;
    });
    
    if (result) {
        return result->vtable;
    }

    return std::nullopt;
} catch(...) {
    spdlog::error("rtti::find_vtable - exception");
    return std::nullopt;
}

std::vector<uintptr_t> find_vtables(HMODULE m, std::string_view type_name) {
    std::vector<uintptr_t> result{};

    detail::for_each(m, [&](const detail::Vtable& vtable) {
        if (vtable.ti->name() == type_name || vtable.ti->raw_name() == type_name) {
            result.push_back(vtable.vtable);
        }
    });

    // Sort the vtables by the offset into each vtable (_s_RTTICompleteObjectLocator)
    std::sort(result.begin(), result.end(), [](uintptr_t a, uintptr_t b) {
        const auto locator_a = *(_s_RTTICompleteObjectLocator**)(a - sizeof(void*));
        const auto locator_b = *(_s_RTTICompleteObjectLocator**)(b - sizeof(void*));

        return locator_a->offset < locator_b->offset;
    });

    return result;
}

std::optional<uintptr_t> find_vtable_partial(HMODULE m, std::string_view type_name) try {
    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return std::string_view{vtable.ti->name()}.find(type_name) != std::string_view::npos;
    });
    
    if (result) {
        return result->vtable;
    }

    return std::nullopt;
} catch(...) {
    spdlog::error("rtti::find_vtable_partial - exception");
    return std::nullopt;
}

std::optional<uintptr_t> find_vtable_regex(HMODULE m, std::string_view reg_str) {
    std::regex reg{reg_str.data()};

    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return std::regex_match(vtable.ti->name(), reg);
    });

    if (result) {
        return result->vtable;
    }

    return std::nullopt;
}

std::vector<uintptr_t*> find_vtables_derived_from(HMODULE m, std::string_view friendly_type_name) {
    const auto base_vtable = find_vtable(m, friendly_type_name);

    if (!base_vtable) {
        return {};
    }

    std::vector<uintptr_t*> result{};
    detail::for_each(m, [&](const detail::Vtable& vtable) {
        // trycatch block because sometimes bad entries get into the array.
        try {
            if (derives_from((void*)&vtable.vtable, friendly_type_name)) {
                result.push_back((uintptr_t*)vtable.vtable);
            }
        } catch(...) {
            return;
        }
    });

    return result;
}

std::optional<uintptr_t> find_object_inline(HMODULE m, std::string_view type_name) {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtable = find_vtable(m, type_name);

    if (!vtable) {
        spdlog::error("Failed to find object {} (Could not find vtable)", type_name);
        return std::nullopt;
    }

    std::optional<uintptr_t> result{};

    concurrency::parallel_for(begin, end, sizeof(void*), [&](uintptr_t addr) {
        if (result != std::nullopt || IsBadReadPtr((void*)addr, sizeof(void*))) {
            return;
        }

        auto obj = (void*)addr;

        if (IsBadReadPtr((void*)obj, sizeof(void*))) {
            return;
        }

        const auto possible_vtable = *(uintptr_t*)obj;

        if (possible_vtable == *vtable) {
            result = addr;
        }
    });

    return result;
}

std::optional<uintptr_t*> find_object_ptr(HMODULE m, std::string_view type_name) {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtables = find_vtables(m, type_name);

    if (vtables.empty()) {
        spdlog::error("Failed to find object {} (Could not find vtable)", type_name);
        return std::nullopt;
    }


    std::optional<uintptr_t*> result{};

    concurrency::parallel_for(begin, end, sizeof(void*), [&](uintptr_t addr) {
        if (result != std::nullopt || IsBadReadPtr((void*)addr, sizeof(void*))) {
            return;
        }

        auto& obj = *(void**)addr;

        if (IsBadReadPtr((void*)obj, sizeof(void*))) {
            return;
        }

        const auto possible_vtable = *(uintptr_t*)obj;

        if (std::find(vtables.begin(), vtables.end(), possible_vtable) != vtables.end()) {
            result = (uintptr_t*)addr;
        }
    });

    return result;
}

std::optional<uintptr_t*> find_object_ptr(HMODULE vtable_module, uintptr_t begin, uintptr_t end, std::string_view type_name) {
    const auto vtables = find_vtables(vtable_module, type_name);

    if (vtables.empty()) {
        spdlog::error("Failed to find object {} (Could not find vtable)", type_name);
        return std::nullopt;
    }

    std::optional<uintptr_t*> result{};

    concurrency::parallel_for(begin, end, sizeof(void*), [&](uintptr_t addr) {
        if (result != std::nullopt || IsBadReadPtr((void*)addr, sizeof(void*))) {
            return;
        }

        auto& obj = *(void**)addr;

        if (IsBadReadPtr((void*)obj, sizeof(void*))) {
            return;
        }

        const auto possible_vtable = *(uintptr_t*)obj;

        if (std::find(vtables.begin(), vtables.end(), possible_vtable) != vtables.end()) {
            result = (uintptr_t*)addr;
        }
    });

    return result;
}

std::vector<uintptr_t*> find_objects_ptr(HMODULE m, std::string_view type_name) {
    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtables = find_vtables(m, type_name);

    if (vtables.empty()) {
        spdlog::error("Failed to find object {} (Could not find vtable)", type_name);
        return {};
    }

    std::vector<uintptr_t*> result{};
    std::mutex result_mutex{};

    concurrency::parallel_for(begin, end, sizeof(void*), [&](uintptr_t addr) {
        if (IsBadReadPtr((void*)addr, sizeof(void*))) {
            return;
        }

        auto& obj = *(void**)addr;

        if (IsBadReadPtr((void*)obj, sizeof(void*))) {
            return;
        }

        const auto possible_vtable = *(uintptr_t*)obj;

        if (std::find(vtables.begin(), vtables.end(), possible_vtable) != vtables.end()) {
            std::scoped_lock _{result_mutex};
            result.push_back((uintptr_t*)addr);
        }
    });

    std::sort(result.begin(), result.end(), [](uintptr_t* a, uintptr_t* b) {
        return (uintptr_t)a < (uintptr_t)b;
    });

    return result;
}
}
}