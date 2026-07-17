#include <ppl.h>

// Include MSVC internal RTTI headers
#ifdef __clang__
#define _ThrowInfo ThrowInfo
#endif

#include <vcruntime.h>
#include <rttidata.h>

#include <regex>
#include <mutex>
#include <unordered_map>

#include <utility/Logging.hpp>

#include <utility/Module.hpp>
#include <utility/RTTI.hpp>
#include <utility/Scan.hpp>
#include <utility/Benchmark.hpp>

#include <utility/thirdparty/parallel-util.hpp>

#ifndef _WIN32
namespace kananlib_msvc {
// MSVC lays std::type_info out as a TypeDescriptor inside the image: a vftable
// pointer, an undecorated-name cache slot, then the decorated name (".?AV...").
// The PE bytes kananlib reads ARE such descriptors, not host std::type_info
// objects, so we reinterpret them through this type to read the name. The host
// CRT has no MSVC name undecorator, so name() returns the decorated form.
struct type_info {
    const void* _vfptr;
    void*       _spare;
    char        _decorated[1];
    const char* raw_name() const { return _decorated; }
    const char* name() const { return _decorated; }
};
}
using KANANLIB_RTTI_TI = kananlib_msvc::type_info;
#else
using KANANLIB_RTTI_TI = std::type_info;
#endif

namespace utility {
namespace rtti {
namespace detail {
struct Vtable {
    KANANLIB_RTTI_TI* ti{nullptr};
    uintptr_t vtable{};
    TargetArch arch{host_arch()};
    bool loaded{true};  // false for images we mapped ourselves (map_view_of_pe)

    // Decorated RTTI name (".?AV..."). It sits 2 * the target pointer width into
    // the TypeDescriptor (past the vfptr and undecorated-name cache slot), which
    // is exactly where a host type_info's raw_name() points -- so computing the
    // offset works for both loaded and mapped (possibly foreign-arch) modules.
    std::string_view raw_name() const {
        return reinterpret_cast<const char*>(
            reinterpret_cast<uintptr_t>(ti) + 2 * pointer_width(arch));
    }

    // Undecorated name ("class Foo"). Only a genuinely loaded, host-arch module
    // exposes a usable host type_info; undecorating a foreign or mapped-image
    // type_info is unsafe (wrong layout / read-only pages), so those match on
    // the decorated name instead.
    std::string_view name() const {
        return (loaded && arch == host_arch())
            ? std::string_view{ti->name()}
            : raw_name();
    }
};

std::recursive_mutex s_vtable_cache_mutex{};
std::unordered_map<HMODULE, std::vector<Vtable>> s_vtable_cache{};

void for_each_uncached(HMODULE m, std::function<void(const Vtable&)> predicate) {
    KANANLIB_BENCH();

    const auto begin = (uintptr_t)m;
    const auto module_size = utility::get_module_size(m);
    if (!module_size) {
        return;
    }

    const auto arch = utility::get_module_arch(m);
    const auto width = utility::pointer_width(arch);
    if (*module_size < width) {
        return;
    }
    const auto end = begin + *module_size;

    // Mapped modules (any arch) are not in the loader list, so the
    // get_type_info path below can't resolve them; walk them directly at the
    // target's pointer width. Loaded modules keep the original host path.
    if (utility::is_mapped_module(m)) {
        // Parse the complete-object-locator / TypeDescriptor by hand at the
        // target pointer width (a mapped image can be a foreign arch, e.g. a
        // 32-bit PE in a 64-bit process). Mapped absolute pointers are already
        // real host addresses (SEC_IMAGE relocated them), so no translation.
        for (auto i = begin + width; i < end; i += width) KANANLIB_AV_TRY {
            const auto col = width == 4
                ? (uintptr_t)*(uint32_t*)(i - width)
                : (uintptr_t)*(uint64_t*)(i - width);
            if (col == 0 || IsBadReadPtr((void*)col, sizeof(_s_RTTICompleteObjectLocator))) {
                continue;
            }

            const auto locator = (_s_RTTICompleteObjectLocator*)col;
            // pTypeDescriptor is an image-relative RVA on x64 and an absolute
            // pointer on x86; normalize to a 32-bit field either way.
            const uint32_t td_field = (uint32_t)(uintptr_t)locator->pTypeDescriptor;
            const auto td = locator->signature == 1 ? begin + td_field : (uintptr_t)td_field;
            const auto ti = (KANANLIB_RTTI_TI*)td;
            if (td == 0 || IsBadReadPtr(ti, width * 2 + 4)) {
                continue;
            }

            const auto rn = (const char*)(td + width * 2);
            if (rn[0] != '.' || rn[1] != '?') {
                continue;
            }
            if (std::string_view{rn}.find("@") == std::string_view::npos) {
                continue;
            }

            predicate(Vtable{ti, i, arch, /*loaded=*/false});
        } KANANLIB_AV_EXCEPT {
            continue;
        }
        return;
    }

    for (auto i = begin; i < end - sizeof(void*); i += sizeof(void*)) KANANLIB_AV_TRY {
        const auto fake_obj = (void*)i;
        const auto ti = (KANANLIB_RTTI_TI*)get_type_info(&fake_obj);

        if (ti == nullptr) {
            continue;
        }

        // Using IsBadReadPtr helps us stop accidentally triggering some Vectored Exception Handlers
        // if those get triggered, it MASSIVELY slows down this function, especially if they write mini dumps.
        if (IsBadReadPtr(ti, sizeof(void*))) {
            continue;
        }

        const auto rn = ti->raw_name();

        if (IsBadReadPtr(rn, sizeof(void*))) {
            continue;
        }

        if (rn[0] != '.' || rn[1] != '?') {
            continue;
        }

        if (std::string_view{rn}.find("@") == std::string_view::npos) {
            continue;
        }

        predicate(Vtable{ti, i, arch});
    } KANANLIB_AV_EXCEPT {
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

std::optional<HMODULE> cached_get_module_within(uintptr_t addr) {
#if !defined(_WIN32)
    // No loader module list off Windows; resolve against the registered fake
    // module ranges instead.
    return ::utility::get_module_within(addr);
#endif
    struct ModuleInfo {
        uintptr_t begin{};
        uintptr_t end{};
    };

    static thread_local std::vector<ModuleInfo> cache{};

    if (cache.empty()) {
        utility::foreach_module([&](LIST_ENTRY* entry, _LDR_DATA_TABLE_ENTRY* module) {
            cache.push_back({(uintptr_t)module->DllBase, (uintptr_t)module->DllBase + utility::get_module_size((HMODULE)module->DllBase).value_or(0)});
        });
    }

    for (const auto& info : cache) {
        if (addr >= info.begin && addr < info.end) {
            return (HMODULE)info.begin;
        }
    }

    return std::nullopt;
}
}

// On x64, RTTI cross-references are image-relative RVAs (signature==1).
// On x86, they are absolute pointers (signature==0).
inline uintptr_t resolve_rtti_ref(uintptr_t module, uint32_t field, uint32_t signature) {
    return signature == 1 ? module + field : (uintptr_t)field;
}

bool is_vtable(const void* vtable) {
    if (vtable == nullptr) {
        return false;
    }
    
    const auto module_within = detail::cached_get_module_within((uintptr_t)vtable);

    if (!module_within) {
        return false;
    }

    bool result = false;

    detail::for_each(*module_within, [&](const detail::Vtable& entry) {
        if (entry.vtable == (uintptr_t)vtable) {
            result = true;
        }
    });

    return result;
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

    const auto module_within = detail::cached_get_module_within((uintptr_t)locator);

    if (!module_within) {
        return nullptr;
    }

    const auto module = (uintptr_t)*module_within;
    const auto ti = (std::type_info*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)locator->pTypeDescriptor, locator->signature);

    return ti;
}

std::type_info* get_type_info(HMODULE m, std::string_view type_name) {
    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return vtable.name() == type_name || vtable.raw_name() == type_name;
    });

    if (result) {
        return (std::type_info*)result->ti;
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

    const auto module_within = detail::cached_get_module_within((uintptr_t)locator);

    if (!module_within) {
        return false;
    }

    const auto module = (uintptr_t)*module_within;
    const auto class_hierarchy = (_s_RTTIClassHierarchyDescriptor*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)locator->pClassDescriptor, locator->signature);

    if (class_hierarchy == nullptr) {
        return false;
    }

    const auto base_classes = (_s_RTTIBaseClassArray*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)class_hierarchy->pBaseClassArray, locator->signature);

    if (base_classes == nullptr) {
        return false;
    }

    for (auto i = 0; i < class_hierarchy->numBaseClasses; ++i) {
        const auto desc_offset = base_classes->arrayOfBaseClassDescriptors[i];

        if (desc_offset == 0) {
            continue;
        }

        const auto desc = (_s_RTTIBaseClassDescriptor*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)desc_offset, locator->signature);

        if (desc == nullptr) {
            continue;
        }

        const auto ti = (KANANLIB_RTTI_TI*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)desc->pTypeDescriptor, locator->signature);

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
    const auto class_hierarchy = (_s_RTTIClassHierarchyDescriptor*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)locator->pClassDescriptor, locator->signature);

    if (class_hierarchy == nullptr) {
        return false;
    }

    const auto base_classes = (_s_RTTIBaseClassArray*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)class_hierarchy->pBaseClassArray, locator->signature);

    if (base_classes == nullptr) {
        return false;
    }

    for (auto i = 0; i < class_hierarchy->numBaseClasses; ++i) {
        const auto desc_offset = base_classes->arrayOfBaseClassDescriptors[i];

        if (desc_offset == 0) {
            continue;
        }

        const auto desc = (_s_RTTIBaseClassDescriptor*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)desc_offset, locator->signature);

        if (desc == nullptr) {
            continue;
        }

        const auto ti = (std::type_info*)resolve_rtti_ref(module, (uint32_t)(uintptr_t)desc->pTypeDescriptor, locator->signature);

        if (ti == ti_compare) {
            return true;
        }
    }

    return false;
}

std::optional<uintptr_t> find_vtable(HMODULE m, std::string_view type_name) try {
    KANANLIB_BENCH();

    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return vtable.name() == type_name || vtable.raw_name() == type_name;
    });
    
    if (result) {
        return result->vtable;
    }

    return std::nullopt;
} catch(...) {
    SPDLOG_ERROR("rtti::find_vtable - exception");
    return std::nullopt;
}

std::vector<uintptr_t> find_vtables(HMODULE m, std::string_view type_name) {
    KANANLIB_BENCH();

    std::vector<uintptr_t> result{};

    detail::for_each(m, [&](const detail::Vtable& vtable) {
        if (vtable.name() == type_name || vtable.raw_name() == type_name) {
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
    KANANLIB_BENCH();

    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        return vtable.name().find(type_name) != std::string_view::npos;
    });
    
    if (result) {
        return result->vtable;
    }

    return std::nullopt;
} catch(...) {
    SPDLOG_ERROR("rtti::find_vtable_partial - exception");
    return std::nullopt;
}

std::optional<uintptr_t> find_vtable_regex(HMODULE m, std::string_view reg_str) {
    KANANLIB_BENCH();

    std::regex reg{reg_str.data()};

    const auto result = detail::find(m, [&](const detail::Vtable& vtable) {
        const auto name = vtable.name();
        return std::regex_match(name.begin(), name.end(), reg);
    });

    if (result) {
        return result->vtable;
    }

    return std::nullopt;
}

std::vector<uintptr_t*> find_vtables_derived_from(HMODULE m, std::string_view friendly_type_name) {
    KANANLIB_BENCH();

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

std::vector<uintptr_t> find_all_vtables(HMODULE m) {
    KANANLIB_BENCH();

    std::vector<uintptr_t> result{};

    detail::for_each(m, [&](const detail::Vtable& vtable) {
        result.push_back(vtable.vtable);
    });

    return result;
}

std::optional<uintptr_t> find_object_inline(HMODULE m, std::string_view type_name) {
    KANANLIB_BENCH();

    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtable = find_vtable(m, type_name);

    if (!vtable) {
        SPDLOG_ERROR("Failed to find object {} (Could not find vtable)", type_name);
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
    KANANLIB_BENCH();

    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtables = find_vtables(m, type_name);

    if (vtables.empty()) {
        SPDLOG_ERROR("Failed to find object {} (Could not find vtable)", type_name);
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
    KANANLIB_BENCH();

    const auto vtables = find_vtables(vtable_module, type_name);

    if (vtables.empty()) {
        SPDLOG_ERROR("Failed to find object {} (Could not find vtable)", type_name);
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
    KANANLIB_BENCH();

    const auto begin = (uintptr_t)m;
    const auto end = begin + *utility::get_module_size(m);

    const auto vtables = find_vtables(m, type_name);

    if (vtables.empty()) {
        SPDLOG_ERROR("Failed to find object {} (Could not find vtable)", type_name);
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