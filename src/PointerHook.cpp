#include <stdexcept>

#include <windows.h>

#include <utility/Logging.hpp>

#include <utility/PointerHook.hpp>

PointerHook::PointerHook(void** old_ptr, void* new_ptr)
    : m_replace_ptr{old_ptr},
    m_destination{new_ptr}
{
    if (old_ptr == nullptr) {
        SPDLOG_ERROR("PointerHook: old_ptr is nullptr");
        throw std::invalid_argument("old_ptr cannot be nullptr");
    }

    if (IsBadReadPtr(old_ptr, sizeof(void*))) {
        SPDLOG_ERROR("PointerHook: old_ptr is not readable");
        throw std::invalid_argument("old_ptr is not readable");
    }

    ProtectionOverride overrider{old_ptr, sizeof(void*), PAGE_EXECUTE_READWRITE};

    SPDLOG_INFO("[PointerHook] Hooking {:x}->{:x} to {:x}", (uintptr_t)old_ptr, (uintptr_t)*old_ptr, (uintptr_t)new_ptr);

    m_original = *old_ptr;
    *old_ptr = new_ptr;
}

PointerHook::~PointerHook() {
    remove();
}

bool PointerHook::remove() {
    if (m_replace_ptr != nullptr && !IsBadReadPtr(m_replace_ptr, sizeof(void*)) && *m_replace_ptr == m_destination) {
        try {
            ProtectionOverride overrider{m_replace_ptr, sizeof(void*), PAGE_EXECUTE_READWRITE};
            *m_replace_ptr = m_original;
        } catch (std::exception& e) {
            SPDLOG_ERROR("PointerHook: {}", e.what());
            return false;
        }
    }

    return true;
}

bool PointerHook::restore() {
    if (m_replace_ptr != nullptr && !IsBadReadPtr(m_replace_ptr, sizeof(void*)) && *m_replace_ptr != m_destination) {
        try {
            ProtectionOverride overrider{m_replace_ptr, sizeof(void*), PAGE_EXECUTE_READWRITE};
            *m_replace_ptr = m_destination;
        } catch (std::exception& e) {
            SPDLOG_ERROR("PointerHook: {}", e.what());
            return false;
        }
    }

    return true;
}

ProtectionOverride::ProtectionOverride(void* address, size_t size, uint32_t protection)
    : m_address{address},
    m_size{size}
{
    if (!VirtualProtect(address, size, protection, (DWORD*)&m_old)) {
        SPDLOG_ERROR("PointerHook: VirtualProtect failed ({:x})", (uintptr_t)address);
        throw std::runtime_error("VirtualProtect failed");
    }
}

ProtectionOverride::~ProtectionOverride() {
    VirtualProtect(m_address, m_size, m_old, (DWORD*)&m_old);
}
