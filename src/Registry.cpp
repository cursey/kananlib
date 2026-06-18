#include <string>

#include <utility/Logging.hpp>

#include <utility/Registry.hpp>

namespace utility {
std::optional<uint32_t> get_registry_dword(HKEY key, std::string_view subkey, std::string_view value) {
    HKEY subkey_handle{};

    // RegOpenKeyExA / RegQueryValueExA require null-terminated C strings, but a
    // string_view's data() is not guaranteed to be null-terminated. Copy into
    // owned std::strings so the Reg* APIs never read past the view's length.
    const std::string subkey_str{subkey};
    const std::string value_str{value};

    if (auto res = RegOpenKeyExA(key, subkey_str.c_str(), 0, KEY_QUERY_VALUE, &subkey_handle); res != ERROR_SUCCESS) {
        SPDLOG_ERROR("({}) Failed to open registry key {}", res, subkey);
        return std::nullopt;
    }

    DWORD type{};
    DWORD size{};

    if (auto res = RegQueryValueExA(subkey_handle, value_str.c_str(), nullptr, &type, nullptr, &size); res != ERROR_SUCCESS) {
        SPDLOG_ERROR("({}) Failed to query registry value {}", res, value);
        RegCloseKey(subkey_handle);
        return std::nullopt;
    }

    if (type != REG_DWORD) {
        SPDLOG_ERROR("Registry value is not of type REG_DWORD: {}", value);
        RegCloseKey(subkey_handle);
        return std::nullopt;
    }

    DWORD result{};

    if (auto res = RegQueryValueExA(subkey_handle, value_str.c_str(), nullptr, nullptr, (LPBYTE)&result, &size); res != ERROR_SUCCESS) {
        SPDLOG_ERROR("({}) Failed to query registry value 2 {}", res, value);
        RegCloseKey(subkey_handle);
        return std::nullopt;
    }

    RegCloseKey(subkey_handle);
    return result;
}
}