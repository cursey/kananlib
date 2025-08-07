#include <unordered_map>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <map>
#include <spdlog/spdlog.h>

#include <Windows.h>
#include <urlmon.h>

#ifdef KANANLIB_USE_DIA_SDK
#include <comdef.h>
#include <atlbase.h>
#include <dia2.h>
#pragma comment(lib, "diaguids.lib")
#endif

#include <utility/PDB.hpp>
#include <utility/String.hpp>
#include <utility/Module.hpp>

#pragma comment(lib, "urlmon.lib")

namespace utility::pdb {
std::unordered_map<std::string, std::string> pdb_cache{}; // module path -> local pdb path after download
std::unordered_map<size_t, std::unordered_map<std::string, uintptr_t>> symbol_cache{}; // module hash -> symbol -> address

std::string get_temp_folder() {
    static std::string temp_folder;
    if (temp_folder.empty()) {
        char buffer[MAX_PATH];
        if (GetTempPathA(MAX_PATH, buffer)) {
            temp_folder = buffer;
        }
    }
    return temp_folder;
}

bool file_exists(const std::string& path) {
    return GetFileAttributesA(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

std::string guid_to_string(const GUID& guid, uint32_t age) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(8) << std::hex << std::uppercase 
        << guid.Data1 
        << std::setw(4) << guid.Data2 
        << std::setw(4) << guid.Data3;
    
    for (const auto byte : guid.Data4) {
        ss << std::setw(2) << static_cast<unsigned>(byte);
    }
    
    ss << std::setw(1) << age;
    return ss.str();
}

void ensure_com_initialized() {
#ifdef KANANLIB_USE_DIA_SDK
    static bool initialized = false;
    if (!initialized) {
        CoInitialize(nullptr);
        initialized = true;
    }
#endif
}

std::optional<std::string> get_pdb_path(const uint8_t* module) {
    if (module == nullptr) {
        SPDLOG_ERROR("get_pdb_path: module pointer is null");
        return std::nullopt;
    }

    const auto module_within = utility::get_module_within((uintptr_t)module).value_or(nullptr);
    const auto is_memory_module = module_within != nullptr && module_within == (HMODULE)module;

    // get dos header
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        SPDLOG_ERROR("Invalid DOS header signature");
        return std::nullopt;
    }

    // get nt headers
    auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(module + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        SPDLOG_ERROR("Invalid NT headers signature");
        return std::nullopt;
    }

    // get debug directory
    auto debug_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (debug_directory.VirtualAddress == 0 || debug_directory.Size == 0) {
        SPDLOG_ERROR("No debug directory found");
        return std::nullopt;
    }

    auto debug_data = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(is_memory_module ? module + debug_directory.VirtualAddress : (uint8_t*)utility::ptr_from_rva(module, debug_directory.VirtualAddress).value_or(0));
    auto num_entries = debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    
    for (size_t i = 0; i < num_entries; ++i) {
        if (debug_data[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) {
            continue;
        }

        // get codeview data - use AddressOfRawData for memory-mapped modules
        auto codeview_data = reinterpret_cast<const uint8_t*>(module + (is_memory_module ? debug_data[i].AddressOfRawData : debug_data[i].PointerToRawData));
        auto signature = *reinterpret_cast<const uint32_t*>(codeview_data);
        
        if (signature != 0x53445352) { // 'RSDS'
            SPDLOG_ERROR("Invalid CodeView signature: 0x{:08X}", signature);
            continue;
        }

        // extract PDB info
        auto guid = *reinterpret_cast<const GUID*>(codeview_data + 4);
        auto age = *reinterpret_cast<const uint32_t*>(codeview_data + 20);
        auto pdb_filename = reinterpret_cast<const char*>(codeview_data + 24);

        // create cache key from module pointer
        std::stringstream cache_key_ss;
        cache_key_ss << std::hex << reinterpret_cast<uintptr_t>(module);
        std::string cache_key = cache_key_ss.str();
        
        // check if we've already resolved this
        if (auto it = pdb_cache.find(cache_key); it != pdb_cache.end()) {
            return it->second;
        }

        // check if PDB exists at original path
        if (file_exists(pdb_filename)) {
            pdb_cache[cache_key] = pdb_filename;
            return pdb_filename;
        }

        // construct symbol server path structure
        std::string temp_folder = get_temp_folder();
        std::string guid_age_str = guid_to_string(guid, age);
        
        std::filesystem::path pdb_dir = std::filesystem::path(temp_folder) / 
                                       std::filesystem::path(pdb_filename).filename().string() / 
                                       guid_age_str;
        
        std::filesystem::path local_pdb_path = pdb_dir / std::filesystem::path(pdb_filename).filename();

        // check if we've already downloaded it
        if (file_exists(local_pdb_path.string())) {
            pdb_cache[cache_key] = local_pdb_path.string();
            return local_pdb_path.string();
        }

        // create directories
        std::error_code ec;
        std::filesystem::create_directories(pdb_dir, ec);
        if (ec) {
            SPDLOG_ERROR("Failed to create directory {}: {}", pdb_dir.string(), ec.message());
            continue;
        }

        // download from symbol server
        std::string symbol_url = "http://msdl.microsoft.com/download/symbols/" + 
                                std::filesystem::path(pdb_filename).filename().string() + "/" +
                                guid_age_str + "/" +
                                std::filesystem::path(pdb_filename).filename().string();

        SPDLOG_INFO("Downloading PDB from: {}", symbol_url);
        
        HRESULT hr = URLDownloadToFileA(nullptr, 
                                       symbol_url.c_str(), 
                                       local_pdb_path.string().c_str(), 
                                       0, 
                                       nullptr);

        if (SUCCEEDED(hr) && file_exists(local_pdb_path.string())) {
            SPDLOG_INFO("Successfully downloaded PDB to: {}", local_pdb_path.string());
            pdb_cache[cache_key] = local_pdb_path.string();
            return local_pdb_path.string();
        } else {
            SPDLOG_ERROR("Failed to download PDB from symbol server (HRESULT: 0x{:08X})", hr);
        }
    }

    return std::nullopt;
}

std::optional<uintptr_t> get_symbol_address(const uint8_t* module, std::string_view symbol_name) {
    if (module == nullptr) {
        SPDLOG_ERROR("Invalid module pointer");
        return std::nullopt;
    }

#ifdef KANANLIB_USE_DIA_SDK
    ensure_com_initialized();

    // Create cache key from hash of module data
    // get size of headers
    auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        SPDLOG_ERROR("Invalid DOS header signature");
        return std::nullopt;
    }

    // get nt headers
    auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(module + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        SPDLOG_ERROR("Invalid NT header signature");
        return std::nullopt;
    }

    // get size of headers
    const auto end_of_nt_headers = reinterpret_cast<const uint8_t*>(nt_headers) + sizeof(IMAGE_NT_HEADERS);
    const auto module_header_size = end_of_nt_headers - module;
    const auto module_key = utility::hash(module, (size_t)module_header_size);

    // Check if we've already resolved this symbol for this module
    if (auto module_it = symbol_cache.find(module_key); module_it != symbol_cache.end()) {
        if (auto symbol_it = module_it->second.find(std::string(symbol_name)); symbol_it != module_it->second.end()) {
            SPDLOG_INFO("Found cached symbol '{}' at address: 0x{:08X}", symbol_name, symbol_it->second);
            return symbol_it->second;
        }
    }

    // get PDB path
    auto pdb_path_opt = get_pdb_path(module);
    if (!pdb_path_opt) {
        SPDLOG_ERROR("Failed to get PDB path for module");
        return std::nullopt;
    }

    std::string pdb_path = *pdb_path_opt;
    
    // construct symbol info cache file path
    std::filesystem::path pdb_file_path(pdb_path);

    // load PDB using DIA SDK
    CComPtr<IDiaDataSource> data_source;
    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&data_source);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to create DIA data source (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    // convert path to wide string
    std::wstring wide_pdb_path = utility::widen(pdb_path);
    hr = data_source->loadDataFromPdb(wide_pdb_path.c_str());
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to load PDB file: {} (HRESULT: 0x{:08X})", pdb_path, hr);
        return std::nullopt;
    }

    CComPtr<IDiaSession> session;
    hr = data_source->openSession(&session);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to open DIA session (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    CComPtr<IDiaSymbol> global_scope;
    hr = session->get_globalScope(&global_scope);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to get global scope (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    // convert symbol name to wide string
    std::wstring wide_symbol_name = utility::widen(symbol_name);
    
    CComPtr<IDiaEnumSymbols> enum_symbols;
    hr = global_scope->findChildren(SymTagNull, wide_symbol_name.c_str(), nsNone, &enum_symbols);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to find symbols (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    // Check if we got any symbols
    LONG symbol_count = 0;
    if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
        SPDLOG_INFO("Found {} symbols matching '{}'", symbol_count, symbol_name);
    } else {
        SPDLOG_WARN("Could not get symbol count for '{}'", symbol_name);
    }

    if (symbol_count == 0) {
        // Try different search strategies
        SPDLOG_INFO("No exact matches found, trying case-insensitive search for '{}'", symbol_name);
        
        enum_symbols.Release();
        hr = global_scope->findChildren(SymTagNull, wide_symbol_name.c_str(), nsCaseInsensitive, &enum_symbols);
        if (SUCCEEDED(hr)) {
            if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
                SPDLOG_INFO("Case-insensitive search found {} symbols", symbol_count);
            }
        }

        if (symbol_count == 0) {
            SPDLOG_INFO("Trying regex search for '{}'", symbol_name);
            enum_symbols.Release();
            hr = global_scope->findChildren(SymTagNull, wide_symbol_name.c_str(), nsRegularExpression, &enum_symbols);
            if (SUCCEEDED(hr)) {
                if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
                    SPDLOG_INFO("Regex search found {} symbols", symbol_count);
                }
            }
        }
    }

    CComPtr<IDiaSymbol> symbol;
    ULONG celt = 0;

    SPDLOG_INFO("Enumerating symbols for '{}'...", symbol_name);
    
    while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1) {
        DWORD sym_tag = 0;
        BSTR name = nullptr;
        DWORD rva = 0;
        
        // Get symbol information for debugging
        if (SUCCEEDED(symbol->get_symTag(&sym_tag))) {
            SPDLOG_DEBUG("Found symbol with tag: {}", sym_tag);
        }
        
        if (SUCCEEDED(symbol->get_name(&name)) && name) {
            std::wstring symbol_name_found(name);
            std::string narrow_name = utility::narrow(symbol_name_found);
            SPDLOG_DEBUG("Symbol name: '{}'", narrow_name);
            SysFreeString(name);
        }
        
        hr = symbol->get_relativeVirtualAddress(&rva);
        SPDLOG_DEBUG("Symbol RVA query result: HRESULT=0x{:08X}, RVA=0x{:08X}", hr, rva);

        if (SUCCEEDED(hr) && rva != 0) {
            // cache the result
            uintptr_t address = static_cast<uintptr_t>(rva);
            symbol_cache[module_key][std::string(symbol_name)] = address;
            
            SPDLOG_INFO("Found symbol '{}' at RVA: 0x{:08X}", symbol_name, address);
            return address;
        }
        
        symbol.Release();
    }

    // If we didn't find anything, try searching specifically for functions
    if (symbol_count == 0) {
        SPDLOG_INFO("Trying function-specific search for '{}'", symbol_name);
        enum_symbols.Release();
        hr = global_scope->findChildren(SymTagFunction, wide_symbol_name.c_str(), nsCaseInsensitive, &enum_symbols);
        if (SUCCEEDED(hr)) {
            if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
                SPDLOG_INFO("Function search found {} symbols", symbol_count);
            }
            
            while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1) {
                DWORD rva = 0;
                hr = symbol->get_relativeVirtualAddress(&rva);

                if (SUCCEEDED(hr) && rva != 0) {
                    uintptr_t address = static_cast<uintptr_t>(rva);
                    symbol_cache[module_key][std::string(symbol_name)] = address;
                    
                    SPDLOG_INFO("Found function symbol '{}' at RVA: 0x{:08X}", symbol_name, address);
                    return address;
                }
                
                symbol.Release();
            }
        }
    }

    // Try searching for public symbols (exports)
    if (symbol_count == 0) {
        SPDLOG_INFO("Trying public symbol search for '{}'", symbol_name);
        enum_symbols.Release();
        hr = global_scope->findChildren(SymTagPublicSymbol, wide_symbol_name.c_str(), nsCaseInsensitive, &enum_symbols);
        if (SUCCEEDED(hr)) {
            if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
                SPDLOG_INFO("Public symbol search found {} symbols", symbol_count);
            }
            
            while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1) {
                DWORD rva = 0;
                hr = symbol->get_relativeVirtualAddress(&rva);

                if (SUCCEEDED(hr) && rva != 0) {
                    uintptr_t address = static_cast<uintptr_t>(rva);
                    symbol_cache[module_key][std::string(symbol_name)] = address;
                    
                    SPDLOG_INFO("Found public symbol '{}' at RVA: 0x{:08X}", symbol_name, address);
                    return address;
                }
                
                symbol.Release();
            }
        }
    }

    // Try wildcard search for partial matches
    if (symbol_count == 0) {
        std::string wildcard_pattern = "*" + std::string(symbol_name) + "*";
        std::wstring wide_wildcard = utility::widen(wildcard_pattern);
        
        SPDLOG_INFO("Trying wildcard search for '{}'", wildcard_pattern);
        enum_symbols.Release();
        hr = global_scope->findChildren(SymTagNull, wide_wildcard.c_str(), nsRegularExpression, &enum_symbols);
        if (SUCCEEDED(hr)) {
            if (SUCCEEDED(enum_symbols->get_Count(&symbol_count))) {
                SPDLOG_INFO("Wildcard search found {} symbols", symbol_count);
            }
            
            // Show the first few matches for debugging
            size_t matches_shown = 0;
            while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1 && matches_shown < 5) {
                BSTR name = nullptr;
                DWORD rva = 0;
                
                if (SUCCEEDED(symbol->get_name(&name)) && name) {
                    std::wstring symbol_name_found(name);
                    std::string narrow_name = utility::narrow(symbol_name_found);
                    
                    if (SUCCEEDED(symbol->get_relativeVirtualAddress(&rva)) && rva != 0) {
                        SPDLOG_INFO("Found similar symbol: '{}' at RVA: 0x{:08X}", narrow_name, rva);
                        
                        // If it's an exact match after transformation, use it
                        if (narrow_name == symbol_name) {
                            uintptr_t address = static_cast<uintptr_t>(rva);
                            symbol_cache[module_key][std::string(symbol_name)] = address;
                            
                            SysFreeString(name);
                            SPDLOG_INFO("Found exact match in wildcard search: '{}' at RVA: 0x{:08X}", symbol_name, address);
                            return address;
                        }
                    }
                    
                    SysFreeString(name);
                    matches_shown++;
                }
                
                symbol.Release();
            }
        }
    }

    SPDLOG_ERROR("Symbol '{}' not found in PDB", symbol_name);
    return std::nullopt;
#else
    // Fallback implementation without DIA SDK
    SPDLOG_ERROR("Symbol resolution not supported: kananlib was compiled without DIA SDK support");
    SPDLOG_INFO("To enable symbol resolution, define KANANLIB_USE_DIA_SDK and ensure DIA SDK is available");
    return std::nullopt;
#endif
}

std::vector<std::string> enumerate_symbols(const uint8_t* module, size_t max_symbols) {
    std::vector<std::string> symbols;
    
    if (module == nullptr) {
        SPDLOG_ERROR("Invalid module pointer");
        return symbols;
    }

#ifdef KANANLIB_USE_DIA_SDK
    ensure_com_initialized();

    // get PDB path
    auto pdb_path_opt = get_pdb_path(module);
    if (!pdb_path_opt) {
        SPDLOG_ERROR("Failed to get PDB path for module");
        return symbols;
    }

    std::string pdb_path = *pdb_path_opt;

    // load PDB using DIA SDK
    CComPtr<IDiaDataSource> data_source;
    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&data_source);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to create DIA data source (HRESULT: 0x{:08X})", hr);
        return symbols;
    }

    // convert path to wide string
    std::wstring wide_pdb_path = utility::widen(pdb_path);
    hr = data_source->loadDataFromPdb(wide_pdb_path.c_str());
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to load PDB file: {} (HRESULT: 0x{:08X})", pdb_path, hr);
        return symbols;
    }

    CComPtr<IDiaSession> session;
    hr = data_source->openSession(&session);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to open DIA session (HRESULT: 0x{:08X})", hr);
        return symbols;
    }

    CComPtr<IDiaSymbol> global_scope;
    hr = session->get_globalScope(&global_scope);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to get global scope (HRESULT: 0x{:08X})", hr);
        return symbols;
    }

    // Enumerate all children (functions, data, etc.)
    CComPtr<IDiaEnumSymbols> enum_symbols;
    hr = global_scope->findChildren(SymTagNull, NULL, nsNone, &enum_symbols);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to enumerate symbols (HRESULT: 0x{:08X})", hr);
        return symbols;
    }

    CComPtr<IDiaSymbol> symbol;
    ULONG celt = 0;
    size_t count = 0;

    SPDLOG_INFO("Enumerating up to {} symbols from PDB...", max_symbols);

    while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1 && count < max_symbols) {
        BSTR name = nullptr;
        DWORD sym_tag = 0;
        DWORD rva = 0;
        
        if (SUCCEEDED(symbol->get_name(&name)) && name) {
            if (SUCCEEDED(symbol->get_symTag(&sym_tag)) && 
                SUCCEEDED(symbol->get_relativeVirtualAddress(&rva)) && rva != 0) {
                
                std::wstring symbol_name_found(name);
                std::string narrow_name = utility::narrow(symbol_name_found);
                
                // Add symbol with its type information
                std::string symbol_info = narrow_name;
                switch (sym_tag) {
                    case SymTagFunction:
                        symbol_info += " (function)";
                        break;
                    case SymTagData:
                        symbol_info += " (data)";
                        break;
                    case SymTagPublicSymbol:
                        symbol_info += " (public)";
                        break;
                    default:
                        symbol_info += " (tag:" + std::to_string(sym_tag) + ")";
                        break;
                }
                
                symbols.push_back(symbol_info);
                count++;
            }
            SysFreeString(name);
        }
        
        symbol.Release();
    }

    SPDLOG_INFO("Found {} symbols in PDB", symbols.size());
    
    // Also try to enumerate public symbols specifically
    if (symbols.size() < max_symbols / 2) {
        SPDLOG_INFO("Also enumerating public symbols...");
        enum_symbols.Release();
        hr = global_scope->findChildren(SymTagPublicSymbol, NULL, nsNone, &enum_symbols);
        if (SUCCEEDED(hr)) {
            while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1 && count < max_symbols) {
                BSTR name = nullptr;
                DWORD rva = 0;
                
                if (SUCCEEDED(symbol->get_name(&name)) && name &&
                    SUCCEEDED(symbol->get_relativeVirtualAddress(&rva)) && rva != 0) {
                    
                    std::wstring symbol_name_found(name);
                    std::string narrow_name = utility::narrow(symbol_name_found);
                    std::string symbol_info = narrow_name + " (public symbol)";
                    
                    symbols.push_back(symbol_info);
                    count++;
                    
                    SysFreeString(name);
                }
                
                symbol.Release();
            }
        }
    }

#else
    SPDLOG_ERROR("Symbol enumeration not supported: kananlib was compiled without DIA SDK support");
#endif

    return symbols;
}

std::optional<StructInfo> get_struct_info(const uint8_t* module, std::string_view struct_name) {
    if (module == nullptr) {
        SPDLOG_ERROR("Invalid module pointer");
        return std::nullopt;
    }

#ifdef KANANLIB_USE_DIA_SDK
    ensure_com_initialized();

    // get PDB path
    auto pdb_path_opt = get_pdb_path(module);
    if (!pdb_path_opt) {
        SPDLOG_ERROR("Failed to get PDB path for module");
        return std::nullopt;
    }

    std::string pdb_path = *pdb_path_opt;

    // load PDB using DIA SDK
    CComPtr<IDiaDataSource> data_source;
    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&data_source);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to create DIA data source (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    std::wstring wide_pdb_path = utility::widen(pdb_path);
    hr = data_source->loadDataFromPdb(wide_pdb_path.c_str());
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to load PDB file: {} (HRESULT: 0x{:08X})", pdb_path, hr);
        return std::nullopt;
    }

    CComPtr<IDiaSession> session;
    hr = data_source->openSession(&session);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to open DIA session (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    CComPtr<IDiaSymbol> global_scope;
    hr = session->get_globalScope(&global_scope);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to get global scope (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    // Search for the structure
    std::wstring wide_struct_name = utility::widen(struct_name);
    CComPtr<IDiaEnumSymbols> enum_symbols;
    hr = global_scope->findChildren(SymTagUDT, wide_struct_name.c_str(), nsCaseInsensitive, &enum_symbols);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to find UDT symbols (HRESULT: 0x{:08X})", hr);
        return std::nullopt;
    }

    CComPtr<IDiaSymbol> struct_symbol;
    ULONG celt = 0;
    
    if (FAILED(enum_symbols->Next(1, &struct_symbol, &celt)) || celt != 1) {
        SPDLOG_ERROR("Structure '{}' not found in PDB", struct_name);
        return std::nullopt;
    }

    StructInfo struct_info;
    struct_info.name = std::string(struct_name);

    // Get structure size
    ULONGLONG struct_size = 0;
    if (SUCCEEDED(struct_symbol->get_length(&struct_size))) {
        struct_info.size = static_cast<uint32_t>(struct_size);
    }

    SPDLOG_INFO("Found structure '{}' with size {} bytes", struct_name, struct_info.size);

    // Enumerate structure members
    CComPtr<IDiaEnumSymbols> enum_members;
    hr = struct_symbol->findChildren(SymTagData, NULL, nsNone, &enum_members);
    if (SUCCEEDED(hr)) {
        CComPtr<IDiaSymbol> member_symbol;
        ULONG member_celt = 0;
        
        while (SUCCEEDED(enum_members->Next(1, &member_symbol, &member_celt)) && member_celt == 1) {
            StructMember member;
            
            // Initialize all flags explicitly to avoid garbage values
            member.is_pointer = false;
            member.is_array = false;
            member.array_count = 0;
            member.is_bitfield = false;
            member.bit_position = 0;
            member.bit_length = 0;
            
            // Get member name
            BSTR member_name = nullptr;
            if (SUCCEEDED(member_symbol->get_name(&member_name)) && member_name) {
                member.name = utility::narrow(std::wstring(member_name));
                SysFreeString(member_name);
            }

            // Get member offset
            LONG member_offset = 0;
            if (SUCCEEDED(member_symbol->get_offset(&member_offset))) {
                member.offset = static_cast<uint32_t>(member_offset);
            }

            // Get member type information
            CComPtr<IDiaSymbol> type_symbol;
            if (SUCCEEDED(member_symbol->get_type(&type_symbol))) {
                BSTR type_name = nullptr;
                ULONGLONG type_size = 0;
                DWORD type_tag = 0;
                
                // Get basic type information first
                type_symbol->get_length(&type_size);
                member.size = static_cast<uint32_t>(type_size);
                
                // Get the type tag to determine what kind of type this is
                type_symbol->get_symTag(&type_tag);
                
                SPDLOG_DEBUG("Member '{}': type_tag={}, size={}", member.name, type_tag, type_size);
                
                if (type_tag == SymTagPointerType) {
                    // This is a pointer type - ONLY set pointer flag, leave array flag false
                    member.is_pointer = true;
                    member.is_array = false;
                    
                    // Get the pointed-to type
                    CComPtr<IDiaSymbol> pointed_type;
                    if (SUCCEEDED(type_symbol->get_type(&pointed_type))) {
                        BSTR pointed_type_name = nullptr;
                        if (SUCCEEDED(pointed_type->get_name(&pointed_type_name)) && pointed_type_name) {
                            member.type = utility::narrow(std::wstring(pointed_type_name));
                            SysFreeString(pointed_type_name);
                        } else {
                            member.type = "void"; // fallback for unnamed pointed type
                        }
                    } else {
                        member.type = "void";
                    }
                } else if (type_tag == SymTagArrayType) {
                    // This is an array type - ONLY set array flag, leave pointer flag false
                    member.is_pointer = false;
                    member.is_array = true;
                    
                    // Get array count
                    DWORD array_count = 0;
                    if (SUCCEEDED(type_symbol->get_count(&array_count))) {
                        member.array_count = array_count;
                    }
                    
                    // Get the array element type
                    CComPtr<IDiaSymbol> element_type;
                    if (SUCCEEDED(type_symbol->get_type(&element_type))) {
                        BSTR element_type_name = nullptr;
                        if (SUCCEEDED(element_type->get_name(&element_type_name)) && element_type_name) {
                            member.type = utility::narrow(std::wstring(element_type_name));
                            SysFreeString(element_type_name);
                        } else {
                            // Try to resolve element type by base type
                            DWORD element_base_type = 0;
                            ULONGLONG element_length = 0;
                            element_type->get_length(&element_length);
                            
                            if (SUCCEEDED(element_type->get_baseType(&element_base_type))) {
                                switch (element_base_type) {
                                    case btUInt:
                                        switch (element_length) {
                                            case 1: member.type = "unsigned __int8"; break;
                                            case 2: member.type = "unsigned __int16"; break;
                                            case 4: member.type = "unsigned __int32"; break;
                                            case 8: member.type = "unsigned __int64"; break;
                                            default: member.type = "unsigned int"; break;
                                        }
                                        break;
                                    case btInt:
                                        switch (element_length) {
                                            case 1: member.type = "__int8"; break;
                                            case 2: member.type = "__int16"; break;
                                            case 4: member.type = "__int32"; break;
                                            case 8: member.type = "__int64"; break;
                                            default: member.type = "int"; break;
                                        }
                                        break;
                                    case btChar: member.type = "char"; break;
                                    default: member.type = "unsigned __int8"; break;
                                }
                            } else {
                                member.type = "unsigned __int8";
                            }
                        }
                    }
                } else {
                    // Regular type (struct, union, basic type, etc.) - NOT a pointer or array
                    member.is_pointer = false;
                    member.is_array = false;
                    
                    // Try to get the type name first
                    if (SUCCEEDED(type_symbol->get_name(&type_name)) && type_name) {
                        member.type = utility::narrow(std::wstring(type_name));
                        SysFreeString(type_name);
                    } else {
                        // If no type name, try to resolve by base type
                        DWORD base_type = 0;
                        if (SUCCEEDED(type_symbol->get_baseType(&base_type))) {
                            switch (base_type) {
                                case btUInt: 
                                    switch (type_size) {
                                        case 1: member.type = "unsigned __int8"; break;
                                        case 2: member.type = "unsigned __int16"; break;
                                        case 4: member.type = "unsigned __int32"; break;
                                        case 8: member.type = "unsigned __int64"; break;
                                        default: member.type = "unsigned int"; break;
                                    }
                                    break;
                                case btInt:
                                    switch (type_size) {
                                        case 1: member.type = "__int8"; break;
                                        case 2: member.type = "__int16"; break;
                                        case 4: member.type = "__int32"; break;
                                        case 8: member.type = "__int64"; break;
                                        default: member.type = "int"; break;
                                    }
                                    break;
                                case btChar: member.type = "char"; break;
                                case btWChar: member.type = "wchar_t"; break;
                                case btFloat: member.type = (type_size == 4) ? "float" : "double"; break;
                                case btBool: member.type = "bool"; break;
                                case btVoid: member.type = "void"; break;
                                case btLong: member.type = (type_size == 4) ? "long" : "__int64"; break;
                                case btULong: member.type = (type_size == 4) ? "unsigned long" : "unsigned __int64"; break;
                                default: 
                                    // Unknown base type, use size-based fallback
                                    switch (type_size) {
                                        case 1: member.type = "UCHAR"; break;
                                        case 2: member.type = "USHORT"; break;
                                        case 4: member.type = "ULONG"; break;
                                        case 8: member.type = "ULONGLONG"; break;
                                        default: member.type = "UNKNOWN_TYPE_" + std::to_string(type_size); break;
                                    }
                                    break;
                            }
                        } else {
                            // No base type, use size-based fallback
                            switch (type_size) {
                                case 1: member.type = "UCHAR"; break;
                                case 2: member.type = "USHORT"; break;
                                case 4: member.type = "ULONG"; break;
                                case 8: member.type = "ULONGLONG"; break;
                                default: member.type = "UNKNOWN_TYPE_" + std::to_string(type_size); break;
                            }
                        }
                    }
                }
            }

            // Check for bitfield information
            DWORD bit_position = 0;
            ULONGLONG bit_length = 0;
            bool is_bitfield = false;
            
            // A member is a bitfield if:
            // 1. We can get bit position and length successfully
            // 2. The bit length is > 0 and < size * 8 (not the full storage unit)
            // 3. OR if bit_position > 0 (indicating it starts mid-byte)
            if (SUCCEEDED(member_symbol->get_bitPosition(&bit_position)) &&
                SUCCEEDED(member_symbol->get_length(&bit_length))) {
                
                if (bit_length > 0 && (bit_length < member.size * 8 || bit_position > 0)) {
                    is_bitfield = true;
                }
            }

            if (is_bitfield) {
                SPDLOG_DEBUG("Bitfield Member: {} {} at offset 0x{:X}.{} (bit length: {}, size: {})", 
                            member.type, member.name, member.offset, bit_position, bit_length, member.size);
                
                // Store bitfield information in the member
                member.is_bitfield = true;
                member.bit_position = bit_position;
                member.bit_length = static_cast<uint32_t>(bit_length);
            } else {
                SPDLOG_DEBUG("Member: {} {} at offset 0x{:X} (size: {})", 
                            member.type, member.name, member.offset, member.size);
            }
            
            struct_info.members.push_back(member);
            member_symbol.Release();
        }
    }

    return struct_info;
#else
    SPDLOG_ERROR("Structure analysis not supported: kananlib was compiled without DIA SDK support");
    return std::nullopt;
#endif
}

std::vector<std::string> enumerate_structs(const uint8_t* module, size_t max_structs) {
    std::vector<std::string> structs;
    
    if (module == nullptr) {
        SPDLOG_ERROR("Invalid module pointer");
        return structs;
    }

#ifdef KANANLIB_USE_DIA_SDK
    ensure_com_initialized();

    // get PDB path
    auto pdb_path_opt = get_pdb_path(module);
    if (!pdb_path_opt) {
        SPDLOG_ERROR("Failed to get PDB path for module");
        return structs;
    }

    std::string pdb_path = *pdb_path_opt;

    // load PDB using DIA SDK
    CComPtr<IDiaDataSource> data_source;
    HRESULT hr = CoCreateInstance(CLSID_DiaSource, NULL, CLSCTX_INPROC_SERVER, __uuidof(IDiaDataSource), (void**)&data_source);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to create DIA data source (HRESULT: 0x{:08X})", hr);
        return structs;
    }

    std::wstring wide_pdb_path = utility::widen(pdb_path);
    hr = data_source->loadDataFromPdb(wide_pdb_path.c_str());
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to load PDB file: {} (HRESULT: 0x{:08X})", pdb_path, hr);
        return structs;
    }

    CComPtr<IDiaSession> session;
    hr = data_source->openSession(&session);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to open DIA session (HRESULT: 0x{:08X})", hr);
        return structs;
    }

    CComPtr<IDiaSymbol> global_scope;
    hr = session->get_globalScope(&global_scope);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to get global scope (HRESULT: 0x{:08X})", hr);
        return structs;
    }

    // Enumerate all UDT (User Defined Types) symbols
    CComPtr<IDiaEnumSymbols> enum_symbols;
    hr = global_scope->findChildren(SymTagUDT, NULL, nsNone, &enum_symbols);
    if (FAILED(hr)) {
        SPDLOG_ERROR("Failed to enumerate UDT symbols (HRESULT: 0x{:08X})", hr);
        return structs;
    }

    // Check total count of UDT symbols
    LONG total_udt_count = 0;
    if (SUCCEEDED(enum_symbols->get_Count(&total_udt_count))) {
        SPDLOG_INFO("Total UDT symbols found in PDB: {}", total_udt_count);
    } else {
        SPDLOG_WARN("Could not get UDT symbol count");
    }

    CComPtr<IDiaSymbol> symbol;
    ULONG celt = 0;
    size_t count = 0;

    SPDLOG_INFO("Enumerating up to {} structures from PDB...", max_structs);

    while (SUCCEEDED(enum_symbols->Next(1, &symbol, &celt)) && celt == 1 && count < max_structs) {
        BSTR name = nullptr;
        ULONGLONG struct_size = 0;
        DWORD udt_kind = 0;
        
        if (SUCCEEDED(symbol->get_name(&name)) && name &&
            SUCCEEDED(symbol->get_length(&struct_size)) &&
            SUCCEEDED(symbol->get_udtKind(&udt_kind))) {
            
            std::wstring struct_name_found(name);
            std::string narrow_name = utility::narrow(struct_name_found);

            structs.push_back(narrow_name);
            count++;
            
            SysFreeString(name);
        }
        
        symbol.Release();
    }

    SPDLOG_INFO("Found {} structures in PDB", structs.size());
    
    // If we didn't find any structures, let's see what other symbol types are available
    if (structs.empty()) {
        SPDLOG_WARN("No UDT structures found. Checking what symbol types are available...");
        
        // Try to enumerate all symbol types to see what's available
        CComPtr<IDiaEnumSymbols> all_symbols;
        hr = global_scope->findChildren(SymTagNull, NULL, nsNone, &all_symbols);
        if (SUCCEEDED(hr)) {
            LONG total_symbols = 0;
            if (SUCCEEDED(all_symbols->get_Count(&total_symbols))) {
                SPDLOG_INFO("Total symbols of all types: {}", total_symbols);
            }
            
            // Sample first few symbols to see their types
            CComPtr<IDiaSymbol> sample_symbol;
            ULONG sample_celt = 0;
            size_t samples_checked = 0;
            std::map<DWORD, int> symbol_type_counts;
            
            while (SUCCEEDED(all_symbols->Next(1, &sample_symbol, &sample_celt)) && 
                   sample_celt == 1 && samples_checked < 100) {
                DWORD sym_tag = 0;
                if (SUCCEEDED(sample_symbol->get_symTag(&sym_tag))) {
                    symbol_type_counts[sym_tag]++;
                }
                sample_symbol.Release();
                samples_checked++;
            }
            
            SPDLOG_INFO("Symbol type distribution (first 100 symbols):");
            for (const auto& [tag, count] : symbol_type_counts) {
                std::string tag_name;
                switch (tag) {
                    case SymTagFunction: tag_name = "Function"; break;
                    case SymTagData: tag_name = "Data"; break;
                    case SymTagPublicSymbol: tag_name = "PublicSymbol"; break;
                    case SymTagUDT: tag_name = "UDT"; break;
                    case SymTagEnum: tag_name = "Enum"; break;
                    case SymTagTypedef: tag_name = "Typedef"; break;
                    default: tag_name = "Tag" + std::to_string(tag); break;
                }
                SPDLOG_INFO("  {}: {}", tag_name, count);
            }
        }
    }
#else
    SPDLOG_ERROR("Structure enumeration not supported: kananlib was compiled without DIA SDK support");
#endif

    return structs;
}

std::string generate_c_struct(const StructInfo& struct_info) {
    std::stringstream ss;
    
    ss << "typedef struct {\n";
    
    // Sort members by offset to ensure correct order
    auto sorted_members = struct_info.members;
    std::sort(sorted_members.begin(), sorted_members.end(), 
              [](const StructMember& a, const StructMember& b) {
                  return a.offset < b.offset;
              });
    
    uint32_t current_offset = 0;
    uint32_t current_bitfield_offset = UINT32_MAX; // Track current bitfield group
    
    for (const auto& member : sorted_members) {
        // Handle bitfields specially
        if (member.is_bitfield && member.bit_length > 0) {
            // If this is a new bitfield group (different offset), add padding if needed
            if (member.offset != current_bitfield_offset) {
                // Add padding if there's a gap before this bitfield
                if (member.offset > current_offset) {
                    uint32_t padding_size = member.offset - current_offset;
                    ss << "    char _padding_0x" << std::hex << current_offset 
                       << "[0x" << std::hex << padding_size << "]; // Padding\n";
                }
                current_bitfield_offset = member.offset;
            }
            
            // Generate bitfield member
            ss << "    ";
            
            // Handle type
            std::string type_str = member.type;
            if (type_str.empty()) {
                type_str = "unsigned __int32"; // default for bitfields
            }
            
            ss << type_str << " " << member.name << " : " << std::dec << member.bit_length;
            ss << "; // 0x" << std::hex << member.offset << "." << std::dec << member.bit_position;
            ss << " (bit length: " << member.bit_length << ")\n";
            
            // Update current_offset to the end of this bitfield's storage unit
            current_offset = member.offset + member.size;
        } else {
            // Handle regular (non-bitfield) members
            
            // Add padding if there's a gap
            if (member.offset > current_offset) {
                uint32_t padding_size = member.offset - current_offset;
                ss << "    char _padding_0x" << std::hex << current_offset 
                   << "[0x" << std::hex << padding_size << "]; // Padding\n";
            }
            
            // Add member
            ss << "    ";
            
            // Handle type
            std::string type_str = member.type;
            if (type_str.empty()) {
                type_str = "void"; // fallback for unknown types
            }
            
            // Add pointer indicator if needed
            if (member.is_pointer) {
                ss << type_str << "*";
            } else {
                ss << type_str;
            }
            
            ss << " " << member.name;
            
            // Add array indicator if needed
            if (member.is_array && member.array_count > 0) {
                ss << "[" << std::dec << member.array_count << "]";
            }
            
            ss << "; // 0x" << std::hex << member.offset;
            if (member.size > 0) {
                ss << " (size: 0x" << std::hex << member.size << ")";
            }
            ss << "\n";
            
            current_offset = member.offset + (member.size > 0 ? member.size : 1);
            current_bitfield_offset = UINT32_MAX; // Reset bitfield tracking
        }
    }
    
    // Add final padding if needed
    if (current_offset < struct_info.size) {
        uint32_t final_padding = struct_info.size - current_offset;
        ss << "    char _padding_final[0x" << std::hex << final_padding << "]; // Final padding\n";
    }
    
    ss << "} " << struct_info.name << "; // Total size: 0x" << std::hex << struct_info.size << " (" << std::dec << struct_info.size << " bytes)\n";
    
    return ss.str();
}

}
