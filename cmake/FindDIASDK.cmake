# FindDIASDK.cmake - Find Microsoft Debug Interface Access SDK
#
# This module finds the DIA SDK that comes with Visual Studio
# Based on Microsoft's official approach
#
# Variables set by this module:
#   DIASDK_FOUND          - True if DIA SDK was found
#   DIASDK_INCLUDE_DIRS   - Include directories for DIA SDK
#   DIASDK_LIBRARIES      - Libraries to link against
#   DIASDK_LIBRARY_DIRS   - Library directories
#   DIASDK_BINARY_DIRS    - Binary directories (for msdia140.dll)
#
# Example usage:
#   find_package(DIASDK REQUIRED)
#   target_include_directories(my_target PRIVATE ${DIASDK_INCLUDE_DIRS})
#   target_link_libraries(my_target PRIVATE ${DIASDK_LIBRARIES})

# Find the DIA SDK path using CMAKE_GENERATOR_INSTANCE first
# CMAKE_GENERATOR_INSTANCE has the location of Visual Studio used
# i.e. C:/Program Files (x86)/Microsoft Visual Studio/2019/Community
if(CMAKE_GENERATOR_INSTANCE)
    set(VS_PATH ${CMAKE_GENERATOR_INSTANCE})
    get_filename_component(VS_DIA_INC_PATH "${VS_PATH}/DIA SDK/include" ABSOLUTE)
endif()

# Starting in VS 15.2, vswhere is included.
# Search for Visual Studio installations with C++ toolset
set(PROGRAMFILES_X86 "ProgramFiles(x86)")
if(EXISTS "$ENV{${PROGRAMFILES_X86}}/Microsoft Visual Studio/Installer/vswhere.exe")
    execute_process(
        COMMAND "$ENV{${PROGRAMFILES_X86}}/Microsoft Visual Studio/Installer/vswhere.exe" 
                -latest 
                -products * 
                -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 
                -property installationPath
        OUTPUT_VARIABLE VSWHERE_LATEST
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

# Fallback search paths for older Visual Studio versions or manual installations
set(DIASDK_FALLBACK_PATHS
    "$ENV{VSINSTALLDIR}/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Enterprise/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Professional/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2022/Community/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2019/Enterprise/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2019/Professional/DIA SDK"
    "$ENV{ProgramFiles}/Microsoft Visual Studio/2019/Community/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Enterprise/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Professional/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2022/Community/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2019/Enterprise/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2019/Professional/DIA SDK"
    "C:/Program Files/Microsoft Visual Studio/2019/Community/DIA SDK"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/DIA SDK"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Professional/DIA SDK"
    "C:/Program Files (x86)/Microsoft Visual Studio/2019/Community/DIA SDK"
)

# Find dia2.h header file
find_path(DIASDK_INCLUDE_DIR
    dia2.h
    HINTS 
        "${VS_DIA_INC_PATH}"
        "${VSWHERE_LATEST}/DIA SDK/include"
        "${MSVC_DIA_SDK_DIR}/include"
    PATHS
        ${DIASDK_FALLBACK_PATHS}
    PATH_SUFFIXES
        include
    DOC "Path to DIA SDK header files"
)

# Find the diaguids.lib library based on architecture
# Use proper CMake architecture detection like Microsoft's approach
if(DIASDK_INCLUDE_DIR)
    # Determine library subdirectory based on target architecture
    if((CMAKE_GENERATOR_PLATFORM STREQUAL "x64") OR ("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" STREQUAL "x64") OR (CMAKE_SIZEOF_VOID_P EQUAL 8))
        set(DIASDK_LIB_SUBDIR "amd64")
    elseif((CMAKE_GENERATOR_PLATFORM STREQUAL "ARM") OR ("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" STREQUAL "ARM"))
        set(DIASDK_LIB_SUBDIR "arm")
    elseif((CMAKE_GENERATOR_PLATFORM MATCHES "ARM64.*") OR ("${CMAKE_C_COMPILER_ARCHITECTURE_ID}" MATCHES "ARM64.*"))
        set(DIASDK_LIB_SUBDIR "arm64")
    else()
        set(DIASDK_LIB_SUBDIR "")  # x86 libraries are in the root lib directory
    endif()
    
    # Find the diaguids.lib library
    if(DIASDK_LIB_SUBDIR)
        find_library(DIASDK_GUIDS_LIBRARY 
            NAMES diaguids.lib diaguids
            HINTS "${DIASDK_INCLUDE_DIR}/../lib/${DIASDK_LIB_SUBDIR}"
            DOC "Path to DIA SDK diaguids library"
        )
        set(DIASDK_BINARY_DIRS "${DIASDK_INCLUDE_DIR}/../bin/${DIASDK_LIB_SUBDIR}")
    else()
        find_library(DIASDK_GUIDS_LIBRARY 
            NAMES diaguids.lib diaguids
            HINTS "${DIASDK_INCLUDE_DIR}/../lib"
            DOC "Path to DIA SDK diaguids library"
        )
        set(DIASDK_BINARY_DIRS "${DIASDK_INCLUDE_DIR}/../bin")
    endif()
    
    # Set the library directory for linking
    if(DIASDK_GUIDS_LIBRARY)
        get_filename_component(DIASDK_LIBRARY_DIRS "${DIASDK_GUIDS_LIBRARY}" DIRECTORY)
    endif()
    
    # Set output variables
    set(DIASDK_LIBRARIES ${DIASDK_GUIDS_LIBRARY})
    set(DIASDK_INCLUDE_DIRS ${DIASDK_INCLUDE_DIR})
endif()

# Handle the standard arguments
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DIASDK
    DEFAULT_MSG
    DIASDK_LIBRARIES 
    DIASDK_INCLUDE_DIR
)

if(DIASDK_FOUND)
    message(STATUS "Found DIA SDK:")
    message(STATUS "  Include dir: ${DIASDK_INCLUDE_DIRS}")
    message(STATUS "  Library: ${DIASDK_LIBRARIES}")
    message(STATUS "  Library dir: ${DIASDK_LIBRARY_DIRS}")
    message(STATUS "  Binary dir: ${DIASDK_BINARY_DIRS}")
    message(STATUS "  Architecture: ${DIASDK_LIB_SUBDIR}")
    
    # Create imported target
    if(NOT TARGET DIASDK::DIASDK)
        add_library(DIASDK::DIASDK INTERFACE IMPORTED)
        set_target_properties(DIASDK::DIASDK PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${DIASDK_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${DIASDK_LIBRARIES}"
        )
    endif()
endif()

mark_as_advanced(
    DIASDK_INCLUDE_DIR
    DIASDK_GUIDS_LIBRARY
    DIASDK_INCLUDE_DIRS
    DIASDK_LIBRARY_DIRS
    DIASDK_BINARY_DIRS
    DIASDK_LIBRARIES
)
