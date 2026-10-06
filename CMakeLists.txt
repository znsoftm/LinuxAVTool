cmake_minimum_required(VERSION 3.10)

project(sysinfo
    VERSION 0.1.0
    DESCRIPTION "Cross-platform system information detection tool"
    LANGUAGES CXX)

# ---- C++ standard: at least C++11 ----
if(NOT CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 11)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---- Sources ----
# Module sources (os/cpu/memory/disk info) are appended here as they are added.
set(SYSINFO_SOURCES
    src/main.cpp
    src/report.cpp
    src/text_table.cpp
    src/tui.cpp
    src/locale_info.cpp
    src/i18n.cpp
    src/memory_info.cpp
    src/disk_info.cpp
    src/clamav_scan.cpp
)

# ---- Executable entry point ----
add_executable(sysinfo ${SYSINFO_SOURCES})

target_include_directories(sysinfo PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ---- ClamAV / libclamav ----------------------------------------------------
# The security module scans files in-process through the libclamav C API. When
# the library is missing it is installed automatically into a private prefix
# (no root required), so a plain `cmake -S . -B build` yields a fully featured
# build. Set -DSYSINFO_USE_CLAMAV=OFF for a build that only inspects a ClamAV
# command line installation, or -DSYSINFO_AUTO_INSTALL_CLAMAV=OFF to never
# touch the network during configuration.
if(POLICY CMP0074)
    # Honour <PackageName>_ROOT in find_package (ClamAV_ROOT).
    cmake_policy(SET CMP0074 NEW)
endif()

option(SYSINFO_USE_CLAMAV "Integrate the ClamAV anti-virus engine (libclamav)" ON)
option(SYSINFO_AUTO_INSTALL_CLAMAV
       "Install libclamav automatically when it cannot be found" ON)

set(ClamAV_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/clamav"
    CACHE PATH "Preferred ClamAV install prefix")

if(SYSINFO_USE_CLAMAV)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(ClamAV QUIET)

    if(NOT ClamAV_FOUND AND SYSINFO_AUTO_INSTALL_CLAMAV)
        message(STATUS "libclamav not found - installing it automatically")
        find_program(BASH_EXECUTABLE bash)
        if(BASH_EXECUTABLE)
            execute_process(
                COMMAND "${BASH_EXECUTABLE}"
                        "${CMAKE_CURRENT_SOURCE_DIR}/scripts/install_clamav.sh"
                        --prefix "${ClamAV_ROOT}"
                RESULT_VARIABLE _clamav_install_result
                OUTPUT_VARIABLE _clamav_install_output
                ERROR_VARIABLE _clamav_install_error)
            if(NOT _clamav_install_result EQUAL 0)
                message(WARNING "automatic libclamav installation failed:\n"
                                "${_clamav_install_output}${_clamav_install_error}")
            endif()
        else()
            message(WARNING "bash not found, skipping the automatic libclamav installation")
        endif()
        unset(ClamAV_INCLUDE_DIR CACHE)
        unset(ClamAV_LIBRARY CACHE)
        unset(ClamAV_DATABASE_DIR CACHE)
        find_package(ClamAV QUIET)
    endif()

    if(ClamAV_FOUND)
        message(STATUS "libclamav found: ${ClamAV_LIBRARY} (version ${ClamAV_VERSION})")
        target_compile_definitions(sysinfo PRIVATE SYSINFO_HAVE_LIBCLAMAV=1)
        target_include_directories(sysinfo PRIVATE "${ClamAV_INCLUDE_DIR}")
        target_link_libraries(sysinfo PRIVATE "${ClamAV_LIBRARY}")

        # Where the engine looks for its signature database. It can always be
        # overridden at run time with SYSINFO_CLAMAV_DB / CLAMAV_DATADIR.
        if(ClamAV_DATABASE_DIR)
            message(STATUS "ClamAV signature database: ${ClamAV_DATABASE_DIR}")
            target_compile_definitions(sysinfo PRIVATE
                SYSINFO_CLAMAV_DB_DIR="${ClamAV_DATABASE_DIR}")
        else()
            message(WARNING
                "no ClamAV signature database found; run "
                "scripts/install_clamav.sh to download one")
        endif()

        target_compile_definitions(sysinfo PRIVATE
            SYSINFO_LIBCLAMAV_PATH="${ClamAV_LIBRARY}")

        # Keep the private prefix in the run time search path so the binary
        # works without setting LD_LIBRARY_PATH.
        get_filename_component(_clamav_lib_dir "${ClamAV_LIBRARY}" DIRECTORY)
        set_target_properties(sysinfo PROPERTIES
            BUILD_RPATH "${_clamav_lib_dir}"
            INSTALL_RPATH "${_clamav_lib_dir}")
    else()
        message(WARNING
            "building without libclamav: only a ClamAV command line "
            "installation can be inspected")
    endif()
endif()

# ---- Threads ----
# The interactive interface collects information and runs scans on a worker
# thread so the animation keeps rendering.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(sysinfo PRIVATE Threads::Threads)

# ---- Warnings ----
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sysinfo PRIVATE -Wall -Wextra)
endif()
