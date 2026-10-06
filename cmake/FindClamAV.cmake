# FindClamAV - locate the ClamAV anti-virus engine library (libclamav).
#
# Result variables:
#   ClamAV_FOUND         TRUE when the headers and the library were found
#   ClamAV_INCLUDE_DIR   directory containing clamav.h
#   ClamAV_LIBRARY       full path to the libclamav shared object
#   ClamAV_VERSION       version reported by libclamav.pc (may be empty)
#   ClamAV_DATABASE_DIR  directory holding the signature database (may be empty)
#
# Hints:
#   ClamAV_ROOT                    preferred install prefix
#   CLAMAV_ROOT / SYSINFO_CLAMAV_PREFIX (environment)
#   CMAKE_PREFIX_PATH

set(_clamav_roots "")
foreach(_root IN ITEMS
        "${ClamAV_ROOT}"
        "$ENV{CLAMAV_ROOT}"
        "$ENV{SYSINFO_CLAMAV_PREFIX}"
        "${CMAKE_PREFIX_PATH}")
    if(_root)
        list(APPEND _clamav_roots "${_root}")
    endif()
endforeach()

find_path(ClamAV_INCLUDE_DIR
    NAMES clamav.h
    HINTS ${_clamav_roots}
    PATH_SUFFIXES include usr/include include/clamav
)

find_library(ClamAV_LIBRARY
    NAMES clamav libclamav
    HINTS ${_clamav_roots}
    PATH_SUFFIXES lib lib64 usr/lib
)

set(ClamAV_VERSION "")
find_file(_clamav_pkgconfig
    NAMES libclamav.pc
    HINTS ${_clamav_roots}
    PATH_SUFFIXES lib/pkgconfig usr/lib/pkgconfig
)
if(_clamav_pkgconfig)
    file(STRINGS "${_clamav_pkgconfig}" _clamav_pc_version REGEX "^Version:[ \t]*[0-9]")
    if(_clamav_pc_version)
        string(REGEX REPLACE "^Version:[ \t]*" "" ClamAV_VERSION "${_clamav_pc_version}")
        string(STRIP "${ClamAV_VERSION}" ClamAV_VERSION)
    endif()
endif()

# The signature database is normally kept next to the installation prefix, but
# a system wide installation puts it in /var/lib/clamav.
if(NOT ClamAV_DATABASE_DIR)
    set(_clamav_db_candidates "")
    foreach(_root IN LISTS _clamav_roots)
        list(APPEND _clamav_db_candidates "${_root}/database")
    endforeach()
    list(APPEND _clamav_db_candidates "/var/lib/clamav")
    foreach(_dir IN LISTS _clamav_db_candidates)
        file(GLOB _clamav_db_files "${_dir}/*.cvd" "${_dir}/*.cld")
        if(_clamav_db_files)
            set(ClamAV_DATABASE_DIR "${_dir}")
            break()
        endif()
    endforeach()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ClamAV
    REQUIRED_VARS ClamAV_LIBRARY ClamAV_INCLUDE_DIR
    VERSION_VAR ClamAV_VERSION
)

mark_as_advanced(ClamAV_INCLUDE_DIR ClamAV_LIBRARY)
