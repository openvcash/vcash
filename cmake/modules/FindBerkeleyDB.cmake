# FindBerkeleyDB.cmake - version 2.0.2
# Author: sum01 <sum01@protonmail.com>
# Git: https://github.com/sum01/cmake-modules
#
# This module finds the BerkeleyDB includes and libraries ("db" "db_cxx" "db_stl" "db_sql"). Minimum 1 library found or it fails.
#
# Output variables to be used in CMakeLists.txt
# ^^^^^^^^^^^
# BERKELEYDB_INCLUDE_DIRS
# BERKELEYDB_LIBRARIES
# BERKELEYDB_VERSION
# BERKELEYDB_MAJOR_VERSION
# BERKELEYDB_MINOR_VERSION
# BERKELEYDB_PATCH_VERSION
#
# Optional user-passable values to help find Berkeley DB
# ^^^^^^^^^^^^^^^^^^^^
# BERKELEYDB_ROOT

# NOTE: If Berkeley DB ever gets a Pkg-config ".pc" file, add pkg_check_modules() here

# Checks if environment paths are empty, set them if they aren't
IF(NOT "$ENV{BERKELEYDB_ROOT}" STREQUAL "")
  set(_BERKELEYDB_HINTS "$ENV{BERKELEYDB_ROOT}")
ELSEIF(NOT "$ENV{BERKELEYDBROOT}" STREQUAL "")
  set(_BERKELEYDB_HINTS "$ENV{BERKELEYDBROOT}")
ELSE()
  # Set just in case, as it's used regardless if it's empty or not
  set(_BERKELEYDB_HINTS "")
ENDIF()

# Allow user to pass a path instead of guessing
IF(BERKELEYDB_ROOT)
  set(_BERKELEYDB_PATHS "${BERKELEYDB_ROOT}")
ELSEIF(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Shameless copy-paste from FindOpenSSL.cmake v3.8
  file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}" _programfiles)
  list(APPEND _BERKELEYDB_HINTS "${_programfiles}")

  # There's actually production release and version numbers in the file path.
  # For example, if they're on v6.2.32: C:/Program Files/Oracle/Berkeley DB 12cR1 6.2.32/
  # But this still works to find it, so I'm guessing it can accept partial path matches.

  foreach(_TARGET_BERKELEYDB_PATH "Oracle/Berkeley DB" "Berkeley DB")
    list(APPEND _BERKELEYDB_PATHS
      "${_programfiles}/${_TARGET_BERKELEYDB_PATH}"
      "C:/Program Files (x86)/${_TARGET_BERKELEYDB_PATH}"
      "C:/Program Files/${_TARGET_BERKELEYDB_PATH}"
      "C:/${_TARGET_BERKELEYDB_PATH}"
    )
  endforeach()
ELSE()
  # Paths for anything other than Windows
  # Cellar/berkeley-db is for macOS from homebrew installation
  list(APPEND _BERKELEYDB_PATHS
    "/usr"
    "/usr/local"
    "/usr/local/Cellar/berkeley-db"
    "/opt"
    "/opt/local"
  )
ENDIF()

# Find includes path
find_path(BERKELEYDB_INCLUDE_DIRS
  NAMES "db.h" "db_cxx.h"
  HINTS ${_BERKELEYDB_HINTS}
  PATH_SUFFIXES "include" "includes"
  PATHS ${_BERKELEYDB_PATHS}
)

# Checks if the version file exists, save the version file to a var, and fail if there's no version file
IF(BERKELEYDB_INCLUDE_DIRS AND EXISTS "${BERKELEYDB_INCLUDE_DIRS}/db.h")
  set(_BERKELEYDB_VERSION_file "${BERKELEYDB_INCLUDE_DIRS}/db.h")
ELSE()
  message(FATAL_ERROR "Failed to find Berkeley DB's header file \"db.h\"! Try setting \"BERKELEYDB_ROOT\" when initiating Cmake.")
ENDIF()

# Read the version file db.h into a variable
file(READ ${_BERKELEYDB_VERSION_file} _BERKELEYDB_header_contents)
# Parse the DB version into variables to be used in the lib names
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*" "\\1" BERKELEYDB_MAJOR_VERSION "${_BERKELEYDB_header_contents}")
string(REGEX REPLACE ".*DB_VERSION_MINOR	([0-9]+).*" "\\1" BERKELEYDB_MINOR_VERSION "${_BERKELEYDB_header_contents}")
# Patch version example on non-crypto installs: x.x.xNC
string(REGEX REPLACE ".*DB_VERSION_PATCH	([0-9]+(NC)?).*" "\\1" BERKELEYDB_PATCH_VERSION "${_BERKELEYDB_header_contents}")
# The actual returned/output version variable (the others can be used if needed)
set(BERKELEYDB_VERSION "${BERKELEYDB_MAJOR_VERSION}.${BERKELEYDB_MINOR_VERSION}.${BERKELEYDB_PATCH_VERSION}")

foreach(_TARGET_BERKELEYDB_LIB "db" "db_cxx" "db_sql" "db_stl")
  # Sets the various libnames for the variable used in find_library.
  # Different systems sometimes have a version in the lib name...
  # and some have a dash or underscore before the versions.
  # CMake recommends to put unversioned names before versioned names
  list(APPEND _BERKELEYDB_LIBNAMES
    "${_TARGET_BERKELEYDB_LIB}"
    "lib${_TARGET_BERKELEYDB_LIB}"
    "lib${_TARGET_BERKELEYDB_LIB}${BERKELEYDB_MAJOR_VERSION}.${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}-${BERKELEYDB_MAJOR_VERSION}.${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}_${BERKELEYDB_MAJOR_VERSION}.${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}${BERKELEYDB_MAJOR_VERSION}${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}-${BERKELEYDB_MAJOR_VERSION}${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}_${BERKELEYDB_MAJOR_VERSION}${BERKELEYDB_MINOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}${BERKELEYDB_MAJOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}-${BERKELEYDB_MAJOR_VERSION}"
    "lib${_TARGET_BERKELEYDB_LIB}_${BERKELEYDB_MAJOR_VERSION}"
  )

  find_library(_BERKELEYDB_LIB
    NAMES ${_BERKELEYDB_LIBNAMES}
    HINTS ${_BERKELEYDB_HINTS}
    PATH_SUFFIXES "lib" "lib64" "libs" "libs64"
    PATHS ${_BERKELEYDB_PATHS}
  )

  # If anything is found, append to BERKELEYDB_LIBRARIES
  IF(_BERKELEYDB_LIB)
    list(APPEND BERKELEYDB_LIBRARIES "${_BERKELEYDB_LIB}")
    # The library seems to get cached instead of only set in scope, so we unset the CACHE
    unset(_BERKELEYDB_LIB CACHE)
  ENDIF()
  # Clear out leftover names before setting them
  unset(_BERKELEYDB_LIBNAMES)
endforeach()

# Needed for find_package_handle_standard_args()
include(FindPackageHandleStandardArgs)
# Fails if required vars aren't found, or if the version doesn't meet specifications.
find_package_handle_standard_args(BerkeleyDB
  FOUND_VAR BERKELEYDB_FOUND # "FOUND_VAR is obsolete and only for older versions of cmake."
  REQUIRED_VARS BERKELEYDB_INCLUDE_DIRS BERKELEYDB_LIBRARIES
  VERSION_VAR BERKELEYDB_VERSION
)

# This loops through each found library and shows them in a more readable format.
# Get the list length
list(LENGTH BERKELEYDB_LIBRARIES _BDB_LENGTH)
IF(_BDB_LENGTH GREATER 0)
  # Minus 1 on index length to avoid out-of-bounds
  math(EXPR _BDB_LENGTH "${_BDB_LENGTH}-1")
ENDIF()
# Pre-loop message
message(STATUS "Found the following Berkeley DB libraries:")
# Loop with a range of the list length
foreach(_loopcount RANGE 0 ${_BDB_LENGTH})
  # Get the current index item into a var
  list(GET BERKELEYDB_LIBRARIES ${_loopcount} _BDB_INDEX_ITEM)
  # Gets basename of current index item
  get_filename_component(_BDB_INDEX_ITEM_BASENAME "${_BDB_INDEX_ITEM}" NAME)
  # Output library basename, and path without library name, of index item
  message(STATUS "  ${_BDB_INDEX_ITEM_BASENAME}")
endforeach()
