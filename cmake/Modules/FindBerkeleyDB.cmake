include(FindPackageHandleStandardArgs)

# Find INCLUDES and LIBS
# BerkeleyDB is also known as DB, so we add DB_ROOT to HINTS
IF(UNIX)
  find_path(_BERKELEYDB_INCLUDE_DIR
    NAMES db_cxx.h db.h
    HINTS $ENV{BERKELEYDB_ROOT} $ENV{DB_ROOT} ${BERKELEYDB_ROOT} ${DB_ROOT} ${CMAKE_SOURCE_DIR}/deps/db
    PATH_SUFFIXES include
    PATHS /usr /usr/local /opt /opt/local
  )

  find_library(_BERKELEYDB_LIBRARIES
    NAMES libdb_cxx.so
    HINTS $ENV{BERKELEYDB_ROOT} $ENV{DB_ROOT} ${BERKELEYDB_ROOT} ${DB_ROOT} ${CMAKE_SOURCE_DIR}/deps/db
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local
  )
ELSEIF(WIN32)
  # TEST/WIP
  find_path(_BERKELEYDB_INCLUDE_DIR
    NAMES db_cxx.h db.h
    HINTS $ENV{BERKELEYDB_ROOT} $ENV{DB_ROOT} ${BERKELEYDB_ROOT} ${DB_ROOT} ${CMAKE_SOURCE_DIR}/deps/db
    PATH_SUFFIXES "Program Files\\db" "Program Files (x86)\\db" berkeleydb db
    PATHS C:\\
  )

  find_library(_BERKELEYDB_LIBRARIES
    NAMES libdb_cxx.so
    HINTS $ENV{BERKELEYDB_ROOT} $ENV{DB_ROOT} ${BERKELEYDB_ROOT} ${DB_ROOT} ${CMAKE_SOURCE_DIR}/deps/db
    PATH_SUFFIXES "Program Files\\db" "Program Files (x86)\\db" berkeleydb db
    PATHS C:\\
  )
ELSE()
  # Fail if not Unix/Windows
  message(FATAL_ERROR "Unsported operating system when trying to find Berkeley DB!")
ENDIF()

# Checks if the version file exists, save the version file to a var, and fail if there's no version file
IF(_BERKELEYDB_INCLUDE_DIR AND EXISTS "${_BERKELEYDB_INCLUDE_DIR}/db.h")
  set(_BERKELEYDB_VERSION_file "${_BERKELEYDB_INCLUDE_DIR}/db.h")
ELSE()
  message(FATAL_ERROR "Error: Can't find Berkeley DB header file db.h")
ENDIF()

# Parse the BerkeleyDB version
file(READ ${_BERKELEYDB_VERSION_file} _BERKELEYDB_header_contents)
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*DB_VERSION_PATCH	([0-9]+).*"
"\\1.\\2.\\3" BERKELEYDB_VERSION "${_BERKELEYDB_header_contents}")

# Should fail if the vars aren't found | FOUND_VAR is obsolete and only for older versions of cmake.
# Underscore in front of vars because the docs recommend it https://cmake.org/cmake/help/latest/module/FindPackageHandleStandardArgs.html
# "... these should typically be cache entries such as FOO_LIBRARY and not output variables like FOO_LIBRARIES."
find_package_handle_standard_args(BerkeleyDB
  FOUND_VAR BERKELEYDB_FOUND
  REQUIRED_VARS _BERKELEYDB_LIBRARIES _BERKELEYDB_INCLUDE_DIR
  VERSION_VAR BERKELEYDB_VERSION
  )

# Get MAJOR version of DB
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*"
"\\1" BERKELEYDB_VER_MAJOR "${_BERKELEYDB_header_contents}")

# Throw a WARNING to people using BerkeleyDB v5, but continue building
IF(BERKELEYDB_VER_MAJOR MATCHES "5")
  message(WARNING
    "==WARNING== \
    Pre-existing wallet data is not backwards compatible with version v5 of Berkeley DB if it was originally built with v6. \
    Read vcash/docs/BUILDING.md for more info. \
    ==WARNING==")
ENDIF()

# Sets the correct, non-cached variables that will be used in CMakeLists.txt
set(BERKELEYDB_INCLUDE_DIRS ${_BERKELEYDB_INCLUDE_DIR})
set(BERKELEYDB_LIBRARIES ${_BERKELEYDB_LIBRARIES})
