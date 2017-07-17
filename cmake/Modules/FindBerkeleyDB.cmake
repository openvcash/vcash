include(FindPackageHandleStandardArgs)

# Easier to change variables than going line by line should this ever need updating..
set(DB_H_NAMES "") # Header names
set(DB_L_NAMES "") # Library names
set(DB_HINTS "")
set(DB_PATHS "")
set(DB_H_SUF "") # Header suffixes
set(DB_L_SUF "") # Library suffixes

# HINTS don't really change across OS's | BerkeleyDB is also known as DB, so we add DB_ROOT to HINTS
list(APPEND DB_HINTS "$ENV{BERKELEYDB_ROOT}" "$ENV{DB_ROOT}" "${BERKELEYDB_ROOT}" "${DB_ROOT}" "${CMAKE_SOURCE_DIR}/deps/db")

# Fill in the variables to search for Berkeley DB
IF(UNIX)
  list(APPEND DB_H_NAMES "db_cxx.h" "db.h")
  list(APPEND DB_L_NAMES "libdb_cxx.so")
  list(APPEND DB_PATHS "/usr" "/usr/local" "/opt" "/opt/local")
  list(APPEND DB_H_SUF "include")
  list(APPEND DB_L_SUF "lib" "lib64")
ELSEIF(WIN32)
  # Append the user-supplied prefix, before C:\, if it exists
  IF(BERKELEYDB_DRIVE_PREFIX)
    list(APPEND DB_PATHS "${BERKELEYDB_DRIVE_PREFIX}")
  ENDIF()

  list(APPEND DB_H_NAMES "db_cxx.h" "db.h")
  list(APPEND DB_L_NAMES "libdb_cxx.so")
  list(APPEND DB_PATHS "C:\\")
  list(APPEND DB_H_SUF "Program Files\\db" "Program Files (x86)\\db" "berkeleydb" "db")
  list(APPEND DB_L_SUF ${DB_H_SUF}) # Just reusing DB_H_SUF because they contain the same things
ELSE()
  # Fail if not Unix/Windows
  message(FATAL_ERROR "Unsported operating system when trying to find Berkeley DB!")
ENDIF()

# Find INCLUDES and LIBS
find_path(_BERKELEYDB_INCLUDE_DIR
  NAMES ${DB_H_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_H_SUF}
  PATHS ${DB_PATHS}
)

find_library(_BERKELEYDB_LIBRARIES
  NAMES ${DB_L_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

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
