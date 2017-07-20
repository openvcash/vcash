# This is a custom module that tries to find Berkeley DB's libraries and header files/paths.
# If any paths/names/suffixes/etc. are missing, add them to the variables with a list(APPEND DB_x_x "missing_value")
# Make sure to not affect the order things are added, as everything is appended to lists in specific orders.

include(FindPackageHandleStandardArgs)

# Easier to change variables than going line by line should this ever need updating..
set(DB_H_NAMES "") # Header names
set(DB_L_NAMES "") # Library names
set(DB_HINTS "") # "These should be paths computed by system introspection, such as a hint provided by the location of another item already found.
set(DB_PATHS "") # "These are typically hard-coded guesses."
set(DB_H_SUF "") # Header suffixes | These get appended onto the path for deeper searches
set(DB_L_SUF "") # Library suffixes | These get appended onto the path for deeper searches

# HINTS don't really change across OS's | BerkeleyDB is also known as DB, so we add DB_ROOT to HINTS
list(APPEND DB_HINTS
  "$ENV{BERKELEYDB_ROOT}"
  "$ENV{DB_ROOT}"
  "${BERKELEYDB_ROOT}"
  "${DB_ROOT}"
)

# Allow user to pass specific values to find Berkeley DB
# Path to users DB header files
IF(BERKELEYDB_INCLUDES_PATHS)
  list(APPEND DB_PATHS "${BERKELEYDB_INCLUDES_PATH}")
ENDIF()
# Path to users DB libs
IF(BERKELEYDB_LIBS_PATHS)
  list(APPEND DB_PATHS "${BERKELEYDB_LIB_PATH}")
ENDIF()

# Header names
list(APPEND DB_H_NAMES
  "db_cxx.h"
  "db.h"
)

# Checks for if the user used custom flags for their library name
IF(BERKELEYDB_LIB_NAME)
    list(APPEND DB_L_NAMES "${BERKELEYDB_LIB_NAME}")
ELSE()
  # Lib names fallback if no flag is used
  list(APPEND DB_L_NAMES "libdb_cxx.so")
ENDIF()

# Fill in the variables to search for Berkeley DB
IF(WIN32)
  # Shameless copy-paste from FindOpenSSL.cmake v3.8
  file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}" _programfiles)
  list(APPEND DB_HINTS "${_programfiles}")

  list(APPEND DB_PATHS "C:/")
  list(APPEND DB_H_SUF
    "${_programfiles}/db"
    "${_programfiles}/berkeleydb"
    "db"
    "berkeleydb"
  )
  list(APPEND DB_L_SUF "${DB_H_SUF}") # Just reusing DB_H_SUF because they contain the same things on Windows
ELSE()
  # Variables for anything other than Windows
  list(APPEND DB_PATHS
    "/usr"
    "/usr/local"
    "/opt"
    "/opt/local"
  )
  list(APPEND DB_H_SUF "include")
  list(APPEND DB_L_SUF
    "lib"
    "lib64"
  )
ENDIF()

# Find INCLUDES directory
find_path(_BERKELEYDB_INCLUDE_DIR
  NAMES ${DB_H_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_H_SUF}
  PATHS ${DB_PATHS}
)
# Find LIBS path
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
  message(FATAL_ERROR "Error: FindBerkeleyDB failed to find the header file \"db.h\"")
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

# Get MAJOR version of DB | This is only for the Vcash-specific warning, so remove it if you are using this module elsewhere.
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*"
"\\1" BERKELEYDB_VER_MAJOR "${_BERKELEYDB_header_contents}")

# Throw a WARNING to people using BerkeleyDB v5, but continue building | This is a Vcash-specific warning, so remove it if you are using this module elsewhere.
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
