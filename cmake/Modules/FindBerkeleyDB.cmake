# This is a custom module that tries to find Berkeley DB's libraries and header files/paths.
# If any paths/names/suffixes/etc. are missing, add them to the variables with a list(APPEND DB_x_x "missing_value")
# Make sure to not affect the order things are added, as everything is appended to lists in specific orders.

include(FindPackageHandleStandardArgs)

# Easier to change variables than going line by line should this ever need updating..
set(DB_H_NAMES "") # Header names
set(DB_L_NAMES "") # Library names | Do not use prefixes or suffixes, cmake adds them based on the OS - ex: "db" gets changed to "libdb.so" on Linux -- But Windows doesn't add prefixes for some reason.
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

# Header names don't really change across OS's
list(APPEND DB_H_NAMES
  "db_cxx.h"
  "db.h"
)

# Checks for if the user used custom flags for their library name
IF(BERKELEYDB_LIB_NAME)
    list(APPEND DB_L_NAMES "${BERKELEYDB_LIB_NAME}")
ENDIF()

# Fill in the variables to search for Berkeley DB
IF(WIN32)
  # Shameless copy-paste from FindOpenSSL.cmake v3.8
  file(TO_CMAKE_PATH "$ENV{PROGRAMFILES}" _programfiles)
  list(APPEND DB_HINTS "${_programfiles}")

  # There's actually production release and version numbers in the file path.
  # For example, if they're on v6.2.32: C:/Program Files/Oracle/Berkeley DB 12cR1 6.2.32/
  # But this still works to find it, through some dark voodoo magic. | It probably just doesn't read past "Berkeley DB" if I'd have to guess.
  list(APPEND DB_PATHS
    "${_programfiles}/Oracle/Berkeley DB"
    "${_programfiles}/Berkeley DB"
    "${_programfiles}/DB"
    "C:/Oracle/Berkeley DB"
    "C:/Oracle/DB"
    "C:/Berkeley DB"
    "C:/DB"
  )
  list(APPEND DB_H_SUF
    "include"
  )
  list(APPEND DB_L_SUF
    "lib"
  )
ELSE()
  list(APPEND DB_L_NAMES
    "db_cxx"
    "db"
  )
  # Variables for anything other than Windows
  list(APPEND DB_PATHS
    "/usr"
    "/usr/local"
    "/opt"
    "/opt/local"
  )
  list(APPEND DB_H_SUF
    "include"
  )
  list(APPEND DB_L_SUF
    "lib"
    "lib64"
  )
ENDIF()

# Find includes path
find_path(_BERKELEYDB_INCLUDE_DIR
  NAMES ${DB_H_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_H_SUF}
  PATHS ${DB_PATHS}
)

# Checks if the version file exists, save the version file to a var, and fail if there's no version file
IF(_BERKELEYDB_INCLUDE_DIR AND EXISTS "${_BERKELEYDB_INCLUDE_DIR}/db.h")
  set(_BERKELEYDB_VERSION_file "${_BERKELEYDB_INCLUDE_DIR}/db.h")
ELSEIF(NOT _BERKELEYDB_INCLUDE_DIR) # Fail if not found. Only used to pass a helpful error message, instead of the generic failure message from find_package_handle_standard_args
  message(FATAL_ERROR "Error: Failed to find Berkeley DB includes path. \
  Try setting BERKELEYDB_INCLUDES_PATH and run cmake again.")
ELSE()
  message(FATAL_ERROR "Error: FindBerkeleyDB failed to find the header file \"db.h\"")
ENDIF()

# Parse the BerkeleyDB version
file(READ ${_BERKELEYDB_VERSION_file} _BERKELEYDB_header_contents)
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*DB_VERSION_PATCH	([0-9]+).*"
"\\1.\\2.\\3" BERKELEYDB_VERSION "${_BERKELEYDB_header_contents}"
)

# For some reason they thought it was a good idea to put MAJOR and MINOR version numbers in the lib name for Windows...
# so we put DB_L_NAMES after includes have been found, so we can use db.h to get the version numbers.
IF(WIN32 AND NOT BERKELEYDB_LIB_NAME) # This doesn't run if they pass their own lib name, which is what we want.
  # Parse the Major and minor DB version into a string
  string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*DB_VERSION_PATCH	([0-9]+).*"
  "\\1\\2" DB_MAJORMINOR_VER "${_BERKELEYDB_header_contents}"
  )
  message(STATUS "Berkeley DB MAJORMINOR v${DB_MAJORMINOR_VER} found, searching for lib names...")
  # Lib name for Windows, example on DB v6.2: libdb62.lib
  # For some reason cmake doesn't correctly append prefixes here, so we add them manually. Automatic suffixes still work.
  list(APPEND DB_L_NAMES
    "libdb${DB_MAJORMINOR_VER}"
  	"libdb_cxx${DB_MAJORMINOR_VER}"
  	"libdb"
  	"libdb_cxx"
    "db"
    "db_cxx"
  )
ENDIF()

# Find library filepath
find_library(_BERKELEYDB_LIBRARIES
  NAMES ${DB_L_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

# Fail if not found. Only used to pass a helpful error message, instead of the generic failure message from find_package_handle_standard_args
IF(NOT _BERKELEYDB_LIBRARIES)
  message(FATAL_ERROR "Error: Failed to find Berkeley DB libs. \
  Try setting BERKELEYDB_LIB_PATH and/or BERKELEYDB_LIB_NAME, then run cmake again.")
ENDIF()

# Should fail if the vars aren't found | FOUND_VAR is obsolete and only for older versions of cmake.
# Underscore in front of vars because the docs recommend it https://cmake.org/cmake/help/latest/module/FindPackageHandleStandardArgs.html
# "... these should typically be cache entries such as FOO_LIBRARY and not output variables like FOO_LIBRARIES."
find_package_handle_standard_args(BerkeleyDB
  FOUND_VAR BERKELEYDB_FOUND
  REQUIRED_VARS _BERKELEYDB_LIBRARIES _BERKELEYDB_INCLUDE_DIR
  VERSION_VAR BERKELEYDB_VERSION
  )

# Don't bother parsing the major version if the flag isn't set.
IF(WITH_INCOMPATIBLE_BDB)
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
ENDIF()

# Sets the correct, non-cached variables that will be used in CMakeLists.txt
set(BERKELEYDB_INCLUDE_DIRS ${_BERKELEYDB_INCLUDE_DIR})
set(BERKELEYDB_LIBRARIES ${_BERKELEYDB_LIBRARIES})
