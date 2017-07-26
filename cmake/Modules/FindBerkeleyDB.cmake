# Output vars ("db" library is required, but "db_cxx" "db_stl" "db_sql" are also included if they are found)
# ^^^^^^^^^^^
# BERKELEYDB_INCLUDE_DIRS
# BERKELEYDB_LIBRARIES
#
# User-passable values
# ^^^^^^^^^^^^^^^^^^^^
# BDB_ROOT_PATH
# BDB_DB_LIBNAME
# BDB_DB_CXX_LIBNAME
# BDB_DB_STL_LIBNAME
# BDB_DB_SQL_LIBNAME
#
# If all else fails, set any of these manually (whatever is failing)
# ^^^^^^^^^^^^^^^^^^^^
# BERKELEYDB_INCLUDE_DIRS
# DB_LIBRARY
# DB_CXX
# DB_STL
# DB_SQL

include(FindPackageHandleStandardArgs)

# HINTS don't change across OS's
# Checks if evnironment paths are empty, set them if they aren't
IF(NOT ("$ENV{BERKELEYDB_ROOT}" STREQUAL ""))
  list(APPEND DB_HINTS "$ENV{BERKELEYDB_ROOT}")
ELSEIF(NOT ("$ENV{DB_ROOT}" STREQUAL ""))
  list(APPEND DB_HINTS "$ENV{DB_ROOT}")
ENDIF()

# Header names
list(APPEND DB_H_NAMES
  "db_cxx.h"
  "db.h"
)

# Header search suffixes | aka /usr/${DB_H_SUF} if searching /usr
list(APPEND DB_H_SUF
  "include"
  "includes"
)

# Library search suffixes | aka /usr/${DB_L_SUF} if searching /usr
list(APPEND DB_L_SUF
  "lib"
  "libs"
  "lib64"
  "libs64"
)

# Allow user to pass a path instead of guessing
IF(BDB_ROOT_PATH)
  list(APPEND DB_PATHS "${BDB_ROOT_PATH}")
ENDIF()
# Default paths to search for Berkeley DB, regardless of root path
IF(CMAKE_SYSTEM_NAME STREQUAL "Windows")
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
ELSE()
  # Paths for anything other than Windows
  # Cellar/berkeley-db is for macOS homebrew
  list(APPEND DB_PATHS
    "/usr"
    "/usr/local"
    "/opt"
    "/opt/local"
    "/usr/local/Cellar"
    "/usr/local/Cellar/db"
    "/usr/local/Cellar/berkeley-db"
    "/usr/local/Cellar/Berkeley DB"
  )
ENDIF()

# Find includes path | This is passed directly to CMakeLists.txt without moving it into a different var.
find_path(BERKELEYDB_INCLUDE_DIRS
  NAMES ${DB_H_NAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_H_SUF}
  PATHS ${DB_PATHS}
)

# Checks if the version file exists, save the version file to a var, and fail if there's no version file
IF(BERKELEYDB_INCLUDE_DIRS AND EXISTS "${BERKELEYDB_INCLUDE_DIRS}/db.h")
  set(_BERKELEYDB_VERSION_file "${BERKELEYDB_INCLUDE_DIRS}/db.h")
ELSE()
  message(FATAL_ERROR "Error: Failed to find the Berkeley DB header file \"db.h\"")
ENDIF()

# Parse the BerkeleyDB version to be eventually checked against the minimum
file(READ ${_BERKELEYDB_VERSION_file} _BERKELEYDB_header_contents)
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*DB_VERSION_PATCH	([0-9]+).*"
"\\1.\\2.\\3" BERKELEYDB_VERSION "${_BERKELEYDB_header_contents}"
)

# Parse the DB version into multiple strings to be used in lib names | Ex: DB v6.2 gets put into variables as 62 6.2 and 6
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*" "\\1\\2" DB_MAJORMINOR_VER "${_BERKELEYDB_header_contents}")
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*" "\\1.\\2" DB_MAJOR_DOT_MINOR_VER "${_BERKELEYDB_header_contents}")
string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*" "\\1" DB_MAJOR_VER "${_BERKELEYDB_header_contents}")

# We put lib name vars after includes have been found, so we can use db.h to get the version numbers.
# I would do some fancy macro/forloop stuff here, but uh.. Yeah..
# Checks for if the user used custom flags for their "db" library name
IF(BDB_DB_LIBNAME)
    list(APPEND DB_LIBNAMES "${BDB_DB_LIBNAME}")
ELSE()
  # Start guessing names if no libname is passed
  list(APPEND DB_LIBNAMES
    "db"
    "libdb"
    "libdb${DB_MAJOR_DOT_MINOR_VER}"
    "libdb-${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_${DB_MAJOR_DOT_MINOR_VER}"
    "libdb${DB_MAJORMINOR_VER}"
    "libdb-${DB_MAJORMINOR_VER}"
    "libdb_${DB_MAJORMINOR_VER}"
    "libdb${DB_MAJOR_VER}"
    "libdb-${DB_MAJOR_VER}"
    "libdb_${DB_MAJOR_VER}"
  )
ENDIF()
# Checks for if the user used custom flags for their "db_cxx" library name
IF(BDB_DB_CXX_LIBNAME)
  list(APPEND DB_CXX_LIBNAMES "${BDB_DB_CXX_LIBNAME}")
ELSE()
  # Start guessing names if no libname is passed
  list(APPEND DB_CXX_LIBNAMES
    "db_cxx"
    "libdb_cxx"
    "libdb_cxx${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_cxx-${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_cxx_${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_cxx${DB_MAJORMINOR_VER}"
    "libdb_cxx-${DB_MAJORMINOR_VER}"
    "libdb_cxx_${DB_MAJORMINOR_VER}"
    "libdb_cxx${DB_MAJOR_VER}"
    "libdb_cxx-${DB_MAJOR_VER}"
    "libdb_cxx_${DB_MAJOR_VER}"
  )
ENDIF()
# Checks for if the user used custom flags for their "db_stl" library name
IF(BDB_DB_STL_LIBNAME)
  list(APPEND DB_STL_LIBNAMES "${BDB_DB_STL_LIBNAME}")
ELSE()
  # Start guessing names if no libname is passed
  list(APPEND DB_STL_LIBNAMES
    "db_stl"
    "libdb_stl"
    "libdb_stl${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_stl-${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_stl_${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_stl${DB_MAJORMINOR_VER}"
    "libdb_stl-${DB_MAJORMINOR_VER}"
    "libdb_stl_${DB_MAJORMINOR_VER}"
    "libdb_stl${DB_MAJOR_VER}"
    "libdb_stl-${DB_MAJOR_VER}"
    "libdb_stl_${DB_MAJOR_VER}"
  )
ENDIF()
# Checks for if the user used custom flags for their "db_stl" library name
IF(BDB_DB_SQL_LIBNAME)
  list(APPEND DB_SQL_LIBNAMES "${BDB_DB_SQL_LIBNAME}")
ELSE()
  # Start guessing names if no libname is passed
  list(APPEND DB_SQL_LIBNAMES
    "db_sql"
    "libdb_sql"
    "libdb_sql${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_sql-${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_sql_${DB_MAJOR_DOT_MINOR_VER}"
    "libdb_sql${DB_MAJORMINOR_VER}"
    "libdb_sql-${DB_MAJORMINOR_VER}"
    "libdb_sql_${DB_MAJORMINOR_VER}"
    "libdb_sql${DB_MAJOR_VER}"
    "libdb_sql-${DB_MAJOR_VER}"
    "libdb_sql_${DB_MAJOR_VER}"
  )
ENDIF()

# Find "db" library filepath
find_library(DB_LIBRARY
  NAMES ${DB_LIBNAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

# Find "db_cxx" library filepath
find_library(DB_CXX
  NAMES ${DB_CXX_LIBNAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

# Find "db_stl" library filepath
find_library(DB_STL
  NAMES ${DB_STL_LIBNAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

# Find "db_sql" library filepath
find_library(DB_SQL
  NAMES ${DB_SQL_LIBNAMES}
  HINTS ${DB_HINTS}
  PATH_SUFFIXES ${DB_L_SUF}
  PATHS ${DB_PATHS}
)

# Should fail if the vars aren't found, although there's pre-checks above this. | "FOUND_VAR is obsolete and only for older versions of cmake."
find_package_handle_standard_args(BerkeleyDB
  FOUND_VAR BERKELEYDB_FOUND
  REQUIRED_VARS DB_LIBRARY BERKELEYDB_INCLUDE_DIRS
  VERSION_VAR BERKELEYDB_VERSION
)

# Required lib set to temp var
set(_dblibs "${DB_LIBRARY}")
# Combine all found libs into temp var
IF(DB_CXX)
  list(APPEND _dblibs "${DB_CXX}")
ENDIF()
IF(DB_STL)
  list(APPEND _dblibs "${DB_STL}")
ENDIF()
IF(DB_SQL)
  list(APPEND _dblibs "${DB_SQL}")
ENDIF()

# The actual var used outside of this find module | BERKELEYDB_INCLUDE_DIRS is already set from earlier.
set(BERKELEYDB_LIBRARIES ${_dblibs})
message(STATUS "All found Berkeley DB libs: ${BERKELEYDB_LIBRARIES}")
