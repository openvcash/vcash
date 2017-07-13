# Copyright (c) 2014 Stefan.Eilemann@epfl.ch

# - Try to find the berkeleydb library
# Once done this will define
#
#  BERKELEYDB_ROOT - Set this variable to the root installation
#
# Read-Only variables:
#  BERKELEYDB_FOUND - system has the berkeleydb library
#  BERKELEYDB_INCLUDE_DIR - the berkeleydb include directory
#  BERKELEYDB_LIBRARIES - The libraries needed to use berkeleydb
#  BERKELEYDB_VERSION - This is set to $major.$minor.$patch (eg. 0.9.8)

# Original that this was created from: https://github.com/egparedes/CMake/blob/master/Findleveldb.cmake

include(FindPackageHandleStandardArgs)

IF(BerkeleyDB_FIND_REQUIRED)
  set(_BERKELEYDB_output_type FATAL_ERROR)
else()
  set(_BERKELEYDB_output_type STATUS)
ENDIF()

IF(BerkeleyDB_FIND_QUIETLY)
  set(_BERKELEYDB_output)
else()
  set(_BERKELEYDB_output 1)
ENDIF()

# Find INCLUDES
IF(UNIX)
  find_path(_BERKELEYDB_INCLUDE_DIR NAMES db_cxx.h db.h
    HINTS ${CMAKE_SOURCE_DIR}/../../.. $ENV{BERKELEYDB_ROOT} ${BERKELEYDB_ROOT}
    PATH_SUFFIXES include
    PATHS /usr /usr/local /opt /opt/local)

    # Feed the DIR into vars, checking which file was found
    IF(_BERKELEYDB_INCLUDE_DIR AND EXISTS "${_BERKELEYDB_INCLUDE_DIR}/db.h")
      set(_BERKELEYDB_VERSION_file "${_BERKELEYDB_INCLUDE_DIR}/db.h")

    ELSE()
      set(_BERKELEYDB_EPIC_FAIL TRUE)

      IF(_BERKELEYDB_output)
        message(${_BERKELEYDB_output_type}
        "Can't find berkeleydb header file db.h")
      ENDIF()
    ENDIF()
ELSEIF(WIN32)

ELSE()
  # Fail if not Unix or Windows
  message(FATAL_ERROR "Unsported operating system!")
ENDIF()

# System-independant stuff for after getting INCLUDES
file(READ ${_BERKELEYDB_VERSION_file} _BERKELEYDB_header_contents)

string(REGEX REPLACE ".*DB_VERSION_MAJOR	([0-9]+).*DB_VERSION_MINOR	([0-9]+).*DB_VERSION_PATCH	([0-9]+).*"
"\\1.\\2.\\3" _BERKELEYDB_VERSION "${_BERKELEYDB_header_contents}")

set(BERKELEYDB_VERSION ${_BERKELEYDB_VERSION} CACHE INTERNAL
"The version of berkeleydb which was detected")

# Version checking
IF(BERKELEYDB_FIND_VERSION AND BERKELEYDB_VERSION)
  IF(BERKELEYDB_FIND_VERSION_EXACT)
    IF(NOT BERKELEYDB_VERSION VERSION_EQUAL ${BERKELEYDB_FIND_VERSION})
      set(_BERKELEYDB_VERSION_not_exact TRUE)
    ENDIF()
  else()
    # version is too low
    IF(NOT BERKELEYDB_VERSION VERSION_EQUAL ${BERKELEYDB_FIND_VERSION} AND
        NOT BERKELEYDB_VERSION VERSION_GREATER ${BERKELEYDB_FIND_VERSION})
      set(_BERKELEYDB_VERSION_not_high_enough TRUE)
    ENDIF()
  ENDIF()
ENDIF()

# Find LIBS
IF(UNIX)
  find_library(BERKELEYDB_LIBRARY NAMES libdb_cxx.so
    HINTS ${CMAKE_SOURCE_DIR}/../../.. $ENV{BERKELEYDB_ROOT} ${BERKELEYDB_ROOT}
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local)
ELSEIF(WIN32)

ENDIF()

# Inform the users with an error message based on what version they
# have vs. what version was required.
IF(NOT BERKELEYDB_VERSION)
  set(_BERKELEYDB_EPIC_FAIL TRUE)
  IF(_BERKELEYDB_output)
    message(${_BERKELEYDB_output_type}
      "Version not found in ${_BERKELEYDB_VERSION_file}.")
  ENDIF()
ELSEIF(_BERKELEYDB_VERSION_not_high_enough)
  set(_BERKELEYDB_EPIC_FAIL TRUE)
  IF(_BERKELEYDB_output)
    message(${_BERKELEYDB_output_type}
      "Version ${BERKELEYDB_FIND_VERSION} or higher of berkeleydb is required. "
      "Version ${BERKELEYDB_VERSION} was found in ${_BERKELEYDB_VERSION_file}.")
  ENDIF()
ELSEIF(_BERKELEYDB_VERSION_not_exact)
  set(_BERKELEYDB_EPIC_FAIL TRUE)
  IF(_BERKELEYDB_output)
    message(${_BERKELEYDB_output_type}
      "Version ${BERKELEYDB_FIND_VERSION} of berkeleydb is required exactly. "
      "Version ${BERKELEYDB_VERSION} was found.")
  ENDIF()
ELSE()
  IF(BerkeleyDB_FIND_REQUIRED)
    IF(BERKELEYDB_LIBRARY MATCHES "BERKELEYDB_LIBRARY-NOTFOUND")
      message(FATAL_ERROR "Missing the berkeleydb library.\n"
        "Consider using CMAKE_PREFIX_PATH or the BERKELEYDB_ROOT environment variable. "
        "See the ${CMAKE_CURRENT_LIST_FILE} for more details.")
    ENDIF()
  ENDIF()
  find_package_handle_standard_args(BerkeleyDB DEFAULT_MSG
                                    BERKELEYDB_LIBRARY _BERKELEYDB_INCLUDE_DIR)
ENDIF()

IF(_BERKELEYDB_EPIC_FAIL)
  # Zero out everything, we didn't meet version requirements
  set(BERKELEYDB_FOUND FALSE)
  set(BERKELEYDB_LIBRARY)
  set(_BERKELEYDB_INCLUDE_DIR)
  set(BERKELEYDB_INCLUDE_DIRS)
  set(BERKELEYDB_LIBRARIES)
ELSE()
  set(BERKELEYDB_INCLUDE_DIRS ${_BERKELEYDB_INCLUDE_DIR})
  set(BERKELEYDB_LIBRARIES ${BERKELEYDB_LIBRARY})
  IF(_BERKELEYDB_output)
    message(STATUS
      "Found berkeleydb ${BERKELEYDB_VERSION} in ${BERKELEYDB_INCLUDE_DIRS};${BERKELEYDB_LIBRARIES}")
  ENDIF()
ENDIF()
