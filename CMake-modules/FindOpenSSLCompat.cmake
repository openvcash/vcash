# Copyright (c) 2014 Stefan.Eilemann@epfl.ch

# - Try to find the openssl library
# Once done this will define
#
#  OPENSSL_ROOT - Set this variable to the root installation
#
# Read-Only variables:
#  OPENSSL_FOUND - system has the openssl library
#  OPENSSL_INCLUDE_DIR - the openssl include directory
#  OPENSSL_LIBRARIES - The libraries needed to use openssl
#  OPENSSL_VERSION - This is set to $major.$minor.$patch (eg. 0.9.8)

# Original that this was created from: https://github.com/egparedes/CMake/blob/master/Findleveldb.cmake

include(FindPackageHandleStandardArgs)

IF(OpenSSL_FIND_REQUIRED)
  set(_OPENSSL_output_type FATAL_ERROR)
else()
  set(_OPENSSL_output_type STATUS)
ENDIF()

IF(OpenSSL_FIND_QUIETLY)
  set(_OPENSSL_output)
else()
  set(_OPENSSL_output 1)
ENDIF()

# Find INCLUDES
IF(UNIX)
  find_path(_OPENSSL_INCLUDE_DIR NAMES bn.h
    PATH_SUFFIXES include/openssl-1.0/openssl include/openssl-1.0
    PATHS /usr /usr/local /opt /opt/local)

    # Feed the DIR into vars, checking which file was found
    IF(_OPENSSL_INCLUDE_DIR AND EXISTS "${_OPENSSL_INCLUDE_DIR}/opensslv.h")
      set(_OPENSSL_VERSION_file "${_OPENSSL_INCLUDE_DIR}/opensslv.h")

    ELSE()
      set(_OPENSSL_EPIC_FAIL TRUE)

      IF(_OPENSSL_output)
        message(${_OPENSSL_output_type}
        "Can't find openssl-1.0 header file bn.h")
      ENDIF()
    ENDIF()
ELSE()
  # Fail if not Unix
  message(FATAL_ERROR "Unsported operating system!")
ENDIF()

# System-independant stuff for after getting INCLUDES
file(READ ${_OPENSSL_VERSION_file} _OPENSSL_header_contents)

string(REGEX REPLACE ".*OPENSSL_VERSION_TEXT    \"OpenSSL ([0-9]+)\\.([0-9]+)\\.([0-9]+)([a-z]).*"
"\\1.\\2.\\3\\4" _OPENSSL_VERSION "${_OPENSSL_header_contents}")

set(OPENSSL_VERSION ${_OPENSSL_VERSION} CACHE INTERNAL
"The version of openssl which was detected")
#".*OpenSSL.+[0-9]\\.[0-9]\\.[0-9][a-z]"

# Set root directory
string(REGEX MATCH ".*/openssl-1.0" OPENSSL_ROOT_DIR ${_OPENSSL_INCLUDE_DIR})

# Version checking
IF(OPENSSL_FIND_VERSION AND OPENSSL_VERSION)
  IF(OPENSSL_FIND_VERSION_EXACT)
    IF(NOT OPENSSL_VERSION VERSION_EQUAL ${OPENSSL_FIND_VERSION})
      set(_OPENSSL_VERSION_not_exact TRUE)
    ENDIF()
  else()
    # version is too low
    IF(NOT OPENSSL_VERSION VERSION_EQUAL ${OPENSSL_FIND_VERSION} AND
        NOT OPENSSL_VERSION VERSION_GREATER ${OPENSSL_FIND_VERSION})
      set(_OPENSSL_VERSION_not_high_enough TRUE)
    ENDIF()
  ENDIF()
ENDIF()

# Find LIBS
IF(UNIX)
  find_library(OPENSSL_CRYPTO_LIBRARY NAMES "libcrypto.so.1.0.0" "libcrypto.so.1.0.2" "libcrypto.so.1.0"
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local)

  find_library(OPENSSL_SSL_LIBRARY NAMES "libssl.so.1.0.0" "libssl.so.1.0.2" "libssl.so.1.0"
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local)
ELSE()
  # Fail if not Unix
  message(FATAL_ERROR "Unsported operating system!")
ENDIF()

# Inform the users with an error message based on what version they
# have vs. what version was required.
IF(NOT OPENSSL_VERSION)
  set(_OPENSSL_EPIC_FAIL TRUE)
  IF(_OPENSSL_output)
    message(${_OPENSSL_output_type}
      "Version not found in ${_OPENSSL_VERSION_file}.")
  ENDIF()
ELSEIF(_OPENSSL_VERSION_not_high_enough)
  set(_OPENSSL_EPIC_FAIL TRUE)
  IF(_OPENSSL_output)
    message(${_OPENSSL_output_type}
      "Version ${OPENSSL_FIND_VERSION} or higher of openssl is required. "
      "Version ${OPENSSL_VERSION} was found in ${_OPENSSL_VERSION_file}.")
  ENDIF()
ELSEIF(_OPENSSL_VERSION_not_exact)
  set(_OPENSSL_EPIC_FAIL TRUE)
  IF(_OPENSSL_output)
    message(${_OPENSSL_output_type}
      "Version ${OPENSSL_FIND_VERSION} of openssl is required exactly. "
      "Version ${OPENSSL_VERSION} was found.")
  ENDIF()
ELSE()
  IF(OpenSSL_FIND_REQUIRED)
    IF(NOT (${OPENSSL_CRYPTO_LIBRARY} AND ${OPENSSL_SSL_LIBRARY}))
      message(FATAL_ERROR "Missing the openssl libraries.\n"
        "Consider using CMAKE_PREFIX_PATH or the OPENSSL_ROOT environment variable. "
        "See the ${CMAKE_CURRENT_LIST_FILE} for more details.")
    ENDIF()
  ENDIF()
  find_package_handle_standard_args(OpenSSLCompat DEFAULT_MSG
  OPENSSL_SSL_LIBRARY OPENSSL_CRYPTO_LIBRARY _OPENSSL_INCLUDE_DIR)
ENDIF()

IF(_OPENSSL_EPIC_FAIL)
  # Zero out everything, we didn't meet version requirements
  set(OPENSSL_FOUND FALSE)
  set(OPENSSL_LIBRARY)
  set(_OPENSSL_INCLUDE_DIR)
  set(OPENSSL_INCLUDE_DIR)
  set(OPENSSL_LIBRARIES)
ELSE()
  set(OPENSSL_FOUND TRUE)
  set(OPENSSL_INCLUDE_DIR ${_OPENSSL_INCLUDE_DIR})
  set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
  IF(_OPENSSL_output)
    message(STATUS
    "Found OpenSSL (COMPAT): ${OPENSSL_VERSION} in ${OPENSSL_ROOT_DIR};${OPENSSL_INCLUDE_DIR};${OPENSSL_LIBRARIES}")
  ENDIF()
ENDIF()
