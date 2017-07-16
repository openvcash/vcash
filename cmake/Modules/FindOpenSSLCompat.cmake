include(FindPackageHandleStandardArgs)

# Find INCLUDES and LIBS
IF(UNIX)
  find_path(_OPENSSL_INCLUDE_DIR
    NAMES bn.h
    HINTS $ENV{OPENSSL-1.0_ROOT} $ENV{OPENSSL-1.0.2_ROOT} ${OPENSSL-1.0_ROOT} ${OPENSSL-1.0.2_ROOT} ${CMAKE_SOURCE_DIR}/deps
    PATH_SUFFIXES include/openssl-1.0/openssl include/openssl-1.0
    PATHS /usr /usr/local /opt /opt/local
  )

  find_library(_OPENSSL_CRYPTO_LIBRARY
    NAMES "libcrypto.so.1.0.0" "libcrypto.so.1.0.2" "libcrypto.so.1.0"
    HINTS $ENV{OPENSSL-1.0_ROOT} $ENV{OPENSSL-1.0.2_ROOT} ${OPENSSL-1.0_ROOT} ${OPENSSL-1.0.2_ROOT} ${CMAKE_SOURCE_DIR}/deps
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local
  )

  find_library(_OPENSSL_SSL_LIBRARY
    NAMES "libssl.so.1.0.0" "libssl.so.1.0.2" "libssl.so.1.0"
    HINTS $ENV{OPENSSL-1.0_ROOT} $ENV{OPENSSL-1.0.2_ROOT} ${OPENSSL-1.0_ROOT} ${OPENSSL-1.0.2_ROOT} ${CMAKE_SOURCE_DIR}/deps
    PATH_SUFFIXES lib lib64
    PATHS /usr /usr/local /opt /opt/local
  )
ELSE()
  # Fail if not Unix
  message(FATAL_ERROR "Unsported operating system when using OPENSSL_COMPAT flag! UNIX only.")
ENDIF()

# Checks if the version file exists, save the version file to a var, and fail if there's no version file
IF(_OPENSSL_INCLUDE_DIR AND EXISTS "${_OPENSSL_INCLUDE_DIR}/opensslv.h")
  set(_OPENSSL_VERSION_file "${_OPENSSL_INCLUDE_DIR}/opensslv.h")
ELSE()
  message(FATAL_ERROR "Error: Can't find OpenSSL-1.0 header file opensslv.h")
ENDIF()

# Parse the OpenSSL-1.0 version, but ignore the letter
file(READ ${_OPENSSL_VERSION_file} _OPENSSL_header_contents)
string(REGEX REPLACE ".*OPENSSL_VERSION_TEXT    \"OpenSSL ([0-9]+)\\.([0-9]+)\\.([0-9]+)[a-z].*"
"\\1.\\2.\\3" OPENSSL_VERSION "${_OPENSSL_header_contents}")

# Should fail if the vars aren't found | FOUND_VAR is obsolete and only for older versions of cmake.
# Underscore in front of vars because the docs recommend it https://cmake.org/cmake/help/latest/module/FindPackageHandleStandardArgs.html
# "... these should typically be cache entries such as FOO_LIBRARY and not output variables like FOO_LIBRARIES."
find_package_handle_standard_args(OpenSSL
  FOUND_VAR OPENSSL_FOUND
  REQUIRED_VARS _OPENSSL_SSL_LIBRARY _OPENSSL_CRYPTO_LIBRARY _OPENSSL_INCLUDE_DIR
  VERSION_VAR OPENSSL_VERSION
  )

# Sets the correct, non-cached variables that will be used in CMakeLists.txt
set(OPENSSL_INCLUDE_DIR ${_OPENSSL_INCLUDE_DIR})
set(OPENSSL_SSL_LIBRARY ${_OPENSSL_SSL_LIBRARY})
set(OPENSSL_CRYPTO_LIBRARY ${_OPENSSL_CRYPTO_LIBRARY})
set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
