include(FindPackageHandleStandardArgs)

IF(NOT UNIX)
  message(FATAL_ERROR "Unsported operating system when using OPENSSL_COMPAT flag - Unix only!")
ENDIF()

# Set the vars to search for
set(OPENSSL_H_NAMES "")
set(OPENSSL_L_CRYPT_NAMES "")
set(OPENSSL_L_SSL_NAMES "")
set(OPENSSL_HINTS "")
set(OPENSSL_H_SUF "")
set(OPENSSL_L_SUF "")
set(OPENSSL_PATHS "")

# While we could've just used set(), we used list() because reasons...
list(APPEND OPENSSL_H_NAMES "bn.h")
list(APPEND OPENSSL_L_CRYPT_NAMES "libcrypto.so.1.0.0" "libcrypto.so.1.0.2" "libcrypto.so.1.0")
list(APPEND OPENSSL_L_SSL_NAMES "libssl.so.1.0.0" "libssl.so.1.0.2" "libssl.so.1.0")
list(APPEND OPENSSL_HINTS "$ENV{OPENSSL-1.0_ROOT}" "$ENV{OPENSSL-1.0.2_ROOT}" "${OPENSSL-1.0_ROOT}" "${OPENSSL-1.0.2_ROOT}" "${CMAKE_SOURCE_DIR}/deps/openssl")
list(APPEND OPENSSL_H_SUF "include/openssl-1.0/openssl" "include/openssl-1.0")
list(APPEND OPENSSL_L_SUF "lib" "lib64")
list(APPEND OPENSSL_PATHS "/usr" "/usr/local" "/opt" "/opt/local")

# Find INCLUDES and LIBS
find_path(_OPENSSL_INCLUDE_DIR
  NAMES ${OPENSSL_H_NAMES}
  HINTS ${OPENSSL_HINTS}
  PATH_SUFFIXES ${OPENSSL_H_SUF}
  PATHS ${OPENSSL_PATHS}
)

find_library(_OPENSSL_CRYPTO_LIBRARY
  NAMES ${OPENSSL_L_CRYPT_NAMES}
  HINTS ${OPENSSL_HINTS}
  PATH_SUFFIXES ${OPENSSL_L_SUF}
  PATHS ${OPENSSL_PATHS}
)

find_library(_OPENSSL_SSL_LIBRARY
  NAMES ${OPENSSL_L_SSL_NAMES}
  HINTS ${OPENSSL_HINTS}
  PATH_SUFFIXES ${OPENSSL_L_SUF}
  PATHS ${OPENSSL_PATHS}
)

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
