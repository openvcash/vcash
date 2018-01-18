# Dependency versions & find_package() commands in a small module for easier updating

# TODO: Remove OPENSSL_MAX_VER and max version check when 1.1.x compatibility fix is merged to master branch
# TODO: Remove BERKELEYDB_MAX_VER and max version check when Vcash is compatible with version > 6.2

# ~~ Boost ~~
find_package(Boost "1.54.0" COMPONENTS system REQUIRED)
# v1.66.0 removed a lot of previously working (but deprecated) things
# TODO: Remove when https://github.com/openvcash/vcash/issues/38 is fixed
set(BOOST_MAX_VER "1.65.1")
# Max version check
IF(Boost_VERSION VERSION_GREATER ${BOOST_MAX_VER})
	message(FATAL_ERROR "The detected Boost v${Boost_VERSION} isn't compatible! Maximum of v${BOOST_MAX_VER} is compatible")
ENDIF()

# ~~ OpenSSL ~~
# Do not set the letter ("status") version for OpenSSL!
find_package(OpenSSL "1.0.1" REQUIRED)
set(OPENSSL_MAX_VER "1.0.2") # Used in max ver check

# Max version check
IF(OPENSSL_VERSION VERSION_GREATER ${OPENSSL_MAX_VER})
  message(FATAL_ERROR "The detected OpenSSL v${OPENSSL_VERSION} isn't compatible! Maximum of v${OPENSSL_MAX_VER} is compatible.")
ENDIF()

# Only libcoin needs Berkeley DB
IF(BUILD_VCASH_DAEMON OR INSTALL_LIBCOIN)
  # ~~ Berkeley DB ~~
  # Prevent accidental building with DB v5, which isn't compatible with wallets built with DB v6
  option(WITH_INCOMPATIBLE_BDB "Enables building with a Berkeley DB v5 minimum instead of v6 minimum." OFF)
  IF(WITH_INCOMPATIBLE_BDB)
    set(BERKELEYDB_MIN_VER "5.0.0")
  ELSE()
    set(BERKELEYDB_MIN_VER "6.0.0")
  ENDIF()
  set(BERKELEYDB_MAX_VER "6.1.36") # Last release ver before v6.2, which isn't compatible
  find_package(BerkeleyDB ${BERKELEYDB_MIN_VER} REQUIRED)

  # Max version check
  IF(BERKELEYDB_VERSION VERSION_GREATER "${BERKELEYDB_MAX_VER}")
    message(FATAL_ERROR "The detected BerkeleyDB v${BERKELEYDB_VERSION} isn't compatible! Maximum of v${BERKELEYDB_MAX_VER} is compatible.")
  # Throw a warning if the user has DB ver < 6 but continue building
  ELSEIF(BERKELEYDB_VERSION VERSION_LESS "6.0.0")
    message(WARNING "Pre-existing wallet data is not backwards compatible with version v5 of Berkeley DB if it was originally built with v6. Read https://github.com/openvcash/vcash/wiki/Compile-With-Cmake#preamble--warning for more info.")
  ENDIF()
ENDIF()

# ~~ Threads ~~
# Only default threads settings if none were passed by the user
IF(NOT CMAKE_USE_SPROC_INIT AND NOT CMAKE_USE_WIN32_THREADS_INIT AND NOT CMAKE_USE_PTHREADS_INIT AND NOT CMAKE_HP_PTHREADS_INIT AND NOT CMAKE_THREAD_PREFER_PTHREAD AND NOT THREADS_PREFER_PTHREAD_FLAG)
  IF(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    message(STATUS "${CMAKE_SYSTEM_NAME} detected, using WIN32 threads...")
    # Tells FindThreads to get the WIN32 threads
    set(CMAKE_USE_WIN32_THREADS_INIT ON)
  ELSE()
    # Tells find_package(Threads) to get pthread.h & use -lpthread compile flag
    message(STATUS "Non-Windows OS detected, defaulting to using pthreads...")
    set(THREADS_PREFER_PTHREAD_FLAG ON)
  ENDIF()
ENDIF()

# Code uses #include <thread>
find_package(Threads REQUIRED)
