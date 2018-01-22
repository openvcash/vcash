# Dependency versions & find_package() commands in a small module for easier updating

# TODO: Remove Boost max version check when https://github.com/openvcash/vcash/issues/38 fixed
# TODO: Remove OpenSSL max version check when 1.1.x compatibility fix is merged to master branch
# TODO: Remove BerkeleyDB max version check when Vcash is compatible with version > 6.2

function(max_ver_allowed dep_name check_ver max_ver)
	IF(${check_ver} VERSION_GREATER ${max_ver})
		message(FATAL_ERROR "Detected ${dep_name} v${check_ver}, which isn't compatible! Maximum of v${max_ver} is compatible.")
	ENDIF()
endfunction()

# ~~ Boost ~~
find_package(Boost "1.54.0" COMPONENTS system REQUIRED)
# v1.66.0 removed a lot of previously working (but deprecated) things
# TODO: Remove when https://github.com/openvcash/vcash/issues/38 is fixed
max_ver_allowed("Boost" "${Boost_MAJOR_VERSION}.${Boost_MINOR_VERSION}.${Boost_SUBMINOR_VERSION}" "1.65.1")

# ~~ OpenSSL ~~
# Do not set the letter ("status") version for OpenSSL!
find_package(OpenSSL "1.0.1" REQUIRED)
max_ver_allowed("OpenSSL" ${OPENSSL_VERSION} "1.0.2")

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
  find_package(BerkeleyDB ${BERKELEYDB_MIN_VER} REQUIRED)
	max_ver_allowed("BerkeleyDB" ${BERKELEYDB_VERSION} "6.1.36")

  IF(BERKELEYDB_VERSION VERSION_LESS "6.0.0")
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
