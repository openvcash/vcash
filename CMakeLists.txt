CMAKE_MINIMUM_REQUIRED(VERSION 3.2.3)
# == START Minimum version requirement list ==
# 3.0 for versioning inside of project()
# 3.1 for set(THREADS_PREFER_PTHREAD_FLAG ON)
# 3.1.3 for CMAKE_CXX_STANDARD
# 3.2.3 for OPENSSL_CRYPTO_LIBRARY and OPENSSL_SSL_LIBRARY
# EVENTUALLY: 3.7.2 for CMAKE_FIND_PACKAGE_SORT_ORDER and CMAKE_FIND_PACKAGE_SORT_DIRECTION
# EVENTUALLY: 3.9 for the addition of a DESCRIPTION to project()
# == END Minimum version requirement list ==

# Get version string from constants.hpp and feed it into the project var
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/coin/include/coin/constants.hpp PROJECT_VER REGEX "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
project(Vcash VERSION ${PROJECT_VER} LANGUAGES C CXX)

# Default to a release build if nothing is specified
IF(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
ENDIF()

# Require/Build for C++11 | Consider changing to target_compile_features in the future -sum01
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_CXX_EXTENSIONS OFF) # Was recommended to be set to OFF by https://crascit.com/2015/03/28/enabling-cxx11-in-cmake/ -sum01
#add_definitions("-D_FILE_OFFSET_BITS=64" "-DBOOST_NO_CXX11_NUMERIC_LIMITS") # Unsure if needed
# Old comments taken out of add_definitions, unsure if important -sum01
  # Temporarily disable Alerts
  # "-DBYPASS_ALERTS"
  # -DOLD_VCASH"

# Dependency versions | Trying to keep them at the max of what's in Ubuntu repo's, but these are only used as minimums.
# Someone good at REGEX should consider pulling these from docs/dependencies.md instead of manually entering them. -sum01
set(OPENSSL_MIN_VER "1.0.2")
set(BOOST_MIN_VER "1.60.0")
set(BERKELEYDB_MIN_VER "5.3.0")
set(LEVELDB_MIN_VER "1.18")
# set(THREADS_MIN_VER "???")

# Important settings for finding dependencies
#set(CMAKE_FIND_PACKAGE_SORT_ORDER NATURAL) # Sort into order by ver
#set(CMAKE_FIND_PACKAGE_SORT_DIRECTION DEC) # Pick the highest ver accepted
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-modules) # Adds our find_package modules to the list of modules available for cmake

set(CMAKE_THREAD_PREFER_PTHREAD ON) # Redundant with PTHREAD_FLAG most likely
#set(THREADS_PREFER_PTHREAD_FLAG ON) # Tells find_package(Threads) to use pthread flags

# Start of finding dependencies
find_package(Boost ${BOOST_MIN_VER} REQUIRED COMPONENTS system) #COMPONENTS system) # Is system needed?
find_package(Threads REQUIRED)
find_package(LevelDB ${LEVELDB_MIN_VER} REQUIRED)
find_package(BerkeleyDB ${BERKELEYDB_MIN_VER} REQUIRED)
find_package(OpenSSL ${OPENSSL_MIN_VER} EXACT)

# Work-around for Arch (and maybe other rolling-releases?) to get pre-1.1 OpenSSL -sum01
IF(NOT OPENSSL_FOUND AND UNIX)
    find_path(OPENSSL_INCLUDE_DIR_ALT NAMES bn.h
      PATH_SUFFIXES include/openssl-1.0/openssl include/openssl-1.0
      PATHS /usr /usr/local /opt /opt/local)

    find_library(OPENSSL_CRYPTO_LIBRARY_ALT NAMES "libcrypto.so.1.0.0" "libcrypto.so.1.0.2" "libcrypto.so.1.0"
      PATH_SUFFIXES lib lib64
      PATHS /usr /usr/local /opt /opt/local)

    find_library(OPENSSL_SSL_LIBRARY_ALT NAMES "libssl.so.1.0.0" "libssl.so.1.0.2" "libssl.so.1.0"
      PATH_SUFFIXES lib lib64
      PATHS /usr /usr/local /opt /opt/local)

    IF(OPENSSL_INCLUDE_DIR_ALT AND OPENSSL_CRYPTO_LIBRARY_ALT AND OPENSSL_SSL_LIBRARY_ALT)
      set(OPENSSL_FOUND TRUE)
      set(OPENSSL_VERSION "1.0.2") # Doesn't get checked anywhere, probably pointless
      # The find commands don't seem to overwrite these well (or at all?), so we force it
      set(OPENSSL_INCLUDE_DIR ${OPENSSL_INCLUDE_DIR_ALT})
      set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARY_ALT})
      set(OPENSSL_SSL_LIBRARY ${OPENSSL_SSL_LIBRARY_ALT})
      set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    ENDIF()
ENDIF()

# Fail if the workaround doesn't find OpenSSL | Double-check, but put outside of above IF, as WIN32 could get past without it.
IF(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "Error: The OpenSSL dependency could not be found, even after trying a workaround.")
ENDIF()

# Sources for coin
SET(SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/account.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/accounting_entry.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/address.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/address_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/alert.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/alert_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/alert_unsigned.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/base58.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/big_number.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/blake256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/block_index.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/block_index_disk.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/block_locator.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/block_merkle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender_broadcast.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender_join.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender_leave.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/chainblender_status.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/checkpoints.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/checkpoint_sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/checkpoint_sync_unsigned.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/configuration.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/crypter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/database_stack.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db_env.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db_tx_bdb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db_tx.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db_tx_ldb.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/db_wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/ecdhe.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/file.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/filesystem.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/gateway.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/globals.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/hash.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/hc256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/hd_configuration.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/hd_ecdsa.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/hd_keychain.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/http_transport.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_answer.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_collaterals.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_question.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_sync.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/incentive_vote.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/inventory_vector.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/kernel.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_pool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_public.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_reserved.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_store_basic.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_store_crypto.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/key_wallet_master.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/merkle_tree_partial.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/message.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/mining.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/mining_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/nat_pmp_client.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/nat_pmp.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/pbkdf2.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/point_in.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/point_out.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/reward.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/ripemd160.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/rpc_connection.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/rpc_json_parser.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/rpc_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/rpc_server.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/rpc_transport.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/script_checker.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/script_checker_queue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/script.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/secret.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/sha256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/signature_cache.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/stack.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/stack_impl.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/status_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/tcp_acceptor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/tcp_connection.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/tcp_connection_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/tcp_transport.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_bloom_filter.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_in.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_index.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_merkle.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_out.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_pool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_position.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/transaction_wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/upnp_client.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/utility.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/wallet.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/wallet_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/whirlpool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime_answer.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime_lock.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime_manager.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime_question.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/coin/src/zerotime_vote.cpp
	)

set(DATABASE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/block.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/broadcast_operation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/compression.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/ecdhe.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/entry.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/find_operation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/hc256.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/key_pool.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/message.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/node.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/node_impl.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/operation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/operation_queue.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/ping_operation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/query.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/routing_table.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/rpc.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/slot.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/stack.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/stack_impl.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/storage.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/store_operation.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/udp_handler.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/udp_multiplexor.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/database/src/whirlpool.cpp
	)

include_directories(
	${CMAKE_CURRENT_SOURCE_DIR}/coin/include
	${CMAKE_CURRENT_SOURCE_DIR}/database/include
	${Boost_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
  ${LEVELDB_INCLUDE_DIR}
  ${BERKELEYDB_INCLUDE_DIR}
  )

add_library(coin ${SOURCES}) # Optional: a STATIC/SHARED/MODULE before the source | Not sure what it should be, so letting it auto-detect
add_library(database ${DATABASE_SOURCES}) # Optional: a STATIC/SHARED/MODULE before the source | Not sure what it should be, so letting it auto-detect
add_executable(vcashd ${CMAKE_CURRENT_SOURCE_DIR}/coin/test/main.cpp)
target_link_libraries(vcashd coin database ${LEVELDB_LIBRARIES} ${BERKELEYDB_LIBRARIES} ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} ${CMAKE_THEAD_LIBS_INIT}) # Is Threads needed?

# This needs a IF(UNIX) ELSEIF(WIN32), I think...

install(TARGETS vcashd database coin
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib/static) # Does coin actually need to be in lib/static ?
#install(TARGETS database DESTINATION /some/full/path) # seems redundant, but it's shown in docs
