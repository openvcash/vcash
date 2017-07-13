CMAKE_MINIMUM_REQUIRED(VERSION 3.2.3)
# == START Minimum version requirement list ==
# 3.0 for versioning inside of project()
# 3.1 for set(THREADS_PREFER_PTHREAD_FLAG ON)
# 3.1.3 for CMAKE_CXX_STANDARD
# 3.2.3 for OPENSSL_CRYPTO_LIBRARY and OPENSSL_SSL_LIBRARY
# EVENTUALLY: 3.7.2 for CMAKE_FIND_PACKAGE_SORT_ORDER and CMAKE_FIND_PACKAGE_SORT_DIRECTION
# EVENTUALLY: 3.9 for the addition of a DESCRIPTION to project()
# == END Minimum version requirement list ==

# Check for user-provided install/bin/lib paths
IF(NOT (CMAKE_INSTALL_PREFIX AND CMAKE_INSTALL_BINDIR AND CMAKE_INSTALL_LIBDIR))
  message(FATAL_ERROR "Error: You did not provide the needed installation/binary/library path(s).")
ENDIF()

# Get version string from constants.hpp and feed it into the project var
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/coin/include/coin/constants.hpp" PROJECT_VER_STRING)
string(REGEX REPLACE ".*version_string = \"([0-9]+)\\.([0-9]+)\\.([0-9]+)\\.([0-9]+).*"
"\\1.\\2.\\3.\\4" PROJECT_VER "${PROJECT_VER_STRING}")

message("Vcash version: ${PROJECT_VER}")
project(Vcash VERSION ${PROJECT_VER} LANGUAGES C CXX)#

# Adds an optional cmake build flag for machines with OpenSSL v1.1+
option(OPENSSL_COMPAT "Target OpenSSL-1.0 on machines with 1.1+" OFF)

# Default to a release build if nothing is specified
IF(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
ENDIF()

# Require/Build for C++11 | Consider changing to target_compile_features in the future -sum01
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependency versions
set(OPENSSL_MIN_VER "1.0.2") # EXACT
set(BOOST_MIN_VER "1.54.0") # Minimum
set(BERKELEYDB_MIN_VER "5.3.0") # Minimum

# Adds our find_package modules to the list of modules available for cmake
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/CMake-modules)

# Start of finding dependencies
find_package(Boost ${BOOST_MIN_VER} REQUIRED COMPONENTS system)# Is system needed?
find_package(BerkeleyDB ${BERKELEYDB_MIN_VER} REQUIRED)

IF(OPENSSL_COMPAT)
  # Work-around for Arch (and maybe other rolling-releases?) to get pre-1.1 OpenSSL -sum01
  find_package(OpenSSLCompat ${OPENSSL_MIN_VER} EXACT REQUIRED)
ELSE()
  # If no workaround required, find normally
  find_package(OpenSSL ${OPENSSL_MIN_VER} EXACT REQUIRED)
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
  ${BERKELEYDB_INCLUDE_DIRS}
  )

add_library(coin ${SOURCES}) # Optional: a STATIC/SHARED/MODULE before the source | Not sure what it should be, so letting it auto-detect
add_library(database ${DATABASE_SOURCES}) # Optional: a STATIC/SHARED/MODULE before the source | Not sure what it should be, so letting it auto-detect
add_executable(vcashd ${CMAKE_CURRENT_SOURCE_DIR}/coin/test/main.cpp)

target_link_libraries(vcashd coin database ${BERKELEYDB_LIBRARIES} ${OPENSSL_LIBRARIES} ${Boost_LIBRARIES} -lpthread)

# Tells Make where to put the files when running Make install, might not be Windows-safe
install(TARGETS vcashd database coin
  RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
