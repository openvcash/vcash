/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash developers
 *
 * This file is part of vcash.
 *
 * vcash is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License with
 * additional permissions to the one published by the Free Software
 * Foundation, either version 3 of the License, or (at your option)
 * any later version. For more information see LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef COIN_STACK_IMPL_HPP
#define COIN_STACK_IMPL_HPP

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include <boost/asio.hpp>

#include <coin/big_number.hpp>
#include <coin/configuration.hpp>
#include <coin/db_wallet.hpp>
#include <coin/point_out.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class address_manager;
    class alert_manager;
    class block;
    class block_index;
    class block_merkle;
    class chainblender_manager;
    class database_stack;
    class db_env;
    class incentive_manager;
    class mining_manager;
    class nat_pmp_client;
    class rpc_manager;
    class stack;
    class status_manager;
    class tcp_acceptor;
    class tcp_connection;
    class tcp_connection_manager;
    class upnp_client;
    class zerotime_manager;
    
    /**
     * The stack implementation.
     */
    class stack_impl
    {
        public:
        
            /**
             * Constructor
             * @param owner The stack.
             */
            stack_impl(coin::stack &);
            
            /**
             * Starts the stack.
             */
            void start();
        
            /**
             * Stops the stack.
             */
            void stop();
        
            /**
             * Sends coins.
             * @param amount The amount.
             * @param destination The destination.
             * @param wallet_values The wallet ke/values.
             */
            void send_coins(
                const std::int64_t & amount, const std::string & destination,
                const std::map<std::string, std::string> & wallet_values
            );
        
            /** 
             * Starts mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void start_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /** 
             * Stops mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void stop_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /**
             * Broadcasts an alert.
             * @param pairs An std::map<std::string, std::string>.
             */
            void broadcast_alert(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Encrypts the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_encrypt(const std::string & passphrase);
        
            /**
             * Locks the wallet.
             */
            void wallet_lock();
            
            /**
             * Unlocks the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_unlock(const std::string & passphrase);
        
            /**
             * Changes the wallet passphrase.
             * @param passphrase_old The old passphrase.
             * @param password_new The new passphrase.
             */
            void wallet_change_passphrase(
                const std::string & passphrase_old,
                const std::string & password_new
            );
            
            /**
             * The local endpoint.
             */
            const boost::asio::ip::tcp::endpoint & local_endpoint() const;
        
            /**
             * If true a wallet file exists.
             */
            static bool wallet_exists(const bool & is_client);
            
            /**
             * If true the wallet is crypted.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_crypted(const std::uint32_t & wallet_id);
        
            /**
             * If true the wallet is locked.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_locked(const std::uint32_t & wallet_id);

            /**
             * Performs a ZeroTime lock on the transaction.
             * @param tx_id The transaction id.
             */
            void wallet_zerotime_lock(const std::string & tx_id);
        
            /**
             * Get's the wallet HD keychain seed (if configured).
             */
            std::string wallet_hd_keychain_seed();
        
            /**
             * Generates a new wallet address.
             * @param label The label.
             */
            void wallet_generate_address(const std::string & label);
            
            /**
             * Starts chainblender.
             */
            void chainblender_start();
        
            /**
             * Stops chainblender.
             */
            void chainblender_stop();
            
            /**
             * Sends an RPC command line.
             * @param command_line The command line.
             */
            void rpc_send(const std::string & command_line);
        
            /**
             * Rescans the chain.
             */
            void rescan_chain();
            
            /**
             * Sets the wallet.transaction.history.maximum
             * @param val The value.
             */
            void set_configuration_wallet_transaction_history_maximum(
                const std::time_t & val
            );
        
            /**
             * The wallet.transaction.history.maximum.
             */
            const std::time_t
                configuration_wallet_transaction_history_maximum() const
            ;
        
            /**
             * Sets chainblender to use common output denominations.
             * @param val The value.
             */
            void set_configuration_chainblender_use_common_output_denominations(
                const bool & val
            );
        
            /**
             * The chainblender.use_common_output_denominations.
             */
            const bool
                configuration_chainblender_use_common_output_denominations()
            const;
            
            /**
             * Performs an http get operation toward the url.
             * @param url The url.
             * @param f The function.
             */
            void url_get(
                const std::string & url,
                const std::function<void (const std::map<std::string,
                std::string> &, const std::string &)> & f
            );
        
            /**
             * Performs an http post operation toward the url.
             * @param url The url.
             * @param port The port.
             * @param headers The headers.
             * @param body The body.
             * @param f The function.
             */
            void url_post(
                const std::string & url,
                const std::uint16_t & port,
                const std::map<std::string, std::string> & headers,
                const std::string & body,
                const std::function<void (const std::map<std::string,
                std::string> &,
                const std::string &)> & f
            );
        
            /**
             * Processes a block from a network connection.
             * @param connection The tcp_connection.
             * @param blk The block.
             */
            bool process_block(
                const std::shared_ptr<tcp_connection> & connection,
                const std::shared_ptr<block> & blk
            );
        
            /**
             * Saves the (SPV) block_merkle's.
             */
            void spv_block_merkles_save();
        
            /**
             * Loads the (SPV) block_merkle's.
             * @param trys The number of recursive trys,
             */
            void spv_block_merkles_load(std::uint8_t & trys);
        
            /**
             * The configuration.
             */
            configuration & get_configuration();
        
            /**
             * The address_manager.
             */
            std::shared_ptr<address_manager> & get_address_manager();
        
            /**
             * The alert_manager.
             */
            std::shared_ptr<alert_manager> & get_alert_manager();
        
            /**
             * The chainblender_manager.
             */
            std::shared_ptr<chainblender_manager> & get_chainblender_manager();
        
            /**
             * The database_stack.
             */
            std::shared_ptr<database_stack> & get_database_stack();
        
            /**
             * The mining_manager.
             */
            std::shared_ptr<mining_manager> & get_mining_manager();
        
            /**
             * The status_manager.
             */
            std::shared_ptr<status_manager> & get_status_manager();
        
            /**
             * The status_manager.
             */
            const std::shared_ptr<status_manager> & get_status_manager() const;
        
            /**
             * The tcp_acceptor.
             */
            std::shared_ptr<tcp_acceptor> & get_tcp_acceptor();
        
            /**
             * The tcp_connection_manager.
             */
            std::shared_ptr<tcp_connection_manager> &
                get_tcp_connection_manager()
            ;
        
            /**
             * The zerotime_manager.
             */
            std::shared_ptr<zerotime_manager> & get_zerotime_manager();
        
            /**
             * The incentive_manager.
             */
            std::shared_ptr<incentive_manager> & get_incentive_manager();

            /**
             * The main std::recursive_mutex.
             */
            static std::recursive_mutex & mutex();

            /**
             * The db_env
             */
            static std::shared_ptr<db_env> & get_db_env();
        
            /**
             * Set's the genesis block.
             */
            static void set_block_index_genesis(block_index * val);
        
            /**
             * The genesis block index.
             */
            static block_index * get_block_index_genesis();
        
            /**
             * The seen stake.
             */
            static std::set<
                std::pair<point_out, std::uint32_t>
            > & get_seen_stake();
        
            /**
             * Set's the best block index.
             * @param val The block_index.
             */
            static void set_block_index_best(block_index * val);
        
            /**
             * The best block index.
             */
            static block_index * get_block_index_best();
        
            /**
             * The best chain trust.
             */
            static big_number & get_best_chain_trust();
        
            /**
             * The best invalid trust.
             */
            static big_number & get_best_invalid_trust();
        
            /**
             * Inserts a block index.
             * @param hash_block The hash of the block.
             */
            static block_index * insert_block_index(
                const sha256 & hash_block
            );

            /**
             * The number of blocks we have.
             */
            const std::int32_t & local_block_count() const;
        
            /**
             * The number of blocks other peers have.
             */
            const std::uint32_t peer_block_count() const;

            /**
             * The block difficulty.
             * index The block_index.
             */
            double difficulty(block_index * index = 0) const;

            /**
             * Calculates the average network hashes per second based on the
             * last N blocks.
             */
            std::uint64_t network_hash_per_second();

            /**
             * Called when an error occurs.
             * @param pairs The key/value pairs.
             */
            void on_error(const std::map<std::string, std::string> & pairs);
        
            /**
             * Called when a status update occurs.
             * @param pairs The key/value pairs.
             */
            void on_status(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when an alert is received.
             * @param pairs The key/value pairs.
             */
            void on_alert(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when an (SPV) merkleblock is received.
             * @param connection The tcp_connection.
             * @param merkle_block The block_merkle.
             * @param transactions_received The transactions we've received that
             * match the current block_merkle's transaction hashes.
             */
            void on_spv_merkle_block(
                const std::shared_ptr<tcp_connection> & connection,
                block_merkle & merkle_block,
                const std::vector<transaction> & transactions_received
            );
        
            /**
             * Sets the (SPV) block height with time and filtered transaction
             * hashes.
             * @param height The height.
             * @param time The time.
             @ @param hashes_tx The (matched) transaction hashes.
             */
            void set_spv_block_height(
                const std::int32_t & height, const std::time_t & time,
                const std::vector<sha256> & hashes_tx
            );
            
        private:
        
            /**
             * Called periodically to inform about blocks.
             */
            void on_status_block();
        
            /**
             * Called periodically to inform about wallet.
             */
            void on_status_wallet();
        
            /**
             * Called periodically to inform about blockchain.
             */
            void on_status_blockchain();
        
            /**
             * Called periodically to perform maintenance on the database
             * environment.
             */
            void on_database_env();
        
            /**
             * The local endpoint.
             */
            boost::asio::ip::tcp::endpoint m_local_endpoint;
        
            /**
             * The configuration.
             */
            configuration m_configuration;
        
            /**
             * The address_manager.
             */
            std::shared_ptr<address_manager> m_address_manager;
        
            /**
             * The alert_manager.
             */
            std::shared_ptr<alert_manager> m_alert_manager;
        
            /**
             * The chainblender_manager.
             */
            std::shared_ptr<chainblender_manager> m_chainblender_manager;
        
            /**
             * The database_stack.
             */
            std::shared_ptr<database_stack> m_database_stack;
        
            /**
             * The mining_manager.
             */
            std::shared_ptr<mining_manager> m_mining_manager;
        
            /**
             * The nat_pmp_client.
             */
            std::shared_ptr<nat_pmp_client> m_nat_pmp_client;
        
            /**
             * The rpc_manager.
             */
            std::shared_ptr<rpc_manager> m_rpc_manager;
        
            /**
             * The status_manager.
             */
            std::shared_ptr<status_manager> m_status_manager;
            
            /**
             * The tcp_acceptor.
             */
            std::shared_ptr<tcp_acceptor> m_tcp_acceptor;
        
            /**
             * The tcp_connection_manager.
             */
            std::shared_ptr<tcp_connection_manager> m_tcp_connection_manager;
        
            /**
             * The upnp_client.
             */
            std::shared_ptr<upnp_client> m_upnp_client;
        
            /**
             * The zerotime_manager.
             */
            std::shared_ptr<zerotime_manager> m_zerotime_manager;
        
            /**
             * The incentive_manager.
             */
            std::shared_ptr<incentive_manager> m_incentive_manager;

            /**
             * The main std::recursive_mutex.
             */
            static std::recursive_mutex g_mutex;
        
            /**
             * The db_env
             */
            static std::shared_ptr<db_env> g_db_env;
        
            /**
             * The genesis block index.
             */
            static block_index * g_block_index_genesis;
        
            /**
             * The seen stake.
             */
            static std::set< std::pair<point_out, std::uint32_t> > g_seen_stake;

            /**
             * The best block index.
             */
            static block_index * g_block_index_best;
        
            /**
             * The best chain trust.
             */
            static big_number g_best_chain_trust;
        
            /**
             * The best invalid trust.
             */
            static big_number g_best_invalid_trust;
        
        protected:
    
            /**
             * Creates suport directories.
             */
            void create_directories();
        
            /**
             * Loads the blkindex.dat file.
             * @param f The callback function.
             */
            void load_block_index(
                const std::function<void (const bool & success)> & f
            );
        
            /**
             * Loads the wallet from disk.
             * @param f The std::function.
             */
            void load_wallet(
                const std::function<void (const bool & first_run,
                const db_wallet::error_t & err)> & f
            );
        
            /**
             * Creates a backup of the last wallet file.
             * @note This deletes the oldest backup from disk.
             */
            void backup_last_wallet_file();
        
            /**
             * Trys to lock the lock file or exits.
             */
            void lock_file_or_exit();
        
            /**
             * Exports the blk000x.dat files into a blockchain.dat file.
             */
            bool export_blockchain_file();
        
            /**
             * Imports a blockchain file from disk.
             * @param path The path.
             */
            bool import_blockchain_file(const std::string & path);
        
            /**
             * Prunes old blocks from disk.
             */
            void prune_old_blocks();
        
            /**
             * The main loop.
             */
            void loop();

            /**
             * Checks for centrally hosted bootstrap peers.
             * @param interval The interval.
             */
            void do_check_peers(const std::uint32_t & interval);
        
            /**
             * The stack.
             */
            coin::stack & stack_;
        
            /**
             * The boost::asio::io_service::work.
             */
            std::shared_ptr<boost::asio::io_service::work> work_;
        
            /**
             * The thread.
             */
            std::vector< std::shared_ptr<std::thread> > threads_;
        
            /**
             * The std::recursive_mutex.
             */
            std::recursive_mutex mutex_callback_;
        
            /**
             * The block status timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_status_block_;
        
            /**
             * The blockchain status timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_status_blockchain_;
        
            /**
             * The wallet status timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_status_wallet_;
        
            /**
             * The database environment timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_database_env_;
        
            /**
             * The (SPV) block_merkle's save timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_block_merkles_save_;
    };
    
} // namespace coin

#endif // COIN_STACK_IMPL_HPP
