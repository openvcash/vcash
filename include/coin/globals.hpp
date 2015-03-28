/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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

#ifndef COIN_GLOBALS_HPP
#define COIN_GLOBALS_HPP

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <set>

#include <boost/asio.hpp>

#include <coin/block_index.hpp>
#include <coin/constants.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/median_filter.hpp>
#include <coin/point_out.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>

/**
 * Enable to use whirlpool over scrypt.
 */
#define USE_WHIRLPOOL 1

namespace coin {

    class block;
    class data_buffer;
    class script;
    class wallet;
    
    /**
     * Implements a settable global variables. It is ok for this to be a
     * singleton even in the presence of multiple instances in the same
     * memory space.
     */
    class globals
    {
        public:

            /**
             * The (application) states.
             */
            typedef enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped
            } state_t;
        
            /**
             * Constructor
             */
            globals();
        
            /**
             * The singleton accessor.
             */
            static globals & instance()
            {
                static globals g_globals;
                
                return g_globals;
            }
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service()
            {
                return m_io_service;
            }
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand()
            {
                return m_strand;
            }
        
            /**
             * Sets the state.
             * @param val The state_t.
             */
            void set_state(const state_t & val)
            {
                m_state = val;
            }
        
            /**
             * The state.
             */
            const state_t & state() const
            {
                return m_state;
            }
        
            /**
             * If true we are in debug mode.
             */
            const bool & debug() const
            {
                return m_debug;
            }
        
            /**
             * Set's the operation mode.
             * @param val The value.
             */
            void set_operation_mode(const protocol::operation_mode_t & val);
        
            /**
             * The protocol::operation_mode_t.
             */
            protocol::operation_mode_t & operation_mode();
        
            /**
             * If true we are a client.
             */
            const bool & is_client() const
            {                
                return m_is_client;
            }
        
            /**
             * Sets the version nonce.
             */
            void set_version_nonce(const std::uint64_t & val)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                assert(val != 0);
                
                m_version_nonce = val;
            }
        
            /**
             * The version nonce (used to detect connections to ourselves).
             */
            const std::uint64_t & version_nonce() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                assert(m_version_nonce != 0);
                
                return m_version_nonce;
            }
        
            /**
             * Sets the best block height.
             * @param value The value.
             */
            void set_best_block_height(const std::int32_t & value)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_best_block_height = value;
            }
        
            /**
             * The best block height.
             */
            const std::int32_t & best_block_height() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_best_block_height;
            }
        
            /**
             * The block indexes.
             */
            std::map<sha256, std::shared_ptr<block_index> > & block_indexes()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_block_indexes;
            }
        
            /**
             * Sets the hash of the best chain.
             */
            void set_hash_best_chain(const sha256 & value)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_hash_best_chain = value;
            }
        
            /**
             * The hash of the best chain.
             */
            sha256 & hash_best_chain()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_hash_best_chain;
            }
        
            /**
             * Sets the block index fbbh last.
             * @param value The block_index.
             */
            void set_block_index_fbbh_last(
                const std::shared_ptr<block_index> & value
                )
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_block_index_fbbh_last = 0;
            }
        
            /**
             * The block index used by find_block_by_height.
             */
            const std::shared_ptr<block_index> & block_index_fbbh_last() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_block_index_fbbh_last;
            }
        
            /**
             * Sets the time best received.
             */
            void set_time_best_received(const std::int64_t & value)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_time_best_received = value;
            }
        
            /**
             * The time of the best received block.
             */
            const std::int64_t & time_best_received() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_time_best_received;
            }
        
            /**
             * Sets the number of transactions that have been updated.
             * @pram value The value.
             *
             */
            void set_transactions_updated(const std::int32_t & value)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_transactions_updated = value;
            }
        
            /**
             * The number of transactions that have been updated.
             */
            const std::uint32_t & transactions_updated() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_transactions_updated;
            }
        
            /**
             * The proofs of stake.
             */
            std::map<sha256, sha256> & proofs_of_stake()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_proofs_of_stake;
            }
        
            /**
             * Sets the main wallet.
             * @param val The wallet.
             */
            void set_wallet_main(const std::shared_ptr<wallet> & val)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                m_wallet_main = val;
            }
        
            /**
             * The (main) wallet.
             */
            const std::shared_ptr<wallet> & wallet_main() const
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_wallet_main;
            }
        
            /**
             * The orphan blocks.
             */
            std::map<sha256, std::shared_ptr<block> > & orphan_blocks()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_orphan_blocks;
            }
        
            /**
             * The orphan blocks by previous.
             */
            std::multimap<
                sha256, std::shared_ptr<block>
            > & orphan_blocks_by_previous()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_orphan_blocks_by_previous;
            }

            /**
             * The orphan transactions.
             */
            std::map<
                sha256, std::shared_ptr<data_buffer>
            > & orphan_transactions()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_orphan_transactions;
            }
        
            /**
             * The orphan transactions by previous.
             */
            std::map<
                sha256, std::map<sha256, std::shared_ptr<data_buffer> >
            > & orphan_transactions_by_previous()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_orphan_transactions_by_previous;
            }
        
            /**
             * The stake seen orphan
             */
            std::set<
                std::pair<point_out, std::uint32_t>
            > & stake_seen_orphan()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_stake_seen_orphan;
            }
        
            /**
             * The number of blocks other peers claim to have.
             */
            median_filter<std::uint32_t> & peer_block_counts()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_peer_block_counts;
            }
        
            /**
             * The relay inventory_vector's.
             */
            std::map<inventory_vector, data_buffer> & relay_invs()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_relay_invs;
            }
        
            /**
             * The relay inventory_vector expirations.
             */
            std::deque<
                std::pair<std::int64_t, inventory_vector>
                > & relay_inv_expirations()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_relay_inv_expirations;
            }
        
            /**
             * Sets the transaction feed.
             * @param val The value.
             */
            void set_transaction_fee(const std::int64_t & val)
            {
                m_transaction_fee = val;
            }
        
            /**
             * The transaction fee.
             */
            const std::int64_t & transaction_fee() const
            {
                return m_transaction_fee;
            }
        
            /**
             * If true the wallet is unlocked for mint only (ppcoin).
             */
            const bool & wallet_unlocked_mint_only() const
            {
                return m_wallet_unlocked_mint_only;
            }
        
            /**
             * Sets the last coin stake search interval.
             */
            void set_last_coin_stake_search_interval(const std::int64_t & val)
            {
                m_last_coin_stake_search_interval = val;
            }
        
            /**
             * The last coin stake search interval.
             */
            const std::int64_t & last_coin_stake_search_interval() const
            {
                return m_last_coin_stake_search_interval;
            }
        
            /**
             * Sets the option to rescan.
             * @param val The value.
             */
            void set_option_rescan(const bool & val)
            {
                m_option_rescan = val;
            }
        
            /**
             * The option to rescan starting at the genesis block.
             */
            const bool & option_rescan() const
            {
                return m_option_rescan;
            }
        
            /**
             * Sets the number of transactions in the last block.
             * @param val The value.
             */
            void set_last_block_transactions(const std::uint64_t & val)
            {
                m_last_block_transactions = val;
            }
        
            /**
             * The number of transactions in the last block.
             */
            const std::uint64_t & last_block_transactions() const
            {
                return m_last_block_transactions;
            }
        
            /**
             * Sets the last block size.
             * @param val The value.
             */
            void set_last_block_size(const std::uint64_t & val)
            {
                m_last_block_size = val;
            }
        
            /**
             * The last block size.
             */
            const std::uint64_t & last_block_size() const
            {
                return m_last_block_size;
            }
        
            /**
             * Set the money supply.
             * @param val The value.
             */
            void set_money_supply(const std::uint64_t & val)
            {
                m_money_supply = val;
            }
        
            /**
             * The money supply.
             */
            const std::uint64_t & money_supply() const
            {
                return m_money_supply;
            }
        
            /**
             * Sets our public address as seen by others.
             * @param val The value.
             */
            void set_address_public(const boost::asio::ip::address & val)
            {
                m_address_public = val;
            }
        
            /**
             * Our public address as seen by others.
             */
            const boost::asio::ip::address & address_public() const
            {
                return m_address_public;
            }
        
            /**
             * The coinbase flags.
             */
            script & coinbase_flags();
        
        private:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service m_io_service;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand m_strand;
        
            /**
             * The state.
             */
            state_t m_state;
        
            /**
             * If true we are in debug mode.
             */
            bool m_debug;
        
            /**
             * The protocol::operation_mode_t.
             */
            protocol::operation_mode_t m_operation_mode;
        
            /**
             * If true we are a client.
             */
            bool m_is_client;
        
            /**
             * The version nonce (used to detect connections to ourselves).
             */
            std::uint64_t m_version_nonce;
        
            /**
             * The best block height.
             */
            std::int32_t m_best_block_height;
        
            /**
             * The block indexes.
             */
            std::map<sha256, std::shared_ptr<block_index> > m_block_indexes;
        
            /**
             * The hash of the best chain.
             */
            sha256 m_hash_best_chain;
        
            /**
             * The block index used by find_block_by_height.
             */
            std::shared_ptr<block_index> m_block_index_fbbh_last;
        
            /**
             * The time of the best received block.
             */
            std::int64_t m_time_best_received;
        
            /**
             * The number of transactions that have been updated.
             */
            std::uint32_t m_transactions_updated;
        
            /**
             * The proofs of stake.
             */
            std::map<sha256, sha256> m_proofs_of_stake;
        
            /**
             * The (main) wallet.
             */
            std::shared_ptr<wallet> m_wallet_main;
        
            /**
             * The orphan blocks.
             */
            std::map<sha256, std::shared_ptr<block> > m_orphan_blocks;
        
            /**
             * The orphan blocks by previous.
             */
            std::multimap<
                sha256, std::shared_ptr<block>
            > m_orphan_blocks_by_previous;

            /**
             * The orphan transactions.
             */
            std::map<
                sha256, std::shared_ptr<data_buffer>
            > m_orphan_transactions;
        
            /**
             * The orphan transactions by previous.
             */
            std::map<
                sha256, std::map<sha256, std::shared_ptr<data_buffer> >
            > m_orphan_transactions_by_previous;
        
            /**
             * The stake seen orphan
             */
            std::set< std::pair<point_out, std::uint32_t> > m_stake_seen_orphan;
        
            /**
             * The number of blocks other peers claim to have.
             */
            median_filter<std::uint32_t> m_peer_block_counts;
        
            /**
             * The relay inventory_vector's.
             */
            std::map<inventory_vector, data_buffer> m_relay_invs;
        
            /**
             * The relay inventory_vector expirations.
             */
            std::deque<
                std::pair<std::int64_t, inventory_vector>
            > m_relay_inv_expirations;
        
            /**
             * The transaction fee.
             */
            std::int64_t m_transaction_fee;
        
            /**
             * If true the wallet is unlocked for mint only (ppcoin).
             */
            bool m_wallet_unlocked_mint_only;
        
            /**
             * The last coin stake search interval.
             */
            std::int64_t m_last_coin_stake_search_interval;
        
            /**
             * The option to rescan starting at the genesis block.
             */
            bool m_option_rescan;
        
            /**
             * The number of transactions in the last block.
             */
            std::uint64_t m_last_block_transactions;
   
            /**
             * The last block size.
             */
            std::uint64_t m_last_block_size;
        
            /**
             * The money supply.
             */
            std::uint64_t m_money_supply;
        
            /**
             * Our public address as seen by others.
             */
            boost::asio::ip::address m_address_public;
        
            /**
             * The coinbase flags.
             */
            std::shared_ptr<script> m_coinbase_flags;
        
        protected:
        
            /**
             * The std::mutex.
             */
            mutable std::mutex mutex_;
    };
    
}  // namespace coin

#endif // COIN_GLOBALS_HPP
