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

#ifndef COIN_CONFIGURATION_HPP
#define COIN_CONFIGURATION_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace coin {

    /**
     * The configuration.
     */
    class configuration
    {
        public:
        
            /**
             * The version.
             */
            enum { version = 1 };
        
            /**
             * Constructor
             */
            configuration();
        
            /**
             * Loads
             */
            bool load();
        
            /**
             * Saves
             */
            bool save();

            /**
             * Sets the arguments.
             * @param val The arguments.
             */
            void set_args(const std::map<std::string, std::string>  & val);
        
            /** 
             * The arguments.
             */
            std::map<std::string, std::string> & args();
        
            /**
             * Sets the network TCP port.
             */
            void set_network_port_tcp(const std::uint16_t & val);
        
            /**
             * The network TCP port.
             */
            const std::uint16_t & network_port_tcp() const;
        
            /**
             * Sets the maximum number of inbound TCP connections.
             * @param val The value.
             */
            void set_network_tcp_inbound_maximum(const std::size_t & val);
        
            /**
             * The maximum number of inbound TCP connections;
             */
            const std::size_t & network_tcp_inbound_maximum() const;
        
            /**
             * If true network UDP support is enabled.
             * @param val the value.
             */
            void set_network_udp_enable(const bool & val);
        
            /**
             * If true network UDP support is enabled.
             */
            const bool & network_udp_enable() const;

            /**
             * Sets the network RPC port.
             */
            void set_rpc_port(const std::uint16_t & val);

            /**
             * The network RPC port.
             */
            const std::uint16_t & rpc_port() const;
        
            /**
             * Sets the bootstrap nodes.
             * @param val The 
             */
            void set_bootstrap_nodes(
                const std::vector< std::pair<std::string, std::uint16_t> > & val
                )
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                m_bootstrap_nodes = val;
            }
        
            /**
             * The bootstrap nodes.
             */
            std::vector<
                std::pair<std::string, std::uint16_t>
                > & bootstrap_nodes()
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                return m_bootstrap_nodes;
            }
        
            /**
             * The bootstrap nodes.
             */
            const std::vector<
                std::pair<std::string, std::uint16_t>
                > & bootstrap_nodes() const
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_);
                
                return m_bootstrap_nodes;
            }
        
            /**
             * Sets the wallet.transaction.history.maximum
             * @param val The value.
             */
            void set_wallet_transaction_history_maximum(
                const std::time_t & val
                )
            {
                m_wallet_transaction_history_maximum = val;
            }
        
            /**
             * The maximum transaction history.
             */
            const std::time_t & wallet_transaction_history_maximum() const
            {
                return m_wallet_transaction_history_maximum;
            }
        
            /**
             * The wallet keypool size.
             */
            const std::int32_t & wallet_keypool_size() const
            {
                return m_wallet_keypool_size;
            }
        
            /**
             * The ZeroTime depth.
             */
            const std::uint8_t & zerotime_depth() const
            {
                return m_zerotime_depth;
            }
        
            /**
             * The ZeroTime answers minimum.
             */
            const std::uint8_t & zerotime_answers_minimum() const
            {
                return m_zerotime_answers_minimum;
            }
        
            /**
             * Set wallet rescan.
             * @param val The value.
             */
            void set_wallet_rescan(const bool & val)
            {
                m_wallet_rescan = val;
            }
        
            /**
             * Wallet rescan.
             */
            const bool & wallet_rescan() const
            {
                return m_wallet_rescan;
            }
        
            /**
             * Set mining Proof-of-Stake.
             * @param val The value.
             */
            void set_mining_proof_of_stake(const bool & val)
            {
                m_mining_proof_of_stake = val;
            }
        
            /**
             * Enable Proof-of-Stake mining.
             */
            const bool & mining_proof_of_stake() const
            {
                return m_mining_proof_of_stake;
            }
        
            /**
             * Set blockchain pruning enabled.
             * @param val The value.
             */
            void set_blockchain_pruning(const bool & val)
            {
                m_blockchain_pruning = val;
            }
        
            /**
             * Enable blockchain pruning.
             */
            const bool & blockchain_pruning() const
            {
                return m_blockchain_pruning;
            }
        
            /**
             * Sets chainblender to use debug options.
             * @param val The value.
             */
            void set_chainblender_debug_options(const bool & val);
        
            /**
             * If true run chainblender with debug options.
             */
            const bool & chainblender_debug_options() const;
        
            /** 
             * Sets chainblender to use common output denominations.
             * @param val The value.
             */
            void set_chainblender_use_common_output_denominations(const bool & val);
        
            /**
             * Enable chainblender common output denominations.
             */
            const bool & chainblender_use_common_output_denominations() const;
        
            /**
             * Sets the database cache size.
             * @param val The value.
             */
            void set_database_cache_size(const std::uint32_t & val);
        
            /**
             * The database cache size.
             */
            const std::uint32_t & database_cache_size() const;
        
            /**
             * Sets if the wallet is deterministic.
             * @param val The value.
             */
            void set_wallet_deterministic(const bool & val);
        
            /**
             * If true the wallet is deterministic.
             */
            const bool & wallet_deterministic() const;
        
            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             * @param val The value.
             */
            void set_db_private(const bool & val);
        
            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             */
            const bool & db_private() const;
        
        private:
        
            /** 
             * The arguments.
             */
            std::map<std::string, std::string> m_args;
        
            /**
             * The network TCP port.
             */
            std::uint16_t m_network_port_tcp;
        
            /**
             * The maximum number of inbound TCP connections;
             */
            std::size_t m_network_tcp_inbound_maximum;
        
            /**
             * If true network UDP support is enabled.
             */
            bool m_network_udp_enable;

            /**
             * The network RPC port.
             */
            std::uint16_t m_rpc_port;

            /**
             * The bootstrap nodes.
             */
            std::vector<
                std::pair<std::string, std::uint16_t>
            > m_bootstrap_nodes;
        
            /**
             * The maximum wallet transaction history.
             */
            std::time_t m_wallet_transaction_history_maximum;
        
            /**
             * The wallet keypool size.
             */
            std::int32_t m_wallet_keypool_size;
        
            /**
             * The ZeroTime depth.
             */
            std::uint8_t m_zerotime_depth;
        
            /**
             * The ZeroTime answers minimum.
             */
            std::uint8_t m_zerotime_answers_minimum;
        
            /**
             * The wallet rescan.
             */
            bool m_wallet_rescan;
        
            /**
             * Enable Proof-of-Stake mining.
             */
            bool m_mining_proof_of_stake;
        
            /**
             * Enable blockchain pruning.
             */
            bool m_blockchain_pruning;
        
            /**
             * If true run chainblender with debug options.
             */
            bool m_chainblender_debug_options;
        
            /**
             * Enable chainblender common output denominations.
             */
            bool m_chainblender_use_common_output_denominations;
        
            /**
             * The database cache size.
             */
            std::uint32_t m_database_cache_size;
        
            /**
             * If true the wallet is deterministic.
             */
            bool m_wallet_deterministic;

            /**
             * If true the database will not be memory mapped, instead held
             * into memory.
             */
            bool m_db_private;
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CONFIGURATION_HPP
