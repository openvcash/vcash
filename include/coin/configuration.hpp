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
             * The wallet rescan.
             */
            bool m_wallet_rescan;
        
            /**
             * Enable Proof-of-Stake mining.
             */
            bool m_mining_proof_of_stake;
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CONFIGURATION_HPP
