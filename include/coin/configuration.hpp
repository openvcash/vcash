/*
 * Copyright (c) 2013-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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
             * Sets the network TCP port.
             */
            void set_network_port_tcp(const std::uint16_t & val);
        
            /**
             * The network TCP port.
             */
            const std::uint16_t & network_port_tcp() const;
        
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
        
        private:
        
            /**
             * The network TCP port.
             */
            std::uint16_t m_network_port_tcp;
        
            /**
             * The bootstrap nodes.
             */
            std::vector<
                std::pair<std::string, std::uint16_t>
            > m_bootstrap_nodes;
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CONFIGURATION_HPP
