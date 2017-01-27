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
 
#ifndef DATABASE_STORAGE_NODE_HPP
#define DATABASE_STORAGE_NODE_HPP

#include <cstdint>
#include <chrono>
#include <ctime>
#include <map>

#include <boost/asio.hpp>

namespace database {

    /**
     * Implements a storage node.
     */
    class storage_node
    {
        public:
        
            storage_node()
                : m_timeouts(0)
                , last_update(std::chrono::steady_clock::now())
                , pinged(false)
                , uptime(std::time(0))
                , rtt(0)
                , stats_udp_bps_inbound(0)
                , stats_udp_bps_outbound(0)
            {
                // ...
            }
        
            bool operator < (const storage_node & rhs) const
            {
                return this->endpoint < rhs.endpoint;
            }
        
            bool operator == (const storage_node & rhs) const
            {
                return this->endpoint == rhs.endpoint;
            }
        
            /**
             * If false the node has never been pinged.
             */
            bool pinged;
            std::time_t uptime;
            boost::asio::ip::udp::endpoint endpoint;
            std::uint32_t rtt;
            std::map<
                std::uint16_t, std::chrono::steady_clock::time_point
            > transaction_ids;
        
            std::uint32_t stats_udp_bps_inbound;
            std::uint32_t stats_udp_bps_outbound;
        
            /**
             * Sets the number of timeouts.
             */
            void set_timeouts(const std::uint8_t & val)
            {
                m_timeouts = val;
            }
        
            /**
             * The number of timeouts.
             */
            const std::uint8_t & timeouts() const
            {
                return m_timeouts;
            }
        
        //private:
        
            /**
             * The number of timeouts.
             */
            std::uint8_t m_timeouts;
        
            /**
             * The time last updated
             */
            std::chrono::steady_clock::time_point last_update;
        
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_STORAGE_NODE_HPP
