/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#ifndef CRAWLER_PEER_HPP
#define CRAWLER_PEER_HPP

#include <cstdint>
#include <ctime>
#include <string>

#include <boost/asio.hpp>

namespace crawler {

    /**
     * Implements a peer.
     */
    class peer
    {
        public:
        
            /**
             * Constructor
             */
            peer()
                : m_version("0")
                , m_protocol(0)
                , m_height(0)
                , m_time_last_seen(0)
                , m_uptime(0)
                , m_last_update(0)
                , m_rtt(0)
                , m_udp_bps_inbound(0)
                , m_udp_bps_outbound(0)
                , m_is_tcp_open(false)
                , m_last_probed(0)
            {
                // ...
            }
        
            /**
             * Constructor
             */
            peer(
                const boost::asio::ip::udp::endpoint & ep,
                const std::time_t & uptime, const std::time_t & last_update,
                const std::int32_t & rtt,
                const std::int32_t & udp_bps_inbound,
                const std::int32_t & udp_bps_outbound
                )
                : m_version("0")
                , m_protocol(0)
                , m_useragent("unknown")
                , m_height(0)
                , m_time_last_seen(std::time(0) - 10 * 60)
                , m_udp_endpoint(ep)
                , m_uptime(uptime)
                , m_last_update(last_update)
                , m_rtt(rtt)
                , m_udp_bps_inbound(udp_bps_inbound)
                , m_udp_bps_outbound(udp_bps_outbound)
                , m_is_tcp_open(false)
                , m_last_probed(0)
            {
                // ...
            }
        
            void set_version(const std::string & val)
            {
                m_version = val;
            }
        
            const std::string & version() const
            {
                return m_version;
            }
        
            void set_protocol(const std::int32_t & val)
            {
                m_protocol = val;
            }
        
            const std::int32_t & protocol() const
            {
                return m_protocol;
            }
        
            void set_useragent(const std::string & val)
            {
                m_useragent = val;
            }
        
            const std::string & useragent() const
            {
                return m_useragent;
            }
        
            void set_height(const std::int32_t & val)
            {
                m_height = val;
            }
        
            const std::int32_t & height() const
            {
                return m_height;
            }
        
            /**
             * Sets the time last seen.
             * @param val The value.
             */
            void set_time_last_seen(const std::time_t & val)
            {
                m_time_last_seen = val;
            }
        
            /**
             * Last seen.
             */
            const std::time_t & time_last_seen() const
            {
                return m_time_last_seen;
            }
        
            /**
             * The
             */
            const boost::asio::ip::udp::endpoint & udp_endpoint() const
            {
                return m_udp_endpoint;
            }
        
            /**
             * The
             */
            const std::time_t & uptime() const
            {
                return m_uptime;
            }
        
            /**
             * The
             */
            const std::time_t & last_update() const
            {
                return m_last_update;
            }
        
            /**
             * The
             */
            const std::int32_t & rtt() const
            {
                return m_rtt;
            }
        
            /**
             * The
             */
            const std::int32_t & udp_bps_inbound() const
            {
                return m_udp_bps_inbound;
            }
        
            /**
             * The
             */
            const std::int32_t & udp_bps_outbound() const
            {
                return m_udp_bps_outbound;
            }
        
            /**
             * If true the UDP port is open.
             */
            bool is_udp_open() const
            {
                return true;
            }
        
            /**
             * Sets if the TCP port is open.
             * @param val The value.
             */
            void set_is_tcp_open(const bool & val)
            {
                m_is_tcp_open = val;
            }
        
            /**
             * If true the UDP port is open.
             */
            bool is_tcp_open() const
            {
                return m_is_tcp_open;
            }
        
            /**
             * Sets the time last probed.
             * @param val The value.
             */
            void set_last_probed(const std::time_t & val)
            {
                m_last_probed = val;
            }
        
            /**
             * The last time the peer was probed.
             */
            const std::time_t & last_probed() const
            {
                return m_last_probed;
            }
        
        private:
        
            std::string m_version;
        
            std::int32_t m_protocol;
        
            std::string m_useragent;
        
            std::int32_t m_height;
        
            /**
             * Last seen.
             */
            std::time_t m_time_last_seen;
        
            /**
             * The
             */
            boost::asio::ip::udp::endpoint m_udp_endpoint;
    
            /**
             * The
             */
            std::time_t m_uptime;
        
            /**
             * The
             */
            std::time_t m_last_update;
        
            /**
             * The
             */
            std::int32_t m_rtt;
        
            /**
             * The
             */
            std::int32_t m_udp_bps_inbound;
        
            /**
             * The
             */
            std::int32_t m_udp_bps_outbound;
        
            /**
             * If true the UDP port is open.
             */
            bool m_is_tcp_open;
        
            /**
             * The last time the peer was probed.
             */
            std::time_t m_last_probed;
        
        protected:
        
            // ...
    };
    
} // namespace crawler

#endif //CRAWLER_PEER_HPP
