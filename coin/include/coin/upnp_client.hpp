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

#ifndef COIN_UPNP_CLIENT_HPP
#define COIN_UPNP_CLIENT_HPP

#if (defined _MSC_VER)
#define USE_UPNP 0
#define _WIN32 1
#define STATICLIB 1
#endif // _MSC_VER

#include <cstdint>
#include <thread>
#include <vector>

#if (defined USE_UPNP && USE_UPNP)
#include <miniupnpc/miniupnpc.h>
#endif // USE_UPNP
#include <boost/asio.hpp>

namespace coin {
    
    /**
     * Implements a UPnP client.
     */
    class upnp_client : public std::enable_shared_from_this<upnp_client>
    {
        public:
        
            /**
             * The protocol type.
             */
            typedef enum
            {
                protocol_udp = 0,
                protocol_tcp = 1,
            } protocol_t;
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            explicit upnp_client(
                boost::asio::io_service & ios, boost::asio::strand & s
            );
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Adds a mapping.
             * @param protocol The protocol.
             * @param port The port.
             */
            void add_mapping(
                const protocol_t & protocol, const std::uint16_t & port
            );
        
            /**
             * Removes a mapping.
             * @param protocol The protocol.
             * @param port The port.
             */
            void remove_mapping(
                const protocol_t & protocol, const std::uint16_t & port
            );
        
            /**
             * Runs the test case.
             */
            static int run_test();
        
        private:
        
            /**
             * Starts
             */
            void do_start();
        
            /**
             * Stops
             */
            void do_stop();
        
            /**
             * Adds a mapping.
             * @param protocol The protocol.
             * @param port The port.
             */
            void do_add_mapping(
                const protocol_t & protocol, const std::uint16_t & port
            );
        
            /**
             * Removes a mapping.
             * @param protocol The protocol.
             * @param port The port.
             */
            void do_remove_mapping(
                const protocol_t & protocol, const std::uint16_t & port
            );
        
            /**
             * Discovers devices.
             */
            void do_discover_devices();
        
            /**
             * The timer handler.
             */
            void tick(const boost::system::error_code &);
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
#if (defined USE_UPNP && USE_UPNP)
            /**
             * The UPNPUrls.
             */
            UPNPUrls upnp_urls_;
        
            /**
             * The IGDdatas.
             */
            IGDdatas igd_data_;
#endif // USE_UPNP

            /**
             * If true we discovered a upnp device.
             */
            bool discovery_did_succeed_;
        
            /**
             * The discover thread.
             */
            std::thread discover_thread_;

            /**
             * A mapping.
             */
            typedef struct
            {
                protocol_t protocol;
                std::uint16_t internal_port;
                std::uint16_t external_port;
                std::time_t time;
            } mapping_t;
        
            /**
             * The mappings.
             */
            std::vector<mapping_t> mappings_;
    };

} // namespace coin

#endif // COIN_UPNP_CLIENT_HPP
