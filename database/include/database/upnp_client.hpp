/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#ifndef database_upnp_client_hpp
#define database_upnp_client_hpp

#if (!defined __arm__ && !defined __thumb__ && \
    !defined _M_ARM && !defined _M_ARMT)
    
#define USE_UPNP 1

#include <cstdint>
#include <thread>

#if (defined USE_UPNP && USE_UPNP)
#include <miniupnpc/miniupnpc.h>
#endif // USE_UPNP
#include <boost/asio.hpp>

namespace database {
  
    class upnp_client : public std::enable_shared_from_this<upnp_client>
    {
        public:
        
            typedef enum
            {
                protocol_udp = 0,
                protocol_tcp = 1,
            } protocol_t;
        
            /**
             * Constructor
             * The boost::asio::io_service.
             */
            upnp_client(boost::asio::io_service & ios);
        
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
            boost::asio::strand strand_;
        
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
        
            /**
             * If true we discovered a upnp device.
             */
            bool discovery_did_succeed_;
        
            /**
             * The discover thread.
             */
            std::thread discover_thread_;
#endif // USE_UPNP
        
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
    
} // database

#endif // __arm__

#endif // database_upnp_client_hpp
