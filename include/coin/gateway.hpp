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

#ifndef COIN_GATEWAY_HPP
#define COIN_GATEWAY_HPP

#include <vector>

#include <boost/asio.hpp>

namespace coin {
    
    class gateway
    {
        public:
        
            /**
             * Returns the default gateway address.
             * @param ios The boost::asio::io_service.
             * @param ec The boost::system::error_code.
             */
            static boost::asio::ip::address default_route(
                boost::asio::io_service & ios, 
                boost::system::error_code & ec
            );
        
            /**
             * Returns the local ip address.
             */
            static boost::asio::ip::address local_address();
        
            typedef struct
            {
                /**
                 * The destination ip address.
                 */
                boost::asio::ip::address destination;
                
                /**
                 * The gateway ip address.
                 */
                boost::asio::ip::address gateway;
                
                /**
                 * The netmask of the network interface.
                 */
                boost::asio::ip::address netmask;

                /**
                 * The name of the network interface.
                 */
                char name[64];
                
            } network_interface_t;
        
            /**
             * Converts a sockaddr to a boost::asio::ip::address .
             * @param addr The sockaddr.
             */
            static boost::asio::ip::address sockaddr_to_address(
                const sockaddr * addr
            );
        
        private:
        
            /**
             * Gets the routes.
             * @param ios The boost::asio::io_service.
             * @param ec The boost::system::error_code.
             */
            static std::vector<network_interface_t> routes(
                boost::asio::io_service & ios, boost::system::error_code & ec
            );
        
            /**
             * Gets the local interfaces.
             * @param ec The boost::system::error_code.
             */
            static std::vector<network_interface_t> local_interfaces(
                boost::system::error_code & ec
            );
        
        protected:

            /**
             * Converts an in_addr to a boost::asio::ip::address.
             * @param addr The in_addr.
             */
            static boost::asio::ip::address inaddr_to_address(
                const in_addr * addr
            );
        
            /**
             * Converts an in6_addr to a boost::asio::ip::address.
             * @param addr The in6_addr.
             */
            static boost::asio::ip::address inaddr6_to_address(
                const in6_addr * addr
            );
        
            /**
             * If true the address is loopback.
             * @param addr The boost::asio::ip::address.
             */
            static bool address_is_loopback(
                const boost::asio::ip::address & addr
            );

            /**
             * If true the address is multicast.
             */
            static bool address_is_multicast(
                const boost::asio::ip::address & addr
            );
        
            /**
             * If true the address is any.
             */
            static bool address_is_any(const boost::asio::ip::address & addr);
    };
    
} // namespace coin

#endif // COIN_GATEWAY_HPP
