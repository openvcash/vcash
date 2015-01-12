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

#ifndef DATABASE_GATEWAY_HPP
#define DATABASE_GATEWAY_HPP

#include <vector>

#include <boost/asio.hpp>

#include <database/network.hpp>

#if (defined __APPLE__ || __POSIX__ || __MACH__)
struct rt_msghdr;
#elif (defined __linux__)
struct nlmsghdr;
#endif

namespace database {
    
    /**
     * Implements internet protocol gateway utility functions.
     */
    class gateway
    {
        public:
        
            /**
             * Returns the default gateway address.
             * @param ios
             * @param ec
             */
            static boost::asio::ip::address default_route(
                boost::asio::io_service & ios, 
                boost::system::error_code & ec
            );
            
        private:
        
            /**
             * Enumerates and returns ip routes.
             */
            static std::vector<network::interface_t> routes(
                boost::asio::io_service & ios, boost::system::error_code & ec
            );   
            
        protected:

			// ...
    };
    
} // namespace database

#endif // DATABASE_GATEWAY_HPP
