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

#ifndef DATABASE_CRYPTO_HANDLER_HPP
#define DATABASE_CRYPTO_HANDLER_HPP

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>

#include <boost/asio.hpp>

#include <database/handler.hpp>

namespace database {

    class crypto_connection;
    class node_impl;
	class udp_multiplexor;

    /**
     * The crypto handler.
     */
    class crypto_handler
        : public handler
        , public std::enable_shared_from_this<crypto_handler>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param multiplexor The udp_multiplexor.
             * @param impl The node_impl.
             */
            explicit crypto_handler(
                boost::asio::io_service &,
                const std::shared_ptr<node_impl> &,
                const std::shared_ptr<udp_multiplexor> &
            );
        
            /**
             * Start
             */
            void start();
            
            /**
             * Stop
             */
            void stop();
            
            /**
             * Performs a send to operation.
             * @param ep The destination endpoint.
             * @param buf The buffer to send.
             * @param len The length of bytes to send.
             */
            virtual void send_to(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
            
            /**
             * The on_async_receive_from handler.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The received buffer.
             * @param len The length of the buffer.
             */
            virtual bool on_async_receive_from(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
            
        private:
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code &);
        
            /**
             * The endpoint.
             */
            boost::asio::ip::udp::endpoint m_endpoint;
            
        protected:
        
            /**
             * The mutex.
             */
            std::recursive_mutex mutex_;
            
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
            
            /**
             * The connections.
             */
            std::map<
                boost::asio::ip::udp::endpoint, std::shared_ptr<crypto_connection>
            > connections_;
    };

} // namespace database

#endif // DATABASE_CRYPTO_HANDLER_HPP
