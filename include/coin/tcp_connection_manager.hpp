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

#ifndef COIN_TCP_CONNECTION_MANAGER_HPP
#define COIN_TCP_CONNECTION_MANAGER_HPP

#include <map>
#include <memory>
#include <mutex>
#include <set>

#include <boost/asio.hpp>

#include <coin/protocol.hpp>

namespace coin {

    class message;
    class stack_impl;
    class tcp_connection;
    class tcp_transport;
    
    /**
     * Implements a tcp connetion manager.
     */
    class tcp_connection_manager
        : public std::enable_shared_from_this<tcp_connection_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param owner The stack_impl.
             */
            tcp_connection_manager(
                boost::asio::io_service & ios, stack_impl & owner
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
             * Handles an incoming tcp connection.
             * @param transport The tcp_transport.
             */
            void handle_accept(std::shared_ptr<tcp_transport> transport);
        
            /**
             * Broadcasts a message to all connected peers.
             * @param buf The buffer.
             * @param len The length.
             */
            void broadcast(const char * buf, const std::size_t & len);
        
            /**
             * The tcp connections.
             */
            std::map<
                boost::asio::ip::tcp::endpoint, std::weak_ptr<tcp_connection>
            > & tcp_connections();
        
        private:
        
            /**
             * Makes a tcp connection to the given endpoint.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            bool connect(const boost::asio::ip::tcp::endpoint & ep);
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code & ec);
        
            /**
             * The tcp connections.
             */
            std::map<
                boost::asio::ip::tcp::endpoint, std::weak_ptr<tcp_connection>
            > m_tcp_connections;
        
        protected:
        
            /**
             * Resolves a list of boost::asio::ip::tcp::resolver::query objects
             * and if succesful adds them to the address_manager.
             * @param q The boost::asio::ip::tcp::resolver::query.
             */
            void do_resolve(
                const std::vector<boost::asio::ip::tcp::resolver::query> &
                queries
            );
        
            /**
             * Checks if a partial ip match is banned.
             * @param val The ip address.
             */
            bool is_ip_banned(const std::string & val);

            /**
             * The minimum number of tcp connections to maintain.
             */
            enum { minimum_tcp_connections = 3 };
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
            /**
             * The boost::asio::ip::tcp::resolver.
             */
            boost::asio::ip::tcp::resolver resolver_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_;

            /**
             * The tcp_connections_ std::recursive_mutex.
             */
            std::recursive_mutex mutex_tcp_connections_;
    };
    
} // namespace coin

#endif // COIN_TCP_CONNECTION_MANAGER_HPP
