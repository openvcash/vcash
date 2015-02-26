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

#ifndef COIN_RPC_MANAGER_HPP
#define COIN_RPC_MANAGER_HPP

#include <mutex>

#include <boost/asio.hpp>

namespace coin {

    class rpc_connection;
    class rpc_server;
    class stack_impl;
    class rpc_transport;
    
    /**
     * Implements an RPC manager.
     */
    class rpc_manager : public std::enable_shared_from_this<rpc_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            explicit rpc_manager(
                boost::asio::io_service & ios, boost::asio::strand & s,
                stack_impl & owner
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
             * Handles an incoming tcp connection.
             * @param transport The rpc_transport.
             */
            void handle_accept(std::shared_ptr<rpc_transport> transport);
        
        private:
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code & ec);
        
            /**
             * The rpc_server.
             */
            std::shared_ptr<rpc_server> m_rpc_server;
        
            /**
             * The tcp connections.
             */
            std::map<
                boost::asio::ip::tcp::endpoint, std::weak_ptr<rpc_connection>
            > m_tcp_connections;
        
            /**
             * We limit the number of connections to 100000.
             */
            enum { max_connections = 100000 };
    
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
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
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

#endif // COIN_RPC_MANAGER_HPP
