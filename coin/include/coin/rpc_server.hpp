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

#ifndef COIN_RPC_SERVER_HPP
#define COIN_RPC_SERVER_HPP

#include <cstdint>
#include <functional>
#include <vector>

#include <boost/asio.hpp>

#include <coin/protocol.hpp>

namespace coin {

    class stack_impl;
    class rpc_transport;
    
    /**
     * Implements an RPC server.
     */
    class rpc_server : public std::enable_shared_from_this<rpc_server>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            explicit rpc_server(
                boost::asio::io_service & ios, boost::asio::strand & s,
                stack_impl & owner
            );
        
            /**
             * Opens the tcp connector given port.
             * @param port The port.
             */
            bool open(const std::uint16_t & port = protocol::default_rpc_port);
        
            /**
             * Closes the acceptor.
             */
            void close();
        
            /**
             * Sets the accept handler
             * @param f The std::function.
             */
            void set_on_accept(
                const std::function<void (std::shared_ptr<rpc_transport>)> & f
            );
        
            /**
             * The rpc_transport's.
             */
            const std::vector< std::weak_ptr<rpc_transport> > &
                rpc_transports() const
            ;
        
            /**
             * Runs the test case.
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             */
            static int run_test(
                boost::asio::io_service & ios, boost::asio::strand & s
            );
        
        private:
        
            /**
             * Performs an ipv4 accept operation.
             */
            void do_ipv4_accept();
        
            /**
             * Performs an ipv6 accept operation.
             */
            void do_ipv6_accept();
        
            /**
             * The tick timerhandler.
             */
            void do_tick(const std::uint32_t & seconds);
        
            /**
             * The on accept handler.
             */
            std::function<void (std::shared_ptr<rpc_transport>)> m_on_accept;
        
            /**
             * The rpc_transport's.
             */
            std::vector< std::weak_ptr<rpc_transport> > m_rpc_transports;
        
        protected:
        
            /**
             * The boost::asio::io_service loop.
             */
            void loop();
        
            /**
             * The std::thread.
             */
            std::thread thread_;
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service io_service_;

            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
            /**
             * The boost::asio::ip::tcp::acceptor.
             */
            boost::asio::ip::tcp::acceptor acceptor_ipv4_;
        
            /**
             * The boost::asio::ip::tcp::acceptor.
             */
            boost::asio::ip::tcp::acceptor acceptor_ipv6_;
        
            /**
             * The transports timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > transports_timer_;
        
            /**
             * The tcp transports mutex.
             */
            mutable std::recursive_mutex rpc_transports_mutex_;
    };
    
} // namespace coin

#endif // COIN_RPC_SERVER_HPP
