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

#ifndef DATABASE_TCP_ACCEPTOR_HPP
#define DATABASE_TCP_ACCEPTOR_HPP

#include <cstdint>
#include <vector>

#include <boost/asio.hpp>

namespace database {

    class node_impl;
    class tcp_transport;
    
    class tcp_acceptor
        : public std::enable_shared_from_this<tcp_acceptor>
    {
        public:
        
            /**
             * The maximum number of tcp connections.
             */
            enum { max_tcp_connections = 350 };
        
            explicit tcp_acceptor(
                boost::asio::io_service & ios,
                const std::shared_ptr<node_impl> & impl
            );
        
            void open(const std::uint16_t & port);
            void close();
        
            /**
             * The local endpoint.
             */
            const boost::asio::ip::tcp::endpoint local_endpoint() const;
        
            /**
             * The tcp_transport's.
             */
            const std::vector< std::weak_ptr<tcp_transport> > &
                tcp_transports() const
            ;
        
            /**
             * Runs the test case.
             */
            static int run_test();
        
        private:
        
            void do_ipv4_accept();
            void do_ipv6_accept();
        
            void do_tick(const std::uint32_t & seconds);
        
            /**
             * Handles a message.
             * @param ep The boost::asio::ip::tcp::endpoint.
             * @param buf The buffer.
             * @param len The length
             */
            void handle_message(
                const std::shared_ptr<tcp_transport> & t, const char *,
                const std::size_t &
            );
        
            /**
             * Handles an http message.
             * @param ep The boost::asio::ip::tcp::endpoint.
             * @param buf The buffer.
             * @param len The length
             */
            void handle_http_message(
                const std::shared_ptr<tcp_transport> & t, const char *,
                const std::size_t &
            );
        
            /**
             * The tcp_transport's.
             */
            std::vector< std::weak_ptr<tcp_transport> > m_tcp_transports;
        
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
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
        
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
            mutable std::recursive_mutex tcp_transports_mutex_;
    };

} // namespace database

#endif // DATABASE_TCP_ACCEPTOR_HPP
