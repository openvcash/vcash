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

#ifndef COIN_TCP_ACCEPTOR_HPP
#define COIN_TCP_ACCEPTOR_HPP

#include <cstdint>
#include <functional>
#include <vector>

#include <boost/asio.hpp>

namespace coin {

    class tcp_transport;
    
    /**
     * Implements a tcp acceptor.
     */
    class tcp_acceptor
        : public std::enable_shared_from_this<tcp_acceptor>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             */
            explicit tcp_acceptor(
                boost::asio::io_service & ios, boost::asio::strand & s
            );
        
            /**
             * Opens the tcp connector given port.
             * @param port The port.
             */
            bool open(const std::uint16_t & port);
        
            /**
             * Closes the acceptor.
             */
            void close();
        
            /**
             * Sets the accept handler
             * @param f The std::function.
             */
            void set_on_accept(
                const std::function<void (std::shared_ptr<tcp_transport>)> & f
            );
        
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
            std::function<void (std::shared_ptr<tcp_transport>)> m_on_accept;
        
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
            boost::asio::strand & strand_;
        
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

} // namespace coin

#endif // COIN_TCP_ACCEPTOR_HPP
