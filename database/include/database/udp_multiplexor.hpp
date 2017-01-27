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

#ifndef DATABASE_UDP_MULTIPLEXOR_HPP
#define DATABASE_UDP_MULTIPLEXOR_HPP

#include <deque>
#include <functional>

#include <boost/asio.hpp>

namespace database {

    /**
     * The udp multiplexor.
     */
    class udp_multiplexor
        : public std::enable_shared_from_this<udp_multiplexor>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             */
            explicit udp_multiplexor(boost::asio::io_service &);
            
            /**
             * Opens the socket(s) binding to port.
             * @param port The port to bind to.
             */
            void open(const unsigned short &);
            
            /**
             * Closes the socket(s).
             */
            void close();
            
            /**
             * Performs a send to operation.
             * @param ep The destination endpoint.
             * @param buf The buffer to send.
             * @param len The length of bytes to send.
             */
            void send_to(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
        
            /**
             * Set the asynchronous receive handler.
             * @param f The std::function.
             */
            void set_on_async_receive_from(
                const std::function<void (
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &)> &
            );
        
            /**
             * The local endpoint.
             */
            const boost::asio::ip::udp::endpoint & local_endpoint() const;
    
            /**
             * The number of bytes sent.
             */
            const std::size_t & bytes_sent() const;
        
            /**
             * The number of bytes sent per second.
             */
            const std::size_t & bps_sent() const;
        
            /**
             * The number of bytes received.
             */
            const std::size_t & bytes_received() const;
        
            /**
             * The number of bytes received per second.
             */
            const std::size_t & bps_received() const;
        
        private:
        
            /**
             * Handles an asynchronous receive from operation.
             * @param ec The boost::system::error_code.
             * @param len The length of bytes received.
             */
            void handle_async_receive_from(
                const boost::system::error_code &, const std::size_t &
            );
        
            /**
             * Handles an asynchronous send to from operation.
             * @param ec The boost::system::error_code.
             */
            void handle_async_send_to(const boost::system::error_code &);
        
            /**
             * The asynchronous receive handler.
             */
            std::function<
                void (const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &)
            > m_on_async_receive_from;
        
            /**
             * The local endpoint.
             */
            boost::asio::ip::udp::endpoint m_local_endpoint;
        
            /**
             * The number of bytes sent.
             */
            std::size_t m_bytes_sent;
        
            /**
             * The number of bytes sent per second.
             */
            std::size_t m_bps_sent;
        
            /**
             * The number of bytes received.
             */
            std::size_t m_bytes_received;
        
            /**
             * The number of bytes received per second.
             */
            std::size_t m_bps_received;
        
        protected:
            /**
             * The maximum receive buffer length.
             */
            enum { max_length = 65535 };
        
            /**
             * The boost::asio::io_service::stand.
             */
            boost::asio::io_service::strand strand_;
            
            /**
             * The ipv4 socket.
             */
            boost::asio::ip::udp::socket socket_ipv4_;
            
            /**
             * The ipv6 socket.
             */
            boost::asio::ip::udp::socket socket_ipv6_;
            
            /**
             * The remote endpoint.
             */
            boost::asio::ip::udp::endpoint remote_endpoint_;
            
            /**
             * The receive buffer.
             */
            char receive_buffer_[max_length];
        
            /**
             * The send time.
             */
            std::time_t send_time_;
        
            /**
             * The receive time.
             */
            std::time_t receive_time_;
    };
    
} // namespace database

#endif // DATABASE_UDP_MULTIPLEXOR_HPP
