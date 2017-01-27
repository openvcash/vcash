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

#include <iostream>
#include <stdexcept>

#include <database/logger.hpp>
#include <database/network.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

udp_multiplexor::udp_multiplexor(boost::asio::io_service & ios)
    : m_bytes_sent(0)
    , m_bps_sent(0)
    , m_bytes_received(0)
    , m_bps_received(0)
    , strand_(ios)
    , socket_ipv4_(ios)
    , socket_ipv6_(ios)
    , send_time_(std::time(0))
    , receive_time_(std::time(0))
{
    // ...
}

void udp_multiplexor::open(const std::uint16_t & port)
{
    assert(!socket_ipv4_.is_open());
    assert(!socket_ipv6_.is_open());
    
    boost::system::error_code ec;
    
    /**
     * Allocate the ipv4 endpoint.
     */
    boost::asio::ip::udp::endpoint ipv4_endpoint(
        boost::asio::ip::address_v4::any(), port
    );
    
    /**
     * Open the ipv4 socket.
     */
    socket_ipv4_.open(ipv4_endpoint.protocol(), ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
    socket_ipv4_.set_option(
        boost::asio::ip::udp::socket::reuse_address(true)
    );
    
    /**
     * Non-blocking IO.
     */
    boost::asio::ip::udp::socket::non_blocking_io non_blocking_io(true);
    
    /**
     * Set the ipv4 socket to non-blocking.
     */
    socket_ipv4_.lowest_layer().io_control(non_blocking_io, ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
    /**
     * Bind the ipv4 socket.
     */
    socket_ipv4_.bind(ipv4_endpoint);
    
    /**
     * Start an asynchronous receive from on the ipv4 socket.
     */
    socket_ipv4_.async_receive_from(
        boost::asio::buffer(receive_buffer_), remote_endpoint_, strand_.wrap(
        std::bind(&udp_multiplexor::handle_async_receive_from,
        shared_from_this(), std::placeholders::_1, std::placeholders::_2))
    );
    
    /**
     * Allocate the ipv6 endpoint.
     */
    boost::asio::ip::udp::endpoint ipv6_endpoint(
        boost::asio::ip::address_v6::any(), port
    );
    
    /**
     * Open the ipv6 socket.
     */
    socket_ipv6_.open(ipv6_endpoint.protocol(), ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
    /**
     * Set the ipv6 socket to non-blocking.
     */
    socket_ipv6_.lowest_layer().io_control(non_blocking_io, ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
#if (! defined _MSC_VER)
    /**
     * Set the ipv6 socket to use v6 only.
     */
    socket_ipv6_.set_option(boost::asio::ip::v6_only(true));
#endif // _MSC_VER
    
    /**
     * Bind the ipv6 socket.
     */
    socket_ipv6_.bind(ipv6_endpoint);
    
    /**
     * Start an asynchronous receive from on the ipv6 socket.
     */
    socket_ipv6_.async_receive_from(
        boost::asio::buffer(receive_buffer_), remote_endpoint_, strand_.wrap(
        std::bind(&udp_multiplexor::handle_async_receive_from,
        shared_from_this(), std::placeholders::_1, std::placeholders::_2))
    );
    
    /**
     * Set the local endpoint.
     */
    m_local_endpoint = boost::asio::ip::udp::endpoint(
        network::local_address(), socket_ipv4_.is_open() ?
        socket_ipv4_.local_endpoint().port() :
        socket_ipv6_.local_endpoint().port()
    );
    
    log_info(
        "Udp multiplexor local ipv4 endpoint = " <<
        boost::asio::ip::udp::endpoint(network::local_address(),
        socket_ipv4_.local_endpoint().port()) << "."
    );
    log_info(
        "Udp multiplexor local ipv6 endpoint = " <<
        boost::asio::ip::udp::endpoint(network::local_address(),
        socket_ipv6_.local_endpoint().port()) << "."
    );
}

void udp_multiplexor::close()
{
    /**
     * Close the ipv4 socket.
     */
    if (socket_ipv4_.is_open())
    {
        socket_ipv4_.close();
    }
    
    /**
     * Close the ipv6 socket.
     */
    if (socket_ipv6_.is_open())
    {
        socket_ipv6_.close();
    }
}

void udp_multiplexor::send_to(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    /**
     * If the length cannot fit within the MTU of the underlying
     * datagram protocol we can perform fragmentation and IP-layer
     * fragmentation is allowed to the size of 2 Kilobytes.
     */
    if (len < 65535)
    {
        m_bytes_sent += len;

        auto uptime = std::time(0) - send_time_;
        
        if (uptime > 0)
        {
            m_bps_sent = m_bytes_sent / uptime;
        
            log_none("m_bps_sent = " << m_bps_sent);
            
            if (uptime > 1)
            {
                send_time_ = std::time(0);
                
                uptime = std::time(0) - send_time_;
                
                m_bytes_sent = 0;
            }
        }
        
        if (ep.protocol() == boost::asio::ip::udp::v4())
        {
            if (socket_ipv4_.is_open())
            {
                boost::system::error_code ec;
                
                /**
                 * Perform a blocking send_to.
                 */
                socket_ipv4_.send_to(boost::asio::buffer(buf, len), ep, 0, ec);
                
                if (ec)
                {
                    log_debug("UDP v4 send failed " << ec.message() << ".");
                    
                    if (ec == boost::asio::error::broken_pipe)
                    {
                        std::uint16_t port = socket_ipv4_.local_endpoint().port();
                        
                        close();
                        
                        open(port);
                        
                        boost::system::error_code ignored_ec;
                        
                        /**
                         * Perform a blocking send_to.
                         */
                        socket_ipv4_.send_to(
                            boost::asio::buffer(buf, len), ep, 0, ignored_ec
                        );
                    }
                }
            }
        }
        else
        {
            if (socket_ipv6_.is_open())
            {
                boost::system::error_code ec;
                
                /**
                 * Perform a blocking send_to.
                 */
                socket_ipv6_.send_to(boost::asio::buffer(buf, len), ep, 0, ec);

                if (ec)
                {
                    log_debug("UDP v6 send failed " << ec.message() << ".");
                    
                    if (ec == boost::asio::error::broken_pipe)
                    {
                        std::uint16_t port = socket_ipv6_.local_endpoint().port();
                        
                        close();
                        
                        open(port);
                        
                        boost::system::error_code ignored_ec;
                        
                        /**
                         * Perform a blocking send_to.
                         */
                        socket_ipv6_.send_to(
                            boost::asio::buffer(buf, len), ep, 0, ignored_ec
                        );
                    }
                }
            }
        }
    }
}

void udp_multiplexor::set_on_async_receive_from(
    const std::function<void (const boost::asio::ip::udp::endpoint &,
    const char *, const std::size_t &)> & f
    )
{
    m_on_async_receive_from = f;
}

const boost::asio::ip::udp::endpoint & udp_multiplexor::local_endpoint() const
{
    return m_local_endpoint;
}

const std::size_t & udp_multiplexor::bytes_sent() const
{
    return m_bytes_sent;
}

const std::size_t & udp_multiplexor::bps_sent() const
{
    return m_bps_sent;
}

const std::size_t & udp_multiplexor::bytes_received() const
{
    return m_bytes_received;
}

const std::size_t & udp_multiplexor::bps_received() const
{
    return m_bps_received;
}

void udp_multiplexor::handle_async_receive_from(
    const boost::system::error_code & ec, const std::size_t & len
    )
{
    m_bytes_received += len;

    auto uptime = std::time(0) - receive_time_;
    
    if (uptime > 0)
    {
        m_bps_received = m_bytes_received / uptime;
    
        log_none("m_bps_received = " << m_bps_received);
        
        if (uptime > 1)
        {
            receive_time_ = std::time(0);
            
            uptime = std::time(0) - receive_time_;
            
            m_bytes_received = 0;
        }
    }

    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec == boost::asio::error::bad_descriptor)
    {
        // ...
    }
    else if (ec)
    {
        log_debug("UDP receive failed, message = " << ec.message() << ".");
        
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
        /**
         * When iOS suspends an app it invalidates all udp sockets, don't
         * receive again and fix the socket when a send is attempted.
         */
#else
        if (remote_endpoint_.protocol() == boost::asio::ip::udp::v4())
        {
            /**
             * Start an asynchronous receive from on the ipv4 socket.
             */
            socket_ipv4_.async_receive_from(
                boost::asio::buffer(receive_buffer_), remote_endpoint_,
                strand_.wrap(std::bind(
                &udp_multiplexor::handle_async_receive_from,
                shared_from_this(), std::placeholders::_1,
                std::placeholders::_2))
            );
        }
        else
        {
            /**
             * Start an asynchronous receive from on the ipv6 socket.
             */
            socket_ipv6_.async_receive_from(
                boost::asio::buffer(receive_buffer_), remote_endpoint_,
                strand_.wrap(std::bind(
                &udp_multiplexor::handle_async_receive_from, shared_from_this(),
                std::placeholders::_1, std::placeholders::_2))
            );
        }
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
    }
    else
    {
        /**
         * Because of the way we fragment packets or let the IP-layer
         * perform fragmentation we should never receive a message larger
         * than 65535 because the largest we *should* send is 2 Kilobytes.
         */
        if (m_on_async_receive_from && (len > 0 && len < 65535))
        {
            m_on_async_receive_from(
                remote_endpoint_, &receive_buffer_[0], len
            );
        }
        
        if (remote_endpoint_.protocol() == boost::asio::ip::udp::v4())
        {
            /**
             * Start an asynchronous receive from on the ipv4 socket.
             */
            socket_ipv4_.async_receive_from(
                boost::asio::buffer(receive_buffer_), remote_endpoint_,
                strand_.wrap(std::bind(
                &udp_multiplexor::handle_async_receive_from, shared_from_this(),
                std::placeholders::_1, std::placeholders::_2))
            );
        }
        else
        {
            /**
             * Start an asynchronous receive from on the ipv6 socket.
             */
            socket_ipv6_.async_receive_from(
                boost::asio::buffer(receive_buffer_), remote_endpoint_,
                strand_.wrap(std::bind(
                &udp_multiplexor::handle_async_receive_from, shared_from_this(),
                std::placeholders::_1, std::placeholders::_2))
            );
        }
    }
}
