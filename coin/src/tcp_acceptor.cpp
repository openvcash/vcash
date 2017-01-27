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

#include <sstream>

#include <boost/asio.hpp>

#include <coin/logger.hpp>
#include <coin/protocol.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_transport.hpp>

using namespace coin;

tcp_acceptor::tcp_acceptor(
    boost::asio::io_service & ios, boost::asio::strand & s
    )
    : io_service_(ios)
    , strand_(s)
    , acceptor_ipv4_(io_service_)
    , acceptor_ipv6_(io_service_)
    , transports_timer_(io_service_)
{
    // ...
}

bool tcp_acceptor::open(const std::uint16_t & port)
{
    assert(!acceptor_ipv4_.is_open());
    assert(!acceptor_ipv6_.is_open());
    
    log_debug("tcp acceptor is opening with port = " << port);
    
    boost::system::error_code ec;
    
    /**
     * Allocate the ipv4 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv4_endpoint(
        boost::asio::ip::address_v4::any(), port
    );
    
    /**
     * Open the ipv4 socket.
     */
    acceptor_ipv4_.open(boost::asio::ip::tcp::v4(), ec);
    
    if (ec)
    {
        log_error("ipv4 open failed, message = " << ec.message());
        
        acceptor_ipv4_.close();
        
        return false;
    }
    
    /**
     * Set option SO_REUSEADDR.
     */
    acceptor_ipv4_.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true)
    );
    
    /**
     * Bind the socket.
     */
    acceptor_ipv4_.bind(ipv4_endpoint, ec);
   
    if (ec)
    {
        log_error("ipv4 bind failed, message = " << ec.message());
        
        acceptor_ipv4_.close();
        
        return false;
    }
    
    /**
     * Listen
     */
    acceptor_ipv4_.listen();
    
    /**
     * Accept
     */
    do_ipv4_accept();
    
    /**
     * Allocate the ipv6 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv6_endpoint(
        boost::asio::ip::address_v6::any(),
        acceptor_ipv4_.local_endpoint().port()
    );
    
    /**
     * Open the ipv6 socket.
     */
    acceptor_ipv6_.open(boost::asio::ip::tcp::v6(), ec);
    
    if (ec)
    {
        log_error("ipv6 open failed, message = " << ec.message());
        
        acceptor_ipv4_.close();
        acceptor_ipv6_.close();
        
        return false;
    }
    
#if defined(__linux__) || defined(__APPLE__)
    acceptor_ipv6_.set_option(boost::asio::ip::v6_only(true));
#endif

    /**
     * Set option SO_REUSEADDR.
     */
    acceptor_ipv6_.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true)
    );
    
    /**
     * Bind the socket.
     */
    acceptor_ipv6_.bind(ipv6_endpoint, ec);
   
    if (ec)
    {
        log_error("ipv6 bind failed, message = " << ec.message());
        
        acceptor_ipv4_.close();
        acceptor_ipv6_.close();
        
        return false;
    }
    
    /**
     * Listen
     */
    acceptor_ipv6_.listen();
    
    /**
     * Accept
     */
    do_ipv6_accept();
    
    /**
     * Start the tick timer.
     */
    do_tick(1);

    return true;
}

void tcp_acceptor::close()
{
    auto self(shared_from_this());
    
    io_service_.post(strand_.wrap(
        [this, self]()
    {
        acceptor_ipv4_.close();
        acceptor_ipv6_.close();
        transports_timer_.cancel();
    }));
}

void tcp_acceptor::set_on_accept(
    const std::function<void (std::shared_ptr<tcp_transport>)> & f
    )
{
    m_on_accept = f;
}

const boost::asio::ip::tcp::endpoint tcp_acceptor::local_endpoint() const
{
    return acceptor_ipv4_.is_open() ?
        acceptor_ipv4_.local_endpoint() :
        acceptor_ipv6_.local_endpoint()
    ;
}

void tcp_acceptor::do_ipv4_accept()
{
    auto self(shared_from_this());

    auto t = std::make_shared<tcp_transport> (io_service_, strand_, true);
    
    m_tcp_transports.push_back(t);
    
    acceptor_ipv4_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (acceptor_ipv4_.is_open() == true)
        {
            if (ec)
            {
                log_error(
                    "TCP acceptor accept failed, message = " <<
                    ec.message() << "."
                );
            }
            else
            {
                try
                {
                    boost::asio::ip::tcp::endpoint remote_endpoint =
                        t->socket().remote_endpoint()
                    ;

                    /**
                     * Callback
                     */
                    if (m_on_accept)
                    {
                        log_info(
                            "Accepting tcp connection from " << remote_endpoint
                        );
                        
                        m_on_accept(t);
                    }
                    else
                    {
                        log_info(
                            "Dropping tcp connection from " <<
                            remote_endpoint << " no handler set."
                        );
                    }
                }
                catch (std::exception & e)
                {
                    log_error(
                        "TCP acceptor remote_endpoint, what = " << e.what()
                    );
                }
            }
            
            do_ipv4_accept();
        }
    }));
}

void tcp_acceptor::do_ipv6_accept()
{
    auto self(shared_from_this());

    auto t = std::make_shared<tcp_transport> (io_service_, strand_, true);
    
    m_tcp_transports.push_back(t);
    
    acceptor_ipv6_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (acceptor_ipv6_.is_open() == true)
        {
            if (ec)
            {
                log_error(
                    "TCP acceptor accept failed, message = " <<
                    ec.message() << "."
                );
            }
            else
            {
                try
                {
                    boost::asio::ip::tcp::endpoint remote_endpoint =
                        t->socket().remote_endpoint()
                    ;
                    
                    log_debug(
                        "Accepting tcp connection from " << remote_endpoint
                    );
                
                    /**
                     * Callback
                     */
                    m_on_accept(t);
                }
                catch (std::exception & e)
                {
                    log_error(
                        "TCP acceptor remote_endpoint, what = " << e.what()
                    );
                }
            }
            
            do_ipv6_accept();
        }
    }));
}

void tcp_acceptor::do_tick(const std::uint32_t & seconds)
{
    transports_timer_.expires_from_now(std::chrono::seconds(seconds));
    transports_timer_.async_wait(strand_.wrap(
        [this, seconds](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            auto it = m_tcp_transports.begin();
            
            while (it != m_tcp_transports.end())
            {
                if (auto t = it->lock())
                {
                    ++it;
                }
                else
                {
                    it = m_tcp_transports.erase(it);
                }
            }
            
            do_tick(seconds);
        }
    }));
}

int tcp_acceptor::run_test(
    boost::asio::io_service & ios, boost::asio::strand & s
    )
{
    auto acceptor = std::make_shared<tcp_acceptor> (ios, s);
    
    acceptor->set_on_accept(
        [] (std::shared_ptr<tcp_transport> transport)
        {
            transport->start();
        }
    );
    
    bool ret = false;
    
    try
    {
        std::uint16_t port = protocol::default_tcp_port;
        
        while (ret == false)
        {
            ret = acceptor->open(port);
            
            if (ret == false)
            {
                port += 2;
            }
            else
            {
                break;
            }
            
            /**
             * Try 50 even ports.
             */
            if (port > protocol::default_tcp_port + 100)
            {
                break;
            }
        }
        
        std::cout <<
            "tcp_acceptor::run_test opened on port = " << port <<
        std::endl;
    }
    catch (std::exception & e)
    {
        std::cerr << "what = " << e.what() << std::endl;
    }
    
    if (ret == false)
    {
        std::cerr << "tcp_acceptor::run_test failed" << std::endl;
    }

    return 0;
}
