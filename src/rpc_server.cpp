/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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

#include <sstream>

#include <boost/algorithm/string.hpp>

#include <coin/http_transport.hpp>
#include <coin/logger.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/stack_impl.hpp>
#include <coin/rpc_server.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/rpc_transport.hpp>

using namespace coin;

rpc_server::rpc_server(
    boost::asio::io_service & ios, boost::asio::strand & s, stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , acceptor_ipv4_(ios)
    , acceptor_ipv6_(ios)
    , transports_timer_(ios)
{
    // ...
}

bool rpc_server::open(const std::uint16_t & port)
{
    assert(!acceptor_ipv4_.is_open());
    assert(!acceptor_ipv6_.is_open());
    
    log_info("RPC server is opening with port = " << port << ".");
    
    boost::system::error_code ec;
    
    /**
     * Allocate the ipv4 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv4_endpoint(
        boost::asio::ip::address_v4::loopback(), port
    );
    
    try
    {
        auto args = stack_impl_.get_configuration().args();
        
        auto it = args.find("rpc-allow-ips");

        if (it != args.end())
        {
            std::vector<std::string> parts;
            
            boost::split(parts, it->second, boost::is_any_of(","));
    
            for (auto & i : parts)
            {
                boost::asio::ip::address addr(
                    boost::asio::ip::address::from_string(i.c_str())
                );
                
                log_info(
                    "RPC server got allow-ip = " << addr.to_string() << "."
                );
                
                /**
                 * Insert the address into the allowed list.
                 */
                network::instance().allowed_addresses_rpc().insert(i);
            }
            
            ipv4_endpoint = boost::asio::ip::tcp::endpoint(
                boost::asio::ip::address_v4::any(), port
            );
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC server failed to parse rpc-allow-ips, what = " <<
            e.what() << "."
        );
    }
    
    /**
     * Open the ipv4 socket.
     */
    acceptor_ipv4_.open(boost::asio::ip::tcp::v4(), ec);
    
    if (ec)
    {
        log_error("RPC server ipv4 open failed, message = " << ec.message());
        
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
        log_error("RPC server ipv4 bind failed, message = " << ec.message());
        
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
     * Start the tick timer.
     */
    do_tick(1);
    
    /**
     * Allocate the ipv6 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv6_endpoint(
        boost::asio::ip::address_v6::loopback(),
        acceptor_ipv4_.local_endpoint().port()
    );
    
    /**
     * Open the ipv6 socket.
     */
    acceptor_ipv6_.open(boost::asio::ip::tcp::v6(), ec);
    
    if (ec)
    {
        log_error("RPC server ipv6 open failed, message = " << ec.message());
        
        /**
         * We do not close the acceptor_ipv4_.
         */
        acceptor_ipv6_.close();
        
        /**
         * This is not a failure.
         */
        return true;
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
        log_error("RPC server ipv6 bind failed, message = " << ec.message());
        
        /**
         * We do not close the acceptor_ipv4_.
         */
        acceptor_ipv6_.close();
        
        /**
         * This is not a failure.
         */
        return true;
    }
    
    /**
     * Listen
     */
    acceptor_ipv6_.listen();
    
    /**
     * Accept
     */
    do_ipv6_accept();
    
    return true;
}

void rpc_server::close()
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

void rpc_server::set_on_accept(
    const std::function<void (std::shared_ptr<rpc_transport>)> & f
    )
{
    m_on_accept = f;
}

const std::vector< std::weak_ptr<rpc_transport> > &
    rpc_server::rpc_transports() const
{
    std::lock_guard<std::recursive_mutex> l(rpc_transports_mutex_);
    
    return m_rpc_transports;
}

void rpc_server::do_ipv4_accept()
{
    auto self(shared_from_this());
    
    auto t = std::make_shared<rpc_transport>(io_service_, strand_);
    
    std::lock_guard<std::recursive_mutex> l(rpc_transports_mutex_);
    
    m_rpc_transports.push_back(t);
    
    acceptor_ipv4_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            try
            {
                boost::asio::ip::tcp::endpoint remote_endpoint =
                    t->socket().remote_endpoint()
                ;
                
                log_debug(
                    "RPC server is accepting tcp connection from " <<
                    remote_endpoint << "."
                );
                
                /**
                 * Callback
                 */
                m_on_accept(t);
            }
            catch (std::exception & e)
            {
                log_none(
                    "RPC server remote_endpoint, what = " <<
                    e.what() << "."
                );
            }
            
            do_ipv4_accept();
        }
    }));
}

void rpc_server::do_ipv6_accept()
{
    auto self(shared_from_this());
    
    auto t = std::make_shared<rpc_transport>(io_service_, strand_);
    
    std::lock_guard<std::recursive_mutex> l(rpc_transports_mutex_);
    
    m_rpc_transports.push_back(t);
    
    acceptor_ipv6_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            try
            {
                boost::asio::ip::tcp::endpoint remote_endpoint =
                    t->socket().remote_endpoint()
                ;
                
                log_debug(
                    "RPC server is accepting tcp connection from " <<
                    remote_endpoint << "."
                );
            
                /**
                 * Callback
                 */
                m_on_accept(t);
            }
            catch (std::exception & e)
            {
                log_none("RPC server remote_endpoint, what = " << e.what());
            }
            
            do_ipv6_accept();
        }
    }));
}

void rpc_server::do_tick(const std::uint32_t & seconds)
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
            std::lock_guard<std::recursive_mutex> l(rpc_transports_mutex_);
            
            auto it = m_rpc_transports.begin();
            
            while (it != m_rpc_transports.end())
            {
                if (auto t = it->lock())
                {
                    ++it;
                }
                else
                {
                    it = m_rpc_transports.erase(it);
                }
            }
            
            do_tick(seconds);
        }
    }));
}

int rpc_server::run_test(
    boost::asio::io_service & ios, boost::asio::strand & s
    )
{
    stack_impl * null_stack_impl = 0;
    
    auto acceptor = std::make_shared<rpc_server> (ios, s, *null_stack_impl);
    
    acceptor->set_on_accept(
        [] (std::shared_ptr<rpc_transport> transport)
        {
            transport->start();
        }
    );
    
    bool ret = false;
    
    try
    {
        auto port = protocol::default_rpc_port + 1;
        
        ret = acceptor->open(port);

        std::cout <<
            "rpc_server::run_test opened on port = " << port <<
        std::endl;
    }
    catch (std::exception & e)
    {
        std::cerr << "what = " << e.what() << std::endl;
    }
    
    if (ret == false)
    {
        std::cerr << "rpc_server::run_test failed" << std::endl;
    }

    return 0;
}
