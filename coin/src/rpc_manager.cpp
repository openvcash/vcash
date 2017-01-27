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

#include <coin/network.hpp>
#include <coin/rpc_connection.hpp>
#include <coin/rpc_manager.hpp>
#include <coin/rpc_server.hpp>
#include <coin/stack_impl.hpp>
#include <coin/rpc_transport.hpp>

using namespace coin;

rpc_manager::rpc_manager(
    boost::asio::io_service & ios, boost::asio::strand & s,
    stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void rpc_manager::start()
{
    /**
     * Allocate the rpc_server.
     */
    m_rpc_server.reset(new rpc_server(io_service_, strand_, stack_impl_));
    
    /**
     * Set the accept handler.
     */
    m_rpc_server->set_on_accept(
        [this] (std::shared_ptr<rpc_transport> transport)
        {
            /**
             * Handle the incoming connection.
             */
            handle_accept(transport);
        }
    );
    
    try
    {
        auto rpc_port = stack_impl_.get_configuration().rpc_port(); 
        
        /**
         * Start the rpc_server.
         */
        if (m_rpc_server->open(rpc_port))
        {
            auto self(shared_from_this());
            
            timer_.expires_from_now(std::chrono::seconds(3));
            timer_.async_wait(strand_.wrap(
                std::bind(&rpc_manager::tick, self,
                std::placeholders::_1))
            );
        }
        else
        {
            throw std::runtime_error("failed to open RPC server");
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC manager failed to open rpc_server, what = " << e.what() << "."
        );
    }
}

void rpc_manager::stop()
{
    if (m_rpc_server)
    {
        m_rpc_server->close();
    }
    
    timer_.cancel();
    
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            connection->stop();
        }
    }
    
    m_tcp_connections.clear();
}

void rpc_manager::handle_accept(
    std::shared_ptr<rpc_transport> transport
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    if (m_tcp_connections.size() >= max_connections)
    {
        log_error(
            "RPC manager is dropping connection from " <<
            transport->socket().remote_endpoint() << ", limit reached."
        );
        
        /**
         * Stop the transport.
         */
        transport->stop();
    }
    else
    {
        if (
            network::instance().is_address_rpc_allowed(
            transport->socket().remote_endpoint().address().to_string())
            )
        {
            log_debug(
                "RPC manager accepted new tcp connection from " <<
                transport->socket().remote_endpoint() << ", " <<
                m_tcp_connections.size() << " connected peers."
            );

            /**
             * Allocate the tcp_connection.
             */
            auto connection = std::make_shared<rpc_connection> (
                io_service_, strand_, stack_impl_, transport
            );
            
            /**
             * Set the read timeout.
             */
            transport->set_read_timeout(60);
            
            /**
             * Set the write timeout.
             */
            transport->set_write_timeout(60);

            /**
             * Retain the connection.
             */
            m_tcp_connections[
                transport->socket().remote_endpoint()] = connection
            ;
            
            /**
             * Start the tcp_connection.
             */
            connection->start();
        }
        else
        {
            log_info(
                "RPC manager is dropping non-whitelisted connection from " <<
                transport->socket().remote_endpoint() << "."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
    }
}

void rpc_manager::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
        
        auto self(shared_from_this());
        
        auto it = m_tcp_connections.begin();
        
        while (it != m_tcp_connections.end())
        {
            if (auto connection = it->second.lock())
            {
                if (connection->is_transport_valid())
                {
                    ++it;
                }
                else
                {
                    connection->stop();
                    
                    it = m_tcp_connections.erase(it);
                }
            }
            else
            {
                it = m_tcp_connections.erase(it);
            }
        }
        
        timer_.expires_from_now(std::chrono::seconds(8));
        timer_.async_wait(strand_.wrap(
            std::bind(&rpc_manager::tick, self,
            std::placeholders::_1))
        );
    }
}
