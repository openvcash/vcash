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

#include <database/crypto.hpp>
#include <database/crypto_connection.hpp>
#include <database/crypto_handler.hpp>
#include <database/logger.hpp>
#include <database/node_impl.hpp>
#include <database/udp_handler.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

crypto_handler::crypto_handler(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl,
    const std::shared_ptr<udp_multiplexor> & multiplexor
    )
    : handler(ios, impl, multiplexor)
    , timer_(ios)
{
    // ...
}

void crypto_handler::start()
{
    /**
     * Start the timer.
     */
    timer_.expires_from_now(std::chrono::seconds(1));
    timer_.async_wait(
        strand_.wrap(std::bind(&crypto_handler::tick, shared_from_this(),
        std::placeholders::_1))
    );
}

void crypto_handler::stop()
{
    timer_.cancel();
}

void crypto_handler::send_to(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    /**
     * Lock the mutex.
     */
    std::lock_guard<std::recursive_mutex> l(mutex_);

    auto it = connections_.find(ep);
    
    if (it == connections_.end())
    {
        std::shared_ptr<crypto_connection> conn(
            new crypto_connection(io_service_, shared_from_this(),
            udp_multiplexor_.lock(), ep, crypto_connection::direction_outbound)
        );
        
        /**
         * Open the connection.
         */
        conn->open();
        
        /**
         * Insert the new connection.
         */
        connections_.insert(std::make_pair(ep, conn));
        
        conn->send(buf, len);
    }
    else
    {
        if (it->second->state() == crypto_connection::state_open)
        {
            it->second->send(buf, len);
        }
        else
        {
            std::shared_ptr<crypto_connection> conn(
                new crypto_connection(io_service_, shared_from_this(),
                udp_multiplexor_.lock(), ep,
                crypto_connection::direction_outbound)
            );
            
            /**
             * Open the connection.
             */
            conn->open();
            
            /**
             * Insert the new connection.
             */
            connections_.insert(std::make_pair(ep, conn));
            
            conn->send(buf, len);
        }
    }
}

bool crypto_handler::on_async_receive_from(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    /**
     * rfc5764
     * The process for demultiplexing a packet is as follows. The receiver
     * looks at the first byte of the packet.  If the value of this byte
     * is 0 or 1, then the packet is STUN.  If the value is in between 128
     * and 191 (inclusive), then the packet is RTP (or RTCP, if both RTCP
     * and RTP are being multiplexed over the same destination port). If
     * the value is between 20 and 63 (inclusive), the packet is DTLS.
     * This process is summarized in Figure 3.
     */
    if (
        static_cast<std::uint8_t> (buf[0]) > 19 &&
        static_cast<std::uint8_t> (buf[0]) < 64
        )
    {        
        /**
         * Lock the mutex.
         */
        std::lock_guard<std::recursive_mutex> l(mutex_);

        auto it = connections_.find(ep);
        
        if (it == connections_.end())
        {
            std::shared_ptr<crypto_connection> conn(
                new crypto_connection(io_service_, shared_from_this(),
                udp_multiplexor_.lock(), ep,
                crypto_connection::direction_inbound)
            );
            
            /**
             * Do not open incoming connections.
             */
            
            /**
             * Insert the new connection.
             */
            connections_.insert(std::make_pair(ep, conn));
            
            /**
             * Inform the connection.
             */
            conn->on_receive(buf, len);
        }
        else
        {
            if (it->second->state() == crypto_connection::state_open)
            {
                /**
                 * Inform the connection.
                 */
                it->second->on_receive(buf, len);
            }
            else
            {
                std::shared_ptr<crypto_connection> conn(
                    new crypto_connection(io_service_, shared_from_this(),
                    udp_multiplexor_.lock(), ep,
                    crypto_connection::direction_inbound)
                );
                
                /**
                 * Do not open incoming connections.
                 */
                
                /**
                 * Insert the new connection.
                 */
                connections_.insert(std::make_pair(ep, conn));
                
                /**
                 * Inform the connection.
                 */
                conn->on_receive(buf, len);
            }
        }
        
        return true;
    }
    
    return false;
}

void crypto_handler::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * Lock the mutex.
         */
        std::lock_guard<std::recursive_mutex> l(mutex_);
        
        auto it = connections_.begin();
        
        while (it != connections_.end())
        {
            std::shared_ptr<crypto_connection> & conn = it->second;
            
            if (conn->state() == crypto_connection::state_closed)
            {
                connections_.erase(it++);
            }
            else
            {
                ++it;
            }
        }
        
        /**
         * Start the timer.
         */
        timer_.expires_from_now(std::chrono::seconds(15));
        timer_.async_wait(
            strand_.wrap(std::bind(&crypto_handler::tick, shared_from_this(),
            std::placeholders::_1))
        );
    }
}
