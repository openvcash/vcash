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

#include <stdexcept>
#include <vector>

#include <coin/database_stack.hpp>
#include <coin/db_tx.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/time.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_lock.hpp>

using namespace coin;

database_stack::database_stack(
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

void database_stack::start(const std::uint16_t & port, const bool & is_client)
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    database::stack::configuration stack_config;
    
    /**
     * The bootstrap contacts.
     */
    std::vector< std::pair<std::string, std::uint16_t> > contacts;
    
    /**
     * Add the hard-coded bootstrap contacts.
     */
    contacts.push_back(std::make_pair("p01.vanillacoin.net", 40004));
    contacts.push_back(std::make_pair("p02.vanillacoin.net", 40006));
    contacts.push_back(std::make_pair("p03.vanillacoin.net", 40008));
    contacts.push_back(std::make_pair("p04.vanillacoin.net", 40010));
    contacts.push_back(std::make_pair("p05.vanillacoin.net", 55555));
    contacts.push_back(std::make_pair("p06.vanillacoin.net", 40014));
    contacts.push_back(std::make_pair("p07.vanillacoin.net", 55555));
    contacts.push_back(std::make_pair("p08.vanillacoin.net", 40018));
    
    /**
     * Set the port.
     */
    stack_config.set_port(port);
    
    /**
     * Set the operation mode.
     */
    stack_config.set_operation_mode(
        is_client ? database::stack::configuration::operation_mode_interface :
        database::stack::configuration::operation_mode_storage
    );
    
    /**
     * Start the database::stack.
     */
    database::stack::start(stack_config);
    
    /**
     * Join the database::stack.
     */
    database::stack::join(contacts);
#endif // USE_DATABASE_STACK

    auto self(shared_from_this());
    
    /**
     * Start the timer.
     */
    timer_.expires_from_now(std::chrono::seconds(8));
    timer_.async_wait(strand_.wrap(
        std::bind(&database_stack::tick, self,
        std::placeholders::_1))
    );
}

void database_stack::stop()
{
    /**
     * Cancel the timer.
     */
    timer_.cancel();

#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    database::stack::stop();
#endif // USE_DATABASE_STACK
}

std::uint16_t database_stack::broadcast(const std::vector<std::uint8_t> & val)
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    return database::stack::broadcast(val);
#else
    return 0;
#endif // USE_DATABASE_STACK
}

std::list< std::pair<std::string, std::uint16_t> > database_stack::endpoints()
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    return database::stack::endpoints();
#else
    return std::list< std::pair<std::string, std::uint16_t> > ();
#endif // USE_DATABASE_STACK
}

std::pair<std::uint16_t, std::vector<std::string> >
    database_stack::poll_find_results(const std::uint16_t & transaction_id
    )
{
    std::pair<std::uint16_t, std::vector<std::string> > ret;
    
    auto it = find_results_.find(transaction_id);
    
    if (it != find_results_.end())
    {
        ret.first = it->first;
        ret.second = it->second;
    
        find_results_.erase(it);
    }
    
    return ret;
}

void database_stack::on_find(
    const std::uint16_t & transaction_id,
    const std::string & query
    )
{
    find_results_[transaction_id].push_back(query);
}

void database_stack::on_udp_receive(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    // ...
}

void database_stack::on_broadcast(
    const char * addr, const std::uint16_t & port,
    const char * buf, const std::size_t & len
    )
{
    /**
     * Packets closer than one second apart from a single endpoint are
     * dropped for rate limiting purposes.
     */
    std::lock_guard<std::mutex> l1(mutex_packet_times_);
    
    if (packet_times_.count(addr) > 0)
    {
        if (std::time(0) - packet_times_[addr] < 2)
        {
            log_debug(
                "Database stack (UDP) is dropping packet received too soon."
            );
            
            return;
        }
    }

    /**
     * Set the time this packet arrived from the address.
     */
    packet_times_[addr] = std::time(0);
    
    enum { max_udp_length = 2048 };
    
    log_debug("Database stack (UDP) got len = " << len << ".");
    
    if (len <= max_udp_length)
    {
        /**
         * Allocate the message.
         */
        message msg(buf, len);

        try
        {
            /**
             * Decode the message.
             */
            msg.decode();
            
            log_debug(
                "Database stack (UDP) got " << msg.header().command <<
                " from " << addr << ":" << port << "."
            );
            
            return;
        }
        catch (std::exception & e)
        {
            log_debug(
                "Database stack (UDP) failed to decode message, "
                "what = " << e.what() << "."
            );
            
            return;
        }
        
        if (msg.header().command == "tx")
        {
            const auto & tx = msg.protocol_tx().tx;
            
            if (tx)
            {
                db_tx txdb("r");
                
                bool missing_inputs = false;
                
                /**
                 * Allocate the data_buffer.
                 */
                data_buffer buffer;
                
                /**
                 * Encode the transaction.
                 */
                tx->encode(buffer);
                
                if (
                    tx->accept_to_transaction_pool(txdb, &missing_inputs).first
                    )
                {
                    /**
                     * Inform the wallet_manager.
                     */
                    wallet_manager::instance().sync_with_wallets(*tx, 0, true);
                    
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_tx, tx->get_hash()
                    );

                    log_info(
                        "Database stack (UDP) is relaying inv message, "
                        "command = " << inv.command() << "."
                    );
                    
                    /**
                     * Allocate the message.
                     */
                    message msg(inv.command(), buffer);

                    /**
                     * Encode the message.
                     */
                    msg.encode();

                    /**
                     * Broadcast the message to "all" connected peers.
                     */
                    stack_impl_.get_tcp_connection_manager()->broadcast(
                        msg.data(), msg.size()
                    );
                }
                else if (missing_inputs)
                {
                    utility::add_orphan_tx(buffer);
                }
            }
        }
        else if (msg.header().command == "ztlock")
        {
            if (globals::instance().is_zerotime_enabled())
            {
                const auto & ztlock = msg.protocol_ztlock().ztlock;

                if (ztlock)
                {
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_ztlock, ztlock->hash_tx()
                    );
                    
                    /**
                     * Check that the zerotime lock is not expired.
                     */
                    if (time::instance().get_adjusted() > ztlock->expiration())
                    {
                        /**
                         * Check if we already have this zerotime lock.
                         */
                        if (
                            zerotime::instance().locks().count(
                            ztlock->hash_tx()) > 0
                            )
                        {
                            // ...
                        }
                        else
                        {
                            /**
                             * Alllocate the buffer for relaying.
                             */
                            data_buffer buffer;
                        
                            /**
                             * Encode the zerotime_lock.
                             */
                            ztlock->encode(buffer);
                            
                            log_info(
                                "Database stack (UDP) is relaying inv "
                                "message, command = " << inv.command() << "."
                            );
                            
                            /**
                             * Allocate the message.
                             */
                            message msg(inv.command(), buffer);

                            /**
                             * Encode the message.
                             */
                            msg.encode();

                            /**
                             * Broadcast the message to "all" connected peers.
                             */
                            stack_impl_.get_tcp_connection_manager(
                                )->broadcast(msg.data(), msg.size()
                            );
                    
                            log_info(
                                "Database stack (UDP) is adding ZeroTime "
                                "lock " << ztlock->hash_tx().to_string() << "."
                            );
                            
                            /**
                             * Insert the zerotime_lock.
                             */
                            zerotime::instance().locks().insert(
                                std::make_pair(ztlock->hash_tx(), *ztlock)
                            );
                            
                            /**
                             * Lock the inputs.
                             */
                            for (auto & i : ztlock->transactions_in())
                            {
                                zerotime::instance().locked_inputs()[
                                    i.previous_out()] = ztlock->hash_tx()
                                ;
                            }
                        }
                    }
                }
            }
        }
    }
}

void database_stack::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        /**
         * If we have not received a packet within eight seconds from an
         * address erase it from the packet times.
         */
        
        std::lock_guard<std::mutex> l1(mutex_packet_times_);
        
        auto it = packet_times_.begin();
        
        while (it != packet_times_.end())
        {
            if (std::time(0) - it->second >= 8)
            {
                it = packet_times_.erase(it);
            }
            else
            {
                ++it;
            }
        }
        
        /**
         * Get the number of udp endpoints in the routing table.
         */
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
        auto udp_connections = endpoints().size();
#else
        auto udp_connections = 0;
#endif // USE_DATABASE_STACK
        
        log_info(
            "Database stack has " << udp_connections << " UDP connections."
        );
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status message.
         */
        status["type"] = "network";
        
        /**
         * Set the value.
         */
        status["value"] = udp_connections > 0 ? "Connected" : "Connecting";
        
        /**
         * Set the network.udp.connections.
         */
        status["network.udp.connections"] = std::to_string(
            udp_connections
        );
        
        /**
         * Callback status.
         */
        stack_impl_.get_status_manager()->insert(status);

        /**
         * Start the timer.
         */
        timer_.expires_from_now(std::chrono::seconds(60));
        timer_.async_wait(strand_.wrap(
            std::bind(&database_stack::tick, self,
            std::placeholders::_1))
        );
    }
}
