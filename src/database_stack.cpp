/*
 * Copyright (c) 2013-2016 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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

#include <stdexcept>
#include <vector>

#include <coin/database_stack.hpp>
#include <coin/db_tx.hpp>
#include <coin/incentive.hpp>
#include <coin/incentive_manager.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/network.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/time.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_lock.hpp>
#include <coin/zerotime_manager.hpp>

using namespace coin;

database_stack::database_stack(
    boost::asio::io_service & ios, boost::asio::strand & s,
    stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , state_(state_stopped)
    , timer_(ios)
{
    // ...
}

void database_stack::start(const std::uint16_t & port, const bool & is_client)
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    /**
     * Do not start the database on test networks.
     */
    if (constants::test_net == false)
    {
        database::stack::configuration stack_config;
        
        /**
         * The bootstrap contacts.
         */
        std::vector< std::pair<std::string, std::uint16_t> > contacts;
        
        /**
         * Add the hard-coded bootstrap contacts.
         */
        contacts.push_back(std::make_pair("p01.v.cash", 32809));
        contacts.push_back(std::make_pair("p02.v.cash", 40006));
        contacts.push_back(std::make_pair("p03.v.cash", 40008));
        contacts.push_back(std::make_pair("p04.v.cash", 60912));
        contacts.push_back(std::make_pair("p05.v.cash", 43355));
        contacts.push_back(std::make_pair("p06.v.cash", 52461));
        contacts.push_back(std::make_pair("p07.v.cash", 51902));
        contacts.push_back(std::make_pair("p08.v.cash", 44111));
        contacts.push_back(std::make_pair("p09.v.cash", 53389));
        contacts.push_back(std::make_pair("p10.v.cash", 38548));
        
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
        join(contacts);
    }
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
    
    state_ = state_started;
}

void database_stack::join(
    const std::vector< std::pair<std::string, std::uint16_t> > & contacts
    )
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    database::stack::join(contacts);
#endif // USE_DATABASE_STACK
}

void database_stack::stop()
{
    if (state_ == state_started)
    {
        /**
         * Cancel the timer.
         */
        timer_.cancel();

#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
        /**
         * Do not stop the database on test networks.
         */
        if (constants::test_net == false)
        {
            database::stack::stop();
        }
#endif // USE_DATABASE_STACK

        state_ = state_stopped;
    }
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
     * Allocate the boost::asio::ip::tcp::endpoint.
     */
    boost::asio::ip::tcp::endpoint ep(
        boost::asio::ip::address::from_string(addr), port
    );
    
    /**
     * Allocate the buffer.
     */
    data_buffer buffer(buf, len);
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap(
        [this, buffer, ep]()
    {
        if (
            network::instance().is_address_banned(
            ep.address().to_string()) == false
            )
        {
            /**
             * Packets closer than 8 seconds apart from a single endpoint are
             * dropped for rate limiting purposes.
             */
            std::lock_guard<std::mutex> l1(mutex_packet_times_);
            
            if (packet_times_.count(ep.address().to_string()) > 0)
            {
                if (std::time(0) - packet_times_[ep.address().to_string()] < 8)
                {
                    log_info(
                        "Database stack (UDP) is dropping packet received too "
                        "soon."
                    );
                    
                    return;
                }
            }

            /**
             * Set the time this packet arrived from the address.
             */
            packet_times_[ep.address().to_string()] = std::time(0);
            
            enum { max_udp_length = 2048 };
            
            log_debug(
                "Database stack (UDP) got len = " << buffer.size() << "."
            );
            
            if (buffer.size() <= max_udp_length)
            {
                /**
                 * Allocate the message.
                 */
                message msg(buffer.data(), buffer.size());

                try
                {
                    /**
                     * Decode the message.
                     */
                    msg.decode();
                    
                    log_debug(
                        "Database stack (UDP) got " << msg.header().command <<
                        " from " << ep << "."
                    );
                }
                catch (std::exception & e)
                {
                    log_error(
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
                        
                        auto missing_inputs = false;
                        
                        /**
                         * Allocate the data_buffer.
                         */
                        data_buffer buffer;
                        
                        /**
                         * Encode the transaction.
                         */
                        tx->encode(buffer);
                        
                        if (
                            tx->accept_to_transaction_pool(txdb,
                            &missing_inputs).first
                            )
                        {
                            /**
                             * Inform the wallet_manager.
                             */
                            wallet_manager::instance().sync_with_wallets(
                                *tx, 0, true
                            );
                            
                            if (
                                globals::instance().operation_mode() ==
                                protocol::operation_mode_peer
                                )
                            {
                                /**
                                 * Allocate the inventory_vector.
                                 */
                                inventory_vector inv(
                                    inventory_vector::type_msg_tx,
                                    tx->get_hash()
                                );

                                log_info(
                                    "Database stack (UDP) is relaying inv "
                                    "message, command = " << inv.command() <<
                                    "."
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
                                 * Broadcast the message to "all" connected
                                 * peers.
                                 */
                                stack_impl_.get_tcp_connection_manager(
                                    )->broadcast(msg.data(), msg.size()
                                );
                            }
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
                                inventory_vector::type_msg_ztlock,
                                ztlock->hash_tx()
                            );

                            /**
                             * Check that the zerotime lock is not expired.
                             */
                            if (
                                time::instance().get_adjusted() <
                                ztlock->expiration()
                                )
                            {
                                /**
                                 * Check that the transaction hash exists in
                                 * the transaction pool before accepting a
                                 * zerotime_lock.
                                 */
                                auto hash_not_found =
                                    transaction_pool::instance().transactions(
                                    ).count(ztlock->hash_tx()) == 0
                                ;
                            
                                if (hash_not_found)
                                {
                                    log_info(
                                        "Database stack (UDP) got ZeroTime "
                                        "(hash not found), dropping " <<
                                        ztlock->hash_tx().to_string(
                                        ).substr(0, 8) << "."
                                    );
                                }
                                else if (
                                    zerotime::instance().locks().count(
                                    ztlock->hash_tx()) > 0
                                    )
                                {
                                    // ...
                                }
                                else
                                {
                                    /**
                                     * Prevent a peer from sending a
                                     * conflicting lock.
                                     */
                                    if (
                                        zerotime::instance().has_lock_conflict(
                                        ztlock->transactions_in(),
                                        ztlock->hash_tx())
                                        )
                                    {
                                        log_info(
                                            "TCP connection got ZeroTime "
                                            "(lock conflict), dropping " <<
                                            ztlock->hash_tx().to_string(
                                            ).substr(0, 8) << "."
                                        );
                                    }
                                    else
                                    {
                                        if (
                                            globals::instance(
                                            ).operation_mode() ==
                                            protocol::operation_mode_peer
                                            )
                                        {
                                            /**
                                             * Alllocate the buffer for
                                             * relaying.
                                             */
                                            data_buffer buffer;
                                        
                                            /**
                                             * Encode the zerotime_lock.
                                             */
                                            ztlock->encode(buffer);
                                            
                                            log_info(
                                                "Database stack (UDP) is "
                                                "relaying inv message, "
                                                "command = " <<
                                                inv.command() << "."
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
                                             * Broadcast the message to "all"
                                             * connected peers.
                                             */
                                            stack_impl_.get_tcp_connection_manager(
                                                )->broadcast(
                                                msg.data(), msg.size()
                                            );
                                        }
                                    
                                        log_info(
                                            "Database stack (UDP) is adding "
                                            "ZeroTime lock " <<
                                            ztlock->hash_tx().to_string() << "."
                                        );
                                        
                                        /**
                                         * Insert the zerotime_lock.
                                         */
                                        zerotime::instance().locks().insert(
                                            std::make_pair(ztlock->hash_tx(),
                                            *ztlock)
                                        );
                                        
                                        /**
                                         * Lock the inputs.
                                         */
                                        for (
                                            auto & i : ztlock->transactions_in()
                                            )
                                        {
                                            zerotime::instance(
                                                ).locked_inputs()[
                                                i.previous_out()] =
                                                ztlock->hash_tx()
                                            ;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                else if (msg.header().command == "ztvote")
                {
                    if (globals::instance().is_zerotime_enabled())
                    {
                        const auto & ztvote = msg.protocol_ztvote().ztvote;

                        if (ztvote)
                        {
                            /**
                             * Allocate the inventory_vector.
                             */
                            inventory_vector inv(
                                inventory_vector::type_msg_ztvote,
                                ztvote->hash_nonce()
                            );

                            if (
                                zerotime::instance().votes().count(
                                ztvote->hash_nonce()) > 0
                                )
                            {
                                // ...
                            }
                            else
                            {
                                /**
                                 * Insert the zerotime_vote.
                                 */
                                zerotime::instance().votes()[
                                    ztvote->hash_nonce()] = *ztvote
                                ;
                                
                                /**
                                 * Inform the zerotime_manager.
                                 */
                                stack_impl_.get_zerotime_manager(
                                    )->handle_vote(ep, *ztvote
                                );

                                if (
                                    globals::instance().operation_mode() ==
                                    protocol::operation_mode_peer
                                    )
                                {
                                    /**
                                     * Allocate the data_buffer.
                                     */
                                    data_buffer buffer;
                                    
                                    /**
                                     * Encode the transaction (reuse the
                                     * signature).
                                     */
                                    ztvote->encode(buffer, true);
                            
                                    log_info(
                                        "Database stack (UDP) is relaying inv "
                                        "message, command = " <<
                                        inv.command() << "."
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
                                     * Broadcast the message to "all" connected
                                     * peers.
                                     */
                                    stack_impl_.get_tcp_connection_manager(
                                        )->broadcast(msg.data(), msg.size()
                                    );
                                }
                            }
                        }
                    }
                }
                else if (msg.header().command == "ivote")
                {
                    if (globals::instance().is_incentive_enabled())
                    {
                        if (utility::is_initial_block_download() == false)
                        {
                            const auto & ivote = msg.protocol_ivote().ivote;
                            
                            if (ivote)
                            {
                                /**
                                 * Allocate the inventory_vector.
                                 */
                                inventory_vector inv(
                                    inventory_vector::type_msg_ivote,
                                    ivote->hash_nonce()
                                );

                                if (
                                    incentive::instance().votes().count(
                                    ivote->hash_nonce()) > 0
                                    )
                                {
                                    // ...
                                }
                                else
                                {
                                    /**
                                     * Check the vote score.
                                     */
                                    if (ivote->score() < 0)
                                    {
                                        log_debug(
                                            "Database stack (UDP) is dropping "
                                            "invalid ivote, score = " <<
                                            ivote->score() << "."
                                        );
                                    
                                        return;
                                    }
                                    else if (
                                        stack_impl_.get_incentive_manager(
                                        )->validate_collateral(*ivote) == false
                                        )
                                    {
                                        log_info(
                                            "Database stack (UDP) is dropping "
                                            "ivote invalid collateral."
                                        );
                                        
                                        return;
                                    }
                                    
                                    /**
                                     * Get the best block_index.
                                     */
                                    auto index_previous =
                                        stack_impl::get_block_index_best()
                                    ;
                                    
                                    /**
                                     * Get the next block height
                                     */
                                    auto height =
                                        index_previous ?
                                        index_previous->height() + 1 : 0
                                    ;
            
                                    /**
                                     * Check that the block height is close to
                                     * ours (within one blocks).
                                     */
                                    if (
                                        ivote->block_height() + 2 < height &&
                                        static_cast<std::int32_t> (height) -
                                        (ivote->block_height() + 2) > 0
                                        )
                                    {
                                        log_debug(
                                            "Database stack (UDP) is "
                                            "dropping old vote " <<
                                            ivote->block_height() + 2 <<
                                            ", diff = " <<
                                            static_cast<std::int32_t> (
                                            height) -
                                            (ivote->block_height() + 2) << "."
                                        );
                                        
                                        return;
                                    }
            
                                    /**
                                     * Insert the incentive_vote.
                                     */
                                    incentive::instance().votes()[
                                        ivote->hash_nonce()] = *ivote
                                    ;
                                    
                                    /**
                                     * Inform the incentive_manager.
                                     */
                                    stack_impl_.get_incentive_manager(
                                        )->handle_message(ep, msg
                                    );

                                    if (
                                        globals::instance().operation_mode() ==
                                        protocol::operation_mode_peer
                                        )
                                    {
                                        /**
                                         * Allocate the data_buffer.
                                         */
                                        data_buffer buffer;
                                        
                                        /**
                                         * Encode the transaction (reuse the
                                         * signature).
                                         */
                                        ivote->encode(buffer, true);
                                        
                                        log_info(
                                            "Database stack (UDP) is relaying "
                                            "inv message, command = " <<
                                            inv.command() << "."
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
                                         * Broadcast the message to "all"
                                         * connected peers.
                                         */
                                        stack_impl_.get_tcp_connection_manager(
                                            )->broadcast(msg.data(), msg.size()
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }));
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
