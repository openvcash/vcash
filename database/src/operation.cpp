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

#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/operation.hpp>
#include <database/operation_queue.hpp>
#include <database/protocol.hpp>
#include <database/slot.hpp>

using namespace database;

operation::operation(
    boost::asio::io_service & ios, const std::uint16_t & transaction_id,
    std::shared_ptr<operation_queue> & queue,
    std::shared_ptr<node_impl> impl, const std::string & query,
    const std::set<std::uint16_t> & slot_ids,
    const std::set<boost::asio::ip::udp::endpoint> & snodes
    )
    : m_state(state_none)
    , m_transaction_id(transaction_id)
    , m_query(query)
    , m_slot_ids(slot_ids)
    , m_storage_nodes(snodes)
    , io_service_(ios)
    , strand_(ios)
    , uptime_(std::chrono::steady_clock::now())
    , timeout_timer_(ios)
    , run_timer_(ios)
    , operation_queue_(queue)
    , node_impl_(impl)
{
    BOOST_STATIC_ASSERT(
        static_cast<uint8_t> (timeout_interval) > 
        static_cast<uint8_t> (rpc::timeout_interval)
    );
}

void operation::start()
{
    /**
     @note Some classes overload this function.
     */
    std::lock_guard<std::recursive_mutex> l(probe_mutex_);
    
    /**
     * Set the state.
     */
    m_state = state_starting;
    
    /**
     * Insert the slot's storage node endpoints into the unprobed list.
     */
    unprobed_.insert(
        unprobed_.begin(), m_storage_nodes.begin(), m_storage_nodes.end()
    );
    
    /**
     * Start the timeout timer.
     */
    timeout_timer_.expires_from_now(
        std::chrono::seconds(timeout_interval)
    );
    timeout_timer_.async_wait(
        strand_.wrap(std::bind(&operation::timeout_tick, shared_from_this(),
        std::placeholders::_1))
    );
    
    /**
     * Set the state.
     */
    m_state = state_started;
    
    /**
     * Start the run timer.
     */
    run(boost::system::error_code());
}

void operation::stop()
{
    log_none("Operation " << m_transaction_id << " is stopping.");
    
    if (m_state == state_started)
    {
        /**
         * Set the state.
         */
        m_state = state_stopping;
        
        /**
         * cancel the timeout timer.
         */
        timeout_timer_.cancel();
        
        /**
         * Cancel the run timer.
         */
        run_timer_.cancel();

        std::lock_guard<std::recursive_mutex> l(rpcs_mutex_);
        
        auto it = m_rpcs.begin();
        
        while (it != m_rpcs.end())
        {
            if (it->second)
            {
                it->second->stop();
            }
            
            m_rpcs.erase(it++);
        }
        
        /**
         * Set the state.
         */
        m_state = state_stopped;
    }
}

const operation::state_t & operation::state() const
{
    return m_state;
}

const std::uint16_t & operation::transaction_id() const
{
    return m_transaction_id;
}

std::uint16_t operation::next_transaction_id()
{
    static std::uint16_t g_transaction_id = 0;
    
    return ++g_transaction_id;
}

std::map<std::uint16_t, std::shared_ptr<rpc> > & operation::rpcs()
{
    std::lock_guard<std::recursive_mutex> l(rpcs_mutex_);
    
    return m_rpcs;
}

const std::set<std::uint16_t> & operation::message_tids() const
{
    std::lock_guard<std::recursive_mutex> l(message_tids_mutex_);
    
    return m_message_tids;
}

const std::set<boost::asio::ip::udp::endpoint> &
    operation::storage_nodes() const
{
    return m_storage_nodes;
}

void operation::run(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        if (m_state == state_started)
        {
            std::lock_guard<std::recursive_mutex> l1(probe_mutex_);
            std::lock_guard<std::recursive_mutex> l2(rpcs_mutex_);

            /**
             * Continue to probe contacts while there are unprobed and the
             * number of inflight contacts is less than alpha.
             */
            while (!unprobed_.empty() && m_rpcs.size() < 3)
            {
                /**
                 * If the next contact hasn't been probed probe it.
                 */
                if (std::find(
                    probed_.begin(), probed_.end(), unprobed_.front()
                    ) == probed_.end())
                {
                    /**
                     * Move the contact from un-probed to probed.
                     */
                    probed_.push_back(unprobed_.front());

                    /**
                     * Get the next message.
                     */
                    std::shared_ptr<message> msg = next_message(
                        unprobed_.front()
                    );
                    
                    if (msg)
                    {                    
                        /**
                         * Allocate the rpc.
                         */
                        std::shared_ptr<rpc> call(
                            new rpc(io_service_, msg->header_transaction_id(),
                            unprobed_.front())
                        );
                        
                        /**
                         * Set the timeout handler.
                         */
                        call->set_on_timeout(
                            strand_.wrap(std::bind(&operation::on_rpc_timeout,
                            shared_from_this(), std::placeholders::_1))
                        );
                        
                        /**
                         * Allocate an rpc.
                         */
                        m_rpcs.insert(
                            std::make_pair(msg->header_transaction_id(), call)
                        );
                        
                        std::lock_guard<std::recursive_mutex> l(
                            message_tids_mutex_
                        );
                        
                        /**
                         * Retain the message transaction id.
                         */
                        m_message_tids.insert(msg->header_transaction_id());
                        
                        /**
                         * Start the rpc.
                         */
                        call->start();

                        if (std::shared_ptr<node_impl> n = node_impl_.lock())
                        {
                            /**
                             * Send the next message.
                             */
                            n->send_message(unprobed_.front(), msg);
                        }

                        /**
                         * Remove the probed contact.
                         */
                        unprobed_.pop_front();
                    }
                    else
                    {
                        /**
                         * We got a null message, return, aborting but
                         * not stopping the operation.
                         */
                        return;
                    }

                }
                else
                {
                    unprobed_.pop_front();
                }
            }

            /**
             * Start the run timer.
             */
            run_timer_.expires_from_now(std::chrono::seconds(1));
            run_timer_.async_wait(
                strand_.wrap(std::bind(&operation::run, shared_from_this(),
                std::placeholders::_1))
            );
        }
    }
}

void operation::on_response(message & msg, const bool & done)
{
    if (m_state == state_started)
    {
        std::lock_guard<std::recursive_mutex> l1(probe_mutex_);

        if (done)
        {
            /**
             * Inform the node_impl that the rpc has a response.
             */
            node_impl_.lock()->handle_rpc_response(
                m_transaction_id, msg.header_transaction_id(),
                msg.source_endpoint()
            );
            
            std::lock_guard<std::recursive_mutex> l2(rpcs_mutex_);
            
            std::map<std::uint16_t, std::shared_ptr<rpc> >::iterator
                it = m_rpcs.find(msg.header_transaction_id())
            ;
            
            if (it != m_rpcs.end())
            {
                /**
                 * Stop the rpc.
                 */
                if (it->second)
                {
                    it->second->stop();
                }
                
                /**
                 * Erase the rpc.
                 */
                m_rpcs.erase(it);
            }
        }
        else
        {
            switch (msg.header_code())
            {
                case protocol::message_code_ack:
                case protocol::message_code_nack:
                {
                    for (auto & i : msg.endpoint_attributes())
                    {
                        bool found = std::find(
                            unprobed_.begin(), unprobed_.end(), i.value
                        ) != unprobed_.end();
                        
                        if (found)
                        {
                            continue;
                        }
                        
                        found = std::find(
                            probed_.begin(), probed_.end(), i.value
                        ) != probed_.end();

                        if (found)
                        {
                            continue;
                        }
                        else
                        {
#ifndef NDEBUG
                            /**
                             * Get the slot id for the endpoint.
                             */
                            std::int16_t slot_id = slot::id_from_endpoint(
                                i.value
                            );
    
                            log_debug(
                                "Got (" << m_transaction_id << ") new node: " <<
                                i.value << ", Slot#" << slot_id << "."
                            );
#endif // NDEBUG
                            unprobed_.push_back(i.value);
                        }
                    }
                }
                break;
                default:
                break;
            }

            /**
             * Inform the node_impl that the rpc has a response.
             */
            node_impl_.lock()->handle_rpc_response(
                m_transaction_id, msg.header_transaction_id(),
                msg.source_endpoint()
            );
            
            std::lock_guard<std::recursive_mutex> l2(rpcs_mutex_);
            
            std::map<std::uint16_t, std::shared_ptr<rpc> >::iterator
                it = m_rpcs.find(msg.header_transaction_id())
            ;
            
            if (it != m_rpcs.end())
            {
                /**
                 * Stop the rpc.
                 */
                if (it->second)
                {
                    it->second->stop();
                }
                
                /**
                 * Erase the rpc.
                 */
                m_rpcs.erase(it);
            }

            if (m_rpcs.size() < 3 && !unprobed_.empty())
            {
                run_timer_.cancel();
                
                run(boost::system::error_code());
            }
        }
    }
}

void operation::on_rpc_timeout(const std::uint16_t & tid)
{
    if (m_state == state_started)
    {
        std::lock_guard<std::recursive_mutex> l(rpcs_mutex_);
        
        auto it = m_rpcs.find(tid);
        
        if (it != m_rpcs.end())
        {
            log_none(
                "Operation, rpc " << it->second->transaction_id() <<
                " to " << it->second->endpoint() <<  " timed out"
            );
            
            /**
             * Inform the node_impl that the rpc has timed out.
             */
            node_impl_.lock()->handle_rpc_timeout(
                it->second->transaction_id(), it->second->endpoint()
            );
            
            m_rpcs.erase(it);
        }
        
        if (m_rpcs.size() < 3 && !unprobed_.empty())
        {
            run_timer_.cancel();
            
            run(boost::system::error_code());
        }
    }
}

void operation::timeout_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        log_none(
            "Operation " << m_transaction_id << " has timed out."
        );
        
        /**
         * The operation has timed out, call stop.
         */
        stop();
    }
}
