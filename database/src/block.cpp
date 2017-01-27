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

#include <database/block.hpp>
#include <database/logger.hpp>
#include <database/node_impl.hpp>
#include <database/protocol.hpp>
#include <database/routing_table.hpp>
#include <database/slot.hpp>

using namespace database;

block::block(
    boost::asio::io_service & ios, std::shared_ptr<node_impl> impl,
    const std::uint16_t & index
    )
    : m_index(index)
    , io_service_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , timer_(ios)
    , gossip_index_(0)
{
    /**
     * Calculate the (first) slot id from the index.
     */
    std::uint16_t slot_id = (index * 8);
    
    for (auto & i : m_slots)
    {
        log_none(
            "Block " << index << " allocating slot #" << slot_id << "."
        );
        
        /**
         * Allocate the slot.
         */
        i.reset(new slot(ios, impl, slot_id));
        
        /**
         * Increment the slot id.
         */
        slot_id++;
    }
}

void block::start()
{
    for (auto & i : m_slots)
    {
        if (i)
        {
            i->start();
        }
    }
    
    /**
     * Make all block timers fire within 60 seconds.
     */
    auto timeout = std::chrono::seconds(m_index % 60);
    
    timer_.expires_from_now(timeout);
    timer_.async_wait(
        std::bind(&block::gossip_tick, this, std::placeholders::_1)
    );
}

void block::stop()
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);
    
    for (auto & i : m_slots)
    {
        if (i)
        {
            i->stop();
        }
    }
}

const std::uint16_t & block::index() const
{
    return m_index;
}

std::array< std::shared_ptr<slot>, block::slot_length> & block::slots()
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);
    
    return m_slots;
}

bool compare_slot_storage_node_size(
    const std::shared_ptr<slot> & lhs,
    const std::shared_ptr<slot> & rhs
    )
{
    return lhs->storage_nodes().size() < rhs->storage_nodes().size();
}

void block::update(
    const boost::asio::ip::udp::endpoint & ep,
    const std::uint16_t & transaction_id
    )
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);

    bool did_update_slot = false;
    
    for (auto & i : m_slots)
    {
        if (i)
        {
            did_update_slot = i->update(ep, transaction_id);
            
            if (did_update_slot)
            {
                break;
            }
        }
    }
    
    /**
     * The storage node doesn't yet exist in any slot in this block, add it.
     */
    if (did_update_slot == false)
    {
        /**
         * Get the slot id for the endpoint.
         */
        std::int16_t slot_id = slot::id_from_endpoint(ep);
        
        if (slot_id > -1)
        {
            log_debug(
                "Block " << m_index << " is inserting " << ep <<
                " into slot #" << slot_id << "."
            );
            
            /**
             * Only allow one unique IP address per block (slots also
             * enforce a similar rule).
             */
            auto found = false;
            
            if (auto n = node_impl_.lock())
            {
                auto blocks = n->routing_table_->blocks();
                
                for (auto & i : blocks)
                {
                    for (auto & j : i->slots())
                    {
                        auto snodes = j->storage_node_endpoints();
                        
                        for (auto & k : snodes)
                        {
                            if (k.address() == ep.address())
                            {
                                found = true;
                                
                                break;
                            }
                        }
                    }
                }
                
                if (found == false)
                {
                    for (auto & i : m_slots)
                    {
                        if (i->id() == slot_id)
                        {
                            i->insert(ep);

                            break;
                        }
                    }
                }
            }
        }
        else
        {
            log_error(
                "Block #" << m_index << " got invalid slot #" << slot_id <<
                " for endpoint = " << ep << "."
            );
        }

        /**
         * Ping the endpoint.
         */
        if (auto n = node_impl_.lock())
        {
            n->queue_ping(ep);
        }
    }
}

void block::update_statistics(
    const boost::asio::ip::udp::endpoint & ep,
    const message::attribute_uint32 & attr
    )
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);

    for (auto & i : m_slots)
    {
        if (i)
        {
            if (i->update_statistics(ep, attr))
            {
                break;
            }
        }
    }
}

bool block::handle_response(
    const std::uint16_t & operation_id,
    const std::uint16_t & transaction_id,
    const boost::asio::ip::udp::endpoint & ep
    )
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);
    
    bool ret = false;
    
    for (auto & i : m_slots)
    {
        if (i)
        {
            ret = i->handle_response(operation_id, transaction_id, ep);
            
            if (ret)
            {
                break;
            }
        }
    }
    
    return ret;
}

bool block::handle_timeout(const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(slots_mutex_);
    
    bool ret = false;
    
    for (auto & i : m_slots)
    {
        if (i)
        {
            ret = i->handle_timeout(ep);
            
            if (ret)
            {
                break;
            }
        }
    }
    
    return ret;
}

void block::gossip_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(slots_mutex_);
        
        log_none(
            "Block #" << m_index << ", gossip_index = " << gossip_index_ << "."
        );

        if (m_slots[gossip_index_] && m_slots[gossip_index_]->needs_update())
        {
            log_debug(
                "Block detected slot #" <<
                m_slots[gossip_index_]->id() << " needs update."
            );
            
            if (auto n = node_impl_.lock())
            {
                if (
                    n->config().operation_mode() ==
                    stack::configuration::operation_mode_interface
                    )
                {
                    // ...
                }
                else
                {
                    /**
                     * Get all of the storage nodes from all slots in this block.
                     */
                    std::vector<storage_node> snodes;

                    for (auto & i2 : m_slots)
                    {
                        for (auto & i3 : i2->storage_nodes())
                        {
                            snodes.push_back(i3);
                        }
                    }
                    
                    /**
                     * Randomize the storage nodes.
                     */
                    std::random_shuffle(snodes.begin(), snodes.end());
                    
                    /**
                     * Clamp size.
                     */
                    if (snodes.size() > slot_length)
                    {
                        snodes.resize(slot_length);
                    }
                    
                    log_debug(
                        "Block is sending " << snodes.size() << " storage nodes "
                        "to least seen."
                    );
                    
                    /**
                     * Inform the slot to ping it's least seen storage node and 
                     * piggy back other storage nodes.
                     */
                    m_slots[gossip_index_]->ping_least_seen(snodes);
                }
            }
        }
        
        /**
         * Increment the gossip index.
         */
        if (++gossip_index_ >= slot_length)
        {
            gossip_index_ = 0;
        }
        
        /**
         * ~4.26 seconds
         */
        auto timeout = std::chrono::seconds(
            static_cast<std::int64_t> (std::ceil(4.26))
        );

        timer_.expires_from_now(timeout);
        timer_.async_wait(
            std::bind(&block::gossip_tick, this, std::placeholders::_1)
        );
    }
}
