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
#include <database/constants.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/slot.hpp>
#include <database/store_operation.hpp>

using namespace database;

store_operation::store_operation(
    boost::asio::io_service & ios, const std::uint16_t & transaction_id,
    std::shared_ptr<operation_queue> & queue,
    std::shared_ptr<node_impl> impl, const std::string & query,
    const std::set<std::uint16_t> & slot_ids,
    const std::set<boost::asio::ip::udp::endpoint> & snodes
    )
    : operation(ios, transaction_id, queue, impl, query, slot_ids, snodes)
    , store_responses_(0)
{
    // ...
}

std::shared_ptr<message> store_operation::next_message(
    const boost::asio::ip::udp::endpoint & ep
    )
{
    if (m_slot_ids.empty())
    {
        return std::shared_ptr<message> ();
    }
    
    std::shared_ptr<message> ret(new message(protocol::message_code_store));
    
    /**
     * Get the slot id for the endpoint.
     */
    std::int16_t slot_id = slot::id_from_endpoint(ep);

    /**
     * Determine which block the endpoint belongs to.
     */
    std::int16_t block_index = slot_id / 8;

    /**
     * 0 for slot level accuracy, 1 for block level accuracy.
     */
#define STORE_USE_BLOCK_LEVEL_ACCURACY 1
#if (defined STORE_USE_BLOCK_LEVEL_ACCURACY && STORE_USE_BLOCK_LEVEL_ACCURACY)
    bool found_block = false;
    
    std::int16_t current_slot_id = -1;
    
    for (auto it = m_slot_ids.begin(); it != m_slot_ids.end(); ++it)
    {
        if (*it / 8 == block_index)
        {
            current_slot_id = *it;
            
            found_block = true;
            
            break;
        }
    }
    
    log_debug(
        "found_block: << " << found_block << ", block# " <<
        block_index << " slot# " << slot_id
    );

    if (found_block)
#else
    bool found_slot = false;
    
    std::int16_t current_slot_id = -1;
    
    for (auto it = m_slot_ids.begin(); it != m_slot_ids.end(); ++it)
    {
        if (*it == slot_id)
        {
            current_slot_id = *it;
            
            found_slot = true;
            
            break;
        }
    }

    if (found_slot)
#endif
    {
        /**
         * Send the query.
         */
        message::attribute_string attr1;
        
        attr1.type = message::attribute_type_storage_query;
        attr1.length = m_query.str().size();
        attr1.value = m_query.str();
        
        ret->string_attributes().push_back(attr1);
        
        /**
         * Send a slot request(s).
         */
        auto it = m_slot_ids.begin();
        
        while (it != m_slot_ids.end())
        {
            if (slots_sent_.find(*it) == slots_sent_.end())
            {
                slots_sent_[*it] = 0;
            }

            message::attribute_uint32 attr2;
            
            attr2.type = message::attribute_type_slot;
            attr2.length = 0;
            attr2.value = *it;
            
            ret->uint32_attributes().push_back(attr2);
            
            slots_sent_[*it]++;
            
            if (slots_sent_[*it] >= block::slot_length)
            {
                ++it;
            }
            else
            {
                ++it;
            }
        }
        
        slots_sent_[current_slot_id]++;
        
        if (probed_slots_.find(current_slot_id) == probed_slots_.end())
        {
            probed_slots_[current_slot_id] = 0;
        }
        
        probed_slots_[current_slot_id]++;
        
        log_debug(
            "Store operation storing " << current_slot_id << " at " <<
            slot_id << ", stored so far " <<
            probed_slots_[current_slot_id] << " times."
        );

        if (
            probed_slots_[current_slot_id] >= block::slot_length
            )
        {
            for (auto it = m_slot_ids.begin(); it != m_slot_ids.end(); ++it)
            {
                if (*it == current_slot_id)
                {
                    m_slot_ids.erase(it);
                    
                    break;
                }
            }
        }
        
    }
    else
    {
        auto it = m_slot_ids.begin();
        
        while (it != m_slot_ids.end())
        {
            if (slots_sent_.find(*it) == slots_sent_.end())
            {
                slots_sent_[*it] = 0;
            }

            message::attribute_uint32 attr2;
            
            attr2.type = message::attribute_type_slot;
            attr2.length = 0;
            attr2.value = *it;
            
            ret->uint32_attributes().push_back(attr2);
            
            slots_sent_[*it]++;
            
            if (slots_sent_[*it] >= block::slot_length)
            {
                ++it;
            }
            else
            {
                ++it;
            }
        }
    }

    return ret;
}

void store_operation::on_response(message & msg, const bool & done)
{
    if (state() == state_started)
    {
        /**
         * Inform base class.
         */
        operation::on_response(msg, done);
        
        if (msg.header_code() == protocol::message_code_ack)
        {
            /**
             * Increment the number of store responses.
             */
            store_responses_++;
            
            log_debug(
                "store_responses_ = " << store_responses_ << ", ep = " <<
                msg.source_endpoint()
            );

            /**
             * If we've stored at N storage nodes call stop.
             */
            if (
                store_responses_ >=
                (m_query.pairs_public().size() *
                constants::snodes_per_keyword) || store_responses_ >= 128
                )
            {
                log_debug(
                    "Store operation probed " << probed_.size() <<
                    " storage nodes, value stored at " << store_responses_ <<
                    " storage nodes, stopping."
                );
                
                /**
                 * Stop
                 */
                stop();
            }
        }
    }
}

void store_operation::on_rpc_timeout(const std::uint16_t & tid)
{
    if (state() == state_started)
    {
        /**
         * Inform base class.
         */
        operation::on_rpc_timeout(tid);

        /**
         * Nothing is done here.
         */
    }
}
