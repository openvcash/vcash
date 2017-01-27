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
#include <database/find_operation.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/protocol.hpp>
#include <database/slot.hpp>

using namespace database;

find_operation::find_operation(
    boost::asio::io_service & ios, const std::uint16_t & transaction_id,
    std::shared_ptr<operation_queue> & queue,
    std::shared_ptr<node_impl> impl, const std::string & query_string,
    const std::set<std::uint16_t> & slot_ids,
    const std::set<boost::asio::ip::udp::endpoint> & snodes,
    const std::size_t & max_results
    )
    : operation(ios, transaction_id, queue, impl, query_string, slot_ids, snodes)
    , find_responses_(0)
    , max_results_(max_results)
{
    // ...
}

std::shared_ptr<message> find_operation::next_message(
    const boost::asio::ip::udp::endpoint & ep
    )
{
    if (m_slot_ids.empty())
    {
        return std::shared_ptr<message> ();
    }
    
    /**
     * Get the slot id for the endpoint.
     */
    std::int16_t slot_id = slot::id_from_endpoint(ep);
    
    /**
     * Determine which block the endpoint belongs to.
     */
    std::int16_t block_index = slot_id / 8;
    
    /**
     * The found slot id that most closely matches the endpoint's slot id.
     */
    std::int16_t slot_id_found = 0;
    
    auto found_block = false;
    
    for (auto it = m_slot_ids.begin(); it != m_slot_ids.end(); ++it)
    {
        if (*it / 8 == block_index)
        {
            found_block = true;
            
            slot_id_found = *it;
            
            break;
        }
    }
    
    /**
     * Allocate the message.
     */
    std::shared_ptr<message> ret(new message(protocol::message_code_find));

    /**
     * 0 for slot level accuracy, 1 for block level accuracy.
     */
#define FIND_USE_BLOCK_LEVEL_ACCURACY 1
#if (defined FIND_USE_BLOCK_LEVEL_ACCURACY && FIND_USE_BLOCK_LEVEL_ACCURACY)
    if (found_block)
#else
    bool found_slot = false;
    
    for (auto it = m_slot_ids.begin(); it != m_slot_ids.end(); ++it)
    {
        if (*it== slot_id)
        {
            found_slot = true;
            
            slot_id_found = *it;
            
            break;
        }
    }
    
    if (found_slot)
#endif
    {
        log_debug(
            "Using slot# " << slot_id << ", for slot# " << slot_id_found
        );
        
        message::attribute_string attr1;
        
        attr1.type = message::attribute_type_storage_query;
        attr1.length = m_query.str().size();
        attr1.value = m_query.str();
        
        ret->string_attributes().push_back(attr1);
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
            
            if (
                slots_sent_[*it] >=
                (m_slot_ids.size() * (block::slot_length * 8))
                )
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

void find_operation::on_response(message & msg, const bool & done)
{
    if (state() == state_started)
    {
        /**
         * Inform base class.
         */
        operation::on_response(msg, done);

        /**
         * Check if we've got a response.
         */
        if (msg.header_code() == protocol::message_code_ack)
        {
            /**
             * Increment the number of find responses.
             */
            find_responses_++;
            
            log_debug(
                "Find operation " << m_transaction_id << " find_responses = " <<
                find_responses_ << ", ep = " << msg.source_endpoint()
            );
            
            /**
             * If the number of responses is acceptable call stop.
             */
            if (find_responses_ >= max_results_)
            {
                auto elapsed = std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(std::chrono::steady_clock::now() - uptime_).count();
                
                log_debug(
                    "Find operation is stopping, probed = " <<
                    probed_.size() << ", find_responses_ = " <<
                    find_responses_ << ", elapsed = " << elapsed << "."
                );

                /**
                 * Stop
                 */
                stop();
            }
        }
    }
}

void find_operation::on_rpc_timeout(const std::uint16_t & tid)
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
