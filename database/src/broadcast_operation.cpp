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

#include <random>

#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/broadcast_operation.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

broadcast_operation::broadcast_operation(
    boost::asio::io_service & ios, const std::uint16_t & transaction_id,
    std::shared_ptr<operation_queue> & queue,
    std::shared_ptr<node_impl> impl,
    const std::set<boost::asio::ip::udp::endpoint> & snodes,
    const std::vector<std::uint8_t> & buffer
    )
    : operation(
        ios, transaction_id, queue, impl, "", std::set<std::uint16_t> (), snodes
    )
    , m_buffer(buffer)
    , broadcast_responses_(0)
{
    // ...
}

std::shared_ptr<message> broadcast_operation::next_message(
    const boost::asio::ip::udp::endpoint & ep
    )
{
    std::shared_ptr<message> ret;
    
    if (state() == state_started)
    {
        /**
         * Allocate the message using the pre-defined transaction id.
         */
        ret.reset(
            new message(protocol::message_code_broadcast, transaction_id())
        );

        /**
         * Add the attribute_type_binary.
         */
        message::attribute_binary attr;
        
        attr.type = message::attribute_type_broadcast_buffer;
        attr.length = m_buffer.size();
        attr.value = m_buffer;
        
        ret->binary_attributes().push_back(attr);
    }
    
    return ret;
}

void broadcast_operation::on_response(message & msg, const bool & done)
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
             * Increment the number of broadcast responses.
             */
            broadcast_responses_++;
            
            log_debug(
                "Broadcast operation " << transaction_id() << " got" <<
                " response from " << msg.source_endpoint() << ", total = " <<
                broadcast_responses_ << "."
            );

            /**
             * If we've probed N storage nodes call stop.
             */
            if (broadcast_responses_ >= storage_nodes().size())
            {
                log_info(
                    "Broadcast operation probed " << probed_.size() <<
                    " storage nodes, value broadcasted to " <<
                    broadcast_responses_ << " storage nodes, stopping."
                );
                
                /**
                 * Stop
                 */
                stop();
            }
        }
    }
}

void broadcast_operation::on_rpc_timeout(const std::uint64_t & tid)
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
