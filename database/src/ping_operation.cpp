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
#include <database/ping_operation.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

ping_operation::ping_operation(
    boost::asio::io_service & ios, const std::uint16_t & transaction_id,
    std::shared_ptr<operation_queue> & queue,
    std::shared_ptr<node_impl> impl, const boost::asio::ip::udp::endpoint & ep,
    const std::vector<storage_node> & snodes
    )
    : operation(
        ios, transaction_id, queue, impl, "", std::set<std::uint16_t> (),
        std::set<boost::asio::ip::udp::endpoint> ()
    )
    , m_storage_nodes(snodes)
{
    unprobed_.push_back(ep);
}

std::shared_ptr<message> ping_operation::next_message(
    const boost::asio::ip::udp::endpoint & ep
    )
{
    std::shared_ptr<message> ret;
    
    if (state() == state_started)
    {
        ret.reset(new message(protocol::message_code_ping));
        
        /**
         * Piggyback storage nodes.
         */
        for (auto & i : m_storage_nodes)
        {
            message::attribute_endpoint attr1;
            
            attr1.type = message::attribute_type_endpoint;
            attr1.length = 0;
            attr1.value = i.endpoint;
            
            ret->endpoint_attributes().push_back(attr1);
        }

        /**
         * Randomly piggyback statistics.
         */
        auto piggyback = std::rand() % 2 == 1;
        
        if (piggyback)
        {
            /**
             * Piggyback statistics.
             */
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
                     * Add the attribute_type_stats_udp_bps_inbound.
                     */
                    message::attribute_uint32 attr1;
                    
                    attr1.type =
                        message::attribute_type_stats_udp_bps_inbound
                    ;
                    attr1.length = sizeof(attr1.value);
                    attr1.value = n->udp_multiplexor_->bps_received();
                    
                    ret->uint32_attributes().push_back(attr1);
                    
                    /**
                     * Add the attribute_type_stats_udp_bps_outbound.
                     */
                    message::attribute_uint32 attr2;
                    
                    attr2.type =
                        message::attribute_type_stats_udp_bps_outbound
                    ;
                    attr2.length = sizeof(attr2.value);
                    attr2.value = n->udp_multiplexor_->bps_sent();
                    
                    ret->uint32_attributes().push_back(attr2);
                }
            }
        }
    
    }
    
    return ret;
}

void ping_operation::on_response(message & msg, const bool & done)
{
    if (state() == state_started)
    {
        /**
         * Inform base class (we are done).
         */
        operation::on_response(msg, true);
        
        /**
         * Call stop.
         */
        stop();
    }
}

void ping_operation::on_rpc_timeout(const std::uint64_t & tid)
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
