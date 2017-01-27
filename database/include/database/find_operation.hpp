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

#ifndef DATABASE_FIND_OPERATION_HPP
#define DATABASE_FIND_OPERATION_HPP

#include <cstdint>
#include <mutex>
#include <set>

#include <database/operation.hpp>

namespace database {

    class message;
    class node_impl;
    class slot;

    /**
     * Implements a find operation.
     */
    class find_operation : public operation
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param transaction_id The transaction_id.
             * @param queue The operation_queue.
             * @param impl The node_impl.
             * @param query The query.
             * @param slot_ids The slot id's.
             * @param snodes The storage nodes.
             * @param max_results The maximum number of results.
             */
            explicit find_operation(
                boost::asio::io_service &, const std::uint16_t &,
                std::shared_ptr<operation_queue> &,
                std::shared_ptr<node_impl>, const std::string &,
                const std::set<std::uint16_t> &,
                const std::set<boost::asio::ip::udp::endpoint> &,
                const std::size_t &
            );
            
            /**
             * Gets the next message.
             */
            virtual std::shared_ptr<message> next_message(
                const boost::asio::ip::udp::endpoint & ep
            );
            
            /**
             * Called when a response is received.
             * @param msg The message.
             * @param done If true the operation must not continue processing
             * it's probe queue.
             */
            virtual void on_response(message &, const bool & done = false);
            
            /**
             * Called when an rpc times out.
             * @param tid The transaction identifier.
             */
            virtual void on_rpc_timeout(const std::uint16_t &);
        
        private:
        
            // ...

        protected:

            /**
             * The number of find responses.
             */
            std::size_t find_responses_;
        
            /**
             * The maximum number of results.
             */
            std::size_t max_results_;
        
            /**
             * The number of sent messages that included
             * message::attribute_type_slot.
             */
            std::map<std::int16_t, std::uint32_t> slots_sent_;
        
            /**
             * The probed slots.
             */
            std::map<std::int16_t, std::uint32_t> probed_slots_;
    };
    
} // namespace database

#endif // DATABASE_FIND_OPERATION_HPP
