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

#ifndef DATABASE_BROADCAST_OPERATION_HPP
#define DATABASE_BROADCAST_OPERATION_HPP

#include <cstdint>
#include <vector>

#include <boost/asio.hpp>

#include <database/operation.hpp>
#include <database/storage_node.hpp>

namespace database {

    class message;
    class node_impl;
    
    /**
     * Implements a broadcast operation.
     */
    class broadcast_operation : public operation
    {
        public:
        
            /**
             * Constructor
             * @Parma ios The boost::asio::io_service.
             * @param transaction_id The transaction_id.
             * @param queue The operation_queue.
             * @param impl The node_impl.
             * @param snodes The storage_node's.
             * @param buffer The buffer.
             */
            explicit broadcast_operation(
                boost::asio::io_service &, const std::uint16_t & transaction_id,
                std::shared_ptr<operation_queue> &, std::shared_ptr<node_impl>,
                const std::set<boost::asio::ip::udp::endpoint> & snodes,
                const std::vector<std::uint8_t> & buffer
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
            virtual void on_rpc_timeout(const std::uint64_t &);
            
        private:
        
            /**
             * The buffer.
             */
            std::vector<std::uint8_t> m_buffer;
            
        protected:
        
            /**
             * The number of broadcast responses.
             */
            std::size_t broadcast_responses_;
    };
    
} //  namespace database

#endif // DATABASE_BROADCAST_OPERATION_HPP
