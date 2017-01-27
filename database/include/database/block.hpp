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

#ifndef DATABASE_BLOCK_HPP
#define DATABASE_BLOCK_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <mutex>

#include <boost/asio.hpp>

#include <database/message.hpp>

namespace database {

    class node_impl;
    class slot;
    
    class block
    {
        public:
        
            /**
             * The slot length.
             */
            enum { slot_length = 8 };
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param index The index.
             */
            explicit block(
                boost::asio::io_service &, std::shared_ptr<node_impl>,
                const std::uint16_t &
            );
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * The index.
             */
            const std::uint16_t & index() const;
        
            /**
             * The slots.
             */
            std::array< std::shared_ptr<slot>, slot_length> & slots();
        
            /**
             * Called when a message is received from the endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param transaction_id The transaction id.
             */
            void update(
                const boost::asio::ip::udp::endpoint &, const std::uint16_t &
            );
    
            /**
             * Updates the routing_table statistics.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param attr The message::attribute_uint32.
             */
            void update_statistics(
                const boost::asio::ip::udp::endpoint &,
                const message::attribute_uint32 &
            );
        
            /**
             * Called when a response occurs.
             * @param operation_id The operation identifier.
             * @param transaction_id The transaction identifier.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            bool handle_response(
                const std::uint16_t & operation_id,
                const std::uint16_t & transaction_id,
                const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * Called when a timeout occurs.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            bool handle_timeout(const boost::asio::ip::udp::endpoint &);
        
        private:
        
            /**
             * The index.
             */
            std::uint16_t m_index;
        
            /**
             * The slots.
             */
            std::array< std::shared_ptr<slot>, slot_length> m_slots;
        
        protected:
        
            /**
             * The gossip timer handler.
             * @param ec The boost::system::error_code.
             */
            void gossip_tick(const boost::system::error_code &);
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
            
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
        
            /**
             * The gossip index.
             */
            std::int16_t gossip_index_;
        
            /**
             * The slots mutex.
             */
            std::recursive_mutex slots_mutex_;
    };
    
} // namespace database

#endif // DATABASE_BLOCK_HPP
