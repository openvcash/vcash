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

#ifndef DATABASE_SLOT_HPP
#define DATABASE_SLOT_HPP

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

#include <boost/asio.hpp>

#include <database/protocol.hpp>
#include <database/storage_node.hpp>

namespace database {

    class node_impl;
    
    class slot
        : public std::enable_shared_from_this<slot>
    {
        public:
        
            /**
             * The update interval.
             * Warning, lower numbers significantly increase overall network
             * traffic.
             */
            enum { update_interval = 256 };
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param val An up to 5 byte value.
             */
            explicit slot(
                boost::asio::io_service &, std::shared_ptr<node_impl>,
                const std::string &
            );
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param id The id.
             */
            explicit slot(
                boost::asio::io_service &, std::shared_ptr<node_impl>,
                const std::uint32_t &
            );
        
            /**
             * Starts the slot.
             */
            void start();
        
            /**
             * Stops the slot.
             */
            void stop();
        
            /**
             * The value.
             */
            const std::string & value() const;
        
            /**
             * The id.
             */
            const std::int32_t & id() const;
        
            /**
             * If true the slot needs updating.
             */
            bool needs_update();
        
            /**
             * Inserts a storage node into the slot.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            void insert(const boost::asio::ip::udp::endpoint &);
        
            /**
             * Insert an endpoint into the slot.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param transaction_id The transaction id.
             */
            bool update(
                const boost::asio::ip::udp::endpoint &, const std::uint16_t &
            );
        
            /**
             * Updates the routing_table statistics.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param attr The message::attribute_uint32.
             */
            bool update_statistics(
                const boost::asio::ip::udp::endpoint &,
                const message::attribute_uint32 &
            );
        
            /**
             * Pings the most recently seen storage node.
             * @param snodes The storage nodes to piggy back.
             * @param force Forces the ping regardless of the last update of
             * the storage node.
             * @ret True if a storage ndoe was pinged.
             */
            bool ping_least_seen(
                const std::vector<storage_node> &, const bool & force = false
            );
        
            /**
             * The storage nodes sorted by time last seen.
             */
            std::vector<storage_node> storage_nodes();
        
            /**
             * Returns all storage nodes by boost::asio::ip::udp::endpoint.
             * @param limit Limits the number of storage nodes returned.
             */
            std::set<boost::asio::ip::udp::endpoint> storage_node_endpoints(
                const std::uint32_t & limit = 0
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
        
            /**
             * Generates an id associated with the input value.
             * @param val The value.
             */
            static std::int32_t id(const std::string &);
        
            /**
             * Generates an id associated with the input
             * boost::asio::ip::udp::endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            static std::int32_t id_from_endpoint(
                const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * Generates an id associated with the input
             * boost::asio::ip::udp::endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            static std::int32_t id_from_endpoint2(
                const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * The minimum node count.
             */
            enum { min_node_count = 1 };
        
            /**
             * The maximum node count.
             */
            enum { max_node_count = 64 };

            /**
             * The number of slots in the system.
             */
            enum { length = 64 };
        
            /**
             * Runs the test case.
             */
            static int run_test();
        
        private:
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void handle_tick(const boost::system::error_code &);
        
            /**
             * Queues a ping to be sent at a later time.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            void queue_ping(const boost::asio::ip::udp::endpoint &);
        
            /**
             * The ping queue timer handler.
             * @param ec The boost::system::error_code.
             */
            void ping_queue_tick(const boost::system::error_code &);
        
            /**
             * The value.
             */
            std::string m_value;
        
            /**
             * The id.
             */
            std::int32_t m_id;
        
            /**
             * The storage nodes.
             */
            std::map<
                boost::asio::ip::udp::endpoint, storage_node
            > m_storage_nodes;
        
        protected:
        
            /**
             * Generates an id associated with the input value.
             * @param val The value.
             */
            static std::int32_t associated_id(const std::string &);
        
            /**
             * The custom crc32 algorithm for id generation.
             * @param crc The crc value.
             * @param word The 4-byte input.
             */
            static std::uint32_t crc32(
                const std::uint32_t &, const std::uint32_t &
            );
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
        
            /**
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
        
            /**
             * The ping queue mutex.
             */
            std::recursive_mutex ping_queue_mutex_;
        
            /**
             * The ping queue timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > ping_queue_timer_;
        
            /**
             * Pings to be sent at a later date.
             */
            std::set<boost::asio::ip::udp::endpoint> ping_queue_;
    };
    
} // namespace database

#endif // DATABASE_SLOT_HPP
