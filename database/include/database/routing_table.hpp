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

#ifndef DATABASE_ROUTING_TABLE_HPP
#define DATABASE_ROUTING_TABLE_HPP

#include <array>
#include <chrono>
#include <mutex>
#include <set>
#include <vector>

#include <boost/asio.hpp>

#include <database/message.hpp>
#include <database/slot.hpp>

namespace database {
    
    class block;
    class node_impl;
    
    /**
     * Implements a routing table.
     */
    class routing_table
        : public std::enable_shared_from_this<routing_table>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             */
            explicit routing_table(
                boost::asio::io_service &, std::shared_ptr<node_impl>
            );
        
            /**
             * Starts the routing_table.
             */
            void start();
        
            /**
             * Stops the routing_table.
             */
            void stop();
        
            /**
             * Updates the routing_table.
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
             * The blocks.
             */
            const
                std::array< std::shared_ptr<block>, slot::length / 8> &
                blocks() const
            ;
        
            /**
             * Returns all storage nodes from all slots in all blocks.
             */
            std::set<storage_node> storage_nodes();
        
            /**
             * Returns all storage nodes from all slots in all blocks.
             * @param limit Limits the number of storage nodes returned.
             */
            std::set<boost::asio::ip::udp::endpoint> storage_nodes(
                const std::uint32_t & limit
            );

            /**
             * Returns a random number of storage nodes.
             * @param limit The limit.
             */
            std::vector<storage_node> random_storage_nodes(
                const std::uint32_t & limit
            );
        
            /**
             * Returns all storage nodes that are responsible for the query.
             * @param query_string The query string.
             * @param snodes_per_keyword The number of storage nodes for each
             * keyword.
             */
            std::set<boost::asio::ip::udp::endpoint> storage_nodes_for_query(
                const std::string &, const std::size_t &
            );
        
            /**
             * Returns a random storage node from each slot.
             */
            std::set<boost::asio::ip::udp::endpoint>
                random_storage_node_from_each_slot()
            ;
        
            /**
             * Returns a random storage node from each block.
             */
            std::set<boost::asio::ip::udp::endpoint>
                random_storage_node_from_each_block()
            ;
        
            /**
             * Returns all slot id's that are responsible for the given query.
             * @param query_string The query string.
             */
            std::set<std::uint16_t> slot_ids_for_query(const std::string &);
        
            /**
             * Returns the responsible slot for the given slot id.
             * @param slot_id The slot id.
             */
            std::shared_ptr<slot> slot_for_id(const std::uint16_t & slot_id);
        
            /**
             * Returns the responsible slots for the given slot id.
             * @param slot_id The slot id.
             */
            std::vector< std::shared_ptr<slot> > slots_for_id(
                const std::uint16_t &
            );
        
            /**
             * Called when an rpc response is received.
             * @param operation_id The operation identifier.
             * @param transaction_id The transaction identifier.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            void handle_rpc_response(
                const std::uint16_t & operation_id,
                const std::uint16_t & transaction_id,
                const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * Called when an rpc times out.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            void handle_rpc_timeout(const boost::asio::ip::udp::endpoint &);
        
            /**
             * Queues an endpoint to be pinged at a later time.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param force_queue If true the ping will be forcefully queued.
             */
            void queue_ping(
                const boost::asio::ip::udp::endpoint &,
                const bool & force_queue = false
            );
        
            /**
             * Runs the test case.
             */
            static int run_test();
        
        private:
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code &);
        
            /**
             * The statistics timer handler.
             * @param ec The boost::system::error_code.
             */
            void statistics_tick(const boost::system::error_code &);
        
            /**
             * The ping queue timer handler.
             * @param ec The boost::system::error_code.
             */
            void ping_queue_tick(const boost::system::error_code &);
        
            /**
             * The random find timer handler.
             * @param ec The boost::system::error_code.
             */
            void random_find_tick(const boost::system::error_code &);
        
            /**
             * The state.
             */
            enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped,
            } m_state;
        
            /**
             * The slot count.
             */
            enum { slot_count = slot::length };
        
            /**
             * The blocks.
             */
            std::array< std::shared_ptr<block>, slot::length / 8> m_blocks;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
        
            /**
             * The statistics timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > statistics_timer_;
        
            /**
             * The boost::shared_mutex.
             */
            mutable std::recursive_mutex mutex_;
            
            /**
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
        
            /**
             * The slot index.
             */
            std::uint16_t slot_index_;
        
            /**
             * The block index.
             */
            std::uint16_t block_index_;
        
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
        
            /**
             * The number of pings sent.
             */
            std::uint32_t pings_sent_;
        
            /**
             * Holds the time last pinged for the endpoints.
             */
            std::map<
                boost::asio::ip::udp::endpoint, std::time_t
            > ping_queue_times_;
        
            /**
             * The random find timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > random_find_timer_;
        
            /**
             * The index used to determine how quickly random find operations
             * should be started.
             */
            std::int16_t random_find_index_;
        
            /**
             * The number of random find operations performs.
             */
            std::uint32_t random_find_iterations_;
    };
    
} // namespace database

#endif // DATABASE_ROUTING_TABLE_HPP
