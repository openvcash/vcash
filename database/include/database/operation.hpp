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

#ifndef DATABASE_OPERATION_HPP
#define DATABASE_OPERATION_HPP

#include <chrono>
#include <cstdint>
#include <list>
#include <map>
#include <mutex>
#include <set>

#include <boost/asio.hpp>

#include <database/query.hpp>
#include <database/rpc.hpp>

namespace database {

    class message;
    class node_impl;
    class operation_queue;
    class slot;
    
    /**
     * Implements an operation.
     */
    class operation : public std::enable_shared_from_this<operation>
    {
        public:

            /**
             * Constructor
             * @parma ios The boost::asio::io_service.
             * @param transaction_id The transaction_id.
             * @param queue The operation queue.
             * @param impl The node_impl.
             * @param query The query.
             * @param slot_ids The slot id's.
             * @param snodes The storage nodes.
             */
            explicit operation(
                boost::asio::io_service &, const std::uint16_t &,
                std::shared_ptr<operation_queue> &,
                std::shared_ptr<node_impl>, const std::string &,
                const std::set<std::uint16_t> &,
                const std::set<boost::asio::ip::udp::endpoint> &
            );
        
            /**
             * Starts the operation.
             */
            virtual void start();
            
            /**
             * Stops the operation.
             */
            virtual void stop();
        
            /**
             * The state.
             */
            typedef enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped,
            } state_t;
            
            /**
             * The state.
             */
            const state_t & state() const;
            
            /**
             * The transaction identifier.
             */
            const std::uint16_t & transaction_id() const;
        
            /**
             * The transaction identifier.
             */
            static std::uint16_t next_transaction_id();
            
            /**
             * Gets the next message.
             */
            virtual std::shared_ptr<message> next_message(
                const boost::asio::ip::udp::endpoint & ep
            ) = 0;
            
            /**
             * The rpc objects.
             */
            std::map< std::uint16_t, std::shared_ptr<rpc> > & rpcs();
        
            /**
             * The message transaciton id's associated with this operation.
             */
            const std::set<std::uint16_t> & message_tids() const;
        
            /**
             * The storage nodes.
             */
            const
                std::set<boost::asio::ip::udp::endpoint> & storage_nodes() const
            ;
        
            /**
             * Called when a response is received.
             * @param msg The message.
             * @param done If true the operation must not continue processing
             * it's probe queue.
             */
            virtual void on_response(message &, const bool & done = false) = 0;
            
            /**
             * Called when an rpc times out.
             * @param tid The transaction identifier.
             */
            virtual void on_rpc_timeout(const std::uint16_t &);
        
            /**
             * Runs one iteration of the operation.
             * @param ec The boost::system::error_code.
             */
            virtual void run(const boost::system::error_code &);
        
        private:

            friend class find_operation;
            friend class store_operation;
        
            /**
             * The timeout timer handler.
             */
            void timeout_tick(const boost::system::error_code &);
            
            /**
             * The timeout interval in seconds.
             */
            enum { timeout_interval = 10 };
        
            /**
             * The state.
             */
            state_t m_state;
            
            /**
             * The transaction identifier.
             */
            std::uint16_t m_transaction_id;
            
            /**
             * The rpc objects.
             */
            std::map<std::uint16_t, std::shared_ptr<rpc> > m_rpcs;
        
            /**
             * The message transaciton id's associated with this operation.
             */
            std::set<std::uint16_t> m_message_tids;
            
            /**
             * The query.
             */
            query m_query;
        
            /**
             * The slot id's.
             */
            std::set<std::uint16_t> m_slot_ids;
        
            /**
             * The storage nodes.
             */
            std::set<boost::asio::ip::udp::endpoint> m_storage_nodes;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
            
            /**
             * The boost::asio::io_service::strand.
             */
            boost::asio::io_service::strand strand_;
        
            /**
             * The uptime.
             */
            std::chrono::steady_clock::time_point uptime_;
        
            /**
             * The probe mutex.
             */
            std::recursive_mutex probe_mutex_;
        
            /**
             * The rpc mutex.
             */
            std::recursive_mutex rpcs_mutex_;
        
            /**
             * The message tids mutex.
             */
            mutable std::recursive_mutex message_tids_mutex_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timeout_timer_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > run_timer_;
        
            /**
             * The operation_queue.
             */
            std::weak_ptr<operation_queue> operation_queue_;
            
            /**
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
            
            /**
             * The unprobed contacts.
             */
            std::list<boost::asio::ip::udp::endpoint> unprobed_;
            
            /**
             * The probed contacts.
             */
            std::list<boost::asio::ip::udp::endpoint> probed_;
    };
    
} // namespace database

#endif // DATABASE_OPERATION_HPP
