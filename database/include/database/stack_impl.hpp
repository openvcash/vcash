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

#ifndef DATABASE_STACK_IMPL_HPP
#define DATABASE_STACK_IMPL_HPP

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace database {

    class id;
    class node;
    class stack;
    
    /**
     * The stack implementation.
     */
    class stack_impl
    {
        public:
        
            /**
             * Constructor
             * @param owner The stack.
             */
            stack_impl(stack &);
            
            /**
             * Starts the stack.
             * @param config The stack::configuration.
             */
            void start(const stack::configuration &);
            
            /**
             * Stops the stack.
             */
            void stop();
        
            /**
             * Runs
             */
            void run();
        
            /**
             * Joins the overlay.
			 * @param contacts The bootstrap contacts.
             */
            void join(
                const std::vector< std::pair<std::string, unsigned short> > &
            );

			/**
			 * Leaves the overlay.
			 */
			void leave();
        
            /**
             * Performs a store operation.
             * @param query The query.
             */
            std::uint16_t store(const std::string &);
        
            /**
             * Performs a lookup on the query.
             * @param query The query.
             * @param max_results The maximum results.
             */
            std::uint16_t find(const std::string &, const std::size_t &);
        
            /**
             * Performs a broadcast operation.
             * @param buffer The buffer.
             */
            std::uint16_t broadcast(const std::vector<std::uint8_t> &);
        
            /**
             * Returns all of the storage nodes in the routing table.
             */
            std::vector< std::map<std::string, std::string> > storage_nodes();
            
            /**
             * Returns all of the endpoints in the routing table.
             */
            std::list< std::pair<std::string, std::uint16_t> > endpoints();
        
            /**
             * Called when a search result is received.
             * @param transaction_id The transaction id.
             * @param query The query.
             */
            void on_find(
                const std::uint16_t & transaction_id,
                const std::string & query
            );
        
            /**
             * Called when a udp packet doesn't match the protocol fingerprint.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_udp_receive(
                const char * addr, const std::uint16_t & port, const char * buf,
                const std::size_t & len
            );
        
            /**
             * Called when a broadcast message is received.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_broadcast(
                const char * addr, const std::uint16_t & port,
                const char * buf, const std::size_t & len
            );
            
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service();
            
        private:
        
            /**
             * Performs a join operation.
             * @param contacts The bootstrap contacts.
             */
            void do_join(
                const std::vector< std::pair<std::string, unsigned short> > &
            );
            
            /**
             * Performs a leave operation.
             */
            void do_leave();
            
            /**
             * Handles a udp resolve operation.
             * @param ec The boost::system::error_code.
             * @param it The boost::asio::ip::udp::resolver::iterator.
             */
            void handle_udp_resolve(
                const boost::system::error_code &,
                boost::asio::ip::udp::resolver::iterator
            );
            
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service m_io_service;
            
            /**
             * The node.
             */
            std::shared_ptr<node> m_node;
            
        protected:
            
            /**
             * The stack.
             */
            stack & stack_;
            
            /**
             * The boost::recursive_mutex.
             */
            std::recursive_mutex mutex_;
            
            /**
             * The boost::asio::io_service::stand.
             */
            boost::asio::io_service::strand strand_;
        
            /**
             * The boost::asio::ip::udp::resolver.
             */
            boost::asio::ip::udp::resolver udp_resolver_;
        
            std::vector< std::shared_ptr<std::thread> > threads_;
    };
    
} // namespace database

#endif // DATABASE_STACK_IMPL_HPP
