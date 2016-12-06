/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#ifndef CRAWLER_DATABASE_STACK_HPP
#define CRAWLER_DATABASE_STACK_HPP

#define USE_DATABASE_STACK 1

#include <chrono>
#include <cstdint>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
#include <database/stack.hpp>
#endif // USE_DATABASE_STACK

namespace crawler {

    class stack_impl;
    
    /**
     * Implements a database::stack subclass.
     */
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    class database_stack
        : public database::stack
        , public std::enable_shared_from_this<database_stack>
#else
    class database_stack
        : public std::enable_shared_from_this<database_stack>
#endif // USE_DATABASE_STACK
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            explicit database_stack(
                boost::asio::io_service & ios, boost::asio::strand & s,
                stack_impl & owner
            );
        
            /**
             * Starts the stack.
             * @param port The port.
             * @param is_client If true we are a client node.
             */
            void start(const std::uint16_t & port, const bool & is_client);
            
            /**
             * Stops the stack.
             */
            void stop();
        
            /**
             * Performs a broadcast operation.
             * @param buffer The buffer.
             */
            std::uint16_t broadcast(const std::vector<std::uint8_t> &);
        
            /**
             * Returns all of the endpoints in the routing table.
             */
            std::list< std::pair<std::string, std::uint16_t> > endpoints();
        
        private:
        
            /**
             * Called when a search result is received.
             * @param transaction_id The transaction id.
             * @param query The query.
             */
            virtual void on_find(
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
            virtual void on_udp_receive(
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
            virtual void on_broadcast(
                const char * addr, const std::uint16_t & port,
                const char * buf, const std::size_t & len
            );
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code & ec);
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_;
    };
    
} // namespace crawler

#endif // CRAWLER_DATABASE_STACK_HPP
