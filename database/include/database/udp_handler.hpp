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

#ifndef DATABASE_UDP_HANDLER_HPP
#define DATABASE_UDP_HANDLER_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <set>

#include <boost/asio.hpp>

#include <database/handler.hpp>

namespace database {

    class message;
    class node_impl;
    class udp_multiplexor;
    
    /**
     * The udp handler.
     */
    class udp_handler
        : public handler
        , public std::enable_shared_from_this<udp_handler>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param multiplexor The udp_multiplexor.
             */
            explicit udp_handler(
                boost::asio::io_service &, const std::shared_ptr<node_impl> &,
                std::shared_ptr<udp_multiplexor> &
            );
            
            /**
             * Stop
             */
            void stop();
            
            /**
             * Performs a send to operation.
             * @param ep The destination endpoint.
             * @param buf The buffer to send.
             * @param len The length of bytes to send.
             */
            virtual void send_to(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
            
            /**
             * The on_async_receive_from handler.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The received buffer.
             * @param len The length of the buffer.
             */
            virtual bool on_async_receive_from(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
            
            /**
             * Sends a message to the endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void send_message(
                const boost::asio::ip::udp::endpoint &,
                std::shared_ptr<message>
            );
        
            /**
             * The transaction id's that have been sent.
             */
            const std::set<std::uint16_t> & sent_transaction_ids();
            
        private:
        
            /**
             * Called when data is received.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_data(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
        
            /**
             * The transaction id's that have been sent.
             */
            std::set<std::uint16_t> m_sent_transaction_ids;
            
        protected:
        
            /**
             * The sent transaction ids mutex.
             */
            std::recursive_mutex sent_transaction_ids_mutex_;
    };
    
} // namespace database

#endif // DATABASE_UDP_HANDLER_HPP
