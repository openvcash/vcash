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
 
#ifndef DATABASE_RPC_HPP
#define DATABASE_RPC_HPP

#include <chrono>
#include <cstdint>
#include <functional>

#include <boost/asio.hpp>

namespace database {

    /**
     * Implements a remote procedure call.
     */
    class rpc : public std::enable_shared_from_this<rpc>
    {
        public:
        
            /**
             * The timeout interval in seconds.
             */
            enum { timeout_interval = 5 };
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param tid The transaction identifier.
             */
            rpc(
                boost::asio::io_service &, const std::uint16_t &,
                const boost::asio::ip::udp::endpoint &
            );
            
            /**
             * Starts the rpc.
             */
            void start();
            
            /**
             * Stops the rpc.
             */
            void stop();
            
            /**
             * Set the timeout handler.
             * @param f The function.
             */
            void set_on_timeout(
                const std::function<void (const std::uint16_t &)> &
            );
            
            /**
             * The transaction identifier.
             */
            const std::uint16_t & transaction_id() const;
        
            /**
             * The endpoint.
             */
            const boost::asio::ip::udp::endpoint & endpoint() const;
        
        private:
        
            /**
             * The timeout timer handler.
             * @param ec The boost::system::error_code.
             */
            void timeout_tick(const boost::system::error_code &);
            
            /**
             * The timeout handler.
             */
            std::function<void (const std::uint16_t &)> m_on_timeout;
            
            /**
             * The transaction identifier.
             */
            std::uint16_t m_transaction_id;
        
            /**
             * The boost::asio::ip::udp::endpoint.
             */
            boost::asio::ip::udp::endpoint m_endpoint;
            
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
             * The timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timeout_timer_;
    };
    
} // namespace database

#endif // DATABASE_RPC_HPP
