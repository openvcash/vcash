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
 
#ifndef DATABASE_HANDLER_HPP
#define DATABASE_HANDLER_HPP

#include <functional>
#include <string>

#include <boost/asio.hpp>

namespace database {

    class node_impl;
    class udp_multiplexor;
    
    /**
     * The handler.
     */
    class handler
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param multiplexor The udp_multiplexor.
             */
            explicit handler(
                boost::asio::io_service & ios,
                const std::shared_ptr<node_impl> & impl,
                const std::shared_ptr<udp_multiplexor> & multiplexor
            )
            : io_service_ (ios)
            , strand_(ios)
            , node_impl_(impl)
            , udp_multiplexor_(multiplexor) { }
             
            /**
             * Performs a send to operation.
             * @param ep The destination endpoint.
             * @param buf The buffer to send.
             * @param len The length of bytes to send.
             */
            virtual void send_to(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            ) = 0;
                
            /**
             * The on_async_receive_from handler.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The received buffer.
             * @param len The length of the buffer.
             */
            virtual bool on_async_receive_from(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            ) = 0;
            
            /**
             * Set the data handler.
             */
            void set_on_data(
                const std::function<void (
                const boost::asio::ip::udp::endpoint &,
                const char *, const std::size_t &)> & f
                )
            {
                m_on_data = f;
            }
            
            /**
             * The data handler.
             */
            std::function<
                void (const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &)
            > & on_data()
            {
                return m_on_data;
            }
            
        private:
        
            /**
             * The data handler.
             */
            std::function<
                void (const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &)
            > m_on_data;
            
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
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
            
            /**
             * The udp_multiplexor.
             */
            std::weak_ptr<udp_multiplexor> udp_multiplexor_;
    };
    
} // namespace database

#endif // DATABASE_HANDLER_HPP
