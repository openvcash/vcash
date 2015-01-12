/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#ifndef DATABASE_CRYPTO_CONNECTION_HPP
#define DATABASE_CRYPTO_CONNECTION_HPP

#include <deque>
#include <mutex>
#include <queue>

#include <boost/asio.hpp>

#include <database/crypto_message.hpp>
#include <database/hc256.hpp>

namespace database {
    
    class crypto_handler;
    class udp_multiplexor;
    
    /**
     * Implements an crypto connection.
     */
    class crypto_connection
        : public std::enable_shared_from_this<crypto_connection>
    {
        public:
        
            /**
             * The directions.
             */
            typedef enum directions
            {
                direction_none,
                direction_inbound,
                direction_outbound,
            } direction_t;
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param h The crypto_handler.
             * @param multiplexor The udp_multiplexor.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param d The direction.
             */
            explicit crypto_connection(
                boost::asio::io_service &, const std::shared_ptr<crypto_handler> &,
                const std::shared_ptr<udp_multiplexor> &,
                const boost::asio::ip::udp::endpoint &,
                const direction_t &
            );
            
            /**
             * Destructor
             */
            ~crypto_connection();
        
            /**
             * Opens
             */
            void open();
        
            /**
             * Sends the buffer.
             * @param buf The buffer.
             * @param len The length.
             */
            void send(const char * buf, const std::size_t & len);
            
            /**
             * The receive handler.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_receive(const char *, const std::size_t &);
            
            /**
             * The states.
             */
            typedef enum states
            {
                state_open,
                state_closed,
            } state_t;
            
            /**
             * The state.
             */
            const state_t & state() const;
        
            /**
             * Sets the boost::asio::ip::udp::endpoint.
             * @param val The value.
             */
            void set_endpoint(const boost::asio::ip::udp::endpoint & val);
        
            /**
             * The boost::asio::ip::udp::endpoint.
             */
            const boost::asio::ip::udp::endpoint & endpoint() const;
        
        private:
            
            /**
             * Processes the send queue.
             */
            void process_send_queue();
        
            /**
             * Handles a message.
             * @param msg The crypto_message.
             */
            void handle_message(std::shared_ptr<crypto_message>);
        
            /**
             * The retransmit timer handler.
             */
            void retransmit_tick(const boost::system::error_code & ec);
        
            /**
             * The timeout tick handler.
             */
            void timeout_tick(const boost::system::error_code & ec);
        
            /**
             * Sends DTLS packets to make the connection lool like DTLS.
             */
            void send_dtls();
        
            /**
             * The state.
             */
            state_t m_state;
        
            /**
             * The direction.
             */
            direction_t m_direction;
            
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
             * The boost::asio::io_service::stand.
             */
            boost::asio::io_service::strand strand_;
        
            /**
             * The crypto_handler.
             */
            std::weak_ptr<crypto_handler> crypto_handler_;
            
            /**
             * The udp_multiplexor.
             */
            std::weak_ptr<udp_multiplexor> udp_multiplexor_;
        
            /**
             * The retransmit timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > retransmit_timer_;
        
            /**
             * The timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timeout_timer_;
            
            /**
             * The send queue.
             */
            std::queue< std::shared_ptr<crypto_message> > send_queue_;
            
            /**
             * If true sending is in-progress.
             */
            bool sending_;
            
            /**
             * The send mutex.
             */
            std::recursive_mutex send_mutex_;
            
            /**
             * The receive mutex.
             */
            std::recursive_mutex receive_mutex_;
            
            /**
             * Estimate of round trip time.
             */
            enum { rto = 600 };
            
            /**
             * Rc
             */
            enum { Rc = 7 };
        
            /**
             * Ti
             */
            enum { Ti = 39500 };
            
            /**
             * Rm
             */
            enum { Rm = 16 };
            
            /**
             * The number of times a message has been sent.
             */
            std::uint32_t sent_;
            
            /**
             * The time after which a message will be retransmitted.
             */
            std::uint32_t timeout_;
        
            /**
             * The next transaction id.
             */
            std::uint16_t next_transaction_id_;
        
            /**
             * The encryption context.
             */
            std::unique_ptr<hc256> hc256_;
    };
    
} // namespace database

#endif // DATABASE_CRYPTO_CONNECTION_HPP
