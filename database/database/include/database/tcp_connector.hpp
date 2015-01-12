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

#ifndef database_tcp_connector_hpp
#define database_tcp_connector_hpp

#include <cstdint>
#include <deque>
#include <map>

#include <boost/asio.hpp>

namespace database {

    class node_impl;
    class tcp_transport;
    
    /**
     * This class maintains a single tcp connection to a storage node,
     * preferably always the same one.
     * start
     * tcp to last endpoint
     *  if tcp acceptance
     *   then
     *    success
     *   else
     *   udp probe
     *   if tcp acceptance
     *    then
     *     success
     *   else
     *   tcp probe
     *   if tcp acceptance
     *   then success
     * goto start
     */
    class tcp_connector
        : public std::enable_shared_from_this<tcp_connector>
    {
        public:
        
            typedef enum
            {
                state_disconnected,
                state_connecting,
                state_connected,
            } state_t;
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             * @param f1 The std::function.
             * @param f2 The std::function.
             * @param f3 The std::function.
             */
            tcp_connector(
                boost::asio::io_service &, const std::shared_ptr<node_impl> &,
                const std::function<void (const boost::asio::ip::tcp::endpoint &)> & f1,
                const std::function<void (const boost::asio::ip::tcp::endpoint &)> & f2,
                const std::function<void (const boost::asio::ip::tcp::endpoint &, message & msg)> & f3
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
             * Sedns the buffer to the connected endpoint.
             * @param buf The buffer.
             * @param len The length.
             */
            bool send(const char * buf, const std::size_t & len);
        
            /**
             * Handles a message.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The buffer.
             * @param len The length
             */
            void handle_message(
                const boost::asio::ip::udp::endpoint &, message & msg
            );
        
        private:
        
            /**
             * The state.
             */
            state_t m_state;
        
            /**
             * The on connected handler.
             */
            std::function<
                void (const boost::asio::ip::tcp::endpoint &)
            > m_on_connected;
        
            /**
             * The on disconnected handler.
             */
            std::function<
                void (const boost::asio::ip::tcp::endpoint &)
            > m_on_disconnected;
        
            /**
             * The on message handler.
             */
            std::function<
                void (const boost::asio::ip::tcp::endpoint &, message & msg)
            > m_on_message;
        
            /**
             * The current endpoint.
             */
            boost::asio::ip::tcp::endpoint m_current_endpoint;
        
            /**
             * The endpoints.
             */
            std::list<boost::asio::ip::udp::endpoint> m_endpoints;
        
        protected:

            /**
             * attempt TCP connection with last known
             */
            void do_step2();

            /**
             * send UDP packet(s) to HC
             */
            void do_step3();

            /**
             * attempt TCP connection with HC
             */
            void do_step4();
        
            /**
             * Self explanatory.
             */
            void do_finish();
        
            /**
             * Starts the tick timer.
             */
            void do_tick(const std::uint32_t & seconds);
        
            /**
             * Starts the ping timer.
             */
            void do_ping(const std::uint32_t & seconds);
        
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
             * The connected tcp transport.
             */
            std::weak_ptr<tcp_transport> tcp_transport_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_;
        
            /**
             * The udp probe queue.
             */
            std::deque<boost::asio::ip::udp::endpoint> udp_probe_queue_;
        
            /**
             * The inflight udp probes timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > inflight_udp_probes_timer_;
        
            /**
             * The sent udp probes.
             */
            std::map<std::uint16_t, std::time_t> sent_udp_probes_;
        
            /**
             * The step 4 timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > step4_timer_;
        
            /**
             * The number of tcp connection attempts.
             */
            std::size_t tcp_attempts_;
        
            /**
             * The handshake timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > handshake_timeout_timer_;
        
            /**
             * The handshake transaction id.
             */
            std::uint16_t handshake_transaction_id_;
        
            /**
             * The ping timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > ping_timer_;
    };
    
} // namespace database

#endif // database_tcp_connector_hpp
