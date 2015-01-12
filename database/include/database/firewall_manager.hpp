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

#ifndef DATABASE_FIREWALL_MANAGER_HPP
#define DATABASE_FIREWALL_MANAGER_HPP

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>

#include <boost/asio.hpp>

namespace database {

    class firewall;
    class message;
    class node_impl;
#if (!defined __arm__ && !defined __thumb__ && !defined _M_ARM && !defined _M_ARMT)
    class nat_pmp_client;
    class upnp_client;
#endif // __arm__

    class firewall_manager
        : public std::enable_shared_from_this<firewall_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl
             */
            explicit firewall_manager(
                boost::asio::io_service &, const std::shared_ptr<node_impl> &
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
             * The tcp score.
             */
            const float & tcp_score() const;
        
            /**
             * The udp score.
             */
            const float & udp_score() const;
        
            /**
             * Handles a message.
             * @param ep Theboost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            bool handle_message(
                const boost::asio::ip::udp::endpoint &, message &
            );
        
            /**
             * Handles a message.
             * @param ep Theboost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            bool handle_message(
                const boost::asio::ip::tcp::endpoint &, message &
            );

        private:
        
            /**
             * The number of nodes to send firewall messages to.
             */
            enum { firewall_nodes = 8 };
        
            /**
             * The timer handler.
             */
            void tick(const boost::system::error_code &);
        
            /**
             * The timer handler.
             */
            void firewall_check_tick(const boost::system::error_code &);
        
            /**
             * Starts firewall checks.
             */
            void start_firewall_checks();

            /**
             * Stops firewall checks.
             */
            void stop_firewall_checks();
        
            /**
             * The firewall check queue timer.
             * @param ec The
             */
            void process_firewall_check_queue_tick(
                const boost::system::error_code & ec
            );
        
            /**
             * The checks sent.
             */
            std::uint32_t m_checks_sent;
        
            /**
             * The tcp checks success.
             */
            std::uint32_t m_tcp_checks_success;
        
            /**
             * The udp checks success.
             */
            std::uint32_t m_udp_checks_success;
        
            /**
             * The tcp score.
             */
            float m_tcp_score;
    
            /**
             * The udp score.
             */
            float m_udp_score;
        
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
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
        
            /**
             * The local ip address as determined via the system.
             */
            boost::asio::ip::address local_address_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > firewall_check_timer_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > firewall_check_queue_timer_;
        
            /**
             * The firewall.
             */
            std::shared_ptr<firewall> firewall_;
#if (!defined __arm__ && !defined __thumb__ && !defined _M_ARM && !defined _M_ARMT)
            /**
             * The nat_pmp_client.
             */
            std::shared_ptr<nat_pmp_client> nat_pmp_client_;
        
            /**
             * The upnp_client.
             */
            std::shared_ptr<upnp_client> upnp_client_;
#endif // __arm__

            /**
             * The firewall check queue.
             */
            std::deque<boost::asio::ip::udp::endpoint> firewall_check_queue_;
        
            /**
             * The firewall check queue mutex.
             */
            std::recursive_mutex firewall_check_queue_mutex_;

            /**
             * The inflight tcp firewall checks.
             */
            std::map<std::uint16_t, std::time_t> inflight_tcp_firewall_checks_;
        
            /**
             * The inflight udp firewall checks.
             */
            std::map<std::uint16_t, std::time_t> inflight_udp_firewall_checks_;
        
            /**
             * The inflight tcp firewall checks queue mutex.
             */
            std::recursive_mutex inflight_tcp_firewall_checks_mutex_;
        
            /**
             * The inflight udp firewall checks queue mutex.
             */
            std::recursive_mutex inflight_udp_firewall_checks_mutex_;
    };

} // namespace database

#endif // DATABASE_FIREWALL_MANAGER_HPP
