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

#ifndef CHAINBLENDER_MANAGER_HPP
#define CHAINBLENDER_MANAGER_HPP

#include <map>
#include <mutex>
#include <set>
#include <vector>

#include <boost/asio.hpp>

#include <coin/address_manager.hpp>
#include <coin/ecdhe.hpp>
#include <coin/output.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_in.hpp>

namespace coin {

    class coin_control;
    class stack_impl;
    class tcp_connection;
    
    /**
     * Implements a ChainBlender manager.
     */
    class chainblender_manager
        : public std::enable_shared_from_this<chainblender_manager>
    {
        public:

            /**
             * The blend state.
             */
            typedef enum blend_state_s
            {
                blend_state_none,
                blend_state_active,
                blend_state_passive,
            } blend_state_t;

            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            chainblender_manager(
                boost::asio::io_service & ios, boost::asio::strand & s,
                stack_impl & owner
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
             * Restarts
             * @param interval The interval in seconds to wait to restart.
             */
            void restart(const std::uint32_t & interval = 64);
        
            /**
             * Sets the blend state.
             * @param val The blend_state_t.
             */
            void set_blend_state(const blend_state_t & val);
        
            /**
             * The blend state.
             */
            const blend_state_t & blend_state() const;
        
        private:
        
            /**
             * Connects to the give endpoint.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            void connect(const boost::asio::ip::tcp::endpoint & ep);
        
            /**
             * The blend state.
             */
            blend_state_t m_blend_state;
        
        protected:
        
            /**
             * The tick handler.
             * @param interval The interval.
             */
            void do_tick(const std::uint32_t & interval);

            /**
             * The tick ecdhe handler.
             * @param interval The interval.
             */
            void do_tick_ecdhe(const std::uint32_t & interval);
        
            /**
             * The tick tx handler.
             * @param interval The interval.
             */
            void do_tick_tx(const std::uint32_t & interval);
        
            /**
             * The tick blend handler.
             * @param interval The interval.
             */
            void do_tick_blend(const std::uint32_t & interval);
        
            /**
             * Returns the K closets nodes to the block height.
             * @param nodes The nodes.
             * @param block_height The block heigt.
             * @param k The maximum number of nodes.
             */
            std::vector<address_manager::recent_endpoint_t> k_closest(
                const std::vector<address_manager::recent_endpoint_t> & nodes,
                const std::uint32_t & block_height,
                const std::uint32_t & k
            );
        
            /**
             * Selects coins that qualify for blending.
             */
            std::vector<output> select_coins();
        
            /**
             * Broadcasts new signatures for the blended transaction.
             * @param tx_ins The transaction_in's.
             */
            void broadcast_signatures(
                const std::vector<transaction_in> & tx_ins
            );
        
            /**
             * Attempts to commit a blended transaction.
             * @param tx_blended The blended transaction.
             */
            bool commit_transaction(transaction & tx);
        
            /**
             * Verifies the signatures on my portions of the final blended
             * transaction.
             */
            bool verify_my_blended_transaction_signatures();

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
        
            /**
             * The restart timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_restart_;
        
            /**
             * The blend timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_blend_;
        
            /**
             * The tcp_connection.
             */
            std::shared_ptr<tcp_connection> tcp_connection_;
        
            /**
             * The recently tried nodes.
             */
            std::map<
                address_manager::recent_endpoint_t, std::time_t
            > nodes_tried_;
        
            /**
             * The tried nodes mutex.
             */
            std::recursive_mutex mutex_nodes_tried_;
        
            /**
             * A session.
             */
            struct session_s
            {
                sha256 hash_id;
                std::int64_t denomination;
                std::int64_t sum;
                std::uint8_t participants;
                std::set<std::string> public_keys;
                std::shared_ptr<coin_control> coin_control_inputs;
                std::map<sha256, transaction> transactions;
                transaction transaction_mine;
                transaction transaction_blended;
                std::uint8_t signatures;
                std::uint8_t ecdhe_acks;
                std::uint8_t tx_acks;
                std::uint8_t sig_acks;
                std::shared_ptr<
                    chainblender_broadcast> chainblender_broadcast_type_tx
                ;
            } session_;
        
            /**
             * The type_tx timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_tx_;
        
            /**
             * The type_ecdhe timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ecdhe_;
        
            /**
             * The ECDHE context.
             */
            ecdhe ecdhe_;
        
            /**
             * The ECDHE "Retransmission TimeOut" in milliseconds.
             */
            std::uint32_t ecdhe_rto_;
        
            /**
             * The Tx "Retransmission TimeOut" in milliseconds.
             */
            std::uint32_t tx_rto_;
        
            /**
             * The time we last performed a denomination operation.
             */
            std::time_t time_last_denominate_;
        
            /**
             * The last block height.
             */
            std::uint32_t last_block_height_;
    };
}

#endif // CHAINBLENDER_MANAGER_HPP
