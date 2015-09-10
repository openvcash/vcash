/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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

#ifndef COIN_INCENTIVE_MANAGER_HPP
#define COIN_INCENTIVE_MANAGER_HPP

#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <vector>

#include <boost/asio.hpp>

#include <coin/address_manager.hpp>
#include <coin/incentive_vote.hpp>

namespace coin {

    class message;
    class stack_impl;
    
    /**
     * Implements an incentive manager.
     */
    class incentive_manager
        : public std::enable_shared_from_this<incentive_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            incentive_manager(
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
             * Handles a message.
             * @param ep The boost::asio::ip::tcp::endpoint.
             * @param msg The message.
             */
            bool handle_message(
                const boost::asio::ip::tcp::endpoint & ep, message & msg
            );
        
        private:
        
            /**
             * The tick handler.
             * @param interval The interval.
             */
            void do_tick(const std::uint32_t & interval);
        
            /**
             * Votes for the wallet address for height + 2.
             * @param wallet_address The wallet address.
             */
            bool vote(const std::string & wallet_address);
        
        protected:
        
            /**
             * Returns the K closets nodes to the block height.
             * @param nodes The nodes.
             * @param block_height The block heigt.
             * @param k The maximum number of nodes.
             */
            std::vector<address_manager::recent_endpoint_t> k_closest(
                const std::vector<address_manager::recent_endpoint_t> & nodes,
                const std::uint32_t & block_height,
                const std::uint32_t & k = 20
            );
        
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
             * The last block height.
             */
            std::uint32_t last_block_height_;

            /**
             * The candidates.
             */
            std::map<
                address_manager::recent_endpoint_t,
                std::pair<std::time_t, std::uint32_t>
            > candidates_;
        
            /**
             * The candidates mutex.
             */
            std::mutex mutex_candidates_;
        
            /**
             * The votes.
             */
            std::map<
                std::uint32_t,
                std::map<std::string, std::vector<incentive_vote> >
            > votes_;
        
            /**
             * The votes mutex.
             */
            std::mutex mutex_votes_;
    };
}

#endif // COIN_INCENTIVE_MANAGER_HPP
