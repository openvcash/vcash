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

#ifndef COIN_MINING_MANAGER_HPP
#define COIN_MINING_MANAGER_HPP

/**
 * Workaround bug in gcc 4.7:  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52680
 */
#if (defined __linux__)
#define _GLIBCXX_USE_NANOSLEEP 1
#endif // __linux__

#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace coin {

    class key_reserved;
    class stack_impl;
    
    /**
     * Implements a mining manager.
     */
    class mining_manager
    {
        public:
        
            /**
             * The Proof-of-Work states.
             */
            typedef enum
            {
                state_pow_none,
                state_pow_starting,
                state_pow_started,
                state_pow_stopping,
                state_pow_stopped
            } state_pow_t;
        
            /**
             * The Proof-of-Stake states.
             */
            typedef enum
            {
                state_pos_none,
                state_pos_starting,
                state_pos_started,
                state_pos_stopping,
                state_pos_stopped
            } state_pos_t;
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param owner The stack_impl.
             */
            mining_manager(
                boost::asio::io_service & ios, stack_impl & owner
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
             * Starts mining Proof-of-Work.
             */
            void start_proof_of_work();
        
            /**
             * Stops mining Proof-of-Work.
             */
            void stop_proof_of_work();
        
            /**
             * The number of hashes per second.
             */
            const double & hashes_per_second() const;
        
        private:
        
            /**
             * Starts mining Proof-of-Stake.
             */
            void start_proof_of_stake();
        
            /**
             * Stops mining Proof-of-Stake.
             */
            void stop_proof_of_stake();

            /**
             * The main loop.
             */
            void loop();
        
            /**
             * The Proof-of-Stake timer handler.
             * @param ec The boost::system::error_code.
             */
            void pos_tick(const boost::system::error_code & ec);
        
            /**
             * The state_pow_t.
             */
            state_pow_t m_state_pow;

            /**
             * The state_pos_t.
             */
            state_pos_t m_state_pos;
        
            /**
             * The number of hashes per second.
             */
            double m_hashes_per_second;
        
            /**
             * The time the hps timer was started.
             */
            std::int64_t m_hps_timer_start;

        protected:
        
            /**
             * Checks the work.
             * @param blk The block.
             * @paramw w The wallet.
             * @param reserved_key The key_reserved.
             * @param is_proof_of_stake If true it is Proof-of-Stake.
             */
            void check_work(
                std::shared_ptr<block> & blk,
                const std::shared_ptr<wallet> & w,
                key_reserved & reserve_key, const bool & is_proof_of_stake
            );
        
            /**
             * Increments the extra nonce.
             * @param blk The block.
             * @param index_previous The previous block_index.
             * @param extra_nonce The extra nonce.
             */
            void increment_extra_nonce(
                std::shared_ptr<block> & blk, block_index * index_previous,
                std::uint32_t & extra_nonce
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
             * The std::mutex
             */
            mutable std::mutex mutex_;
        
            /**
             * The (Proof-of-Work) threads.
             */
            std::vector< std::shared_ptr<std::thread> > threads_;
        
            /**
             * The Proof-of-Stake timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_pos_;
    };
    
} // namespace coin

#endif // COIN_MINING_MANAGER_HPP
