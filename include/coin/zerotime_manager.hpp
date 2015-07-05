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

#ifndef COIN_ZEROTIME_MANAGER_HPP
#define COIN_ZEROTIME_MANAGER_HPP

#include <cstdint>
#include <ctime>
#include <map>
#include <vector>

#include <boost/asio.hpp>

#include <coin/sha256.hpp>
#include <coin/transaction_in.hpp>
#include <coin/zerotime_answer.hpp>
#include <coin/zerotime_question.hpp>

namespace coin {

    class stack_impl;
    
    /**
     * Implements a ZeroTime manager.
     */
    class zerotime_manager
        : public std::enable_shared_from_this<zerotime_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand.
             * @param owner The stack_impl.
             */
            zerotime_manager(
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
             * Starts probing the network for answers.
             * @param hash_tx The transaction hash.
             * @param transactions_in The transaction_in's.
             */
            void probe_for_answers(
                const sha256 & hash_tx,
                const std::vector<transaction_in> & transactions_in
            );
        
        private:
        
            /**
             * The answers (we've received over TCP) under key question.
             */
            std::map<sha256, std::vector< std::pair<
                boost::asio::ip::tcp::endpoint, zerotime_answer> > >
                m_answers_tcp
            ;
        
            /**
             * The questions (that we've asked) under key answer.
             */
            std::map<sha256, zerotime_question> m_questions;
        
            /**
             * A map of the times of which questions and all related answers
             * are to be expired.
             */
            std::map<sha256, std::time_t> m_qa_expire_times;
        
            /**
             * The questioned endpoints.
             */
            std::map<
                sha256, std::vector<boost::asio::ip::tcp::endpoint>
            > m_questioned_tcp_endpoints;
        
        protected:
        
            /**
             * The tick handler.
             * @param interval The interval.
             */
            void do_tick(const std::uint32_t & interval);

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
    
} // namespace coin

#endif // COIN_ZEROTIME_MANAGER_HPP
