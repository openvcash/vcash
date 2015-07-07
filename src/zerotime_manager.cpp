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

#include <coin/globals.hpp>
#include <coin/stack_impl.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_manager.hpp>

using namespace coin;

zerotime_manager::zerotime_manager(
    boost::asio::io_service & ios, boost::asio::strand & s, stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void zerotime_manager::start()
{
    /**
     * Start the timer.
     */
    do_tick(60);
}

void zerotime_manager::stop()
{
    timer_.cancel();
}

void zerotime_manager::probe_for_answers(
    const sha256 & hash_tx,
    const std::vector<transaction_in> & transactions_in
    )
{
    if (globals::instance().is_zerotime_enabled())
    {
        std::lock_guard<std::mutex> l1(mutex_questions_);
        
        if (questions_.count(hash_tx) == 0)
        {
            questions_[hash_tx].first = std::time(0);
            questions_[hash_tx].second = zerotime_question(transactions_in);
        }
    }
}

void zerotime_manager::handle_answer(
    const boost::asio::ip::tcp::endpoint & ep, const zerotime_answer & ztanswer
    )
{
    if (globals::instance().is_zerotime_enabled())
    {
        std::lock_guard<std::mutex> l1(mutex_zerotime_answers_tcp_);
        
        zerotime_answers_tcp_[ztanswer.hash_tx()].first = std::time(0);
        zerotime_answers_tcp_[ztanswer.hash_tx()].second[ep] = ztanswer;
    }
}

void zerotime_manager::do_tick(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(interval));
    timer_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (globals::instance().is_zerotime_enabled())
            {
                /**
                 * Clear expired input locks.
                 */
                zerotime::instance().clear_expired_input_locks();
                
                std::lock_guard<std::mutex> l1(mutex_zerotime_answers_tcp_);
                
                auto it1 = zerotime_answers_tcp_.begin();
                
                while (it1 != zerotime_answers_tcp_.end())
                {
                    if (std::time(0) - it1->second.first > interval_six_blocks)
                    {
                        it1 = zerotime_answers_tcp_.erase(it1);
                    }
                    else
                    {
                        ++it1;
                    }
                }
                
                std::lock_guard<std::mutex> l2(mutex_questions_);
                
                auto it2 = questions_.begin();
                
                while (it2 != questions_.end())
                {
                    if (std::time(0) - it2->second.first > interval_six_blocks)
                    {
                        it2 = questions_.erase(it2);
                    }
                    else
                    {
                        ++it2;
                    }
                }
                
                std::lock_guard<std::mutex> l3(
                    mutex_questioned_tcp_endpoints_
                );
                
                auto it3 = questioned_tcp_endpoints_.begin();
                
                while (it3 != questioned_tcp_endpoints_.end())
                {
                    if (std::time(0) - it3->second.first > interval_six_blocks)
                    {
                        it3 = questioned_tcp_endpoints_.erase(it3);
                    }
                    else
                    {
                        ++it3;
                    }
                }
            }
            
            /**
             * Start the timer.
             */
            do_tick(60);
        }
    }));
}
