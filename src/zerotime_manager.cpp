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
        if (m_questions.count(hash_tx) == 0)
        {
            
        }
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
            }
            
            /**
             * Start the timer.
             */
            do_tick(60);
        }
    }));
}
