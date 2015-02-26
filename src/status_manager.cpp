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

#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>

using namespace coin;

status_manager::status_manager(
    boost::asio::io_service & ios, boost::asio::strand & s, stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void status_manager::start()
{
    /**
     * Start the timer.
     */
    do_tick(interval_callback);
}

void status_manager::stop()
{
    timer_.cancel();
    pairs_.clear();
}

void status_manager::insert(const std::map<std::string, std::string> & pairs)
{
    std::lock_guard<std::mutex> l1(mutex_);

    pairs_.push_back(pairs);
}

void status_manager::do_tick(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::milliseconds(interval));
    timer_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            std::lock_guard<std::mutex> l1(mutex_);

            if (pairs_.size() > 0)
            {
                /**
                 * Get the pairs at the front.
                 */
                const auto & pairs = pairs_.front();
                
                /**
                 * Callback the pairs.
                 */
                stack_impl_.on_status(pairs);
                
                /**
                 * Erase the pairs at the front.
                 */
                pairs_.erase(pairs_.begin());

                if (pairs_.size() > 0)
                {
                    /**
                     * Start the timer.
                     */
                    do_tick(interval_callback);
                }
                else
                {
                    /**
                     * Start the timer.
                     */
                    do_tick(1000);
                }
            }
            else
            {
                /**
                 * Start the timer.
                 */
                do_tick(1000);
            }
        }
    }));
}
