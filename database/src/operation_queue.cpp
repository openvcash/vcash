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

#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/operation_queue.hpp>

using namespace database;

operation_queue::operation_queue(boost::asio::io_service & ios)
    : io_service_(ios)
    , strand_(ios)
    , cleanup_timer_(ios)
{
    // ...
}

void operation_queue::start()
{
    /**
     * Start the cleanup timer.
     */
    cleanup_timer_.expires_from_now(std::chrono::seconds(1));
    cleanup_timer_.async_wait(
        strand_.wrap(std::bind(&operation_queue::cleanup_tick,
        shared_from_this(), std::placeholders::_1))
    );
}

void operation_queue::stop()
{
    io_service_.post(
        strand_.wrap(std::bind(&operation_queue::do_stop, shared_from_this()))
    );
}

void operation_queue::do_stop()
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    /**
     * Cancel the cleanup timer.
     */
    cleanup_timer_.cancel();
    
    auto it = operations_.begin();
    
    while (it != operations_.end())
    {
        if (it->second)
        {
            it->second->stop();
        }
        
        it = operations_.erase(it);
    }
}

void operation_queue::insert(std::shared_ptr<operation> op)
{
    io_service_.post(
        strand_.wrap(std::bind(&operation_queue::do_insert, shared_from_this(),
        op))
    );
}

void operation_queue::do_insert(std::shared_ptr<operation> op)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);

    /**
     * Insert the operation.
     */
    auto it = operations_.insert(std::make_pair(op->transaction_id(), op));
    
    if (it.second)
    {
        /**
         * Start the operation.
         */
        op->start();
    }
    else
    {
        log_error(
            "Operation queue failed to insert " << op->transaction_id() <<
            ", already exists."
        );
    }
}

void operation_queue::remove(const std::uint16_t & tid)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    log_debug(
        "Operation queue removing operation " << tid << "."
    );
    
    auto it = operations_.find(tid);
    
    if (it != operations_.end())
    {
        /**
         * Erase
         */
        operations_.erase(it);
    }
}

const std::shared_ptr<operation> operation_queue::find(
    const std::uint16_t & mtid
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    for (auto & i : operations_)
    {
        auto j = i.second->message_tids();
        
        auto it = j.find(mtid);
        
        if (it != j.end())
        {
            return i.second;
        }
    }
    
    return std::shared_ptr<operation> ();
}

void operation_queue::cleanup_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(mutex_);
        
        auto it = operations_.begin();
        
        while (it != operations_.end())
        {
            if (it->second && it->second->state() == operation::state_stopped)
            {
                operations_.erase(it++);
            }
            else
            {
                ++it;
            }
        }
        
        /**
         * Start the cleanup timer.
         */
        cleanup_timer_.expires_from_now(std::chrono::seconds(1));
        cleanup_timer_.async_wait(
            strand_.wrap(std::bind(&operation_queue::cleanup_tick,
            shared_from_this(), std::placeholders::_1))
        );
    }
}
