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

#include <algorithm>

#include <coin/logger.hpp>
#include <coin/script_checker_queue.hpp>

using namespace coin;

script_checker_queue::script_checker_queue()
    : state_(state_stopped)
    , idle_workers_(0)
    , total_workers_(0)
    , is_ok_(true)
    , remaining_(0)
    , batch_size_maximum_(128)
{
    // ...
}

script_checker_queue & script_checker_queue::instance()
{
    static script_checker_queue g_script_checker_queue;
                
    return g_script_checker_queue;
}

void script_checker_queue::start()
{
    if (state_ == state_stopped)
    {
        log_info("Script checker queue is starting.");
        
        /**
         * Set the state to state_starting.
         */
        state_ = state_starting;
        
        /**
         * Get the number of cores.
         */
        auto cores = std::thread::hardware_concurrency();
        
        /**
         * Limit the number of cores.
         */
        cores = std::max(
            static_cast<std::uint32_t> (3 - 1),
            static_cast<std::uint32_t> (cores - 1)
        );
        
        /**
         * Allocate the threads.
         */
        for (auto i = 0; i < cores; i++)
        {
            auto thread = std::make_shared<std::thread> (
                std::bind(&script_checker_queue::loop, this, false)
            );
            
            /**
             * Retain the thread.
             */
            threads_.push_back(thread);
        }
        
        /**
         * Set the state to state_started.
         */
        state_ = state_started;
    }
}

void script_checker_queue::stop()
{
    std::unique_lock<std::mutex> l1(mutex_);
    
    if (state_ == state_started)
    {
        log_info("Script checker queue is stopping.");
        
        /**
         * Set the state to state_stopping.
         */
        state_ = state_stopping;

        condition_variable_worker_.notify_all();

        while (total_workers_ > 0)
        {
            condition_variable_quit_.wait(l1);
        }
        
        /**
         * Join the threads.
         */
        for (auto & i : threads_)
        {
            try
            {
                if (i->joinable())
                {
                    i->join();
                }
            }
            catch (std::exception & e)
            {
                // ...
            }
        }
        
        /**
         * Clear the threads.
         */
        threads_.clear();
        
        /**
         * Set the state to state_stopped.
         */
        state_ = state_stopped;
        
        log_info("Script checker queue is stopped.");
    }
}

bool script_checker_queue::sync_wait()
{
    return loop(true);
}

bool script_checker_queue::is_idle()
{
    std::unique_lock<std::mutex> l1(mutex_);
    
    return total_workers_ == idle_workers_ && remaining_ == 0 && is_ok_ == true;
}

void script_checker_queue::insert(std::vector<script_checker> & checks)
{
    std::unique_lock<std::mutex> l1(mutex_);

    for (auto & i : checks)
    {
        queue_.push_back(i);
    }

    remaining_ += checks.size();

    if (checks.size() == 1)
    {
        condition_variable_worker_.notify_one();
    }
    else if (checks.size() > 1)
    {
        condition_variable_worker_.notify_all();
    }
}

bool script_checker_queue::loop(const bool & is_main_thread)
{
    auto & cond =
        is_main_thread ? condition_variable_main_ : condition_variable_worker_
    ;
    
    std::vector<script_checker> checks;
    
    checks.reserve(batch_size_maximum_);
    
    std::uint32_t work_to_perform = 0;
    
    auto is_ok = true;
    
    while (state_ == state_starting || state_ == state_started)
    {
        std::unique_lock<std::mutex> l1(mutex_);
        
        if (work_to_perform > 0)
        {
            log_debug(
                "Script checker queue " << std::this_thread::get_id() <<
                " is looping, queue = " << queue_.size() <<
                ", work_to_perform = " << work_to_perform <<
                ", remaining = " << remaining_ << "."
            );
        
            is_ok_ &= is_ok;
            
            remaining_ -= work_to_perform;
            
            if (remaining_ == 0 && is_main_thread == false)
            {
                condition_variable_main_.notify_one();
            }
        }
        else
        {
            total_workers_++;
        }
        
        while (queue_.size() == 0)
        {
            if (
                (is_main_thread == true || state_ != state_started) &&
                remaining_ == 0
                )
            {
                total_workers_--;
                
                if (total_workers_ == 0)
                {
                    condition_variable_quit_.notify_one();
                }
                
                auto ret = is_ok_;
                
                if (is_main_thread == true)
                {
                    is_ok_ = true;
                }
                
                return ret;
            }
            
            /**
             * Increment idle.
             */
            idle_workers_++;
            
            /**
             * Wait
             */
            cond.wait(l1);
            
            /**
             * Decrement idle.
             */
            idle_workers_--;
        }
            
        /**
         * Determine the amount of work to perform.
         */
        work_to_perform = std::max(
            static_cast<std::uint32_t> (1),
            (std::min)(batch_size_maximum_, static_cast<std::uint32_t> (
            queue_.size() / (total_workers_ + idle_workers_ + 1)))
        );

        /**
         * Allocate the script_checker's.
         */
        checks.resize(work_to_perform);
        
        for (auto i = 0; i < work_to_perform; i++)
        {
            if (queue_.size() > 0)
            {
                checks[i] = queue_.back();
                
                queue_.pop_back();
            }
        }
        
        is_ok = is_ok_;
        
        /**
         * The std::mutex is no longer needed, unlock it.
         */
        l1.unlock();
        
        /**
         * Perform the script_checker check.
         */
        for (auto & i : checks)
        {
            if (is_ok == true)
            {
                /**
                 * Check the script_checker.
                 */
                is_ok = i.check();
            }
        }
        
        /**
         * Clear the script_checker's.
         */
        checks.clear();
        
    };

    return false;
}
