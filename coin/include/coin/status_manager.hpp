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

#ifndef COIN_STATUS_MANAGER_HPP
#define COIN_STATUS_MANAGER_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace coin {

    class stack_impl;
    
    /**
     * Implements a status manager.
     */
    class status_manager : public std::enable_shared_from_this<status_manager>
    {
        public:
        
            /**
             * Constructor
             * @param owner The stack_impl.
             */
            status_manager(stack_impl & owner);
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Inserts status pairs.
             * @param pairs The pairs.
             */
            void insert(const std::map<std::string, std::string> & pairs);
        
        private:
        
            /**
             * The timer callback interval in milliseconds.
             */
            enum { interval_callback = 1 };
        
        protected:
        
            /**
             * The tick handler.
             * @param interval The interval.
             */
            void do_tick(const std::uint32_t & interval);

            /**
             * The boost::asio::io_service loop.
             */
            void loop();
        
            /**
             * The std::thread.
             */
            std::thread thread_;
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
            
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
             * The std::mutex
             */
            std::mutex mutex_;
        
            /**
             * The pairs.
             */
            std::vector< std::map<std::string, std::string> > pairs_;
    };

} // namespace coin

#endif // COIN_STATUS_MANAGER_HPP
