/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#ifndef CRAWLER_PROBE_MANAGER_HPP
#define CRAWLER_PROBE_MANAGER_HPP

#include <map>
#include <mutex>

#include <crawler/peer.hpp>

namespace crawler {

    class mixer;
    class stack_impl;
    
    /**
     * Implements a mixer manager.
     */
    class probe_manager : public std::enable_shared_from_this<probe_manager>
    {
        public:
        
            /**
             * Constructor
             * @param owner The stack_impl.
             */
            explicit probe_manager(stack_impl & owner);
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
        private:
        
            /**
             * The timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code & ec);
        
            /**
             * The post timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick_post(const boost::system::error_code & ec);
        
            /**
             * The probe timer handler.
             * @param ec The boost::system::error_code.
             */
            void tick_probe(const boost::system::error_code & ec);
        
            /**
             * The peers.
             */
            std::map<std::string, peer> m_peers;
        
        protected:
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
            /**
             * The peers mutex.
             */
            std::mutex mutex_peers_;
        
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_;
        
            /**
             * The post timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_post_;
        
            /**
             * The probe timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_probe_;
    };
    
} // namespace crawler

#endif // CRAWLER_PROBE_MANAGER_HPP
