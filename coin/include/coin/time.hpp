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

#ifndef COIN_TIME_HPP
#define COIN_TIME_HPP

#include <cstdint>
#include <mutex>
#include <set>
#include <vector>

#include <coin/logger.hpp>
#include <coin/median_filter.hpp>
#include <coin/protocol.hpp>
#include <coin/utility.hpp>

namespace coin {

    /**
     * Implements time related functionality. It is ok for this to be a
     * singleton even in the presence of multiple instances in the same
     * memory space.
     */
    class time
    {
        public:
        
            /**
             * Constructor
             */
            time()
                : m_time_offset(0)
                , median_filter_(200, 0)
            {
                // ...
            }
        
            /**
             * The singleton accessor.
             */
            static time & instance()
            {
                static time g_time;
                
                return g_time;
            }
        
            /**
             * Returns the adjusted time.
             */
            const std::uint64_t get_adjusted() const
            {
                return static_cast<
                    std::uint64_t
                > (std::time(0)) + m_time_offset;
            }
        
            /**
             * Adds a peer's timestamp.
             * @param addr The protocol::network_address_t.
             * @param timestamp The timestamp.
             */
            void add(
                protocol::network_address_t & addr,
                const std::uint64_t & timestamp
                )
            {
                /**
                 * Ignore duplicate network addresses.
                 */
                static std::set<protocol::network_address_t> g_seen_addrs;
                
                if (g_seen_addrs.insert(addr).second == false)
                {
                    // ...
                }
                else
                {
                    /**
                     * Calculate the offset sample.
                     */
                    std::uint64_t offset_sample = timestamp - std::time(0);
                    
                    std::lock_guard<std::mutex> l1(mutex_median_filter_);
                    
                    /**
                     * Input the offset sample.
                     */
                    median_filter_.input(offset_sample);
                    
                    log_debug(
                        "Time added filter size = " << median_filter_.size() <<
                        ", offset_sample = " << offset_sample << ", mins = " <<
                        offset_sample / 60
                    );
                    
                    if (
                        median_filter_.size() >= 5 &&
                        median_filter_.size() % 2 == 1
                        )
                    {
                        auto median = median_filter_.median();
                        
                        auto sorted = median_filter_.sorted();
                        
                        /**
                         * Only let other peers alter our time by so much.
                         */
                        if (utility::abs64(median) < 70 * 60)
                        {
                            m_time_offset = median;
                        }
                        else
                        {
                            m_time_offset = 0;
                            
                            /**
                             * Check if our clock is wrong.
                             */
                            bool found = false;
                            
                            for (auto & i : sorted)
                            {
                                if (
                                    m_time_offset != 0 &&
                                    utility::abs64(i) < 5 * 60
                                    )
                                {
                                    found = true;
                                    
                                    break;
                                }
                            }
                            
                            if (found == false)
                            {
                                log_error(
                                    "Time detected incorrect system clock."
                                );
                            }
                        }
                    }
                }
            }
        
        private:

            /**
             * The time offset.
             */
            std::uint64_t m_time_offset;
        
        protected:
        
            /**
             * The median_filter.
             */
            median_filter<std::int64_t> median_filter_;
        
            /**
             * The median_filter_ std::mutex.
             */
            std::mutex mutex_median_filter_;
    };
    
} // namespace coin

#endif // COIN_TIME_HPP
