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

#ifndef COIN_INVENTORY_CACHE_HPP
#define COIN_INVENTORY_CACHE_HPP

#include <deque>
#include <mutex>
#include <set>

#include <coin/inventory_vector.hpp>

namespace coin {

    /**
     * Implements an inventory cache.
     */
    class inventory_cache : public std::set<inventory_vector>
    {
        public:
        
            /**
             * Constructor
             */
            inventory_cache()
                : m_max_size(1000)
            {
                // ...
            }
        
            /**
             * Inserts an element into the set removing the last excess
             * elements.
             * @param inv The inventory_vector.
             */
            std::pair<std::set<inventory_vector>::iterator, bool> insert(
                const inventory_vector & inv
                )
            {
                auto ret = std::set<inventory_vector>::insert(inv);
                
                if (ret.second)
                {
                    if (m_max_size > 0 && queue_.size() >= m_max_size)
                    {
                        std::set<inventory_vector>::erase(queue_.front());
                        
                        queue_.pop_front();
                    }
                    
                    queue_.push_back(inv);
                }
                
                return ret;
            }
        
        private:
        
            /**
             * The maximum size (elements).
             */
            std::size_t m_max_size;
        
        protected:
        
            /**
             * The queue.
             */
            std::deque<inventory_vector> queue_;
    };
    
} // namespace coin

#endif // COIN_INVENTORY_CACHE_HPP
