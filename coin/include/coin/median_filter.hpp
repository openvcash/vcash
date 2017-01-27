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

#ifndef COIN_MEDIAN_FILTER_HPP
#define COIN_MEDIAN_FILTER_HPP

#include <algorithm>
#include <string>
#include <vector>

namespace coin {

    /**
     * Implements a median filter.
     */
    template <typename T> class median_filter
    {
        public:
        
            /**
             * Constructor
             * @param size The size.
             * @param initial_value The initial value.
             */
            median_filter(const std::size_t & size, T initial_value)
                : m_size(size)
            {
                m_values.reserve(size);
                m_values.push_back(initial_value);
                m_sorted = m_values;
            }

            void input(T value)
            {
                if (m_values.size() == m_size)
                {
                    m_values.erase(m_values.begin());
                }
                
                m_values.push_back(value);

                m_sorted.resize(m_values.size());
               
                std::copy(
                    m_values.begin(), m_values.end(), m_sorted.begin()
                );
                
                std::sort(m_sorted.begin(), m_sorted.end());
            }

            T median() const
            {
                T ret = 0;
                
                auto size = m_sorted.size();
                
                if (size > 0)
                {
                    if (size & 1)
                    {
                        ret = m_sorted[size / 2];
                    }
                    
                    if (
                        m_sorted.size() > (size / 2 - 1) + 1 &&
                        m_sorted.size() > (size / 2) + 1
                        )
                    {
                        ret = (m_sorted[size / 2 - 1] + m_sorted[size / 2]) / 2;
                    }
                }
    
                return ret;
            }

            /**
             * The sorted.
             */
            std::vector<T> sorted() const
            {
                return m_sorted;
            }
        
            /**
             * The size.
             */
            std::size_t size() const
            {
                return m_values.size();
            }
        
        private:
        
            /**
             * The values.
             */
            std::vector<T> m_values;
        
            /**
             * The sorted.
             */
            std::vector<T> m_sorted;
        
            /**
             * The size.
             */
            std::size_t m_size;

        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_MEDIAN_FILTER_HPP
