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
 
#ifndef COIN_POINT_OUT_HPP
#define COIN_POINT_OUT_HPP

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements an out point.
     */
    class point_out : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            point_out();
        
            /**
             * Constructor
             * @param h The hash.
             * @param n The n.
             */
            point_out(const sha256 & h, const std::uint32_t & n);
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
        
            /**
             * The hash.
             */
            const sha256 & get_hash() const;
        
            /**
             * The n.
             */
            const std::uint32_t & n() const;
        
            /**
             * to_string
             */
            const std::string to_string() const;
        
            /**
             * operator <
             */
            friend bool operator < (const point_out & a, const point_out & b)
            {
                return
                    a.m_hash < b.m_hash ||
                    (a.m_hash == b.m_hash && a.m_n < b.m_n)
                ;
            }

            /**
             * operator ==
             */
            friend bool operator == (const point_out & a, const point_out & b)
            {
                return a.m_hash == b.m_hash && a.m_n == b.m_n;
            }

            /**
             * operator !=
             */
            friend bool operator != (const point_out & a, const point_out & b)
            {
                return !(a == b);
            }
        
        private:
        
            /**
             * The hash.
             */
            sha256 m_hash;
        
            /**
             * The n.
             */
            std::uint32_t m_n;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_POINT_OUT_HPP
