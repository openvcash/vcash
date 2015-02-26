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

#ifndef COIN_WHIRLPOOL_HPP
#define COIN_WHIRLPOOL_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace coin {

    /**
     * Implements the whirlpool algorithm.
     */
    class whirlpool
    {
        public:
        
            /**
             * The digest length.
             */
            enum { digest_length = 64 };
        
            /**
             * The digest type.
             */
            typedef std::array<std::uint8_t, digest_length> digest_t;
        
            /**
             * Constructor
             */
            whirlpool();
   
            /**
             * Copy Constructor
             */
            whirlpool(const whirlpool & other);
    
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            whirlpool(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Constructor
             * @param digest The digest_t.
             */
            whirlpool(const digest_t & digest);
        
            /**
             * Constructor
             * @param value The value.
             */
            whirlpool(const std::vector<std::uint8_t> & value);
    
            /**
             * Performs a hash operation.
             * @param buf The buffer.
             * @param len The length.
             */
            static digest_t hash(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * The string representation.
             */
            std::string to_string() const;

            /**
             * If true it is empty.
             */
            bool is_empty() const;
        
            /**
             * Clears
             */
            void clear();
        
            /**
             * The digest.
             */
            digest_t & digest();
        
            /**
             * The digest.
             */
            const digest_t & digest() const;
        
            /**
             * operator =
             */
            whirlpool & operator = (const whirlpool & other)
            {
                m_digest = other.digest();
                
                return *this;
            }
    
            /**
             * operator ==
             */
            friend inline bool operator == (
                const whirlpool & a, const whirlpool & b
                )
            {
                for (auto i = 0; i < digest_length; i++)
                {
                    if (a.m_digest[i] != b.m_digest[i])
                    {
                        return false;
                    }
                }
                
                return true;
            }
        
            /**
             * operator <
             */
            friend inline bool operator < (
                const whirlpool & a, const whirlpool & b
                )
            {
                for (auto i = digest_length - 1; i >= 0; i--)
                {
                    if (a.m_digest[i] < b.m_digest[i])
                    {
                        return true;
                    }
                    else if (a.m_digest[i] > b.m_digest[i])
                    {
                        return false;
                    }
                }
                
                return false;
            }
        
        private:
        
            /**
             * The digest.
             */
            digest_t m_digest;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_WHIRLPOOL_HPP