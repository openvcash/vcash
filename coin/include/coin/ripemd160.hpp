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

#ifndef COIN_RIPEMD160_HPP
#define COIN_RIPEMD160_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace coin {

    class ripemd160
    {
        public:
        
            /**
             * The digest length.
             */
            enum { digest_length = 20 };
        
            /**
             * The digest type.
             */
            typedef std::array<std::uint8_t, digest_length> digest_t;
        
            /**
             * Constructor
             */
            ripemd160();
   
            /**
             * Copy Constructor
             */
            ripemd160(const ripemd160 & other);
    
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            ripemd160(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Constructor
             * @param digest The digest_t.
             */
            ripemd160(const digest_t & digest);
        
            /**
             * Constructor
             * @param value The value.
             */
            ripemd160(const std::vector<std::uint8_t> & value);
    
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
            ripemd160 & operator = (const ripemd160 & other)
            {
                m_digest = other.digest();
                
                return *this;
            }
    
            /**
             * operator ==
             */
            friend inline bool operator == (
                const ripemd160 & a, const ripemd160 & b
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
                const ripemd160 & a, const ripemd160 & b
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

#endif // COIN_RIPEMD160_HPP
