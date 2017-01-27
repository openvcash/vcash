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

#ifndef COIN_KEY_PUBLIC_HPP
#define COIN_KEY_PUBLIC_HPP

#include <cstdint>
#include <vector>

#include <coin/ripemd160.hpp>
#include <coin/sha256.hpp>
#include <coin/types.hpp>

namespace coin {

    class data_buffer;
    
    /**
     * Implements a public key.
     */
    class key_public
    {
        public:
        
            /**
             * Constructor
             */
            key_public();
            
            /**
             * Constructor
             * @param bytes The bytes.
             */
            key_public(const std::vector<std::uint8_t> & bytes);
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * The bytes.
             */
            const std::vector<std::uint8_t> & bytes() const;
        
            /**
             * Gets the id.
             */
            types::id_key_t get_id() const;

            /**
             * Get's the hash.
             */
            sha256 get_hash() const;

            /**
             * If true it is valid.
             */
            bool is_valid() const;
        
            /**
             * If true it is compressed.
             */
            bool is_compressed() const;
    
            /**
             * friend bool operator ==
             */
            friend bool operator == (
                const key_public & left, const key_public & right
                )
            {
                return left.m_bytes == right.m_bytes;
            }
        
            /**
             * friend bool operator !=
             */
            friend bool operator != (
                const key_public & left, const key_public & right
                )
            {
                return left.m_bytes != right.m_bytes;
            }
        
            /**
             * friend bool operator <
             */
            friend bool operator < (
                const key_public & left, const key_public & right
                )
            {
                return left.m_bytes < right.m_bytes;
            }
    
        private:
        
            /**
             * The bytes.
             */
            std::vector<std::uint8_t> m_bytes;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_KEY_PUBLIC_HPP
