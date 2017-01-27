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

#ifndef COIN_BLAKE256_HPP
#define COIN_BLAKE256_HPP

#include <array>
#include <cstdint>

namespace coin {
    
    /**
     * Implements blake-256 (8 round).
     */
    class blake256
    {
        public:
        
            /**
             * The digest length.
             */
            enum { digest_length = 32 };
        
            /**
             * The digest type.
             */
            typedef std::array<std::uint8_t, digest_length> digest_t;
        
            /**
             * Performs a hash operation.
             * @param buf The buffer.
             * @param len The length.
             */
            static digest_t hash(
                const std::uint8_t * buf, const std::size_t & len
            );
        
        private:
        
            // ...
        
        protected:
        
            // ...
    };
}

#endif // COIN_BLAKE256_HPP
