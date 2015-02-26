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

#ifndef COIN_HASH_HPP
#define COIN_HASH_HPP

#include <array>
#include <cstdint>

#include <coin/sha256.hpp>
#include <coin/whirlpool.hpp>

namespace coin {

    /**
     * Implements various hashing algorithms.
     */
    class hash
    {
        public:
        
            /**
             * Calculates a sha256d hash.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::array<std::uint8_t, sha256::digest_length> sha256d(
                const std::uint8_t * buf, const std::size_t & len
            );

            /**
             * Calculates a sha256d hash.
             * @param begin The begin.
             * @param end The end.
             */
            static std::array<std::uint8_t, sha256::digest_length> sha256d(
                const std::uint8_t * begin, const std::uint8_t * end
            );
        
            /**
             * Calculates a sha256d hash.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::array<std::uint8_t, sha256::digest_length> sha256d(
                const std::uint8_t * p1begin, const std::uint8_t * p1end,
                    const std::uint8_t * p2begin, const std::uint8_t * p2endn
            );

            /**
             * Calculates a sha256d checksum.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::uint32_t sha256d_checksum(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Calculates a sha256_ripemd160 hash.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::array<std::uint8_t, 20> sha256_ripemd160(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Generates a random sha256 hash.
             */
            static sha256 sha256_random();
        
            /**
             * Calculates a whirlpoolx hash.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::array<std::uint8_t, whirlpool::digest_length / 2>
                whirlpoolx(const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Returns a 64-bit representation of the input.
             * @param buf The buffer.
             * @param n The n.
             */
            static std::uint64_t to_uint64(
                const std::uint8_t * buf, const std::size_t & n = 0
            );
    
        private:
        
            // ...
        
        protected:
        
            // ...
    };
}

#endif // COIN_HASH_HPP
