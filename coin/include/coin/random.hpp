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

#ifndef COIN_RANDOM_HPP
#define COIN_RANDOM_HPP

#include <cstdint>
#include <random>

#include <openssl/rand.h>

namespace coin {

    /**
     * Implements random number generation.
     */
    class random
    {
        public:
        
            /**
             * Generates a random std::uint8_t up to max value.
             * @param max The maximum value.
             */
            static std::uint8_t uint8(
                const std::uint8_t & max =
                std::numeric_limits<std::uint8_t>::max()
                )
            {
                return static_cast<std::uint8_t> (uint64(max));
            }
        
            /**
             * Generates a random std::uint16_t up to max value.
             * @param max The maximum value.
             */
            static std::uint16_t uint16(
                const std::uint16_t & max =
                std::numeric_limits<std::uint16_t>::max()
                )
            {
                return static_cast<std::uint16_t> (uint64(max));
            }
        
            /**
             * Generates a random std::uint16_t in the given range.
             * @param low The low range.
             * @param high The high range.
             */
            static std::uint16_t uint16_random_range(
                const std::uint16_t & low, const std::uint16_t & high
                )
            {
                static std::random_device rd;
                static std::mt19937_64 gen(rd());

                std::uniform_int_distribution<> dist(low, high);
                
                return dist(gen);
            }
        
            /**
             * Generates a random std::uint32_t in the given range.
             * @param low The low range.
             * @param high The high range.
             */
            static std::uint32_t uint32_random_range(
                const std::uint32_t & low, const std::uint32_t & high
                )
            {
                static std::random_device rd;
                static std::mt19937_64 gen(rd());

                std::uniform_int_distribution<> dist(low, high);
                
                return dist(gen);
            }
        
            /**
             * Generates a random std::uint32_t up to max value.
             * @param max The maximum value.
             */
            static std::uint32_t uint32(
                const std::uint32_t & max =
                std::numeric_limits<std::uint32_t>::max()
                )
            {
                return static_cast<std::uint32_t> (uint64(max));
            }
        
            /**
             * Generates a random std::uint64_t up to max value.
             * @param max The maximum value.
             */
            static std::uint64_t uint64(
                const std::uint64_t & max =
                std::numeric_limits<std::uint64_t>::max()
                )
            {
                static std::random_device rd;
                static std::mt19937_64 gen(rd());

                std::uniform_int_distribution<std::uint64_t> dist;
          
                return dist(gen) % max;
            }
        
            /**
             * Increases the uncertainty about the state and makes the PRNG
             * output less predictable.
             * @param tmp The seed.
             */
            static void openssl_RAND_add(const std::uint64_t & tmp = uint64())
            {
                RAND_add(&tmp, sizeof(tmp), 1.5);
                
                std::memset(const_cast<std::uint64_t *> (&tmp), 0, sizeof(tmp));
            }

        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_RANDOM_HPP
