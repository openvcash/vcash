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

#ifndef DATABASE_RANDOM_HPP
#define DATABASE_RANDOM_HPP

#include <random>
#include <string>

namespace database {

    /**
     * Implements random functionality.
     */
    class random
    {
        public:
        
            static std::string string(const std::size_t & length)
            {
                std::string ret(length, 0);
                
                auto randchar = []() -> char
                {
                    const char charset[] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
                    const std::size_t max_index = (sizeof(charset) - 1);
                    return charset[std::rand() % max_index];
                };

                std::generate_n(ret.begin(), length, randchar);
                
                return ret;
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
        
        private:
        
            // ...
        
        protected:
        
            // ...
    };

} // namespace database

#endif // DATABASE_RANDOM_HPP
