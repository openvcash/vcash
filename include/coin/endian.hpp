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

#ifndef COIN_ENDIAN_HPP
#define COIN_ENDIAN_HPP

#include <array>
#include <cstdint>

namespace coin {

    /**
     * Implements endian conversions.
     */
    class endian
    {
        public:
        
            template <typename T, typename Iterator>
            static T from_big(Iterator in)
            {
                T ret = 0;
                
                if (std::is_unsigned<T>::value == false)
                {
                    throw std::runtime_error("value must be unsigned");
                }

                auto i = sizeof(T);
                
                while (0 < i)
                {
                    ret |= static_cast<T>(*in++) << (8 * --i);
                }
                
                return ret;
            }

            template <typename T, typename Iterator>
            static T from_little(Iterator in)
            {
                if (std::is_unsigned<T>::value == false)
                {
                    throw std::runtime_error("value must be unsigned");
                }

                T ret = 0;
                
                auto i = 0;
                
                while (i < sizeof(T))
                {
                    ret |= static_cast<T>(*in++) << (8 * i++);
                }
                
                return ret;
            }

            template <typename T>
            static std::array<std::uint8_t, sizeof(T)> to_big(T n)
            {
                std::array<std::uint8_t, sizeof(T)> ret;
                
                if (std::is_unsigned<T>::value == false)
                {
                    throw std::runtime_error("value must be unsigned");
                }
                
                for (auto i = ret.rbegin(); i != ret.rend(); ++i)
                {
                    *i = n;
                    n >>= 8;
                }
                
                return ret;
            }

            template <typename T>
            static std::array<std::uint8_t, sizeof(T)> to_little(T n)
            {
                std::array<std::uint8_t, sizeof(T)> ret;
                
                if (std::is_unsigned<T>::value == false)
                {
                    throw std::runtime_error("value must be unsigned");
                }

                for (auto i = ret.begin(); i != ret.end(); ++i)
                {
                    *i = n;
                    n >>= 8;
                }
                
                return ret;
            }

        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_ENDIAN_HPP
