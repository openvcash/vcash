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

#ifndef DATABASE_UTILITY_HPP
#define DATABASE_UTILITY_HPP

#include <cstdint>
#include <string>

#if (defined __ANDROID__)
#include <boost/lexical_cast.hpp>
#endif // __ANDROID__

namespace database {

    namespace utility {
    
        template <class T>
        inline std::string to_string(T val)
        {
#if (defined __ANDROID__)
            return boost::lexical_cast<std::string> (val);
#else
            return std::to_string(val);
#endif // __ANDROID__
        }
        
        template <class T>
        inline int to_int(T val)
        {
#if (defined __ANDROID__)
            return boost::lexical_cast<int> (val);
#else
            return  std::stoi(val);
#endif // __ANDROID__
        }
        
        namespace string {
            
            inline bool starts_with(
                const std::string & s1, const std::string & s2
                )
            {
                return s1.compare(0, s2.length(), s2) == 0;
            }
        } // namespace string
        
    } // namespace utility
    
} // namespace database

#endif // DATABASE_UTILITY_HPP
