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

#ifndef COIN_BASE58_HPP
#define COIN_BASE58_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace coin {

    /**
     * Implements base58.
     */
    class base58
    {
        public:
        
            /**
             * Constructor
             */
            base58();

            /**
             * Destructor
             */
            ~base58();

            /**
             * set_data
             * @param version The version.
             * @param buf The buffer.
             * @param len The length.
             */
            void set_data(
                const int & version, const char * buf, const std::size_t & len
            );

            /**
             * set_data
             * @param version The version.
             * @param ptr_begin The ptr_begin.
             * @param ptr_end The ptr_end.
             */
            void set_data(
                const int & version, const char * ptr_begin,
                const char * ptr_end
            );
        
            /**
             * set_string
             * @param value The value.
             */
            bool set_string(const std::string & value);

            /**
             * to_string
             * @param include_version If true the version will be included.
             */
            const std::string to_string(
                const bool & include_version = true
            ) const;

            /**
             * compare_to
             */
            int compare_to(const base58 & b58) const;
        
            /**
             * The version.
             */
            const std::uint8_t & version() const;

            /**
             * The data.
             */
            std::vector<std::uint8_t> & data();
        
            /**
             * operator ==
             */
            bool operator == (const base58 & b58) const
            {
                return compare_to(b58) == 0;
            }

            /**
             * operator <=
             */
            bool operator <= (const base58 & b58) const
            {
                return compare_to(b58) <= 0;
            }

            /**
             * operator >=
             */
            bool operator >= (const base58 & b58) const
            {
                return compare_to(b58) >= 0;
            }

            /**
             * operator <
             */
            bool operator < (const base58 & b58) const
            {
                return compare_to(b58) <  0;
            }

            /**
             * operator >
             */
            bool operator > (const base58 & b58) const
            {
                return compare_to(b58) >  0;
            }
        
        private:
                
            /**
             * The version.
             */
            std::uint8_t m_version;

            /**
             * The data.
             */
            std::vector<std::uint8_t> m_data;
    
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_BASE58_HPP
