/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#ifndef DATABASE_RC4_HPP
#define DATABASE_RC4_HPP

#include <cstdint>
#include <string>

namespace database {
    
    /**
     * Implements the rc4 algorithm.
     */
    class rc4
    {
        public:
        
            typedef struct
            {
                std::int32_t x, y;
                std::uint8_t buf[256];
            } state_t;
        
            /**
             * Constructor
             */
            explicit rc4();
            
            /**
             * Destructor
             */
            ~rc4();

            /**
             * Sets the key.
             */
            void set_key(const std::string &);
            
            /**
             * Performs a crypt operation.
             * @param buf
             * @param len
             */
            void crypt(char *, const std::size_t &);
            
            /**
             * Runs the test case.
             */
            static int run_test();
            
        private:
        
            // ...
            
        protected:
        
            /**
             * The state.
             */
            state_t state_;
        
            /**
             * The key.
             */
            std::string key_;
       };
    
} // namespace database

#endif // DATABASE_RC4_HPP
