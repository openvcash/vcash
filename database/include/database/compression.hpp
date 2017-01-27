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

#ifndef DATABASE_COMPRESSION_HPP
#define DATABASE_COMPRESSION_HPP

#include <string>

namespace database {

    /**
     * Implements a non-ZLIB compatible compression algorithm.
     */
    class compression
    {
        public:
        
            /**
             * Compresses
             * in The input.
             */
            static std::string compress(const std::string & in);
        
            /**
             * Decompresses
             * in The input.
             */
            static std::string decompress(const std::string & in);
        
            /**
             * Runs test case.
             */
            static int run_test();
        
        private:
        
            // ...
            
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_COMPRESSION_HPP
