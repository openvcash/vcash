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

#ifndef DATABASE_CONSTANTS_HPP
#define DATABASE_CONSTANTS_HPP

namespace database {

    namespace constants {
        
        /**
         * The number of storage nodes to be probed for each keyword of a query.
         */
        enum { snodes_per_keyword = 2 };
        
        /**
         * The ip versions.
         */
        enum
        {
            ipv4 = 4,
            ipv6 = 6,
        };
        
        /**
         * The protocols.
         */
        enum
        {
            protocol_udp = 6,
            protocol_tcp = 17,
        };
    
    } // namespace constants
    
} // namespace database

#endif // DATABASE_CONSTANTS_HPP
