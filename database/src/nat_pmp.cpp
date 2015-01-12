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

#include <database/nat_pmp.hpp>

using namespace database;

const char * nat_pmp::string_from_opcode(const unsigned int & opcode)
{
    const char * str;
    
    switch (opcode)
    {
        case error_invalid_args:
            str = "invalid arguments";
    	break;
        case error_socket_error:
            str = "socket() failed";
    	break;
        case error_cannot_get_gateway:
            str = "cannot get default gateway ip address";
    	break;
        case result_out_of_resources:
            str = 
                "Out of resources(NAT box cannot create any more mappings at "
                "this time)."
            ;
    	break;
        case result_network_failure:
            str = 
                "Network Failure, nat box may have not obtained a DHCP lease."
            ;
        break;
        default:
            str = "Unknown NAT-PMP error";
    }
    
    return str;
}
