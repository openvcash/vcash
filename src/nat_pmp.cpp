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

#include <coin/nat_pmp.hpp>

using namespace coin;

std::string nat_pmp::opcode_to_string(const std::uint32_t & opcode)
{
    std::string ret;
    
    switch (opcode)
    {
        case error_code_invalid_args:
        {
            ret = "invalid arguments";
    	}
        break;
        case error_code_socket_error:
        {
           ret = "socket() failed";
    	}
        break;
        case error_code_cannot_get_gateway:
        {
            ret = "cannot get default gateway ip address";
    	}
        break;
        case result_opcode_out_of_resources:
        {
            ret =
                "out of resources(NAT cannot create any more mappings at "
                "this time)"
            ;
        }
    	break;
        case result_opcode_network_failure:
        {
            ret =
                "network failure, NAT may have not obtained a DHCP lease"
            ;
        }
        break;
        default:
        {
            ret = "unknown NAT-PMP error";
        }
        break;
    }
    
    return ret;
}
