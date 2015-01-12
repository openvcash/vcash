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

#ifndef DATABASE_NAT_PMP
#define DATABASE_NAT_PMP

#include <cstdint>

#include <boost/asio.hpp>

namespace database {
	
    /**
     * Implements the NAT-PMP base protocol.
     */
    class nat_pmp
    {
        public:
        
            /**
             * NAT-PMP port.
             */
            enum
            {
                port = 5351
            };
        
            /**
             * Supported protocols.
             */
            typedef enum
            {
                protocol_udp = 1,
                protocol_tcp = 2
            } protocol_t;
            
            /**
             * Result opcodes.
             * 0 - Success
             * 1 - Unsupported Version
             * 2 - Not Authorized/Refused (e.g. box supports mapping, but user 
             * has turned feature off)
             * 3 - Network Failure (e.g. NAT box itself has not obtained a 
             * DHCP lease)
             * 4 - Out of resources
               (NAT box cannot create any more mappings at this time)
             * 5 - Unsupported opcode
             */
            enum result_opcodes
            {
                result_success = 0,
                result_unsupported_version = 1,
                result_not_authorized_refused = 2,
                result_network_failure = 3,
                result_out_of_resources = 4,
                result_unsupported_opcode = 5,
                result_undefined = 64,
            };
            
            /**
             * Error codes.
             */
            enum error_codes
            {
                error_invalid_args = 1,
                error_socket_error = 2,
                error_connect = 3,
                error_send = 4,
                error_receive_from = 5,
                error_source_conflict = 6,
                error_cannot_get_gateway = 7,
            };
            
            /**
             * Mapping request structure.
             */
            struct mapping_request
            {
                bool operator == (const mapping_request & other) const
                {
                    return std::memcmp(
                        buffer, other.buffer, sizeof(buffer)
                    ) == 0;
                }
                
                std::size_t length;
                char buffer[12];
                std::uint8_t retry_count;
            };
        
            /**
             * External ip address request structure.
             */
            struct external_address_request
            {
                std::uint16_t opcode;
            };
        
            /**
             * Mapping response structure.
             */
            struct mapping_response
            {
                bool operator == (const mapping_response & other) const
                {
                    return (
                        private_port == other.private_port &&
                        public_port == other.public_port
                    );
                }
                
                std::uint16_t type;
                std::uint16_t result_code;
                std::uint32_t epoch;
                boost::asio::ip::address public_address;
                std::uint16_t private_port;
                std::uint16_t public_port;
                std::uint32_t lifetime;
        	};
        	
        	/**
        	 * Generates a string representation from an opcode
        	 * @param opcode
        	 */
            static const char * string_from_opcode(const unsigned int &);
        	
        private:
        
            // ...
                
        protected:
        
            // ... 
    };
    
} // namespace database

#endif // DATABASE_NAT_PMP
