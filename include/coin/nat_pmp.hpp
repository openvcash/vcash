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

#ifndef COIN_NAT_PMP_HPP
#define COIN_NAT_PMP_HPP

#include <cstdint>
#include <string>

#include <boost/asio.hpp>

namespace coin {

    /**
     * Implements rfc6886.
     */
    class nat_pmp
    {
        public:
        
            /**
             * Supported protocols.
             */
            typedef enum
            {
                protocol_udp = 1,
                protocol_tcp = 2
            } protocol_t;
        
            /**
             * The port.
             */
            enum { port = 5351 };
        
            /**
             * The result opcodes.
             */
            typedef enum
            {
                result_opcode_success = 0,
                result_opcode_unsupported_version = 1,
                result_opcode_not_authorized_refused = 2,
                result_opcode_network_failure = 3,
                result_opcode_out_of_resources = 4,
                result_opcode_unsupported_opcode = 5,
                result_opcode_undefined = 64,
            } result_opcode_t;
            
            /**
             * The error codes.
             */
            typedef enum
            {
                error_code_invalid_args = 1,
                error_code_socket_error = 2,
                error_code_connect = 3,
                error_code_send = 4,
                error_code_receive_from = 5,
                error_code_source_conflict = 6,
                error_code_cannot_get_gateway = 7,
            } error_code_t;
            
            /**
             * The mapping request.
             */
            typedef struct mapping_request_s
            {
                bool operator == (const mapping_request_s & other) const
                {
                    return std::memcmp(
                        buffer, other.buffer, sizeof(buffer)
                    ) == 0;
                }
                
                std::size_t length;
                std::int8_t buffer[12];
                std::uint8_t retry_count;
            } mapping_request_t;
        
            /**
             * The external address request.
             */
            typedef struct
            {
                std::uint16_t opcode;
            } external_address_request_t;
        
            /**
             * The mapping response
             */
            typedef struct mapping_response_s
            {
                bool operator == (const mapping_response_s & other) const
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
        	} mapping_response_t;

        	/**
        	 * Converts an opcode to a string.
        	 * @param opcode
        	 */
            static std::string opcode_to_string(const std::uint32_t &);

        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_NAT_PMP_HPP
