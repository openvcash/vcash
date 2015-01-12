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

#ifndef DATABASE_PROTOCOL_HPP
#define DATABASE_PROTOCOL_HPP

#include <cstdint>

#define DATABASE_PROTOCOL_CDN 0

namespace database {

    /**
     * The protocol.
     */
    class protocol
    {
        public:

            /**
             * The constant s.
             * 8 = 273.06s = 4.55m
             * 16 = 546.13s = 9.10m
             * 24 = 819.0s = 13.65m
             * 32 = 1092.26s = 18.20m
             * 40 = 1365.33s = 22.75m
             * 48 = 1638.40s = 27.30m
             * 56 = 1911.46s = 31.85m
             * 64 = 2184.53s = 36.40m
             * 128 = 
             * 256 = 
             * Warning, lower numbers significantly increase overall network
             * traffic.
             */
            enum { s = 512 };
        
            /**
             * If true udp packets will be obfuscated.
             */
            enum { udp_obfuscation_enabled = 1 };
        
            /**
             * The header.
             */
            typedef struct header
            {
                std::uint8_t flags;
                std::uint8_t code;
                std::uint16_t transaction_id;
            } header_t;
            
            /**
             * The message codes.
             */
            typedef enum message_codes
            {
                message_code_none = 0,
                message_code_ack = 2,
                message_code_nack = 4,
                message_code_ping = 8,
                message_code_store = 9,
                message_code_find = 10,
                message_code_firewall = 11,
                message_code_probe = 12,
                message_code_handshake = 13,
                message_code_proxy = 20,
                message_code_error = 0xfe,
            } message_code_t;
            
            /**
             * The message flags.
             * 0x01|1|00000001
             * 0x02|2|00000010
             * 0x04|4|00000100
             * 0x08|8|00001000
             * 0x10|16|00010000
             * 0x20|32|00100000
             * 0x40|64|01000000
             * 0x80|128|10000000
             */
            typedef enum message_flags
            {
                message_flag_0x01 = 0x01,
                message_flag_0x02 = 0x02,
                message_flag_dontroute = 0x04,
                message_flag_compressed = 0x08,
                message_flag_obfuscated = 0x10,
                message_flag_0x20 = 0x20,
                message_flag_0x40 = 0x40,
                message_flag_0x80 = 0x80,
            } message_flag_t;
        
        private:
        
            // ...
            
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_PROTOCOL_HPP
