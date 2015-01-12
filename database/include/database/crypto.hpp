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

#ifndef database_crypto_hpp
#define database_crypto_hpp

#include <cstdint>
#include <sstream>
#include <string>

#include <boost/uuid/sha1.hpp>

namespace database {

    struct crypto
    {        
        /**
         * The content types.
         */
        typedef enum
        {
            content_type_change_cipher_spec = 20,
            content_type_alert = 21,
            content_type_handshake = 22,
            content_type_application_data = 23,
        } content_type_t;
        
        /**
         * The message types.
         */
        typedef enum
        {
            msg_type_hello_request = 0,
            msg_type_client_hello = 1,
            msg_type_server_hello = 2,
            msg_type_hello_verify_request = 3,
            msg_type_certificate = 11,
            msg_type_server_key_exchange = 12,
            msg_type_certificate_request = 13,
            msg_type_server_hello_done = 14,
            msg_type_certificate_verify = 15,
            msg_type_client_key_exchange = 16,
            msg_type_finished = 20,
        } msg_type_t;
        
        /**
         * The version major.
         */
        enum { version_major = 1 };
        
        /**
         * The version minor.
         */
        enum { version_minor = 2 };
        
        /**
         * The DTLS header.
         */
        typedef struct
        {
            std::uint8_t content_type;
            std::uint8_t version_major;
            std::uint8_t version_minor;
            std::uint16_t epoch;
            std::uint8_t sequence_number[6];
            std::uint16_t length;
            /* fragment */
        } dtls_header_t;
        
        /**
         * The header length.
         */
        enum { dtls_header_length = 13 };
        
        /**
         * Generates an obfuscation key from a seed.
         * @param seed The seed.
         */
        static std::string generate_obfuscation_key(const std::string & seed)
        {
            boost::uuids::detail::sha1 ctx;

            ctx.process_bytes(
                const_cast<char *> (seed.data()), seed.size()
            );
            
            std::uint32_t digest[5];

            ctx.get_digest(digest);

            std::stringstream ss;
            
            ss <<
                std::hex << digest[0] << std::hex << digest[1] <<
                std::hex << digest[2] << std::hex << digest[3] <<
                std::hex << digest[4]
            ;

            return ss.str().substr(0, 32);
        }
    };
    
} // namespace database

#endif // database_crypto_hpp
