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

#ifndef DATABASE_CRYPTO_MESSAGE_HPP
#define DATABASE_CRYPTO_MESSAGE_HPP

#include <cstdint>

#include <database/byte_buffer.hpp>

namespace database {

    /**
     * Implements a reliable udp message.
     */
    class crypto_message
    {
        public:
        
            /**
             * The codes.
             */
            enum codes
            {
                code_none = 0,
                code_ack = 2,
                code_nack = 4,
                code_cipher = 20,
                code_alert = 21,
                code_handshake = 22,
                code_data = 23,
                code_error = 0xfe,
            } code_t;
        
            /**
             * The header.
             */
            typedef struct header
            {
                std::uint8_t flags;
                std::uint8_t code;
                std::uint16_t transaction_id;
                std::uint16_t padding;
                std::uint16_t length;
            } header_t;
            
            /**
             * Constructor
             */
            crypto_message();
            
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            crypto_message(const char *, const std::size_t &);
            
            /**
             * Encodes the message.
             */
            void encode();
            
            /**
             * Decodes the message.
             */
            void decode();
            
            /**
             * The header.
             */
            header_t & header();
            
            /**
             * Sets the message body.
             */
            void set_body(const char *, const std::size_t &);
            
            /**
             * The body.
             */
            byte_buffer & body();
            
            /**
             * The data.
             */
            const char * data() const;
            
            /**
             * The size.
             */
            const std::size_t & size() const;
        
        private:
        
            /**
             * The header.
             */
            header_t m_header;
            
            /**
             * The body.
             */
            byte_buffer m_body;
            
        protected:
        
            /**
             * The byte_buffer.
             */
            byte_buffer byte_buffer_;
    };
    
} // namesapce database

#endif // DATABASE_CRYPTO_MESSAGE_HPP
