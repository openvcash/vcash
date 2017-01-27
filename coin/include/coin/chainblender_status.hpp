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

#ifndef CHAINBLENDER_STATUS_HPP
#define CHAINBLENDER_STATUS_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements a ChainBlender status message (cbstatus).
     */
    class chainblender_status : public data_buffer
    {
        public:
        
            /**
             * The codes.
             */
            typedef enum code_s
            {
                code_none = 0,
                code_accepted = 1,
                code_declined = 2,
                code_ready = 3,
                code_update = 4,
                code_error = 0xfe,
            } code_t;
        
            /**
             * The flags.
             * 0x01|0|00000000
             * 0x01|1|00000001
             * 0x02|2|00000010
             * 0x04|4|00000100
             * 0x08|8|00001000
             * 0x10|16|00010000
             * 0x20|32|00100000
             * 0x40|64|01000000
             * 0x80|128|10000000
             */
            typedef enum flag_s
            {
                flag_0x00 = 0x00,
                flag_0x01 = 0x01,
                flag_0x02 = 0x02,
                flag_0x04 = 0x04,
                flag_0x08 = 0x08,
                flag_0x10 = 0x10,
                flag_0x20 = 0x20,
                flag_0x40 = 0x40,
                flag_0x80 = 0x80,
            } flag_t;
        
            /**
             * Constructor
             */
            chainblender_status();
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            bool decode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Set's null.
             */
            void set_null();
        
            /**
             * Set the session id.
             * @param val The value.
             */
            void set_hash_session_id(const sha256 & val);
        
            /**
             * The session id.
             */
            const sha256 & hash_session_id() const;
        
            /**
             * Set the code.
             * @param val The value.
             */
            void set_code(const std::uint8_t & val);
        
            /**
             * The code.
             */
            const std::uint8_t & code() const;
        
            /**
             * Set the number of participants.
             * @param val The value.
             */
            void set_participants(const std::uint8_t & val);
        
            /**
             * The number of participants.
             */
            const std::uint8_t & participants() const;
        
            /**
             * Set the flags.
             * @param val The value.
             */
            void set_flags(const std::uint16_t & val);
        
            /**
             * The flags.
             */
            const std::uint16_t & flags() const;
        
        private:
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * The version.
             */
            std::uint32_t m_version;
        
            /**
             * The session id.
             */
            sha256 m_hash_session_id;
        
            /**
             * The code.
             */
            std::uint8_t m_code;
        
            /**
             * The number of participants.
             */
            std::uint8_t m_participants;
        
            /**
             * The flags.
             */
            std::uint16_t m_flags;
    
        protected:
        
            // ...
    };
}

#endif // CHAINBLENDER_STATUS_HPP