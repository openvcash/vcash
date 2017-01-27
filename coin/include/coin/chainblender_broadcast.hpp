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

#ifndef CHAINBLENDER_BROADCAST_HPP
#define CHAINBLENDER_BROADCAST_HPP

#include <cstdint>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements a ChainBlender broadcast message (cbbroadcast).
     */
    class chainblender_broadcast : public data_buffer
    {
        public:
        
            typedef enum type_s
            {
                type_none = 0,
                type_ecdhe = 1,
                type_ecdhe_ack = 2,
                type_tx = 3,
                type_tx_ack = 4,
                type_sig = 5,
                type_sig_ack = 6,
            } type_t;
        
            /**
             * Constructor
             */
            chainblender_broadcast();
        
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
             * Set's the session id.
             * @param val The value.
             */
            void set_session_id(const sha256 & val);
        
            /**
             * The session id.
             */
            const sha256 & hash_session_id() const;
        
            /**
             * Sets the type.
             * @param val The value.
             */
            void set_type(const std::uint16_t & val);
        
            /**
             * The type.
             */
            const std::uint16_t & type() const;
        
            /**
             * Sets the length.
             * @param val The value.
             */
            void set_length(const std::uint16_t & val);
        
            /**
             * The length.
             */
            const std::uint16_t & length() const;
        
            /**
             * Sets the value.
             * @param val The value.
             */
            void set_value(const std::vector<std::uint8_t> & val);
        
            /**
             * The value.
             */
            const std::vector<std::uint8_t> & value() const;
        
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
             * The type.
             */
            std::uint16_t m_type;
        
            /**
             * The length.
             */
            std::uint16_t m_length;
        
            /**
             * The value.
             */
            std::vector<std::uint8_t> m_value;
        
        protected:
        
            // ...
    };
}

#endif // CHAINBLENDER_BROADCAST_HPP
