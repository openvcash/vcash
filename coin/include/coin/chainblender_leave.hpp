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

#ifndef CHAINBLENDER_LEAVE_HPP
#define CHAINBLENDER_LEAVE_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements a ChainBlender leave message (cbleave).
     */
    class chainblender_leave : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            chainblender_leave();
        
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
        
        protected:
        
            // ...
    };
}

#endif // CHAINBLENDER_LEAVE_HPP
