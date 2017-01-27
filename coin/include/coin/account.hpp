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

#ifndef COIN_ACCOUNT_HPP
#define COIN_ACCOUNT_HPP

#include <coin/data_buffer.hpp>
#include <coin/key_public.hpp>

namespace coin {

    /**
     * Implements an account.
     */
    class account : public data_buffer
    {
        public:
        
            /**
             * Encodes.
             */
            void encode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void encode(
                data_buffer & buffer, const bool & encode_version = true
            );
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(
                data_buffer & buffer, const bool & decode_version = true
            );
        
            /**
             * The public key.
             */
            key_public & get_key_public();
        
        private:
        
            /**
             * The public key.
             */
            key_public m_key_public;
        
        protected:
        
            // ...
    };
}

#endif // COIN_ACCOUNT_HPP
