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

#ifndef COIN_KEY_WALLET_HPP
#define COIN_KEY_WALLET_HPP

#include <cstdint>
#include <string>

#include <coin/data_buffer.hpp>
#include <coin/key.hpp>

namespace coin {
    
    /**
     * Implements a wallet (private) key.
     */
    class key_wallet : public data_buffer
    {
        public:

            /**
             * Constructor
             */
            key_wallet(const std::int64_t & expires = 0);
        
            /**
             * Encodes.
             */
            void encode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);
        
            /**
             * The private key.
             */
            const key::private_t & key_private() const;
        
        private:
        
            /**
             * The private key.
             */
            key::private_t m_key_private;
        
            /**
             * The time created.
             */
            std::int64_t m_time_created;
        
            /**
             * The time expires.
             */
            std::int64_t m_time_expires;
        
            /**
             * The comment.
             */
            std::string m_comment;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_KEY_WALLET_HPP
