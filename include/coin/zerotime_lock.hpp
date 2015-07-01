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


#ifndef COIN_ZEROTIME_LOCK_HPP
#define COIN_ZEROTIME_LOCK_HPP

#include <cstdint>
#include <ctime>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements a ZeroTime lock.
     */
    class zerotime_lock : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            zerotime_lock();
        
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
        
        private:

            /**
             * The transaction hash.
             */
            sha256 m_hash_tx;
        
            /**
             *  The expiration.
             */
            std::time_t m_expiration;
        
            /**
             * The signature.
             */
            std::vector<std::uint8_t> m_signature;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_ZEROTIME_LOCK_HPP
