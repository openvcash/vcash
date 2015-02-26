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

#ifndef COIN_KEY_POOL_HPP
#define COIN_KEY_POOL_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/key_public.hpp>

namespace coin {

    /**
     * Implements a key pool.
     */
    class key_pool : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            key_pool();
        
            /**
             * Constructor
             * @param key_pub The key_public.
             */
            key_pool(const key_public & key_pub);
    
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             * @param include_version If true the version will be included.
             */
            void encode(
                data_buffer & buffer, const bool & include_version = true
            );
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             * @param include_version If true the version will be included.
             */
            void decode(
                data_buffer & buffer, const bool & include_version = true
            );
        
            /**
             * The time.
             */
            const std::int64_t & time() const;
        
            /**
             * Sets the key_public.
             * @param value The key_public.
             */
            void set_key_public(const key_public & value);
        
            /**
             * The public key.
             */
            const key_public & get_key_public() const;
        
        private:
        
            /**
             * The time.
             */
            std::int64_t m_time;
        
            /**
             * The public key.
             */
            key_public m_key_public;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_KEY_POOL_HPP
