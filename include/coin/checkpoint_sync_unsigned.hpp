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

#ifndef COIN_CHECKPOINT_SYNC_UNSIGNED_HPP
#define COIN_CHECKPOINT_SYNC_UNSIGNED_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements a synchronized checkpoint.
     */
    class checkpoint_sync_unsigned : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            checkpoint_sync_unsigned();
        
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
             * Get's the hash.
             */
            sha256 get_hash();
        
            /**
             * The version.
             */
            const std::uint32_t & version() const;
        
            /**
             * Sets the hash checkpoint.
             * @param val The hash of the checkpoint.
             */
            void set_hash_checkpoint(const sha256 & val);
        
            /**
             * The hash of the checkpoint.
             */
            const sha256 & hash_checkpoint() const;
        
            /**
             * The string representation.
             */
            std::string to_string() const;
        
        private:
        
            friend class checkpoint_sync;
        
            /**
             * The version.
             */
            std::uint32_t m_version;
        
            /**
             * The hash of the checkpoint.
             */
            sha256 m_hash_checkpoint;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_CHECKPOINT_SYNC_UNSIGNED_HPP
