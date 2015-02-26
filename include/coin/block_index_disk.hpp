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

#ifndef coin_block_index_disk_hpp
#define coin_block_index_disk_hpp

#include <coin/block_index.hpp>
#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {

        class block_index_disk
            : public block_index , public data_buffer
        {
            public:
            
                /**
                 * Constructor
                 * @param buf The buffer.
                 * @param len The length.
                 */
                block_index_disk(const char * buf, const std::size_t & len);
            
                /**
                 * Constructor
                 * @param index The block_index.
                 */
                block_index_disk(block_index & index);
            
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
                 * Sets the previous hash.
                 * @param valhe The sha256.
                 */
                void set_hash_previous(const sha256 & value);
            
                /**
                 * The previous hash.
                 */
                const sha256 & hash_previous() const;
            
                /**
                 * Sets the next hash.
                 * @param valhe The sha256.
                 */
                void set_hash_next(const sha256 & value);
            
                /**
                 * The next hash.
                 */
                const sha256 & hash_next() const;
            
                /**
                 * Gets hte block hash.
                 */
                sha256 get_block_hash() const;
            
            private:
            
                friend class db_tx;
                
                /**
                 * The previous hash.
                 */
                sha256 m_hash_previous;
            
                /**
                 * The next hash.
                 */
                sha256 m_hash_next;
            
            protected:
            
                // ...
        };

} // namespace coin

#endif // coin_block_index_disk_hpp
