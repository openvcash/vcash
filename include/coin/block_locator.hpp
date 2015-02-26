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

#ifndef COIN_BLOCK_LOCATOR_HPP
#define COIN_BLOCK_LOCATOR_HPP

#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class block_index;
    
    /**
     * Implements a block locator, a place in the block chain to another node
     * such that if the other node doesn't have the same branch, it can find a
     * recent common trunk. The further back it is, the further before the
     * fork it may be.
     */
    class block_locator : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            block_locator();

            /**
             * Constructor
             * @param index The block_index.
             */
            explicit block_locator(std::shared_ptr<block_index> index);
        
            /**
             * Constructor
             * @param hash_block The sha256 hash of the block.
             */
            explicit block_locator(sha256 hash_block);
        
            /**
             * Constructor
             * @param have The block hashes.
             */
            block_locator(const std::vector<sha256> & have);
        
            /**
             * Encodes
             * @param encode_version If true the version is encoded.
             */
            void encode(const bool & encode_version = true);
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             * @param encode_version If true the version is encoded.
             */
            void encode(
                data_buffer & buffer, const bool & encode_version = true
            );
        
            /**
             * Decodes
             * @param decode_version If true the version is decoded.
             */
            void decode(const bool & decode_version = true);
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             * @param decode_version If true the version is decoded.
             */
            void decode(
                data_buffer & buffer, const bool & decode_version = true
            );
        
            /**
             * The have.
             */
            const std::vector<sha256> & have() const;
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null();

            /**
             * Sets
             * @param index The block_index.
             */
            void set(const std::shared_ptr<block_index> & index);

            /**
             * Gets the distance back.
             */
            int get_distance_back();

            /**
             *  The block index.
             */
            std::shared_ptr<block_index> get_block_index();

            /**
             * The block hash.
             */
            sha256 get_block_hash();

            /**
             * The height.
             */
            int get_height();
    
        private:
        
            /**
             * The have.
             */
            std::vector<sha256> m_have;
            
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_BLOCK_LOCATOR_HPP
