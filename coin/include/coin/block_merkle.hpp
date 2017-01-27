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

#ifndef COIN_BLOCK_MERKLE_HPP
#define COIN_BLOCK_MERKLE_HPP

#include <cstdint>
#include <vector>

#include <coin/block.hpp>
#include <coin/transaction_bloom_filter.hpp>
#include <coin/data_buffer.hpp>
#include <coin/merkle_tree_partial.hpp>
#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements a BIP-0037 Merkle Block (filtered block).
     */
    class block_merkle
    {
        public:
        
            /**
             * Constructor
             */
            block_merkle();
        
            /**
             * Constructor
             * @param height The height.
             * @param hash_block The hash of the block header.
             */
            block_merkle(
                const std::uint32_t & height, const sha256 & hash_block
            );
        
            /**
             * Constructor
             * @param blk The block.
             */
            block_merkle(const block & blk);
        
            /**
             * Constructor
             * @param blk The block.
             * @param filter The transaction_bloom_filter.
             */
            block_merkle(
                const block & blk, transaction_bloom_filter & filter
            );

            /**
             * Encodes
             * @param buffer The data_buffer.
             * @param to_disk If true we are encoding to disk.
             */
            void encode(
                data_buffer & buffer, const bool & to_disk = false
            );
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             * @param for_disk If true we are decoding from disk.
             */
            bool decode(
                data_buffer & buffer, const bool & from_disk = false
            );
        
            /**
             * Checks the validity for an SPV client.
             */
            bool is_valid_spv();
        
            /**
             * The matched transactions.
             */
            const std::vector<std::pair<std::uint32_t, sha256> > &
                transactions_matched() const
            ;
        
            /**
             * The block header.
             */
            const block::header_t & block_header() const;
        
            /**
             * The hash of the block header.
             */
            const sha256 & get_hash() const;
        
            /**
             * The partial merkle tree.
             */
            const merkle_tree_partial & get_merkle_tree_partial() const;
        
            /**
             * Sets the height.
             * @param val The height.
             */
            void set_height(const std::int32_t & val);
        
            /**
             * The height.
             */
            const std::int32_t & height() const;
        
        private:
        
            /**
             * Intitializes the merkle block.
             * @param blk The block.
             * @param filter The transaction_bloom_filter.
             */
            void initialize(
                const block & blk, transaction_bloom_filter & filter
            );
        
            /**
             * The matched transactions.
             */
            std::vector<
                std::pair<std::uint32_t, sha256> > m_transactions_matched
            ;
        
            /**
             * The block header.
             */
            block::header_t m_block_header;
        
            /**
             * The partial merkle tree.
             */
            merkle_tree_partial m_merkle_tree_partial;
        
            /**
             * The hash of the block header.
             */
            sha256 m_hash;
        
            /**
             * The height.
             */
            std::int32_t m_height;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_BLOCK_MERKLE_HPP
