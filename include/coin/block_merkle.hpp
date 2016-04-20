/*
 * Copyright (c) 2013-2016 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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
             * @param blk The block.
             * @param filter The transaction_bloom_filter.
             */
            block_merkle(
                const block & blk, transaction_bloom_filter & filter
            );

            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * The matched transactions.
             */
            const std::vector<
                std::pair<std::uint32_t, sha256> > &
                transactions_matched() const
            ;
        
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
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_BLOCK_MERKLE_HPP
