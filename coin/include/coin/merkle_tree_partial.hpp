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

#ifndef COIN_MERKLE_TREE_PARTIAL_HPP
#define COIN_MERKLE_TREE_PARTIAL_HPP

#include <cstdint>
#include <vector>

#include <coin/sha256.hpp>

namespace coin {

    class data_buffer;
    
    /**
     * Implements a partial merkle tree.
     */
    class merkle_tree_partial
    {
        public:
        
            /**
             * Constructor
             */
            merkle_tree_partial();
        
            /**
             * Constructor
             * @param txids The transaction id's.
             * @param matches The matches.
             */
            merkle_tree_partial(
                const std::vector<sha256> & txids,
                const std::vector<bool> & matches
            );
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * The total number of transaction.
             */
            const std::uint32_t & total_transactions() const;
        
        private:
        
            /**
             * The total number of transaction.
             */
            std::uint32_t m_total_transactions;
        
            /**
             * The hashes.
             */
            std::vector<sha256> m_hashes;
        
            /**
             * The flags.
             */
            std::vector<bool> m_flags;
        
        protected:
        
            friend class block_merkle;
        
            /**
             * Calculates the hash given height, position and txids.
             * @param height The height.
             * @param position The position.
             * @param txids The transaction id's.
             */
            sha256 calculate_hash(
                const std::int32_t & height, const std::uint32_t & position,
                const std::vector<sha256> & txids
            );

            /**
             * Calculates the tree width given height.
             * @param height The height.
             */
            std::uint32_t calculate_tree_width(const std::int32_t & height);
    
            /**
             * Traverse and build the tree.
             * @param height The height.
             * @param position The position.
             * @param txids The transaction id's.
             * @param matches The matches.
             */
            void traverse_and_build(
                const std::int32_t & height, const std::uint32_t & position,
                const std::vector<sha256> & txids,
                const std::vector<bool> & matches
            );
        
            /**
             * Traverses and extracts.
             * height The height.
             * position The position.
             * @param bits_used The bits used.
             * @param matches The matches.
             */
            sha256 traverse_and_extract(
                const std::int32_t & height, const std::uint32_t & position,
                std::uint32_t & bits_used, std::uint32_t & hashes_used,
                std::vector<sha256> & matches
            );
        
            /**
             * Extracts given matches.
             * matches The matches.
             */
            sha256 extract_matches(std::vector<sha256> & matches);
        
            /**
             * Set when invalid data is found.
             */
            bool is_invalid_;
    };
}

#endif // COIN_MERKLE_TREE_PARTIAL_HPP
