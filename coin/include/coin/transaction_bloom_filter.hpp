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


#ifndef TRANSACTION_BLOOM_FILTER_HPP
#define TRANSACTION_BLOOM_FILTER_HPP

#include <cstdint>
#include <vector>

#include <coin/point_out.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class data_buffer;
    class transaction;
    
    /**
     * Implements bip-0037 (TCP connection bloom filtering).
     */
    class transaction_bloom_filter
    {
        public:
        
            /**
             * The flags.
             */
            typedef enum flags_s
            {
                update_none,
                update_all,
                update_p2pubkey_only,
                update_mask,
            } flags_t;
        
            /**
             * The maximum bloom filter size in bytes.
             */
            enum { max_bloom_filter_size = 36000 };
        
            /** 
             * The maximum hash funcs.
             */
            enum { max_hash_funcs = 50 };

            /**
             * Constructor
             */
            transaction_bloom_filter();
        
            /**
             * Constructor
             * @param elements The number of elements.
             * @param fprate The (false positive) fprate.
             * @param tweak The tweak.
             * @param Flags The flags.
             */
            transaction_bloom_filter(
                const std::uint32_t & elements, const double & fprate,
                const std::uint32_t & tweak, const std::uint8_t & flags
            );
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const;
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Performs murmur3 hash over the data given hashes.
             * @param hashes The number of hashes.
             * @param data The data.
             */
            std::uint32_t hash(
                const std::uint32_t & hashes,
                const std::vector<std::uint8_t> & data
            ) const;
    
            /**
             * Inserts into the filter.
             * @param pub_key The public key bytes.
             */
            void insert(const std::vector<std::uint8_t> & pub_key);
        
            /**
             * Inserts into the filter.
             * @param out_point The point_out.
             */
            void insert(const point_out & out_point);
        
            /**
             * Inserts into the filter.
             * @param h The sha256.
             */
            void insert(const sha256 & h);

            /**
             * If true the filter contains the pub_key.
             * @param pub_key The public key bytes.
             */
            bool contains(const std::vector<std::uint8_t> & pub_key) const;
        
            /**
             * If true the filter contains the point_out.
             * @param point_out The point_out.
             */
            bool contains(const point_out & point_out) const;
        
            /**
             * If true the filter contains the sha256 hash.
             * @param h The sha256.
             */
            bool contains(const sha256 & h) const;

            /**
             * Clears the filter.
             */
            void clear();

            /**
             * If true the size is < max_bloom_filter_size.
             */
            bool is_within_size_constraints() const;
    
            /**
             * Returns true if it is relevant and updates.
             * @param tx The transaction.
             */
            bool is_relevant_and_update(const transaction & tx);
        
            /**
             * Updates empty and full filters.
             */
            void update_empty_full();
        
            /**
             * Runs test case.
             */
            static int run_test();
        
        private:
        
            /**
             * The data.
             */
            std::vector<std::uint8_t> m_data;
        
            /**
             * If true it is full.
             */
            bool m_is_full;
        
            /**
             * If true it is empty.
             */
            bool m_is_empty;
        
            /**
             * The number of hash funcs.
             */
            std::uint32_t m_hash_funcs;
        
            /**
             * The tweak.
             */
            std::uint32_t m_tweak;
        
            /**
             * The flags.
             */
            std::uint8_t m_flags;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // TRANSACTION_BLOOM_FILTER_HPP
