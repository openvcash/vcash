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

#ifndef COIN_MINING_HPP
#define COIN_MINING_HPP

#include <cstdint>

#include <openssl/sha.h>

#include <coin/block.hpp>
#include <coin/mining.hpp>

namespace coin {

    class block;
    class key_reserved;
    class wallet;
    
    /**
     * Implements mining utility functions.
     */
    class mining
    {
        public:
        
            /**
             * Formats hash blocks.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::int32_t format_hash_blocks(
                void * buf, const std::uint32_t & len
            );

            /**
             * sha256_transform
             * @param ptr_state The ptr_state.
             * @param ptr_input The ptr_input.
             * @param ptr_init The ptr_init.
             */
            static void sha256_transform(
                void * ptr_state, void * ptr_input, const void * ptr_init
            );
        
            /**
             *
             * @param blk The block.
             * @param ptr_midstate The ptr_midstate.
             * @param data The data.
             * @param ptr_hash1 The ptr_hash1.
             */
            static void format_hash_buffers(
                const std::shared_ptr<block> & blk, char * ptr_midstate,
                char * data, char * ptr_hash1
            );

            /**
             * Increments a nonce in the block header and hashes it and then
             * scans it for at least some zero bits.
             * @param in_header The block::header_t in.
             * @param max_nonce The maximum nonce.
             * @param out_hashes The number of hashes out.
             * @param out_digest The digest out.
             * @param out_header The block::header_t out.
             */
            static std::uint32_t scan_hash_whirlpool(
                block::header_t * in_header, std::uint32_t max_nonce,
                std::uint32_t & out_hashes, std::uint8_t * out_digest,
                block::header_t * out_header
            );

        private:
        
            // ...
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_MINING_HPP
