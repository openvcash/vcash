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
 
#ifndef COIN_KERNEL_HPP
#define COIN_KERNEL_HPP

#include <cstdint>
#include <map>
#include <memory>

#include <coin/sha256.hpp>

namespace coin {
    
    class block;
    class block_index;
    class point_out;
    class tcp_connection;
    class transaction;
    
    class kernel
    {
        public:

            /**
             * Constructor
             */
            kernel();
        
            /**
             * The singleton accessor.
             */
            static kernel & instance();
        
            /**
             * The modifier interval.
             */
            const std::uint32_t & get_modifier_interval() const;
        
            /**
             * Hard checkpoints of stake modifiers to ensure they are
             * deterministic.
             */
            static std::map<std::uint32_t, std::uint32_t>
                get_stake_modifier_checkpoints()
            ;
        
            /**
             * Compute the hash modifier for proof-of-stake.
             * @param block_position The block position.
             * @param index_previous The previous block index.
             * @param stake_modifier The stake modifier.
             * @param generated_stake_modifier If output is true a stake
             * mofifier was generated.
             */
            bool compute_next_stake_modifier(
                const std::uint32_t & block_position,
                const std::shared_ptr<block_index> & index_previous,
                std::uint64_t & stake_modifier, bool & generated_stake_modifier
            );

            /**
             * Get the stake modifier checksum.
             * @param index The index.
             */
            static std::uint32_t get_stake_modifier_checksum(
                const std::shared_ptr<block_index> & index
            );

            /**
             * Checks the stakemodifier checkspoints.
             * @param height The height.
             * @param checksum The checksum.
             */
            static bool check_stake_modifier_checkpoints(
                const std::uint32_t & height, const std::uint32_t & checksum
            );
        
            /**
             * Check if the coinstake timestamp meets protocol.
             * @param time_block The time_block.
             * @param time_tx The time_tx.
             */
            static bool check_coin_stake_timestamp(
                const std::uint32_t & time_block, const std::uint32_t & time_tx
            );
        
            /**
             * Get the last stake modifier and its generation time from a
             * given block.
             * @param index The block_index.
             * @param stake_modifier The stake modifier.
             * @param modifier_time The modifier time.
             */
            static bool get_last_stake_modifier(
                const std::shared_ptr<block_index> & index,
                std::uint64_t & stake_modifier, std::int64_t & modifier_time
            );

            /**
             * Get selection interval section (in seconds).
             * @param section The section.
             */
            static std::int64_t get_stake_modifier_selection_interval_section(
                const std::int32_t & section
            );
        
            /**
             * Get stake modifier selection interval (in seconds).
             */
            static std::int64_t get_stake_modifier_selection_interval();
        
            /**
             * Selects a block from the candidate blocks whic are sorted by
             * timestamp, excluding the already selected blocks, and with
             * timestamp up to the given interval.
             * @param sorted_by_timestamp The hashes sorted by to timestamp.
             * @param selected_blocks The selected blocks.
             * @param selection_interval_stop The selection interval stop.
             * @param previous_stake_modifier The previous stake modifier.
             * @param index_selected The selected index.
             */
            static bool select_block_from_candidates(
                std::vector<std::pair<std::int64_t, sha256> > & sorted_by_timestamp,
                std::map<sha256, std::shared_ptr<block_index> > & selected_blocks,
                const std::int64_t & selection_interval_stop,
                const std::uint64_t & previous_stake_modifier,
                std::shared_ptr<block_index> & index_selected
            );

            /**
             * Check kernel hash target and coinstake signature.
             * @param connection The tcp_connection if any.
             * @param tx The transaction.
             * @param bit The number of bits.
             * @param hash_pos The hash of the proof-of-stake.
             */
            static bool check_proof_of_stake(
                const std::shared_ptr<tcp_connection> & connection,
                const transaction & tx, const std::uint32_t & bits,
                sha256 & hash_pos
            );
        
            /**
             * The kernel protocol (ppcoin).
             * Coinstake must meet hash target according to the protocol:
             * kernel (input 0) must meet the formula
             * hash(stake_modifier + tx_previous.block.time +
             * tx_previous.offset + tx_previous.time + tx_previous.outs.n +
             * time) <target * coin_day_weight
             * This ensures that the chance of getting a coinstake is
             * proportional to the amount of coin age one owns.
             * The reason this hash is chosen is the following:
             * stake_modifier: (v0.3) Scrambles computation to make it very
             * difficult to precompute future proof-of-stake at the time of
             * the coin's confirmation. (v0.2) bits (deprecated): Encodes all
             * past block timestamps tx_previous.block.time: prevent nodes
             * from guessing a good timestamp to generate transaction for
             * future advantage.
             * tx_previous.offset: The offset of the previous transaction
             * inside block, used to reduce the chance of nodes generating
             * coinstake at the same time.
             * tx_previous.time: Reduce the chance of nodes generating
             * coinstake at the same time
             * tx_previous.outs.n: output number of previous transaction, to
             * reduce the chance of nodes generating coinstake at the same time.
             * The block/tx hash should not be used here as they can be
             * generated in vast quantities so as to generate blocks faster,
             * degrading the system back into a proof-of-work situation.
             * @param bits The bits.
             * @param block_from The block from.
             * @param tx_previous_offset The offset of the previous transaction.
             * @param tx_previous The previous transaction.
             * @param previous_out The previous out.
             * @param time_tx The transaction time.
             * @param hash_pos The hash of the proof-of-stake.
             * @param print_pos If true prints the proof-of-stake.
             */
            static bool check_stake_kernel_hash(
                const std::uint32_t & bits, const block & block_from,
                const std::uint32_t & tx_previous_offset,
                const transaction & tx_previous,
                const point_out & previous_out, const std::uint32_t time_tx,
                sha256 & hash_pos, const bool & print_pos = false
            );
        
            /**
             * The stake modifier used to hash for a stake kernel is chosen as
             * the stake modifier about a selection interval later than the
             * coin generating the kernel.
             * @param hash_block_from The hash of the block from.
             * @param stake_modifier The stake modifier.
             * @param stake_modifier_height The stake modifier height.
             * @param stake_modifier_time The stake modifier time.
             * @param print_pos If true it will print the proof-of-stake.
             */
            static bool get_kernel_stake_modifier(
                const sha256 & hash_block_from, std::uint64_t & stake_modifier,
                std::int32_t & stake_modifier_height,
                std::int64_t & stake_modifier_time, const bool & print_pos
            );
        
        private:
        
            /**
             * The time to elapse before new modifier is computed.
             */
            enum { modifier_interval = 30 * 60 };
        
            /**
             * The modifier interval.
             */
            std::uint32_t m_modifier_interval;

            /**
             * The ratio of group interval length between the last group and
             * the first group.
             */
            enum { modifier_interval_ratio = 3 };
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_KERNEL_HPP
