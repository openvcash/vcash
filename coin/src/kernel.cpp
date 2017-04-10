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

#include <cassert>

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/constants.hpp>
#include <coin/data_buffer.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/kernel.hpp>
#include <coin/logger.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/time.hpp>

using namespace coin;

std::map<std::uint32_t, std::uint32_t> kernel::get_stake_modifier_checkpoints()
{
    return
    {
        {0, 234907403}, {8300, 3018973908}, {14800, 1009362736},
        {17200, 4136115215}, {22927, 484495706}, {25037, 900726625},
        {39000, 609821848}, {42645, 2936275370}, {44709, 2109139941},
        {50300, 1665296579}, {73568, 2497364874}, {100000, 2865615596},
        {113965, 1724769535}, {127440, 3104372474}, {193110, 1390052349},
        {250000, 1624198793}, {300000, 602008884}, {350000, 1784787616},
        {400000, 1333280594}, {450000, 725649406}, {500000, 3458528019},
        {550000, 3282845064}, {590000, 133848742}, {635000, 996299842},
        {635900, 3660419094}, {645000, 139215092}
    };
}

kernel::kernel()
    : m_modifier_interval(modifier_interval)
{
    // ...
}

kernel & kernel::instance()
{
    static kernel g_kernel;
            
    return g_kernel;
}

const std::uint32_t & kernel::get_modifier_interval() const
{
    return m_modifier_interval;
}

std::uint32_t kernel::get_stake_modifier_checksum(const block_index * index)
{
    assert(
        index->block_index_previous() ||
        (constants::test_net ?
        index->get_block_hash() == block::get_hash_genesis_test_net() :
        index->get_block_hash() == block::get_hash_genesis())
    );
    
    data_buffer buffer;
    
    if (index->block_index_previous())
    {
        buffer.write_uint32(
            index->block_index_previous()->stake_modifier_checksum()
        );
    }
    
    buffer.write_uint32(index->flags());
    
    buffer.write_sha256(index->hash_proof_of_stake());
    
    buffer.write_uint64(index->stake_modifier());

    sha256 h = sha256::from_digest(
        &hash::sha256d(reinterpret_cast<std::uint8_t *>(buffer.data()),
        reinterpret_cast<std::uint8_t *>(buffer.data() + buffer.size()))[0]
    );
    
    h >>= (256 - 32);

    return static_cast<std::uint32_t> (h.to_uint64());
}

bool kernel::compute_next_stake_modifier(
    const std::uint32_t & block_position,
    const block_index * index_previous,
    std::uint64_t & stake_modifier, bool & generated_stake_modifier
    )
{
    stake_modifier = 0;
    generated_stake_modifier = false;
    
    /**
     * The genesis block's modifier is 0.
     */
    if (index_previous == 0)
    {
        generated_stake_modifier = true;
        
        return true;
    }
    
    /**
     * First find current stake modifier and its generation block time
     * if it's not old enough, return the same stake modifier.
     */
    std::int64_t modifier_time = 0;
    
    if (
        get_last_stake_modifier(index_previous, stake_modifier,
        modifier_time) == false
        )
    {
        log_error(
            "Kernel, compute next stake modifier failed, unable to get last "
            "modifier."
        );
        
        return false;
    }
    
    if (globals::instance().debug())
    {
        log_none(
            "Kernel, previous stake modifier = " << stake_modifier <<
            ", time = " << modifier_time << "."
        );
    }
    
    if (
        modifier_time / m_modifier_interval >=
        index_previous->time() / m_modifier_interval
        )
    {
        return true;
    }
    
    /**
     * Sort candidate blocks by timestamp.
     */
    std::vector< std::pair<std::int64_t, sha256> > sorted_by_timestamp;

    sorted_by_timestamp.reserve(
        64 * m_modifier_interval / utility::get_target_spacing(index_previous)
    );
    
    auto selection_interval = get_stake_modifier_selection_interval();
    
    auto selection_interval_start =
        (index_previous->time() / m_modifier_interval) *
        m_modifier_interval - selection_interval
    ;
    
    auto * index_tmp = index_previous;
    
    while (index_tmp && index_tmp->time() >= selection_interval_start)
    {
        sorted_by_timestamp.push_back(
            std::make_pair(index_tmp->time(), index_tmp->get_block_hash())
        );
        
        index_tmp = index_tmp->block_index_previous();
    }
    
    auto height_first_candidate = index_tmp ? (index_tmp->height() + 1) : 0;
    
    /**
     * Sort by timestamp.
     */
    std::reverse(sorted_by_timestamp.begin(), sorted_by_timestamp.end());
    std::sort(sorted_by_timestamp.begin(), sorted_by_timestamp.end());
    
    /**
     * Select 64 blocks from candidate blocks to generate stake modifier.
     */
    std::uint64_t stake_modifier_new = 0;
    
    std::int64_t selection_interval_stop = selection_interval_start;
    
    std::map<sha256, block_index *> selected_blocks;
    
    for (
        auto i = 0; i <
        std::min(64, static_cast<std::int32_t> (sorted_by_timestamp.size()));
        i++
        )
    {
        /**
         * Add an interval section to the current selection round.
         */
        selection_interval_stop +=
            get_stake_modifier_selection_interval_section(i)
        ;
        
        /**
         * Select a block from the candidates of current round.
         */
        if (
            select_block_from_candidates(sorted_by_timestamp,
            selected_blocks, selection_interval_stop, stake_modifier,
            &index_tmp) == false
            )
        {
            log_error(
                "Kernel, failed to compute next stake modifier, unable to "
                "select block at round " << i << "."
            );
            
            return false;
        }
        
        /**
         * Write the entropy bit of the selected block.
         */
        stake_modifier_new |= ((static_cast<std::uint64_t> (
            index_tmp->get_stake_entropy_bit()) << i)
        );
        
        /**
         * Add the selected block from candidates to selected list.
         */
        selected_blocks.insert(
            std::make_pair(index_tmp->get_block_hash(),
            const_cast<block_index *> (index_tmp))
        );
        
        /**
         * -printstakemodifier
         */
        if (globals::instance().debug())
        {
            log_none(
                "Kernel, selected round " << i << ", stop = " <<
                selection_interval_stop << ", height = " << index_tmp->height() <<
                ", bit = " << index_tmp->get_stake_entropy_bit() << "."
            );
        }
    }
    
    /**
     * Print selection map for visualization of the selected blocks.
     * -printstakemodifier
     */
    if (globals::instance().debug())
    {
        std::string selection_map = "";
        
        /**
         * '-' indicates Proof-of-Work blocks not selected.
         */
        selection_map.insert(
            0, index_previous->height() - height_first_candidate + 1, '-'
        );
        
        index_tmp = index_previous;
        
        while (index_tmp && index_tmp->height() >= height_first_candidate)
        {
            /**
             * '=' indicates Proof-of-Stake blocks not selected.
             */
            if (index_tmp->is_proof_of_stake())
            {
                selection_map.replace(
                    index_tmp->height() - height_first_candidate, 1, "="
                );
            }
            
            index_tmp = index_tmp->block_index_previous();
        }
        
        for (auto & i : selected_blocks)
        {
            /**
             * 'S' indicates selected Proof-of-Stake blocks.
             * 'W' indicates selected Proof-of-Work blocks.
             */
            selection_map.replace(
                i.second->height() - height_first_candidate, 1,
                i.second->is_proof_of_stake()? "S" : "W"
            );
        }
        
        log_none(
            "Kernel, compute next stake modifier, selection height [" <<
            height_first_candidate << ", " << index_previous->height() <<
            "] map " << selection_map << "."
        );
    }
    
    if (globals::instance().debug())
    {
        log_none(
            "Kernel, new modifier = " << stake_modifier_new << ", time = " <<
            index_previous->time() << "."
        );
    }

    stake_modifier = stake_modifier_new;
    generated_stake_modifier = true;

    return true;
}

bool kernel::check_stake_modifier_checkpoints(
    const std::uint32_t & height, const std::uint32_t & checksum
    )
{
    /**
     * The testnet doesn't have checkpoints.
     */
    if (constants::test_net)
    {
        return true;
    }

    auto stake_modifier_checkpoints = get_stake_modifier_checkpoints();

    if (stake_modifier_checkpoints.count(height) > 0)
	{
        return checksum == stake_modifier_checkpoints[height];
	}
    
    return true;
}

bool kernel::check_coin_stake_timestamp(
    const std::uint32_t & time_block, const std::uint32_t & time_tx
    )
{
    return time_block == time_tx;
}

bool kernel::get_last_stake_modifier(
    const block_index * index, std::uint64_t & stake_modifier,
    std::int64_t & modifier_time
    )
{
    if (index == 0)
    {
        log_error("Kernel get last stake modifier failed, null block index.");
        
        return false;
    }
    
    while (
        index && index->block_index_previous() &&
        index->generated_stake_modifier() == false
        )
    {
        index = index->block_index_previous();
    }
    
    if (index->generated_stake_modifier() == false)
    {
        log_error(
            "Kernel get last stake modifier failed, no generation at genesis "
            "block."
        );
        
        return false;
    }
    
    stake_modifier = index->stake_modifier();
    
    modifier_time = index->time();
    
    return true;
}

std::int64_t kernel::get_stake_modifier_selection_interval_section(
    const std::int32_t & section
    )
{
    assert (section >= 0 && section < 64);
    
    std::int64_t ret =
        kernel::instance().get_modifier_interval() *
        63 / (63 + ((63 - section) * (modifier_interval_ratio - 1))
    );
    
    return ret;
}

std::int64_t kernel::get_stake_modifier_selection_interval()
{
    std::int64_t ret = 0;
    
    for (auto section = 0; section < 64; section++)
    {
        ret += get_stake_modifier_selection_interval_section(
            section
        );
    }
    return ret;
}

bool kernel::select_block_from_candidates(
    std::vector<std::pair<std::int64_t, sha256> > & sorted_by_timestamp,
    std::map<sha256, block_index *> & selected_blocks,
    const std::int64_t & selection_interval_stop,
    const std::uint64_t & previous_stake_modifier,
    const block_index ** index_selected
    )
{
    bool selected = false;
    
    sha256 hash_best = 0;
    
    *index_selected = 0;
    
    for (auto & item : sorted_by_timestamp)
    {
        if (globals::instance().block_indexes().count(item.second) == 0)
        {
            log_error(
                "Kernel, select block from candidates failed to find block "
                "index for candidate block " << item.second.to_string() << "."
            );
            
            return false;
        }
        
        const auto & index = globals::instance().block_indexes()[item.second];
        
        if (selected && index->time() > selection_interval_stop)
        {
            break;
        }
        
        if (selected_blocks.count(index->get_block_hash()) > 0)
        {
            continue;
        }
        
        /*
         * Compute the selection hash by hashing its proof-hash and the
         * previous proof-of-stake modifier.
         */
        sha256 hash_proof =
            index->is_proof_of_stake() ?
            index->hash_proof_of_stake() : index->get_block_hash()
        ;
        
        /**
         * Allocate the buffer to calculate the hash of the
         * selection.
         */
        data_buffer buffer;
        
        /**
         * Write the hash of the proof.
         */
        buffer.write_sha256(hash_proof);
        
        /**
         * Write the previous stake modifier.
         */
        buffer.write_uint64(previous_stake_modifier);
        
        /**
         * Calculate the sha256d hash of the hash of the proof and
         * the previous stake modifier.
         */
        auto hash_selection = sha256::from_digest(&hash::sha256d(
            reinterpret_cast<std::uint8_t *>(buffer.data()),
            buffer.size())[0]
        );

        /**
         * Divide by 2**32 so that Proof-of-Stake blocks are favored over
         * Proof-of-Work blocks.
         */
        if (index->is_proof_of_stake())
        {
            hash_selection >>= 32;
        }
        
        if (selected && hash_selection < hash_best)
        {
            hash_best = hash_selection;
            
            *index_selected = reinterpret_cast<const block_index *> (index);
        }
        else if (selected == false)
        {
            selected = true;
            
            hash_best = hash_selection;
            
            *index_selected = reinterpret_cast<const block_index *> (index);
        }
    }
    
    /**
     * -printstakemodifier
     */
    if (globals::instance().debug())
    {
        log_none(
            "Kernel, select block from candidates, selection hash = " <<
            hash_best.to_string() << "."
        );
    }
    
    return selected;
}

bool kernel::check_proof_of_stake(
    const std::shared_ptr<tcp_connection> & connection,
    const transaction & tx, const std::uint32_t & bits, sha256 & hash_pos
    )
{
     if (tx.is_coin_stake() == false)
     {
        log_error(
            "Kernel, check proof of stake failed, called on non-coinstake " <<
            tx.get_hash().to_string() << "."
        );
        
        return false;
    }
    
    /**
     * Kernel (input 0) must match the stake hash target per coin age (bits).
     */
    auto tx_in = tx.transactions_in()[0];
    
    /**
     * First try to find the previous transaction in database.
     */
    db_tx tx_db("r");
    
    transaction tx_previous;
    
    transaction_index tx_index;
    
    if (
        tx_previous.read_from_disk(tx_db, tx_in.previous_out(),
        tx_index) == false
        )
    {
        if (utility::is_initial_block_download() == true)
        {
            log_debug(
                "Kernel, check proof of stake failed, read tx previous failed "
                "(normal during initial download)."
            );
        }
        else
        {
            log_error(
                "Kernel, check proof of stake failed, read tx previous failed."
            );
            
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(connection->dos_score() + 1);
            }
        }
        
        /**
         * Previous transaction not in main chain, may occur during initial
         * download.
         */
        return false;
    }
    
    tx_db.close();

    /**
     * Skip ECDSA signature verification when checking blocks before the last
     * blockchain checkpoint.
     */
    if (
        globals::instance().best_block_height() >=
        checkpoints::instance().get_total_blocks_estimate()
        )
    {
        /**
         * Verify the signature.
         */
        if (script::verify_signature(tx_previous, tx, 0, true, 0) == false)
        {
            log_error(
                "Kernel, check proof of stake failed, verify_signature"
                " failed on coinstake " << tx.get_hash().to_string() << "."
            );
            
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(100);
            }
            
            return false;
        }
    }
    
    /**
     * Read block header.
     */
    block blk;
    
    if (
        blk.read_from_disk(tx_index.get_transaction_position().file_index(),
        tx_index.get_transaction_position().block_position(), false) == false
        )
    {
        log_error("Kernel, check proof of stake failed, read block failed.");
        
        /**
         * Unable to read the block of the previous transaction.
         */
        return false;
    }
    
    auto print_pos = false;
    
    if (
        check_stake_kernel_hash(bits, blk,
        tx_index.get_transaction_position().tx_position() -
        tx_index.get_transaction_position().block_position(), tx_previous,
        tx_in.previous_out(), tx.time(), hash_pos, print_pos) == false
        )
    {
        if (utility::is_initial_block_download() == true)
        {
            log_debug(
                "Kernel, check proof of stake failed, check kernel failed on "
                "coinstake " << tx.get_hash().to_string() << ", hash_pos = " <<
                hash_pos.to_string() << " (normal during initial download)."
            );
        }
        else
        {
            log_debug(
                "Kernel, check proof of stake failed, check kernel failed on "
                "coinstake " << tx.get_hash().to_string() << ", hash_pos = " <<
                hash_pos.to_string() << "."
            );
            
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(connection->dos_score() + 1);
            }
        }
        
        /**
         * This may occur on initial download or if behind on block chain sync.
         */
        return false;
    }

    return true;
}

bool kernel::check_stake_kernel_hash(
    const std::uint32_t & bits, const block & block_from,
    const std::uint32_t & tx_previous_offset, const transaction & tx_previous,
    const point_out & previous_out, const std::uint32_t time_tx,
    sha256 & hash_pos, const bool & print_pos
    )
{
    /**
     * Check for a transaction timestamp violation.
     */
    if (time_tx < tx_previous.time())
    {
        log_error("Kernel, check stake kernel hash failed, time violation.");
        
        return false;
    }
    
    std::uint32_t time_block_from = block_from.header().timestamp;
    
    /**
     * Check the minimum age requirement.
     */
    if (time_block_from + constants::min_stake_age > time_tx)
    {
        log_error(
            "Kernel, check stake kernel hash failed, minimum age violation."
        );
        
        return false;
    }
    
    big_number target_per_coin_day;
    
    target_per_coin_day.set_compact(bits);
    
    auto value_in = tx_previous.transactions_out()[previous_out.n()].value();

    /**
     * The weight starts from 0 at the minimum age, this increases active
     * coins participating the hash and helps to secure the network when
     * proof-of-stake difficulty is low.
     */
    std::int64_t time_weight = std::min(
        (std::int64_t)time_tx - tx_previous.time(),
        (std::int64_t)constants::max_stake_age) - constants::min_stake_age
    ;
    
    big_number coin_day_weight =
        big_number(value_in) * time_weight / constants::coin / (24 * 60 * 60)
    ;

    data_buffer buffer;
    
    std::uint64_t stake_modifier = 0;
    std::int32_t stake_modifier_height = 0;
    std::int64_t stake_modifier_time = 0;

    if (
        get_kernel_stake_modifier(block_from.get_hash(), stake_modifier,
        stake_modifier_height, stake_modifier_time, print_pos) == false
        )
	{
        return false;
	}

    buffer.write_uint64(stake_modifier);
    buffer.write_uint32(time_block_from);
    buffer.write_uint32(tx_previous_offset);
    buffer.write_uint32(tx_previous.time());
    buffer.write_uint32(previous_out.n());
    buffer.write_uint32(time_tx);
    
    hash_pos = sha256::from_digest(
        &hash::sha256d(reinterpret_cast<std::uint8_t *>(buffer.data()),
        buffer.size())[0]
    );
    
    if (globals::instance().debug() && print_pos)
    {
        log_debug(
            "Kernel, check stake kernel hash, using modifier " <<
            stake_modifier << " at height = " << stake_modifier_height <<
            ", timestamp = " << stake_modifier_time <<
            " for block from height = " <<
            globals::instance().block_indexes()[block_from.get_hash()]->height()
            << ", timestamp = " << block_from.header().timestamp << "."
        );
        
        log_debug(
            "Kernel, check stake kernel hash, check protocol = " <<
            "0.3" << ", modifier = " << stake_modifier <<
            ", time_block_from = " << time_block_from <<
            ", tx_previous_offset = " << tx_previous_offset <<
            ", time_tx_previous = " << tx_previous.time() <<
            ", previous_out.n = " << previous_out.n() <<
            ", time_tx = " << time_tx << ", hash_pos = " <<
            hash_pos.to_string() << "."
        );
    }

    /**
     * Check if the proof-of-stake hash meets target protocol.
     */
    if (big_number(hash_pos) > coin_day_weight * target_per_coin_day)
	{
        return false;
	}
    
    return true;
}

bool kernel::get_kernel_stake_modifier(
    const sha256 & hash_block_from, std::uint64_t & stake_modifier,
    std::int32_t & stake_modifier_height,
    std::int64_t & stake_modifier_time, const bool & print_pos
    )
{
    stake_modifier = 0;
    
    if (globals::instance().block_indexes().count(hash_block_from) == 0)
    {
        log_error(
            "Kernel, get kernel stake modifier failed, block not indexed."
        );
        
        return false;
    }
    
    const auto * index_from =
        globals::instance().block_indexes()[hash_block_from]
    ;
    
    stake_modifier_height = index_from->height();
    
    stake_modifier_time = index_from->time();
    
    auto stake_modifier_selection_interval =
        get_stake_modifier_selection_interval()
    ;
    
    const auto * index = index_from;

    /**
     * Find the stake modifier later by a selection interval.
     */
    while (
        stake_modifier_time < index_from->time() +
        stake_modifier_selection_interval
        )
    {
        if (index->block_index_next() == 0)
        {
            /**
             * We've reached best block, this may happen if node is behind on
             * block chain.
             */
            if (
                print_pos || (index->time() +
                constants::min_stake_age - stake_modifier_selection_interval >
                time::instance().get_adjusted())
                )
            {
                log_debug(
                    "Kernel, get kernel stake modifier reached best block " <<
                    index->get_block_hash().to_string() << " at height " <<
                    index->height() << " from block " <<
                    hash_block_from.to_string() << "."
                );
                
                return false;
            }
            else
			{
                return false;
			}
        }
        
        index = index->block_index_next();
        
        if (index->generated_stake_modifier())
        {
            stake_modifier_height = index->height();
            
            stake_modifier_time = index->time();
        }
    }
    
    stake_modifier = index->stake_modifier();

    return true;
}
