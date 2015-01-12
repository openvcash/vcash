/*
 * Copyright (c) 2013-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/stack_impl.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>

using namespace coin;

utility::disk_info_t utility::disk_info(const std::string & path)
{
    disk_info_t ret = { 0, 0, 0 };
#if (defined _MSC_VER)
    ULARGE_INTEGER avail, total, free;
    
    std::wstring wpath(path.begin(), path.end());
    
    if (
        ::GetDiskFreeSpaceExW(wpath.c_str(), &avail, &total, &free) != 0
        )
    {
        ret.capacity =
            (static_cast<std::uintmax_t> (total.HighPart) << 32) +
            total.LowPart
        ;
        ret.free =
            (static_cast<std::uintmax_t> (free.HighPart) << 32) +
            free.LowPart
        ;
        ret.available =
            (static_cast<std::uintmax_t> (avail.HighPart) << 32) +
            avail.LowPart
        ;
    }
#else
    struct statvfs vfs;

    if (statvfs(path.c_str(), &vfs) == 0)
    {
        ret.capacity =
            static_cast<std::uintmax_t>(vfs.f_blocks) * vfs.f_frsize
        ;
        ret.free =
            static_cast<std::uintmax_t>(vfs.f_bfree) * vfs.f_frsize
        ;
        ret.available =
            static_cast<std::uintmax_t>(vfs.f_bavail) * vfs.f_frsize
        ;
    }
#endif // _MSC_VER
    return ret;
}

std::vector<std::uint8_t> utility::from_hex(const std::string & val)
{
    static const std::int8_t g_hex_digit[256] =
    {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,
        -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,0xa,0xb,0xc,0xd,0xe,0xf,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    const char * ptr = val.c_str();
    
    std::vector<std::uint8_t> vch;
    
    for (;;)
    {
        while (std::isspace(*ptr))
        {
            ptr++;
        }
        
        std::int8_t c = g_hex_digit[(std::uint8_t)*ptr++];
        
        if (c == (std::int8_t)-1)
        {
            break;
        }
        
        std::uint8_t n = (c << 4);
        
        c = g_hex_digit[(std::uint8_t)*ptr++];
        
        if (c == (std::int8_t)-1)
        {
            break;
        }
        
        n |= c;
    
        vch.push_back(n);
    }
    
    return vch;
}

bool utility::is_initial_block_download()
{
    if (
        stack_impl::get_block_index_best() == 0 ||
        globals::instance().best_block_height() <
        checkpoints::instance().get_total_blocks_estimate()
        )
    {
        return true;
    }
    
    static std::time_t g_last_update;
    static std::shared_ptr<block_index> g_index_last_best;

    if (stack_impl::get_block_index_best() != g_index_last_best)
    {
        g_index_last_best = stack_impl::get_block_index_best();
        g_last_update = std::time(0);
    }
    
    return
        std::time(0) - g_last_update < 10 &&
        stack_impl::get_block_index_best()->time() <
        std::time(0) - 24 * 60 * 60
    ;
}

bool utility::is_chain_file(const std::string & file_name)
{
    return file_name == "blkindex.dat";
}

sha256 utility::get_orphan_root(const std::shared_ptr<block> & blk)
{
    auto * ptr = blk.get();

    /**
     * Work back to the first block in the orphan chain.
     */
    while (
        globals::instance().orphan_blocks().count(
        ptr->header().hash_previous_block) > 0
        )
    {
        ptr = globals::instance().orphan_blocks()[
            ptr->header().hash_previous_block
        ].get();
    }
    
    return ptr->get_hash();
}

sha256 utility::wanted_by_orphan(const std::shared_ptr<block> & blk)
{
    auto * ptr = blk.get();
    
    /**
     * Work back to the first block in the orphan chain.
     */
    while (
        globals::instance().orphan_blocks().count(
        ptr->header().hash_previous_block) > 0
        )
    {
        ptr = globals::instance().orphan_blocks()[
            ptr->header().hash_previous_block
        ].get();
    }
    
    return ptr->header().hash_previous_block;
}

bool utility::add_orphan_tx(const data_buffer & buffer)
{
    /**
     * Copy the buffer.
     */
    auto buffer_copy = std::make_shared<data_buffer> (
        buffer.data(), buffer.size()
    );
    
    /**
     * Allocate the transaction.
     */
    transaction tx;
    
    /**
     * Decode the transaction from the buffer.
     */
    tx.decode(*buffer_copy);
    
    /**
     * Rewind the buffer.
     */
    buffer_copy->rewind();
    
    /**
     * Get the hash of the transaction.
     */
    auto hash_tx = tx.get_hash();
    
    if (globals::instance().orphan_transactions().count(hash_tx) > 0)
    {
        return false;
    }

    /**
     * Ignore big transactions, to avoid a send-big-orphans memory
     * exhaustion attack. If a peer has a legitimate large transaction
     * with a missing parent then we assume it will rebroadcast it later,
     * after the parent transaction(s) have been mined or received.
     * 10,000 orphans, each of which is at most 5,000 bytes big is at most 
     * 500 megabytes of orphans.
     */
    if (buffer_copy->size() > 5000)
    {
        log_debug(
            "Utility, add orphan tx ignoring large orphan tx size = " <<
            buffer_copy->size() << ", hash = " <<
            hash_tx.to_string().substr(0, 10)  << "."
        );

        return false;
    }

    globals::instance().orphan_transactions()[hash_tx] = buffer_copy;
    
    for (auto & i : tx.transactions_in())
    {
        globals::instance().orphan_transactions_by_previous()[
            i.previous_out().get_hash()].insert(
            std::make_pair(hash_tx, buffer_copy)
        );
    }

    log_debug(
        "Utility, add orphan tx stored orphan tx " <<
        hash_tx.to_string().substr(0, 10) << ", orphans = " <<
        globals::instance().orphan_transactions().size() << "."
    );
    
    return true;
}

void utility::erase_orphan_tx(const sha256 & hash_tx)
{
    if (globals::instance().orphan_transactions().count(hash_tx) > 0)
    {
        const auto & buffer =
            globals::instance().orphan_transactions()[hash_tx]
        ;
        
        transaction tx;
        
        tx.decode(*buffer);
        
        buffer->rewind();
        
        for (auto & i : tx.transactions_in())
        {
            globals::instance().orphan_transactions_by_previous()[
                i.previous_out().get_hash()
            ].erase(hash_tx);
            
            if (
                globals::instance().orphan_transactions_by_previous()[
                i.previous_out().get_hash()].size() == 0
                )
            {
                globals::instance().orphan_transactions_by_previous().erase(
                    i.previous_out().get_hash()
                );
            }
        }

        globals::instance().orphan_transactions().erase(hash_tx);
    }
}

std::uint32_t utility::limit_orphan_tx_size(const std::uint32_t & max_orphans)
{
    std::uint32_t evicted = 0;
    
    while (globals::instance().orphan_transactions().size() > max_orphans)
    {
        /**
         * Evict a random orphan.
         */
        auto hash_random = hash::sha256_random();
        
        auto it =
            globals::instance().orphan_transactions().lower_bound(
            hash_random)
        ;
        
        if (it == globals::instance().orphan_transactions().end())
        {
            it = globals::instance().orphan_transactions().begin();
        }
        
        erase_orphan_tx(it->first);
        
        ++evicted;
    }
    
    return evicted;
}

const std::shared_ptr<block_index> utility::get_last_block_index(
    const std::shared_ptr<block_index> & index, const bool & is_pos
    )
{
    auto tmp = index;
    
    while (
        tmp && tmp->block_index_previous() &&
        (tmp->is_proof_of_stake() != is_pos)
        )
    {
        tmp = tmp->block_index_previous();
    }
    
    return tmp;
}

std::uint32_t utility::compute_max_bits(
    big_number target_limit, std::uint32_t base, std::int64_t time
    )
{
    big_number ret;
    
    ret.set_compact(base);
    
    ret *= 2;
    
    while (time > 0 && ret < target_limit)
    {
        /**
         * Maximum 200% adjustment per day.
         */
        ret *= 2;
        
        time -= 24 * 60 * 60;
    }
    
    if (ret > target_limit)
    {
        ret = target_limit;
    }
    
    return ret.get_compact();
}

std::uint32_t utility::compute_min_work(
    std::uint32_t base, std::int64_t time
    )
{
    return compute_max_bits(
        constants::proof_of_work_limit, base, time
    );
}

std::uint32_t utility::compute_min_stake(
    std::uint32_t base, std::int64_t time, std::uint32_t time_block
    )
{
    return compute_max_bits(constants::proof_of_stake_limit, base, time);
}

std::uint32_t utility::get_next_target_required(
    const std::shared_ptr<block_index> & index_last, const bool & is_pos
    )
{
    /**
     * The next block height.
     */
    auto height = index_last->height() + 1;
    
    (void)height;
    
    big_number bn_new;
    
    big_number target_limit = constants::proof_of_work_limit;
    
    /*
     * Proof-of-Stake blocks have their own target limit.
     */
    if (is_pos)
    {
        target_limit = constants::proof_of_stake_limit;
    }

    /**
     * The genesis block.
     */
    if (index_last == 0)
    {
        return target_limit.get_compact();
    }
    
    auto index_previous = get_last_block_index(index_last, is_pos);

    /**
     * The first block.
     */
    if (index_previous->block_index_previous() == 0)
    {
        /**
         * Set the difficulty to 0.00388934.
         */
        bn_new.set_compact(503382300);
        
        return bn_new.get_compact();
    }
    
    auto index_previous_previous =
        get_last_block_index(index_previous->block_index_previous(), is_pos
    );

    /**
     * The second block.
     */
    if (index_previous_previous->block_index_previous() == 0)
    {
        /**
         * Set the difficulty to 0.00388934.
         */
        bn_new.set_compact(503382300);
        
        return bn_new.get_compact();
    }
    
    /**
     * DigiShield-like retarget.
     */
    std::int64_t blocks_to_go_back = 0;
    
    std::int64_t target_timespan_re = 0;
    std::int64_t target_spacing_re = 0;

    /**
     * constants::work_and_stake_target_spacing
     */
    target_timespan_re = constants::work_and_stake_target_spacing;
    
    /**
     * constants::work_and_stake_target_spacing
     */
    target_spacing_re = constants::work_and_stake_target_spacing;

    /**
     * 1 block
     */
    static const std::int64_t interval_re =
        target_timespan_re / target_spacing_re
    ;
    
    std::int64_t retarget_timespan = target_timespan_re;
    std::int64_t retarget_interval = interval_re;

    /**
     * Only change once per interval.
     */
    if ((index_last->height() + 1) % retarget_interval != 0)
    {
        return index_last->bits();
    }

    /**
     * Go back the full period unless it's the first retarget after genesis.
     */
    blocks_to_go_back = retarget_interval - 1;

    if ((index_last->height() + 1) != retarget_interval)
    {
        blocks_to_go_back = retarget_interval;
    }
    
    /**
     * Go back by what we want to be N days worth of blocks.
     */
    const auto * index_first = index_last.get();
    
    for (auto i = 0; index_first && i < blocks_to_go_back; i++)
    {
        index_first = index_first->block_index_previous().get();
    }
    
    assert(index_first);

    /**
     * Limit adjustment step.
     */
    std::int64_t actual_timespan = index_last->time() - index_first->time();
    
    if (globals::instance().debug())
    {
        log_debug(
            "Utility, get next target required, actual_timespan = " <<
            actual_timespan << " before bounds."
        );
    }
    
    if (globals::instance().debug())
    {
        log_debug(
            "Utility, get next target required, actual_timespan " <<
            "limiting: " << (retarget_timespan - (retarget_timespan / 4)) <<
            ":" << (retarget_timespan + (retarget_timespan / 2)) << "."
        );
    }

    if (actual_timespan < (retarget_timespan - (retarget_timespan / 4)))
    {
        actual_timespan = (retarget_timespan - (retarget_timespan / 4));
    }
    
    if (actual_timespan > (retarget_timespan + (retarget_timespan / 2)))
    {
        actual_timespan = (retarget_timespan + (retarget_timespan / 2));
    }
    
    if (globals::instance().debug())
    {
        log_debug(
            "Utility, get next target required, corrected "
            "actual_timespan = " << actual_timespan << " before bounds."
        );
    }
    
    bn_new.set_compact(index_last->bits());
    
    bn_new *= actual_timespan;
    bn_new /= retarget_timespan;

    if (bn_new > target_limit)
    {
        bn_new = target_limit;
    }
    
    /**
     * This implements part of the fair solo-mining fixed range difficulty
     * algorithm. Elsewhere we reject blocks that exceed the ceiling via
     * global network conensus. This forces all types of CPU's, GPU's, etc
     * to operate within the fixed target range without being able to
     * over-power one another (they both have a fair chance at solving 
     * Proof-of-Work blocks). Proof-of-Stake will drive the difficulty up
     * causing periodic times where few Proof-of-Work blocks will be solved. As
     * the difficulty drops Proof-of-Work block generation will start up again.
     * This results in a variable block generation time where money supply 
     * will be very slow for some time and then speed up for some time.
     * Because of this you cannot predict when you will have a chance to solve
     * a Proof-of-Work block. When pooled mining is supported via RPC the
     * block timing will remain at the fixed constant which is specified as
     * 200 seconds.
     */
    if (is_pos == false)
    {
        /**
         * If we have reached the minimum difficulty raise it. If we have
         * breached the ceiling lower the difficulty.
         */
        if (bn_new >= constants::proof_of_work_limit)
        {
            /**
             * Raise the difficulty to 0.00388934.
             */
            bn_new.set_compact(503382300);
        }
        else if (bn_new < constants::proof_of_work_limit_ceiling)
        {
            /**
             * Lower the difficulty to 0.00388934.
             */
            bn_new.set_compact(503382300);
        }
        else
        {
            /**
             * The f difficulty.
             */
            std::int32_t f = 0;
            
            /**
             * Gets the one's digit.
             */
            auto ones_digit = index_last->height() % 10;
            
            switch (ones_digit)
            {
                case 0:
                {
                    f = 100;
                }
                break;
                case 1:
                {
                    f = -100;
                }
                break;
                case 2:
                {
                    f = 105;
                }
                break;
                case 3:
                {
                    f = -105;
                }
                break;
                case 4:
                {
                    f = 110;
                }
                break;
                case 5:
                {
                    f = -110;
                }
                break;
                case 6:
                {
                    f = 115;
                }
                break;
                case 7:
                {
                    f = -115;
                }
                break;
                case 8:
                {
                    f = 120;
                }
                break;
                case 9:
                {
                    f = -120;
                }
                break;
                default:
                {
                    f = 0;
                }
                break;
            }
            
            /**
             * Set the f difficulty.
             */
            bn_new.set_compact(bn_new.get_compact() + f);
        }
    }

    return bn_new.get_compact();
}
