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

#include <iomanip>

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/block_merkle.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/point_out.hpp>
#include <coin/stack_impl.hpp>
#include <coin/time.hpp>
#include <coin/transaction_index.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/transaction_position.hpp>
#include <coin/utility.hpp>

using namespace coin;

#define FORK_HEIGHT_V023 74525
#define FORK_HEIGHT_V020 50399

utility::disk_info_t utility::disk_info(const std::string & path)
{
    disk_info_t ret = { 0, 0, 0 };
#if (defined _MSC_VER)
    ULARGE_INTEGER avail, total, free;
    
    DWORD len = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, NULL, 0);
    std::unique_ptr<wchar_t> w_path(new wchar_t[len]);
    MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, w_path.get(), len);
    
    if (
        ::GetDiskFreeSpaceExW(w_path.get(), &avail, &total, &free) != 0
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
#elif defined (__ANDROID__)
    struct statfs vfs;

    if (statfs(path.c_str(), &vfs) == 0)
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

bool utility::is_hex(const std::string & val)
{
    for (auto & i : val)
    {
        if (g_hex_digit[(std::uint8_t)i] < 0)
        {
            return false;
        }
    }
    
    return (val.size() > 0) && (val.size()%2 == 0);
}

std::vector<std::uint8_t> utility::from_hex(const std::string & val)
{
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
    static block_index * g_index_last_best = 0;

    if (stack_impl::get_block_index_best() != g_index_last_best)
    {
        g_index_last_best = stack_impl::get_block_index_best();
        g_last_update = std::time(0);
    }

    return
        std::time(0) - g_last_update < 10 &&
        stack_impl::get_block_index_best()->time() <
        std::time(0) - 1 * 60 * 60
    ;
}

bool utility::is_spv_initial_block_download()
{
    if (
        globals::instance().spv_block_last() == 0 ||
        globals::instance().spv_best_block_height() <
        checkpoints::instance().get_total_blocks_estimate()
        )
    {
        return true;
    }
    
    static std::time_t g_last_update;
    static std::unique_ptr<block_merkle> g_block_merkle_last_best;

    if (g_block_merkle_last_best == nullptr)
    {
        g_block_merkle_last_best.reset(
            new block_merkle(*globals::instance().spv_block_last())
        );
        g_last_update = std::time(0);
    }
    else if (
        globals::instance().spv_block_last()->get_hash() !=
        g_block_merkle_last_best->get_hash()
        )
    {
        g_block_merkle_last_best.reset(
            new block_merkle(*globals::instance().spv_block_last())
        );
        g_last_update = std::time(0);
    }

    return
        std::time(0) - g_last_update < 10 &&
        globals::instance().spv_block_last()->block_header().timestamp <
        std::time(0) - 1 * 60 * 60
    ;
}

bool utility::is_chain_file(const std::string & file_name)
{
    return file_name == "block-index-peer.dat";
}

sha256 utility::get_orphan_root(const std::shared_ptr<block> & blk)
{
    auto * ptr = blk.get();

    /**
     * Work back to the first block in the orphan chain.
     */
    while (
        ptr && globals::instance().orphan_blocks().count(
        ptr->header().hash_previous_block) > 0
        )
    {
        ptr = globals::instance().orphan_blocks()[
            ptr->header().hash_previous_block
        ].get();
    }
    
    return ptr == 0 ? sha256() : ptr->get_hash();
}

sha256 utility::wanted_by_orphan(const std::shared_ptr<block> & blk)
{
    auto * ptr = blk.get();
    
    /**
     * Work back to the first block in the orphan chain.
     */
    while (
        ptr && globals::instance().orphan_blocks().count(
        ptr->header().hash_previous_block) > 0
        )
    {
        ptr = globals::instance().orphan_blocks()[
            ptr->header().hash_previous_block
        ].get();
    }
    
    return ptr == 0 ? sha256() : ptr->header().hash_previous_block;
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

const block_index * utility::get_last_block_index(
    const block_index * index, const bool & is_pos
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

block_index * utility::find_block_index_by_height(
    const std::uint32_t & height
    )
{
    block_index * ret = 0;
    
    if (height < stack_impl::get_block_index_best()->height() / 2)
    {
        ret = stack_impl::get_block_index_genesis();
    }
    else
    {
        ret = stack_impl::get_block_index_best();
    }
    
    if (
        globals::instance().block_index_fbbh_last() &&
        std::abs(static_cast<std::int64_t> (height - ret->height())) >
        std::abs(static_cast<std::int64_t> (height - globals::instance(
        ).block_index_fbbh_last()->height()))
        )
    {
        ret = const_cast<block_index *> (
            globals::instance().block_index_fbbh_last()
        );
    }
    
    while (ret->height() > height)
    {
        ret = ret->block_index_previous();
    }
    
    while (ret->height() < height)
    {
        ret = ret->block_index_next();
    }
    
    globals::instance().set_block_index_fbbh_last(ret);
    
    return ret;
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

std::uint32_t utility::get_target_spacing(
    const block_index * index_last
    )
{
    return constants::work_and_stake_target_spacing;
}

std::uint32_t utility::get_next_target_required(
    const block_index * index_last, const bool & is_pos
    )
{
    /**
     * The next block height.
     */
    auto height = index_last->height() + 1;
    
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
    
    if (constants::test_net == true)
    {
        return get_next_target_required_v023(index_last, is_pos);
    }
    else
    {
        /**
         * These MUST always be top down.
         */
        
        /**
         * The block height at which version 0.2.3 retargeting begins.
         */
        enum { block_height_v023_retargeting = FORK_HEIGHT_V023 };
        
        /**
         * The block height at which version 0.2.0 retargeting begins.
         */
        enum { block_height_v020_retargeting = FORK_HEIGHT_V020 };

        /**
         * Check for version retargeting.
         */
        if (height > block_height_v023_retargeting)
        {
            return get_next_target_required_v023(index_last, is_pos);
        }
        else if (height > block_height_v020_retargeting)
        {
            return get_next_target_required_v020(index_last, is_pos);
        }
        
        /**
         * Version 0.1 retargeting.
         */

        /**
         * DigiShield-like retarget.
         */
        std::int64_t blocks_to_go_back = 0;
        
        /**
         * We alter the block time so that coins will be generated at the same
         * rate while using the fair solo-mining algorithm.
         */

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
        const auto * index_first = index_last;
        
        for (auto i = 0; index_first && i < blocks_to_go_back; i++)
        {
            index_first = index_first->block_index_previous();
        }
        
        assert(index_first);

        /**
         * Limit adjustment step.
         */
        std::int64_t actual_timespan = index_last->time() - index_first->time();
        
        if (globals::instance().debug() && false)
        {
            log_debug(
                "Utility, get next target required, actual_timespan = " <<
                actual_timespan << " before bounds."
            );
        }
        
        if (globals::instance().debug() && false)
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
        
        if (globals::instance().debug() && false)
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
         * Only perform this for blocks less than N after fair solo-mining.
         */
        if (height < 43200)
        {
            /**
             * This implements part of the fair solo-mining fixed range difficulty
             * algorithm. Elsewhere we reject blocks that exceed the ceiling.
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
                     * The flip difficulty.
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
                     * Set the flipped difficulty.
                     */
                    bn_new.set_compact(bn_new.get_compact() + f);
                }
            }
        }
    }
    
    return bn_new.get_compact();
}

std::uint32_t utility::get_next_target_required_v020(
    const block_index * index_last, const bool & is_pos
    )
{
    big_number ret;
    
    /**
     * Get the target limit.
     */
    big_number target_limit =
        is_pos ? constants::proof_of_stake_limit :
        constants::proof_of_work_limit
    ;
    
    /**
     * get the index of the previous index.
     */
    auto index_previous = get_last_block_index(index_last, is_pos);

    assert(index_previous);
    
    /**
     * Get the index of the previous index's index.
     */
    auto index_previous_previous =
        get_last_block_index(index_previous->block_index_previous(), is_pos
    );
    
    assert(index_previous_previous);

    /**
     * Calculate the actual spacing.
     */
    std::int64_t
        actual_spacing = index_previous->time() -
        index_previous_previous->time()
    ;

    /**
     * One week.
     */
    static const std::int64_t target_timespan = 7 * 24 * 60 * 60;
    
    /**
     * Two hours.
     */
    static const std::int64_t
        target_spacing_work_max =
        12 * (constants::work_and_stake_target_spacing * 3)
    ;
    
    /**
     * Spacing
     */
    std::int64_t target_spacing =
        is_pos ? constants::work_and_stake_target_spacing :
        std::min(target_spacing_work_max,
        static_cast<std::int64_t> (constants::work_and_stake_target_spacing *
        (1 + index_last->height() - index_previous->height())))
    ;

    /**
     * Set the bits.
     */
    ret.set_compact(index_previous->bits());
    
    /**
     * Retarget
     */
    ret *=
        ((target_timespan / target_spacing - 1) *
        target_spacing + actual_spacing + actual_spacing)
    ;
    ret /=
        ((target_timespan / target_spacing + 1) * target_spacing)
    ;

    if (ret > target_limit)
    {
        ret = target_limit;
    }

    return ret.get_compact();
}

std::uint32_t utility::get_next_target_required_v023(
    const block_index * index_last, const bool & is_pos
    )
{
    big_number ret;
    
    /**
     * Get the target limit.
     */
    big_number target_limit =
        is_pos ? constants::proof_of_stake_limit :
        constants::proof_of_work_limit
    ;
    
    /**
     * Get the index of the previous index.
     */
    auto index_previous = get_last_block_index(index_last, is_pos);

    assert(index_previous);
    
    /**
     * Get the index of the previous index's index.
     */
    auto index_previous_previous =
        get_last_block_index(index_previous->block_index_previous(), is_pos
    );
    
    assert(index_previous_previous);

    /**
     * 20 minutes.
     */
    static const std::int64_t target_timespan = 20 * 60;
    
    /**
     * Spacing
     */
    std::int64_t target_spacing = constants::work_and_stake_target_spacing;

    /**
     * Set the bits.
     */
    ret.set_compact(index_previous->bits());
    
    /**
     * Calculate the actual spacing.
     */
    std::int64_t
        actual_spacing = index_previous->time() -
        index_previous_previous->time()
    ;

    if (actual_spacing < 0)
    {
        actual_spacing = constants::work_and_stake_target_spacing;
    }
    
    /**
     * Retarget
     */
    ret *=
        (((target_timespan / target_spacing) - 1) *
        target_spacing + actual_spacing + actual_spacing)
    ;
    ret /=
        (((target_timespan / target_spacing) + 1) * target_spacing)
    ;

    if (ret > target_limit)
    {
        ret = target_limit;
    }

    return ret.get_compact();
}

bool utility::get_transaction(
    const sha256 & hash_tx, transaction & tx, sha256 & hash_block_out
    )
{
    if (transaction_pool::instance().exists(hash_tx))
    {
        tx = transaction_pool::instance().lookup(hash_tx);
        
        return true;
    }
    
    db_tx tx_db("r");
    
    transaction_index index;
    
    if (tx.read_from_disk(tx_db, point_out(hash_tx, 0), index))
    {
        block blk;
        
        if (
            blk.read_from_disk(index.get_transaction_position().file_index(),
            index.get_transaction_position().block_position(), false)
            )
        {
            hash_block_out = blk.get_hash();
        }
        
        return true;
    }
    
    return false;
}
