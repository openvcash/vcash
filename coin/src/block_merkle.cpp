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

#include <coin/block_merkle.hpp>
#include <coin/constants.hpp>
#include <coin/time.hpp>
#include <coin/transaction.hpp>

using namespace coin;

block_merkle::block_merkle()
    : m_height(0)
{
    // ...
}
block_merkle::block_merkle(
    const std::uint32_t & height, const sha256 & hash_block
    )
    : m_height(height)
    , m_hash(hash_block)
{
    assert(globals::instance().is_client_spv() == true);
    
    std::memset(&m_block_header, 0, sizeof(m_block_header));
}

block_merkle::block_merkle(const block & blk)
    : m_block_header(blk.header())
    , m_hash(blk.get_hash())
    , m_height(0)
{
    assert(globals::instance().is_client_spv() == true);
}

block_merkle::block_merkle(
    const block & blk, transaction_bloom_filter & filter
    )
    : m_block_header(blk.header())
    , m_hash(blk.get_hash())
    , m_height(0)
{
    initialize(blk, filter);
}

void block_merkle::encode(data_buffer & buffer, const bool & to_disk)
{
    buffer.write_uint32(m_block_header.version);
    buffer.write_sha256(m_block_header.hash_previous_block);
    buffer.write_sha256(m_block_header.hash_merkle_root);
    buffer.write_uint32(m_block_header.timestamp);
    buffer.write_uint32(m_block_header.bits);
    buffer.write_uint32(m_block_header.nonce);
    
    if (to_disk == false)
    {
        m_merkle_tree_partial.encode(buffer);
    }
    else
    {
        buffer.write_uint32(m_height);
    }
}

bool block_merkle::decode(data_buffer & buffer, const bool & from_disk)
{
    m_block_header.version = buffer.read_uint32();
    m_block_header.hash_previous_block = buffer.read_sha256();
    m_block_header.hash_merkle_root = buffer.read_sha256();
    m_block_header.timestamp = buffer.read_uint32();
    m_block_header.bits = buffer.read_uint32();
    m_block_header.nonce = buffer.read_uint32();
    
    /**
     * Allocate a temporary (empty) block to calculate the block hash.
     */
    block block_tmp;
    
    /**
     * Set the temporary block header.
     */
    block_tmp.header() = m_block_header;

    /**
     * Calculate the hash of the block header.
     */
    m_hash = block_tmp.get_hash();
    
    if (from_disk == false)
    {
        /**
         * Decode the merkle_tree_partial.
         */
        m_merkle_tree_partial.decode(buffer);
        
        if (m_merkle_tree_partial.total_transactions() > 0)
        {
            std::vector<sha256> matches;
            
            m_merkle_tree_partial.extract_matches(matches);
            
            std::uint32_t index = 0;
            
            for (auto & i : matches)
            {
                m_transactions_matched.push_back(std::make_pair(index, i));
    
                index++;
            }
        }
    }
    else
    {
        m_height = buffer.read_uint32();
    }
    
    return true;
}

bool block_merkle::is_valid_spv()
{
    /**
     * Check merkle root (only if we were allocated via a block_merkle).
     */
    if (m_merkle_tree_partial.total_transactions() > 0)
    {
        std::vector<sha256> matches;

        auto hash_merkle_root = m_merkle_tree_partial.extract_matches(matches);
        
        if (hash_merkle_root != m_block_header.hash_merkle_root)
        {
            log_error("Block merkle hash merkle root mismatch.");
            
            return false;
        }
    }

    /**
     * Check the timestamp.
     */
    if (
        m_block_header.timestamp >
        time::instance().get_adjusted() + constants::max_clock_drift
        )
    {
        log_error("Block merkle timestamp too far in the future.");
     
        return false;
    }
    
    /**
     * Proof-of-Stake blocks have a nonce of zero.
     */
    if (m_block_header.nonce == 0)
    {
        /**
         * We do not check the Proof-of-Stake because we follow the
         * longest chain rule using Proof-of-Work block hashes as checkpoints.
         */
        
        return true;
    }
    else
    {
        if (
            block::check_proof_of_work(m_hash, m_block_header.bits) == false
            )
        {
            log_error("Block merkle check Proof-of-Work failed.");
            
            return false;
        }
    }

    return true;
}

const std::vector<std::pair<std::uint32_t, sha256> > &
    block_merkle::transactions_matched() const
{
    return m_transactions_matched;
}

const block::header_t & block_merkle::block_header() const
{
    return m_block_header;
}

const sha256 & block_merkle::get_hash() const
{
    return m_hash;
}

const merkle_tree_partial & block_merkle::get_merkle_tree_partial() const
{
    return m_merkle_tree_partial;
}

void block_merkle::set_height(const std::int32_t & val)
{
    m_height = val;
}

const std::int32_t & block_merkle::height() const
{
    return m_height;
}

void block_merkle::initialize(
    const block & blk, transaction_bloom_filter & filter
    )
{
    std::vector<sha256> hashes;
    std::vector<bool> matches;
    
    const auto & transactions = const_cast<block *> (&blk)->transactions();

    hashes.reserve(transactions.size());
    matches.reserve(transactions.size());

    for (auto i = 0; i < transactions.size(); i++)
    {
        const auto & tx = transactions[i];
        
        const auto & h = tx.get_hash();
        
        if (filter.is_relevant_and_update(tx) == true)
        {
            m_transactions_matched.push_back(std::make_pair(i, h));
            
            matches.push_back(true);
        }
        else
        {
            matches.push_back(false);
        }
        
        hashes.push_back(h);
    }

    m_merkle_tree_partial = merkle_tree_partial(hashes, matches);
}
