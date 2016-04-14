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

#include <coin/block_merkle.hpp>
#include <coin/transaction.hpp>

using namespace coin;

block_merkle::block_merkle(
    const block & blk, transaction_bloom_filter & filter
    )
    : m_block_header(blk.header())
{
    initialize(blk, filter);
}

void block_merkle::encode(data_buffer & buffer)
{
    buffer.write_uint32(m_block_header.version);
    buffer.write_sha256(m_block_header.hash_previous_block);
    buffer.write_sha256(m_block_header.hash_merkle_root);
    buffer.write_uint32(m_block_header.timestamp);
    buffer.write_uint32(m_block_header.bits);
    buffer.write_uint32(m_block_header.nonce);
    
    m_merkle_tree_partial.encode(buffer);
}

void block_merkle::decode(data_buffer & buffer)
{
    m_block_header.version = buffer.read_uint32();
    m_block_header.hash_previous_block = buffer.read_sha256();
    m_block_header.hash_merkle_root = buffer.read_sha256();
    m_block_header.timestamp = buffer.read_uint32();
    m_block_header.bits = buffer.read_uint32();
    m_block_header.nonce = buffer.read_uint32();
    
    m_merkle_tree_partial.decode(buffer);
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
