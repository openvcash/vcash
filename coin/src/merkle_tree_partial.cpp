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

#include <coin/block.hpp>
#include <coin/data_buffer.hpp>
#include <coin/hash.hpp>
#include <coin/merkle_tree_partial.hpp>

using namespace coin;

merkle_tree_partial::merkle_tree_partial(
    const std::vector<sha256> & txids, const std::vector<bool> & matches
    )
    : m_total_transactions(txids.size())
    , is_invalid_(false)
{
    m_flags.clear();
    m_hashes.clear();

    auto height = 0;
    
    while (calculate_tree_width(height) > 1)
    {
        height++;
    }

    traverse_and_build(height, 0, txids, matches);
}

merkle_tree_partial::merkle_tree_partial()
    : m_total_transactions(0)
    , is_invalid_(true)
{
    // ...
}

void merkle_tree_partial::encode(data_buffer & buffer)
{
    buffer.write_uint32(m_total_transactions);
    buffer.write_var_int(m_hashes.size());
    
    for (auto & i : m_hashes)
    {
        buffer.write_sha256(i);
    }
    
    std::vector<std::uint8_t> bytes;
    
    bytes.resize((m_flags.size() + 7) / 8);
    
    for (auto i = 0; i < m_flags.size(); i++)
    {
        bytes[i / 8] |= m_flags[i] << (i % 8);
    }
    
    buffer.write_var_int(bytes.size());
    buffer.write_bytes(
        reinterpret_cast<const char *> (&bytes[0]), bytes.size()
    );
}

bool merkle_tree_partial::decode(data_buffer & buffer)
{
    m_total_transactions = buffer.read_uint32();
    
    auto count = buffer.read_var_int();
    
    for (auto i = 0; i < count; i++)
    {
        m_hashes.push_back(buffer.read_sha256());
    }
    
    std::vector<std::uint8_t> bytes;
    
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        bytes.resize(len);
        
        buffer.read_bytes(reinterpret_cast<char *>(&bytes[0]), len);
    }
    
    m_flags.resize(bytes.size() * 8);
    
    for (auto i = 0; i < m_flags.size(); i++)
    {
        m_flags[i] = (bytes[i / 8] & (1 << (i % 8))) != 0;
    }
    
    is_invalid_ = false;
    
    return true;
}

const std::uint32_t & merkle_tree_partial::total_transactions() const
{
    return m_total_transactions;
}

sha256 merkle_tree_partial::calculate_hash(
    const std::int32_t & height, const std::uint32_t & position,
    const std::vector<sha256> & txids
    )
{
    if (height == 0)
    {
        return txids[position];
    }

    sha256 left = calculate_hash(height - 1, position * 2, txids);
    sha256 right;
    
    if (position * 2 + 1 < calculate_tree_width(height - 1))
    {
        right = calculate_hash(height - 1, position * 2 + 1, txids);
    }
    else
    {
        right = left;
    }
    
    return sha256::from_digest(&hash::sha256d(
        left.digest(), left.digest() + sha256::digest_length,
        right.digest(), right.digest() + sha256::digest_length)[0]
    );
}

std::uint32_t merkle_tree_partial::calculate_tree_width(
    const std::int32_t & height
    )
{
    return (m_total_transactions + (1 << height) - 1) >> height;
}

void merkle_tree_partial::traverse_and_build(
    const std::int32_t & height, const std::uint32_t & position,
    const std::vector<sha256> & txids,
    const std::vector<bool> & matches
    )
{
    auto parent_of_match = false;
    
    for (
        auto i = position << height; i < (position + 1) << height &&
        i < m_total_transactions; i++
        )
    {
        parent_of_match |= matches[i];
    }
    
    m_flags.push_back(parent_of_match);
    
    if (height == 0 || parent_of_match == false)
    {
        m_hashes.push_back(calculate_hash(height, position, txids));
    }
    else
    {
        traverse_and_build(height - 1, position * 2, txids, matches);
        
        if (position * 2 + 1 < calculate_tree_width(height - 1))
        {
            traverse_and_build(height - 1, position * 2 + 1, txids, matches);
        }
    }
}

sha256 merkle_tree_partial::traverse_and_extract(
    const std::int32_t & height, const std::uint32_t & position,
    std::uint32_t & bits_used, std::uint32_t & hashes_used,
    std::vector<sha256> & matches
    )
{
    if (bits_used >= m_flags.size())
    {
        is_invalid_ = true;
        
        return sha256();
    }
    
    auto parent_of_match = m_flags[bits_used++];
    
    if (height == 0 || parent_of_match == false)
    {
        if (hashes_used >= m_hashes.size())
        {
            is_invalid_ = true;
            
            return sha256();
        }
        
        const auto & h = m_hashes[hashes_used++];
        
        if (height == 0 && parent_of_match)
        {
            matches.push_back(h);
        }
        
        return h;
    }
    else
    {
        auto left = traverse_and_extract(
            height - 1, position * 2, bits_used, hashes_used, matches
        );
        
        sha256 right;
        
        if (position * 2 + 1 < calculate_tree_width(height - 1))
        {
            right = traverse_and_extract(
                height - 1, position * 2 + 1, bits_used, hashes_used, matches
            );
        }
        else
        {
            right = left;
        }

        return sha256::from_digest(&hash::sha256d(
            left.digest(), left.digest() + sha256::digest_length,
            right.digest(), right.digest() + sha256::digest_length)[0]
        );
    }
    
    return sha256();
}

sha256 merkle_tree_partial::extract_matches(std::vector<sha256> & matches)
{
    matches.clear();
    
    if (m_total_transactions == 0)
    {
        return sha256();
    }
    
    if (m_total_transactions > block::get_maximum_size_median220() / 60)
    {
        return sha256();
    }
    
    if (m_hashes.size() > m_total_transactions)
    {
        return sha256();
    }
    
    if (m_flags.size() < m_hashes.size())
    {
        return sha256();
    }
    
    auto height = 0;
    
    while (calculate_tree_width(height) > 1)
    {
        height++;
    }
    
    std::uint32_t bits_used = 0, hashes_used = 0;
    
    auto hash_merkle_root = traverse_and_extract(
        height, 0, bits_used, hashes_used, matches
    );
    
    if (is_invalid_ == true)
    {
        return sha256();
    }
    
    if ((bits_used + 7) / 8 != (m_flags.size() + 7) / 8)
    {
        return sha256();
    }

    if (hashes_used != m_hashes.size())
    {
        return sha256();
    }
    
    return hash_merkle_root;
}
