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
#include <coin/block_locator.hpp>
#include <coin/constants.hpp>
#include <coin/globals.hpp>
#include <coin/stack_impl.hpp>

using namespace coin;

block_locator::block_locator()
    : data_buffer()
{
    // ...
}

block_locator::block_locator(const block_index * index)
    : data_buffer()
{
    set(index);
}

block_locator::block_locator(sha256 hash_block)
{
    auto it = globals::instance().block_indexes().find(hash_block);
    
    if (it != globals::instance().block_indexes().end())
    {
        set(it->second);
    }
}

block_locator::block_locator(const std::vector<sha256> & have)
{
    m_have = have;
}

void block_locator::encode(const bool & encode_version)
{
    encode(*this, encode_version);
}

void block_locator::encode(
    data_buffer & buffer, const bool & encode_version
    )
{
    if (encode_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(constants::version_client);
    }
    
    buffer.write_var_int(m_have.size());
    
    for (auto & i : m_have)
    {
        buffer.write_sha256(i);
    }
}

void block_locator::decode(const bool & decode_version)
{
    decode(*this, decode_version);
}

void block_locator::decode(data_buffer & buffer, const bool & decode_version)
{
    if (decode_version)
    {
        /**
         * Read the version.
         */
        buffer.read_uint32();
    }
    
    auto len = buffer.read_var_int();
    
    for (auto i = 0; i < len; i++)
    {
        m_have.push_back(buffer.read_sha256());
    }
}

const std::vector<sha256> & block_locator::have() const
{
    return m_have;
}

void block_locator::set_null()
{
    m_have.clear();
}

bool block_locator::is_null()
{
    return m_have.size() == 0;
}

void block_locator::set(const block_index * index)
{
    m_have.clear();
    
    std::int32_t step = 1;
    
    while (index)
    {
        m_have.push_back(index->get_block_hash());

        /**
         * Exponentially larger steps back.
         */
        for (auto i = 0; index && i < step; i++)
        {
            index = index->block_index_previous();
        }
        
        if (m_have.size() > 10)
        {
            step *= 2;
        }
    }
    
    m_have.push_back(
        (constants::test_net == false ?
        block::get_hash_genesis() :
        block::get_hash_genesis_test_net())
    );
}

int block_locator::get_distance_back()
{
    /**
     * Retrace how far back it was in the sender's branch.
     */
    int distance = 0;
    
    int step = 1;
    
    for (auto & i : m_have)
    {
        auto it = globals::instance().block_indexes().find(i);
        
        if (it != globals::instance().block_indexes().end())
        {
            auto pindex = it->second;
            
            if (pindex->is_in_main_chain())
            {
                return distance;
            }
        }
        
        distance += step;
        
        if (distance > 10)
        {
            step *= 2;
        }
    }
    
    return distance;
}

block_index * block_locator::get_block_index()
{
    /**
     * Find the first block the caller has in the main chain.
     */
    for (auto & i : m_have)
    {
        auto it = globals::instance().block_indexes().find(i);
        
        if (it != globals::instance().block_indexes().end())
        {
            auto index = it->second;
            
            if (index->is_in_main_chain())
            {
                return index;
            }
        }
    }
    
    return stack_impl::get_block_index_genesis();
}

sha256 block_locator::get_block_hash()
{
    /**
     * Find the first block the caller has in the main chain.
     */
    for (auto & i : m_have)
    {
        auto it = globals::instance().block_indexes().find(i);
        
        if (it != globals::instance().block_indexes().end())
        {
            auto index = it->second;
            
            if (index->is_in_main_chain())
            {
                return i;
            }
        }
    }
    
    return
        constants::test_net == false ?
        block::get_hash_genesis() :
        block::get_hash_genesis_test_net()
    ;
}

int block_locator::get_height()
{
    auto index = get_block_index();
    
    if (index == 0)
    {
        return 0;
    }
    
    return index->height();
}
