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
#include <coin/constants.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/transaction_index.hpp>

using namespace coin;

transaction_index::transaction_index()
{
    set_null();
}

transaction_index::transaction_index(
    const transaction_position & position,
    const std::uint32_t & outputs
    )
    : m_transaction_position(position)
    , m_spent(outputs)
{
    // ...
}

void transaction_index::encode()
{
    encode(*this);
}

void transaction_index::encode(data_buffer & buffer)
{
    /**
     * Write the version.
     */
    buffer.write_uint32(constants::version_client);
    
    m_transaction_position.encode(buffer);
    
    buffer.write_var_int(m_spent.size());
    
    for (auto & i : m_spent)
    {
        i.encode(buffer);
    }
}

void transaction_index::decode()
{
    decode(*this);
}

void transaction_index::decode(data_buffer & buffer)
{
    /**
     * Read the version.
     */
    buffer.read_uint32();
    
    m_transaction_position.decode(buffer);
    
    /**
     * If there is buffer remaining try to read the spent.
     */
    if (buffer.remaining() > 0)
    {
        try
        {
            auto count = buffer.read_var_int();
            
            for (auto i = 0; i < count ; i++)
            {
                transaction_position tx_pos;
                
                tx_pos.decode(buffer);
                
                m_spent.push_back(tx_pos);
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "Tx index failed to decode spent, what = " << e.what() << "."
            );
        }
    }
}

void transaction_index::set_null()
{
    m_transaction_position.set_null();
    m_spent.clear();
}

bool transaction_index::is_null()
{
    return m_transaction_position.is_null();
}

std::int32_t transaction_index::get_depth_in_main_chain() const
{
    /**
     * Read the block header.
     */
    block blk;
    
    if (
        blk.read_from_disk(m_transaction_position.file_index(),
        m_transaction_position.block_position(), false) == false
        )
    {
        return 0;
    }
    
    /**
     * Find the block in the index.
     */
    auto it = globals::instance().block_indexes().find(blk.get_hash());
    
    if (it == globals::instance().block_indexes().end())
    {
        return 0;
    }

    if (it->second == 0 || it->second->is_in_main_chain() == false)
    {
        return 0;
    }
    
    return
        1 + globals::instance().best_block_height() - it->second->height()
    ;
}

const transaction_position & transaction_index::get_transaction_position() const
{
    return m_transaction_position;
}

std::vector<transaction_position> & transaction_index::spent()
{
    return m_spent;
}
