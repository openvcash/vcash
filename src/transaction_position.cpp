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

#include <coin/transaction_position.hpp>

using namespace coin;

transaction_position::transaction_position()
{
    set_null();
}

transaction_position::transaction_position(
    const std::uint32_t & file_index,
    const std::uint32_t & block_position,
    const std::uint32_t & tx_position
    )
    : m_file_index(file_index)
    , m_block_position(block_position)
    , m_tx_position(tx_position)
{
    // ...
}

void transaction_position::encode()
{
    encode(*this);
}

void transaction_position::encode(data_buffer & buffer)
{
    buffer.write_uint32(m_file_index);
    buffer.write_uint32(m_block_position);
    buffer.write_uint32(m_tx_position);
}

void transaction_position::decode()
{
    decode(*this);
}

void transaction_position::decode(data_buffer & buffer)
{
    m_file_index = buffer.read_uint32();
    m_block_position = buffer.read_uint32();
    m_tx_position = buffer.read_uint32();
}

void transaction_position::set_null()
{
    m_file_index = static_cast<std::uint32_t> (-1);
    m_block_position = 0, m_tx_position = 0;
}

bool transaction_position::is_null() const
{
    return m_file_index == static_cast<std::uint32_t> (-1);
}

std::string transaction_position::to_string() const
{
    std::string ret;
    
    if (is_null())
    {
        return "null";
    }
    
    ret += "(";
    ret += "file index = " + std::to_string(m_file_index);
    ret += ", block position = " + std::to_string(m_block_position);
    ret += ", tx position = " + std::to_string(m_tx_position);
    ret += ")";
    
    return ret;
}

const std::uint32_t & transaction_position::file_index() const
{
    return m_file_index;
}

const std::uint32_t & transaction_position::block_position() const
{
    return m_block_position;
}

const std::uint32_t & transaction_position::tx_position() const
{
    return m_tx_position;
}
