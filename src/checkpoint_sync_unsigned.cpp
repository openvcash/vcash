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

#include <coin/checkpoint_sync_unsigned.hpp>
#include <coin/hash.hpp>

using namespace coin;

checkpoint_sync_unsigned::checkpoint_sync_unsigned()
    : m_version(1)
    , m_hash_checkpoint(0)
{
    // ...
}

void checkpoint_sync_unsigned::encode()
{
    encode(*this);
}

void checkpoint_sync_unsigned::encode(data_buffer & buffer)
{
    buffer.write_int32(m_version);
    buffer.write_sha256(m_hash_checkpoint);
}

bool checkpoint_sync_unsigned::decode()
{
    return decode(*this);
}

bool checkpoint_sync_unsigned::decode(data_buffer & buffer)
{
    m_version = buffer.read_int32();
    m_hash_checkpoint = buffer.read_sha256();
    
    return true;
}

void checkpoint_sync_unsigned::set_null()
{
    m_version = 1;
    m_hash_checkpoint = 0;
}

sha256 checkpoint_sync_unsigned::get_hash()
{
    /**
     * Allocate the buffer.
     */
    data_buffer buffer;
    
    /**
     * Encode the buffer.
     */
    encode(buffer);
    
    /**
     * Return the hash of the buffer.
     */
    return
        sha256::from_digest(&hash::sha256d(
        reinterpret_cast<const std::uint8_t *> (buffer.data()),
        buffer.size())[0]
    );
}

const std::uint32_t & checkpoint_sync_unsigned::version() const
{
    return m_version;
}

void checkpoint_sync_unsigned::set_hash_checkpoint(const sha256 & val)
{
    m_hash_checkpoint = val;
}

const sha256 & checkpoint_sync_unsigned::hash_checkpoint() const
{
    return m_hash_checkpoint;
}

std::string checkpoint_sync_unsigned::to_string() const
{
    std::string ret;
    
    ret += "checkpoint_sync(\n";
    ret += "\tversion = " + std::to_string(m_version);
    ret += "\thash checkpoint = " + m_hash_checkpoint.to_string();
    ret += ")\n";
    
    return ret;
}
