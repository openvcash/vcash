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

#include <coin/data_buffer.hpp>
#include <coin/hash.hpp>
#include <coin/key_public.hpp>

using namespace coin;

key_public::key_public()
{
    // ...
}

key_public::key_public(const std::vector<std::uint8_t> & bytes)
    : m_bytes(bytes)
{
    // ..
}

void key_public::encode(data_buffer & buffer)
{
    buffer.write_var_int(m_bytes.size());
    
    buffer.write_bytes(
        reinterpret_cast<const char *>(&m_bytes[0]), m_bytes.size()
    );
}

bool key_public::decode(data_buffer & buffer)
{
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_bytes.resize(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_bytes[0]), m_bytes.size()
        );
        
        return true;
    }
    
    return false;
}

const std::vector<std::uint8_t> & key_public::bytes() const
{
    return m_bytes;
}

types::id_key_t key_public::get_id() const
{
    types::id_key_t ret;
    
    auto hash160 = hash::sha256_ripemd160(
        &m_bytes[0], m_bytes.size()
    );
    
    std::memcpy(&ret.digest()[0], &hash160[0], hash160.size());
    
    return ret;
}

sha256 key_public::get_hash() const
{
    return sha256::from_digest(
        &hash::sha256d(&m_bytes[0], m_bytes.size())[0]
    );
}

bool key_public::is_valid() const
{
    return m_bytes.size() == 33 || m_bytes.size() == 65;
}

bool key_public::is_compressed() const
{
    return m_bytes.size() == 33;
}
