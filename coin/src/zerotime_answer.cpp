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

#include <cassert>

#include <coin/zerotime_answer.hpp>

using namespace coin;

zerotime_answer::zerotime_answer()
    : m_version(current_version)
{
    set_null();
}

zerotime_answer::zerotime_answer(const sha256 & hash_tx)
    : m_version(current_version)
    , m_hash_tx(hash_tx)
{
    // ...
}

void zerotime_answer::encode()
{
    encode(*this);
}

void zerotime_answer::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Encode the transaction hash.
     */
    buffer.write_bytes(
        reinterpret_cast<const char *> (m_hash_tx.digest()),
        sha256::digest_length
    );
}

bool zerotime_answer::decode()
{
    return decode(*this);
}

bool zerotime_answer::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Decode the transaction hash.
     */
    buffer.read_bytes(
        reinterpret_cast<char *> (m_hash_tx.digest()), sha256::digest_length
    );
    
    return true;
}

void zerotime_answer::set_null()
{
    m_version = current_version;
    m_hash_tx.clear();
}

const sha256 & zerotime_answer::hash_tx() const
{
    return m_hash_tx;
}
