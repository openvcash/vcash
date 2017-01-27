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

#include <coin/chainblender_join.hpp>
#include <coin/logger.hpp>

using namespace coin;

chainblender_join::chainblender_join()
    : m_version(current_version)
    , m_denomination(0)
{
    set_null();
}

void chainblender_join::encode()
{
    encode(*this);
}

void chainblender_join::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * The session id must be null for a cbjoin.
     */
    if (m_hash_session_id.is_empty() == false)
    {
        log_error(
            "ChainBlender join message has invalid hash session "
            "id = " << m_hash_session_id.to_string() << "."
        );
    }
    
    /**
     * Encode the session id.
     */
    buffer.write_sha256(m_hash_session_id);
    
    /**
     * Encode the denomination.
     */
    buffer.write_int64(m_denomination);
}

bool chainblender_join::decode()
{
    return decode(*this);
}

bool chainblender_join::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Decode the session id.
     */
    m_hash_session_id = buffer.read_sha256();
    
    /**
     * Read the denomination.
     */
    m_denomination = buffer.read_int64();
    
    return true;
}

void chainblender_join::set_null()
{
    m_version = current_version;
    m_hash_session_id.clear();
    m_denomination = 0;
}

const sha256 & chainblender_join::hash_session_id() const
{
    return m_hash_session_id;
}

void chainblender_join::set_denomination(const std::int64_t & val)
{
    m_denomination = val;
}

const std::int64_t & chainblender_join::denomination() const
{
    return m_denomination;
}
