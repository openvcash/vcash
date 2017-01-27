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

#include <coin/chainblender_leave.hpp>
#include <coin/logger.hpp>

using namespace coin;

chainblender_leave::chainblender_leave()
    : m_version(current_version)
{
    set_null();
}

void chainblender_leave::encode()
{
    encode(*this);
}

void chainblender_leave::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Encode the session id.
     */
    buffer.write_sha256(m_hash_session_id);
}

bool chainblender_leave::decode()
{
    return decode(*this);
}

bool chainblender_leave::decode(data_buffer & buffer)
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
    
    return true;
}

void chainblender_leave::set_null()
{
    m_version = current_version;
    m_hash_session_id.clear();
}

void chainblender_leave::set_session_id(const sha256 & val)
{
    m_hash_session_id = val;
}

const sha256 & chainblender_leave::hash_session_id() const
{
    return m_hash_session_id;
}
