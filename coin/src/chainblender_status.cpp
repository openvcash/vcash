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

#include <coin/chainblender_status.hpp>
#include <coin/logger.hpp>

using namespace coin;

chainblender_status::chainblender_status()
    : m_version(current_version)
    , m_code(code_none)
    , m_participants(0)
    , m_flags(flag_0x00)
{
    set_null();
}

void chainblender_status::encode()
{
    encode(*this);
}

void chainblender_status::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Encode the session id.
     */
    buffer.write_sha256(m_hash_session_id);
    
    /**
     * Encode the code.
     */
    buffer.write_uint8(m_code);

    /**
     * Encode the number of participants.
     */
    buffer.write_uint8(m_participants);

    /**
     * Encode the flags.
     */
    buffer.write_uint16(m_flags);
}

bool chainblender_status::decode()
{
    return decode(*this);
}

bool chainblender_status::decode(data_buffer & buffer)
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
     * Read the code.
     */
    m_code = buffer.read_uint8();
    
    /**
     * Read the number of participants.
     */
    m_participants = buffer.read_uint8();
    
    /**
     * Read the flags.
     */
    m_flags = buffer.read_uint16();
    
    return true;
}

void chainblender_status::set_null()
{
    m_version = current_version;
    m_hash_session_id.clear();
    m_code = code_none, m_participants = 0, m_flags = 0;
}

void chainblender_status::set_hash_session_id(const sha256 & val)
{
    m_hash_session_id = val;
}

const sha256 & chainblender_status::hash_session_id() const
{
    return m_hash_session_id;
}

void chainblender_status::set_code(const std::uint8_t & val)
{
    m_code = val;
}

const std::uint8_t & chainblender_status::code() const
{
    return m_code;
}

void chainblender_status::set_participants(const std::uint8_t & val)
{
    m_participants = val;
}

const std::uint8_t & chainblender_status::participants() const
{
    return m_participants;
}

void chainblender_status::set_flags(const std::uint16_t & val)
{
    m_flags = val;
}

const std::uint16_t & chainblender_status::flags() const
{
    return m_flags;
}
