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

#include <coin/chainblender_broadcast.hpp>
#include <coin/logger.hpp>

using namespace coin;

chainblender_broadcast::chainblender_broadcast()
    : m_version(current_version)
    , m_type(type_none)
    , m_length(0)
{
    set_null();
}

void chainblender_broadcast::encode()
{
    encode(*this);
}

void chainblender_broadcast::encode(data_buffer & buffer)
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
     * Encode the type.
     */
    buffer.write_uint16(m_type);
    
    assert(m_length == m_value.size());
    
    /**
     * Encode the length.
     */
    buffer.write_uint16(m_length);

    /**
     * Encode the value.
     */
    buffer.write_bytes(
        reinterpret_cast<const char *> (&m_value[0]), m_value.size()
    );
}

bool chainblender_broadcast::decode()
{
    return decode(*this);
}

bool chainblender_broadcast::decode(data_buffer & buffer)
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
     * Decode the type.
     */
    m_type = buffer.read_uint16();
    
    /**
     * Decode the length.
     */
    m_length = buffer.read_uint16();
    
    if (m_length > 0)
    {
        /**
         * Allocate the value.
         */
        m_value.resize(m_length);
    
        /**
         * Decode the value.
         */
        buffer.read_bytes(reinterpret_cast<char *> (&m_value[0]), m_length);
    }
    
    return true;
}

void chainblender_broadcast::set_null()
{
    m_version = current_version;
    m_hash_session_id.clear();
    m_type = type_none;
    m_length = 0;
    m_value.clear();
}

void chainblender_broadcast::set_session_id(const sha256 & val)
{
    m_hash_session_id = val;
}

const sha256 & chainblender_broadcast::hash_session_id() const
{
    return m_hash_session_id;
}

void chainblender_broadcast::set_type(const std::uint16_t & val)
{
    m_type = val;
}

const std::uint16_t & chainblender_broadcast::type() const
{
    return m_type;
}

void chainblender_broadcast::set_length(const std::uint16_t & val)
{
    m_length = val;
}

const std::uint16_t & chainblender_broadcast::length() const
{
    return m_length;
}

void chainblender_broadcast::set_value(const std::vector<std::uint8_t> & val)
{
    m_value = val;
}

const std::vector<std::uint8_t> & chainblender_broadcast::value() const
{
    return m_value;
}
