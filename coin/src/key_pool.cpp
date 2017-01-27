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

#include <coin/constants.hpp>
#include <coin/key_pool.hpp>

using namespace coin;

key_pool::key_pool()
    : m_time(std::time(0))
{
    // ...
}

key_pool::key_pool(const key_public & key_pub)
    : m_time(std::time(0))
    , m_key_public(key_pub)
{
   // ...
}

void key_pool::encode()
{
    encode(*this);
}

void key_pool::encode(data_buffer & buffer, const bool & include_version)
{
    if (include_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(constants::version_client);
    }
    
    /**
     * Write the time.
     */
    buffer.write_int64(m_time);
    
    /**
     * Encode the public key.
     */
    m_key_public.encode(buffer);
}

void key_pool::decode()
{
    decode(*this);
}

void key_pool::decode(data_buffer & buffer, const bool & include_version)
{
    if (include_version)
    {
        /**
         * Read the version.
         */
        buffer.read_uint32();
    }
    
    /**
     * Read the time.
     */
    m_time = buffer.read_int64();
    
    /**
     * Decode the public key.
     */
    m_key_public.decode(buffer);
}

const std::int64_t & key_pool::time() const
{
    return m_time;
}

void key_pool::set_key_public(const key_public & value)
{
    m_key_public = value;
}

const key_public & key_pool::get_key_public() const
{
    return m_key_public;
}
