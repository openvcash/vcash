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

#include <coin/data_buffer.hpp>
#include <coin/hd_configuration.hpp>

using namespace coin;

hd_configuration::hd_configuration()
    : m_version(current_version)
    , m_index(0)
{
    // ...
}

void hd_configuration::encode(data_buffer & buffer) const
{
    assert(m_id_key_master.digest().size() == ripemd160::digest_length);
    buffer.write_uint32(m_version);
    buffer.write_uint32(m_index);
    buffer.write_bytes(
        reinterpret_cast<const char *> (&m_id_key_master.digest()[0]),
        ripemd160::digest_length
    );
}

bool hd_configuration::decode(data_buffer & buffer)
{
    m_version = buffer.read_uint32();
    m_index = buffer.read_uint32();
    buffer.read_bytes(
        reinterpret_cast<char *> (&m_id_key_master.digest()[0]),
        ripemd160::digest_length
    );

    return true;
}

const std::uint32_t & hd_configuration::version() const
{
    return m_version;
}

void hd_configuration::set_index(const std::uint32_t & val)
{
    m_index = val;
}

const std::uint32_t & hd_configuration::index() const
{
    return m_index;
}

void hd_configuration::set_id_key_master(const types::id_key_t & val)
{
    m_id_key_master = val;
}

const types::id_key_t & hd_configuration::id_key_master() const
{
    return m_id_key_master;
}
