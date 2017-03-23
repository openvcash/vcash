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

#include <coin/incentive_sync.hpp>

using namespace coin;

incentive_sync::incentive_sync()
    : m_version(current_version)
{
    set_null();
}

incentive_sync::incentive_sync(const std::set<std::string> & filter)
    : m_version(current_version)
    , m_filter(filter)
{
    // ...
}

void incentive_sync::encode()
{
    encode(*this);
}

void incentive_sync::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Write the number of filter entries.
     */
    buffer.write_var_int(m_filter.size());
    
    /**
     * Write the filter entries.
     */
     for (auto & i : m_filter)
     {
        buffer.write_var_int(i.size());
        buffer.write_bytes(i.data(), i.size());
     }
}

bool incentive_sync::decode()
{
    return decode(*this);
}

bool incentive_sync::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Read the number of filter entries.
     */
    auto count = buffer.read_var_int();
    
    /**
     * Read each filter entry.
     */
    for (auto i = 0; i < count; i++)
    {
        auto len = buffer.read_var_int();
        
        auto filter = buffer.read_bytes(len);
        
        m_filter.insert(std::string(&filter[0], filter.size()));
    }
    
    return true;
}

void incentive_sync::set_null()
{
    m_version = current_version;
    m_filter.clear();
}

std::set<std::string> & incentive_sync::filter()
{
    return m_filter;
}
