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

#include <coin/incentive_question.hpp>

using namespace coin;

incentive_question::incentive_question()
    : m_version(current_version)
{
    set_null();
}

void incentive_question::encode()
{
    encode(*this);
}

void incentive_question::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
}

bool incentive_question::decode()
{
    return decode(*this);
}

bool incentive_question::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    return true;
}

void incentive_question::set_null()
{
    m_version = current_version;
}
