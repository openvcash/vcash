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

#include <coin/zerotime_question.hpp>

using namespace coin;

zerotime_question::zerotime_question()
    : m_version(current_version)
{
    set_null();
}

zerotime_question::zerotime_question(
    const std::vector<transaction_in> & tx_ins
    )
    : m_version(current_version)
    , m_transactions_in(tx_ins)
{
    // ..
}

void zerotime_question::encode()
{
    encode(*this);
}

void zerotime_question::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /** 
     * Encode the transaction inputs length.
     */
    buffer.write_var_int(m_transactions_in.size());
    
    for (auto & i : m_transactions_in)
    {
        /**
         * Encode the transaction_in.
         */
        i.encode(buffer);
    }
}

bool zerotime_question::decode()
{
    return decode(*this);
}

bool zerotime_question::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Decode the transaction inputs length.
     */
    auto len = buffer.read_var_int();

    /**
     * Allocate the transaction inputs.
     */
    m_transactions_in.resize(len);
    
    for (auto i = 0; i < len; i++)
    {
        /**
         * Decode the transaction_in.
         */
        m_transactions_in[i].decode(buffer);
    }
    
    return true;
}

void zerotime_question::set_null()
{
    m_version = current_version;
    m_transactions_in.clear();
}

const std::vector<transaction_in> &
    zerotime_question::transactions_in() const
{
    return m_transactions_in;
}
