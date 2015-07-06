/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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

#include <coin/zerotime_question.hpp>

using namespace coin;

zerotime_question::zerotime_question()
{
    set_null();
}

zerotime_question::zerotime_question(const transaction_in & tx_in)
    : m_transaction_in(tx_in)
{
    set_null();
}

void zerotime_question::encode()
{
    encode(*this);
}

void zerotime_question::encode(data_buffer & buffer)
{
    /**
     * Encode the transaction_in.
     */
    m_transaction_in.encode(buffer);
}

bool zerotime_question::decode()
{
    return decode(*this);
}

bool zerotime_question::decode(data_buffer & buffer)
{
    /**
     * Decode the transaction_in.
     */
    m_transaction_in.decode(buffer);
    
    return true;
}

void zerotime_question::set_null()
{
    m_transaction_in.clear();
}

const transaction_in & zerotime_question::get_transaction_in() const
{
    return m_transaction_in;
}
