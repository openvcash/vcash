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
#include <coin/point_in.hpp>
#include <coin/transaction.hpp>

using namespace coin;

point_in::point_in()
    : m_transaction(0)
    , m_n(static_cast<std::uint32_t> (-1))
{
    // ...
}

point_in::point_in(transaction & tx, const std::uint32_t & n)
    : m_transaction(&tx)
    , m_n(n)
{
    // ...
}

void point_in::set_null()
{
    m_transaction = 0, m_n = static_cast<std::uint32_t> (-1);
}

bool point_in::is_null() const
{
    return
        m_transaction == 0 && m_n == static_cast<std::uint32_t> (-1)
    ;
}

const transaction & point_in::get_transaction() const
{
    return *m_transaction;
}
