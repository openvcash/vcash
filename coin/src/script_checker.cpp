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

#include <coin/logger.hpp>
#include <coin/script_checker.hpp>

using namespace coin;

script_checker::script_checker()
{
    // ...
}
        
script_checker::script_checker(
    const transaction & tx_from, const transaction & tx_to,
    const std::uint32_t & n, const bool & strict_pay_to_script_hash,
    const std::int32_t & hash_type
    )
    : m_script_public_key(tx_from.transactions_out()[
        tx_to.transactions_in()[n].previous_out().n()].script_public_key()
    )
    , m_transaction_to(tx_to)
    , m_n(n)
    , m_strict_pay_to_script_hash(strict_pay_to_script_hash)
    , m_hash_type(hash_type)
{
    // ...
}

bool script_checker::check() const
{
    const auto & script_signature =
        m_transaction_to.transactions_in()[m_n].script_signature()
    ;
    
    if (
        script::verify_script(script_signature, m_script_public_key,
        m_transaction_to, m_n, m_strict_pay_to_script_hash, m_hash_type
        ) == false
        )
    {
        log_error(
            "Script checker failed to verify script " <<
            m_transaction_to.get_hash().to_string().substr(0, 8) << "."
        );

        return false;
    }
    
    return true;
}
