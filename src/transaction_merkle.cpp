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

#include <coin/transaction_merkle.hpp>

using namespace coin;

transaction_merkle::transaction_merkle()
    : transaction()
    , m_index(-1)
{
    // ...
}

transaction_merkle::transaction_merkle(const transaction & tx)
    : transaction(tx)
    , m_index(-1)
{
    // ...
}

void transaction_merkle::encode()
{
    encode(*this);
}

void transaction_merkle::encode(data_buffer & buffer)
{
    transaction::encode(buffer);

    buffer.write_sha256(m_block_hash);

    buffer.write_var_int(m_merkle_branch.size());
    
    for (auto & i : m_merkle_branch)
    {
        buffer.write_sha256(i);
    }

    buffer.write_int32(m_index);
}

void transaction_merkle::decode()
{
    decode(*this);
}

void transaction_merkle::decode(data_buffer & buffer)
{
    transaction::decode(buffer);

    m_block_hash = buffer.read_sha256();

    auto len = buffer.read_var_int();

    for (auto i = 0; i < len; i++)
    {
        m_merkle_branch.push_back(buffer.read_sha256());
    }
    
    m_index = buffer.read_int32();
}

std::pair<bool, std::string> transaction_merkle::accept_to_memory_pool(
    db_tx & tx_db
    )
{
    if (globals::instance().is_client())
    {
        if (is_in_main_chain() == false && client_connect_inputs() == false)
        {
            return std::make_pair(false, "client unknown");
        }
        
        return transaction::accept_to_transaction_pool(tx_db);
    }
    else
    {
        return transaction::accept_to_transaction_pool(tx_db);
    }
    
    return std::make_pair(false, "unknown");
}

std::pair<bool, std::string> transaction_merkle::accept_to_memory_pool()
{
    db_tx tx_db("r");
    
    return accept_to_memory_pool(tx_db);
}
