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

#include <coin/zerotime_lock.hpp>

using namespace coin;

zerotime_lock::zerotime_lock()
    : m_expiration(std::time(0) + 20 * 60)
{
    set_null();
}

void zerotime_lock::encode()
{
    encode(*this);
}

void zerotime_lock::encode(data_buffer & buffer)
{
    /**
     * Encode the transaction_in.
     */
    m_transaction_in.encode(buffer);
    
    /**
     * Encode the transaction hash.
     */
    buffer.write_bytes(
        reinterpret_cast<const char *> (m_hash_tx.digest()),
        sha256::digest_length
    );
    
    /**
     * Encode the expiration.
     */
    buffer.write_uint64(m_expiration);
}

bool zerotime_lock::decode()
{
    return decode(*this);
}

bool zerotime_lock::decode(data_buffer & buffer)
{
    /**
     * Decode the transaction_in.
     */
    m_transaction_in.decode(buffer);
    
    /**
     * Decode the transaction hash.
     */
    buffer.read_bytes(
        reinterpret_cast<char *> (m_hash_tx.digest()), sha256::digest_length
    );
    
    /**
     * Decode the expiration.
     */
    m_expiration = buffer.read_uint64();
    
    return true;
}

void zerotime_lock::set_null()
{
    m_transaction_in.clear();
    m_hash_tx.clear();
    m_expiration = std::time(0) + 20 * 60;
}
