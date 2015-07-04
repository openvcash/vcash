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

#include <cassert>

#include <coin/time.hpp>
#include <coin/zerotime_lock.hpp>

using namespace coin;

zerotime_lock::zerotime_lock()
    : m_expiration(time::instance().get_adjusted() + interval_min_expire)
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
     * Encode the transaction.
     */
    m_transaction.encode(buffer);
    
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
    
    /** 
     * Encode the signature length.
     */
    buffer.write_var_int(m_signature.size());
    
    /** 
     * Encode the signature.
     */
    buffer.write_bytes(
        reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
    );
}

bool zerotime_lock::decode()
{
    return decode(*this);
}

bool zerotime_lock::decode(data_buffer & buffer)
{
    /**
     * Decode the transaction.
     */
    m_transaction.decode(buffer);

    /**
     * Decode the transaction hash.
     */
    buffer.read_bytes(
        reinterpret_cast<char *> (m_hash_tx.digest()), sha256::digest_length
    );
    
    assert(m_transaction.get_hash() == m_hash_tx);
    
    /**
     * Decode the expiration.
     */
    m_expiration = buffer.read_uint64();

    /**
     * Enforce the expiration.
     */
    if (
        m_expiration < time::instance().get_adjusted() + interval_min_expire ||
        m_expiration > time::instance().get_adjusted() + interval_max_expire
        )
    {
        m_expiration = time::instance().get_adjusted() + interval_min_expire;
    }
    
    /**
     * Decode the signature length.
     */
    auto len = buffer.read_var_int();
    
    /**
     * Decode the signature.
     */
    if (len > 0)
    {
        m_signature.resize(len);

        buffer.read_bytes(
            reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
        );
    }
    
    return m_transaction.get_hash() == m_hash_tx;
}

void zerotime_lock::set_null()
{
    m_transaction.set_null();
    m_hash_tx.clear();
    m_expiration = time::instance().get_adjusted() + interval_min_expire;
    m_signature.clear();
}

void zerotime_lock::set_transaction(const transaction & val)
{
    m_transaction = val;
}

const std::vector<transaction_in> & zerotime_lock::transactions_in() const
{
    return m_transaction.transactions_in();
}

void zerotime_lock::set_hash_tx(const sha256 & val)
{
    m_hash_tx = val;
}

const sha256 & zerotime_lock::hash_tx() const
{
    return m_hash_tx;
}

const std::time_t & zerotime_lock::expiration() const
{
    return m_expiration;
}
