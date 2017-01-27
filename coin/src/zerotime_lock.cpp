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

#include <coin/time.hpp>
#include <coin/zerotime_lock.hpp>

using namespace coin;

zerotime_lock::zerotime_lock()
    : m_version(current_version)
    , m_expiration(time::instance().get_adjusted() + interval_min_expire)
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
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
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
     * No signature is required because:
     * 1. The receiver may want to lock a non-zerotime transaction.
     * 2. It causes no harm to let other's lock the transaction.
     * 3. It conserves bandwidth and processing power.
     */
}

bool zerotime_lock::decode()
{
    return decode(*this);
}

bool zerotime_lock::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
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
     * No signature is required because:
     * 1. The receiver may want to lock a non-zerotime transaction.
     * 2. It causes no harm to let other's lock the transaction.
     * 3. It conserves bandwidth and processing power.
     */
    
    return m_transaction.get_hash() == m_hash_tx;
}

void zerotime_lock::set_null()
{
    m_version = current_version;
    m_transaction.set_null();
    m_hash_tx.clear();
    m_expiration = time::instance().get_adjusted() + interval_min_expire;
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
