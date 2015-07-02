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

#include <coin/time.hpp>
#include <coin/zerotime_lock.hpp>

using namespace coin;

zerotime_lock::zerotime_lock()
    : m_expiration(time::instance().get_adjusted() + (20 * 60))
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
     * Encode the m_transactions_in size.
     */
    buffer.write_var_int(m_transactions_in.size());
    
    /**
     * Encode the m_transactions_in.
     */
    for (auto & i : m_transactions_in)
    {
        i.encode(buffer);
    }
    
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
     * Read the number of transactions in.
     */
    auto number_transactions_in = buffer.read_var_int();
    
    for (auto i = 0; i < number_transactions_in; i++)
    {
        /**
         * Allocate the transaction_in.
         */
        transaction_in tx_in;
        
        /**
         * Decode the transaction_in.
         */
        tx_in.decode(buffer);

        /**
         * Retain the transaction_in.
         */
        m_transactions_in.push_back(tx_in);
    }
    
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
    
    return true;
}

void zerotime_lock::set_null()
{
    m_transactions_in.clear();
    m_hash_tx.clear();
    m_expiration = time::instance().get_adjusted() + (20 * 60);
    m_signature.clear();
}

const std::vector<transaction_in> & zerotime_lock::transactions_in() const
{
    return m_transactions_in;
}

const sha256 & zerotime_lock::hash_tx() const
{
    return m_hash_tx;
}

const std::time_t & zerotime_lock::expiration() const
{
    return m_expiration;
}
