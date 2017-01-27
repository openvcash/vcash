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

#include <coin/address.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/key.hpp>
#include <coin/logger.hpp>
#include <coin/types.hpp>
#include <coin/wallet.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_vote.hpp>

using namespace coin;

zerotime_vote::zerotime_vote()
    : m_version(current_version)
    , m_block_height(0)
    , m_score(-1)
{
    set_null();
}

zerotime_vote::zerotime_vote(
    const std::uint32_t & block_height, const sha256 & hash_block,
    const sha256 & hash_tx,
    const std::vector<transaction_in> & transactions_in,
    const key_public & public_key
    )
    : m_version(current_version)
    , m_block_height(block_height)
    , m_hash_block(hash_block)
    , m_hash_tx(hash_tx)
    , m_hash_nonce(
        hash_block ^ hash_tx ^ public_key.get_hash()
    )
    , m_transactions_in(transactions_in)
    , m_public_key(public_key)
    , m_score(-1)
{
    // ...
}

void zerotime_vote::encode()
{
    encode(*this);
}

void zerotime_vote::encode(data_buffer & buffer, const bool & is_copy)
{
    /**
     * Write the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Write the block height.
     */
    buffer.write_uint32(m_block_height);
    
    /**
     * Write the block hash
     */
    buffer.write_sha256(m_hash_block);
    
    /**
     * Write the transaction hash.
     */
    buffer.write_sha256(m_hash_tx);
    
    /**
     * Write the nonce hash.
     */
    buffer.write_sha256(m_hash_nonce);

    /**
     * Write the transactions in.
     */
    buffer.write_var_int(m_transactions_in.size());
    
    for (auto & i : m_transactions_in)
    {
        i.encode(buffer);
    }

    /**
     * Encode the public key.
     */
    m_public_key.encode(buffer);

    /**
     * If we are encoding a copy reuse the existing signature.
     */
    if (is_copy == true)
    {
        /**
         * Write the signature length.
         */
        buffer.write_var_int(m_signature.size());
        
        /**
         * Write the signature.
         */
        buffer.write_bytes(
            reinterpret_cast<char *>(&m_signature[0]),
            m_signature.size()
        );
    }
    else
    {
        /**
         * Sign the message.
         */
        sign(buffer);
    }
}

bool zerotime_vote::decode()
{
    return decode(*this);
}

bool zerotime_vote::decode(data_buffer & buffer)
{
    /**
     * Read the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Read the block height.
     */
    m_block_height = buffer.read_uint32();
    
    /**
     * Read the block hash.
     */
    m_hash_block = buffer.read_sha256();
    
    /**
     * Read the transaction hash.
     */
    m_hash_tx = buffer.read_sha256();
    
    /**
     * Read the nonce hash.
     */
    m_hash_nonce = buffer.read_sha256();
    
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
     * Decode the public key.
     */
    m_public_key.decode(buffer);
    
    /**
     * Check the hash nonce is correct.
     */
    if (m_hash_nonce != (m_hash_block ^ m_hash_tx ^ m_public_key.get_hash()))
    {
        log_error("ZeroTime vote decode failed, invalid nonce.");
        
        return false;
    }

    return verify(buffer);
}

const std::uint32_t & zerotime_vote::block_height() const
{
    return m_block_height;
}

const sha256 & zerotime_vote::hash_block() const
{
    return m_hash_block;
}

const sha256 & zerotime_vote::hash_tx() const
{
    return m_hash_tx;
}

void zerotime_vote::set_null()
{
    m_version = current_version;
    m_block_height = 0;
    m_hash_block.clear();
    m_hash_tx.clear();
    m_hash_nonce.clear();
    m_transactions_in.clear();
    m_score = -1;
}

const sha256 & zerotime_vote::hash_nonce() const
{
    return m_hash_nonce;
}

const std::vector<transaction_in> & zerotime_vote::transactions_in() const
{
    return m_transactions_in;
}

const key_public & zerotime_vote::public_key() const
{
    return m_public_key;
}

const std::int16_t & zerotime_vote::score() const
{
    if (m_score == -1)
    {
        m_score = zerotime::instance().calculate_score(*this);
    }
    
    return m_score;
}

bool zerotime_vote::sign(data_buffer & buffer)
{
    auto ret = false;
    
    /**
     * Calculate the hash of the nonce hash.
     */
    auto digest = hash::sha256d(
        m_hash_nonce.digest(), sha256::digest_length
    );

    /**
     * Hash the encoded message buffer.
     */
    sha256 hash_value = sha256::from_digest(&digest[0]);
    
    if (zerotime::instance().sign(hash_value, m_signature) == true)
    {
        /**
         * Write the signature length.
         */
        buffer.write_var_int(m_signature.size());
        
        /**
         * Write the signature.
         */
        buffer.write_bytes(
            reinterpret_cast<char *>(&m_signature[0]),
            m_signature.size()
        );

        log_debug(
            "ZeroTime vote signed value (" <<
            hash_value.to_string().substr(0, 8) << ")."
        );
        
        ret = true;
    }
    else
    {
        log_error("ZeroTime vote failed to sign value.");
    }
    
    return ret;
}

bool zerotime_vote::verify(data_buffer & buffer)
{
    auto ret = false;
    
    /**
     * Calculate the hash of the nonce hash.
     */
    auto digest = hash::sha256d(
        m_hash_nonce.digest(), sha256::digest_length
    );

    /**
     * Hash the encoded message buffer.
     */
    sha256 hash_value = sha256::from_digest(&digest[0]);
    
    /**
     * Read the signature.
     */
    auto signature_len = buffer.read_var_int();

    if (signature_len > 0)
    {
        m_signature.resize(signature_len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
        );

        if (
            zerotime::instance().verify(m_public_key, hash_value,
            m_signature) == true
            )
        {
            ret = true;
            
            log_debug(
                "ZeroTime vote verified value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
        else
        {
            log_error(
                "ZeroTime vote failed to verify value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
    }
    
    return ret;
}
