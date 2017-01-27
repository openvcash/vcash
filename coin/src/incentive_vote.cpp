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

#include <coin/hash.hpp>
#include <coin/incentive.hpp>
#include <coin/incentive_vote.hpp>
#include <coin/logger.hpp>

using namespace coin;

incentive_vote::incentive_vote()
    : m_version(current_version)
    , m_block_height(0)
    , m_score(-1)
{
    set_null();
}

incentive_vote::incentive_vote(
    const std::uint32_t & block_height, const sha256 & hash_block,
    const std::string & addr, const key_public & public_key
    )
    : m_version(current_version)
    , m_block_height(block_height)
    , m_hash_block(hash_block)
    , m_hash_nonce(
        hash_block ^ sha256::from_digest(&hash::sha256d(
        reinterpret_cast<const std::uint8_t *> (
        addr.data()), addr.size())[0]) ^ public_key.get_hash()
    )
    , m_address(addr)
    , m_public_key(public_key)
    , m_score(-1)
{
    // ...
}

void incentive_vote::encode()
{
    encode(*this);
}

void incentive_vote::encode(data_buffer & buffer, const bool & is_copy)
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
     * Write the nonce hash.
     */
    buffer.write_sha256(m_hash_nonce);
    
    /**
     * Write the address length.
     */
    buffer.write_var_int(m_address.size());
    
    /**
     * Write the address.
     */
    buffer.write_bytes(m_address.data(), m_address.size());

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

bool incentive_vote::decode()
{
    return decode(*this);
}

bool incentive_vote::decode(data_buffer & buffer)
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
     * Read the nonce hash.
     */
    m_hash_nonce = buffer.read_sha256();
    
    /**
     * Read the number of address length.
     */
    auto address_len = buffer.read_var_int();
    
    /**
     * Allocate the address.
     */
    m_address.resize(address_len);
    
    /**
     * Read the address.
     */
    buffer.read_bytes(const_cast<char *>(m_address.data()), m_address.size());
    
    /**
     * Decode the public key.
     */
    m_public_key.decode(buffer);

    /**
     * Check the hash nonce is correct.
     */
    if (
        m_hash_nonce != (m_hash_block ^ sha256::from_digest(&hash::sha256d(
        reinterpret_cast<const std::uint8_t *> (
        m_address.data()), m_address.size())[0]) ^ m_public_key.get_hash())
        )
    {
        log_error("Incentive vote decode failed, invalid nonce.");
        
        return false;
    }

    return verify(buffer);
}

const std::uint32_t & incentive_vote::block_height() const
{
    return m_block_height;
}

const sha256 & incentive_vote::hash_block() const
{
    return m_hash_block;
}

void incentive_vote::set_null()
{
    m_version = current_version;
    m_block_height = 0;
    m_hash_block.clear();
    m_hash_nonce.clear();
    m_address.clear();
    m_score = -1;
}

const sha256 & incentive_vote::hash_nonce() const
{
    return m_hash_nonce;
}

const std::string & incentive_vote::address() const
{
    return m_address;
}

const key_public & incentive_vote::public_key() const
{
    return m_public_key;
}

const std::int16_t & incentive_vote::score() const
{
    if (m_score == -1)
    {
        m_score = incentive::instance().calculate_score(*this);
    }
    
    return m_score;
}

bool incentive_vote::sign(data_buffer & buffer)
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
    
    if (incentive::instance().sign(hash_value, m_signature) == true)
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
            "Incentive vote signed value (" <<
            hash_value.to_string().substr(0, 8) << ")."
        );
        
        ret = true;
    }
    else
    {
        log_error("Incentive vote failed to sign value.");
    }
    
    return ret;
}

bool incentive_vote::verify(data_buffer & buffer)
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
            incentive::instance().verify(m_public_key, hash_value,
            m_signature) == true
            )
        {
            ret = true;
            
            log_none(
                "Incentive vote verified value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
        else
        {
            log_error(
                "Incentive vote failed to verify value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
    }
    
    return ret;
}
