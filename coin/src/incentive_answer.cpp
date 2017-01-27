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
#include <coin/hash.hpp>
#include <coin/incentive.hpp>
#include <coin/incentive_answer.hpp>
#include <coin/key.hpp>
#include <coin/logger.hpp>
#include <coin/types.hpp>

using namespace coin;

incentive_answer::incentive_answer()
    : m_version(current_version)
{
    set_null();
}

incentive_answer::incentive_answer(
    const key_public & public_key, const transaction_in & tx_in
    )
    : m_version(current_version)
    , m_public_key(public_key)
    , m_transaction_in(tx_in)
{
    // ...
}

void incentive_answer::encode()
{
    encode(*this);
}

void incentive_answer::encode(data_buffer & buffer, const bool & is_copy )
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);

    /**
     * Encode the public key.
     */
    m_public_key.encode(buffer);

    /**
     * Encode the transaction_in.
     */
    m_transaction_in.encode(buffer);

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

bool incentive_answer::decode()
{
    return decode(*this);
}

bool incentive_answer::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Decode the key_public.
     */
    m_public_key.decode(buffer);
    
    /**
     * Decode the transaction_in.
     */
    m_transaction_in.decode(buffer);
    
    return verify(buffer);
}

void incentive_answer::set_null()
{
    m_version = current_version;
    m_signature.clear();
}

const key_public & incentive_answer::public_key() const
{
    return m_public_key;
}

const transaction_in & incentive_answer::get_transaction_in() const
{
    return m_transaction_in;
}

const std::string incentive_answer::get_address() const
{
    return address(m_public_key.get_id()).to_string();
}

bool incentive_answer::sign(data_buffer & buffer)
{
    auto ret = false;
    
    /**
     * Hash the encoded message buffer.
     */
    sha256 hash_value = m_public_key.get_hash();
    
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
            "Incentive answer signed value (" <<
            hash_value.to_string().substr(0, 8) << ")."
        );
        
        ret = true;
    }
    else
    {
        log_error("Incentive answer failed to sign value.");
    }
    
    return ret;
}

bool incentive_answer::verify(data_buffer & buffer)
{
    auto ret = false;
    
    /**
     * Hash the encoded message buffer.
     */
    sha256 hash_value = m_public_key.get_hash();
    
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
            incentive::instance().verify(
            m_public_key, hash_value, m_signature) == true
            )
        {
            ret = true;
            
            log_debug(
                "Incentive answer verified value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
        else
        {
            log_error(
                "Incentive answer failed to verify value (" <<
                hash_value.to_string().substr(0, 8) << ")."
            );
        }
    }
    
    return ret;
}
