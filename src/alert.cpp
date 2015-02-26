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

#include <coin/alert.hpp>
#include <coin/constants.hpp>
#include <coin/hash.hpp>
#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/logger.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>

using namespace coin;

void alert::encode()
{
    encode(*this);
}

void alert::encode(data_buffer & buffer)
{
    buffer.write_var_int(m_message.size());
    buffer.write_bytes(
        reinterpret_cast<char *>(&m_message[0]), m_message.size()
    );
    
    buffer.write_var_int(m_signature.size());
    buffer.write_bytes(
        reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
    );
}

bool alert::decode()
{
    return decode(*this);
}

bool alert::decode(data_buffer & buffer)
{
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_message.resize(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_message[0]), m_message.size()
        );
    }
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_signature.resize(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
        );
    }
    
    /**
     * If we have a message, decode it.
     */
    if (m_message.size() > 0)
    {
        /**
         * Allocate the message buffer.
         */
        data_buffer buffer_message;
        
        /**
         * Write the message into the buffer.
         */
        buffer_message.write_bytes(
            reinterpret_cast<const char *>(&m_message[0]), m_message.size()
        );
        
        /**
         * Decode the message.
         */
        alert_unsigned::decode(buffer_message);
    }
    
    return true;
}

bool alert::check_signature() const
{
    /**
     * The alert public key.
     */
    static std::string key_public_alert =
        "041ebbc925a9470ce61e264385d025f2b7f7601682d7ff9474639a2c082643f36d8ab"
        "192c07306389cc6e59867952f7fa2a44daa15379dfbfdd8c206f224ab66bd"
    ;
    
    /**
     * The alert (test net) public key.
     */
    static std::string key_public_alert_test_net =
        "041ebbc925a9470ce61e264385d025f2b7f7601682d7ff9474639a2c082643f36d8ab"
        "192c07306389cc6e59867952f7fa2a44daa15379dfbfdd8c206f224ab66bd"
    ;

    key k;
    
    /**
     * Set the public key.
     */
    if (
        k.set_public_key(key_public(utility::from_hex(
        constants::test_net ? key_public_alert_test_net : key_public_alert))
        ) == false
        )
    {
        log_error(
            "Alert failed to check signature, set_public_key failed."
        );
    
        return false;
    }
    
    /**
     * Calculate the hash of the message.
     */
    auto hash_message = sha256::from_digest(&hash::sha256d(
        &m_message[0], &m_message[0] + m_message.size())[0]
    );
    
    /** 
     * Verify the message against the signature.
     */
    if (k.verify(hash_message, m_signature) == false)
    {
        log_error("Alert failed to check signature, verify failed.");
        
        return false;
    }

    return true;
}

void alert::set_null()
{
    alert_unsigned::set_null();
    
    m_message.clear();
    m_signature.clear();
}

bool alert::is_null() const
{
    return m_expiration == 0;
}

sha256 alert::get_hash() const
{
    return sha256::from_digest(
        &hash::sha256d(&m_message[0], m_message.size())[0]
    );
}

bool alert::is_in_effect() const
{
    return time::instance().get_adjusted() < m_expiration;
}

bool alert::cancels(const alert & val) const
{
    if (is_in_effect())
    {
        return val.id() <= m_cancel || m_cancels.count(val.id()) > 0;
    }
    
    return false;
}

bool alert::applies_to(
    const std::int32_t & version, const std::string & sub_version
    ) const
{
    if (
        is_in_effect() && (m_sub_versions.size() == 0 ||
        m_sub_versions.count(sub_version) > 0)
        )
    {
        return version >= m_minimum_version && version <= m_maximum_version;
    }
    
    return false;
}

bool alert::applies_to_me() const
{
    return applies_to(
        protocol::version, utility::format_sub_version(
        constants::client_name, constants::version_client,
        std::vector<std::string> ())
    );
}

void alert::set_message(const std::vector<std::uint8_t> & val)
{
    m_message = val;
}

const std::vector<std::uint8_t> & alert::message() const
{
    return m_message;
}

void alert::set_signature(const std::vector<std::uint8_t> & val)
{
    m_signature = val;
}

std::vector<std::uint8_t> & alert::signature()
{
    return m_signature;
}

const std::vector<std::uint8_t> & alert::signature() const
{
    return m_signature;
}
