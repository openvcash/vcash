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

#include <coin/key_wallet_master.hpp>
#include <coin/logger.hpp>

using namespace coin;

key_wallet_master::key_wallet_master()
    : m_derive_iterations(25000)
    , m_derivation_method(0)
{
    // ...
}

void key_wallet_master::encode()
{
    encode(*this);
}

void key_wallet_master::encode(data_buffer & buffer) const
{
    /**
     * Write the crypted key.
     */
    buffer.write_var_int(m_crypted_key.size());
    buffer.write_bytes(
        reinterpret_cast<const char *>(&m_crypted_key[0]),
        m_crypted_key.size()
    );

    /**
     * Write the salt.
     */
    buffer.write_var_int(m_salt.size());
    buffer.write_bytes(
        reinterpret_cast<const char *>(&m_salt[0]), m_salt.size()
    );
    
    /**
     * Write the derivation methods.
     */
    buffer.write_uint32(m_derivation_method);

    /**
     * Write derive iterations.
     */
    buffer.write_uint32(m_derive_iterations);
    
    /**
     * Write the other derivation parameters.
     */
    buffer.write_var_int(m_other_derivation_parameters.size());
    buffer.write_bytes(
        reinterpret_cast<const char *>(&m_other_derivation_parameters[0]),
        m_other_derivation_parameters.size()
    );
}

void key_wallet_master::decode()
{
    decode(*this);
}

void key_wallet_master::decode(data_buffer & buffer)
{
    /**
     * Read the crypted key.
     */
    auto len = buffer.read_var_int();

    if (len > 0)
    {
        m_crypted_key.resize(len);
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_crypted_key[0]), m_crypted_key.size()
        );
    }
    
    /**
     * Read the salt.
     */
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_salt.resize(len);
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_salt[0]), m_salt.size()
        );
    }
    
    /**
     * Read the derivation method.
     */
    m_derivation_method = buffer.read_uint32();
    
    /**
     * Read the derive iterations.
     */
    m_derive_iterations = buffer.read_uint32();
    
    /**
     * Read the other derivation parameters.
     */
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_other_derivation_parameters.resize(len);
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_other_derivation_parameters[0]),
            m_other_derivation_parameters.size()
        );
    }
}

std::vector<std::uint8_t> & key_wallet_master::crypted_key()
{
    return m_crypted_key;
}

const std::vector<std::uint8_t> & key_wallet_master::crypted_key() const
{
    return m_crypted_key;
}

std::vector<std::uint8_t> & key_wallet_master::salt()
{
    return m_salt;
}

const std::uint32_t & key_wallet_master::derivation_method() const
{
    return m_derivation_method;
}

void key_wallet_master::set_derive_iterations(const std::uint32_t & val)
{
    m_derive_iterations = val;
}

const std::uint32_t & key_wallet_master::derive_iterations() const
{
    return m_derive_iterations;
}
