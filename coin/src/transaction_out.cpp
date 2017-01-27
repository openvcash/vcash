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
 
#include <coin/transaction_out.hpp>

using namespace coin;

transaction_out::transaction_out()
    : data_buffer()
    , m_value(0)
    , m_script_public_key()
{
    // ...
}

transaction_out::transaction_out(
    const std::uint64_t & value, const script & script_public_key
    )
    : data_buffer()
    , m_value(value)
    , m_script_public_key(script_public_key)
{
    // ...
}

void transaction_out::encode()
{
    encode(*this);
}

void transaction_out::encode(data_buffer & buffer) const
{
    /**
     * Write the value.
     */
    buffer.write_int64(m_value);
    
    /**
     * Write the m_script_public_key size var_int.
     */
    buffer.write_var_int(m_script_public_key.size());
    
    if (m_script_public_key.size() > 0)
    {
        /**
         * Write the m_script_public_key.
         */
        buffer.write_bytes(
            reinterpret_cast<const char *> (&m_script_public_key[0]),
            m_script_public_key.size()
        );
    }
}

void transaction_out::decode()
{
    decode(*this);
}

void transaction_out::decode(data_buffer & buffer)
{
    /**
     * Decode the value.
     */
    m_value = buffer.read_int64();
    
    /**
     * Read the var_int.
     */
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        /**
         * Read the script.
         */
        auto bytes = buffer.read_bytes(len);
        
        /**
         * Insert the script.
         */
        m_script_public_key.insert(
            m_script_public_key.begin(), bytes.begin(), bytes.end()
        );
    }
}

std::string transaction_out::to_string() const
{
    if (is_empty())
    {
        return "transaction_out(empty)";
    }
    else if (m_script_public_key.size() < 6)
    {
        return "transaction_out(error)";
    }
    
    return
        "transaction_out(value = " + utility::format_money(m_value) +
        ", script public key = " + m_script_public_key.to_string()
    ;
}

void transaction_out::set_value(const std::int64_t & val)
{
    m_value = val;
}

const std::int64_t & transaction_out::value() const
{
    return m_value;
}

script & transaction_out::script_public_key()
{
    return m_script_public_key;
}

const script & transaction_out::script_public_key() const
{
    return m_script_public_key;
}

void transaction_out::set_null()
{
    m_value = -1;
    m_script_public_key.clear();
}

bool transaction_out::is_null()
{
    return m_value == -1;
}

void transaction_out::set_empty()
{
    m_value = 0;
    m_script_public_key.clear();
}

bool transaction_out::is_empty() const
{
    return m_value == 0 && m_script_public_key.empty();
}

sha256 transaction_out::get_hash() const
{
    assert(0);

    /**
     * The hash of the output is never used, I find this odd.
     */
    
    return sha256();
}
