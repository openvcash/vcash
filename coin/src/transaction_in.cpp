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

#include <coin/transaction_in.hpp>

using namespace coin;

transaction_in::transaction_in()
    : data_buffer()
    , m_previous_out()
    , m_sequence(std::numeric_limits<std::uint32_t>::max())
{
    // ...
}

transaction_in::transaction_in(
    point_out point_out_previous, script script_signature,
    const std::uint32_t & sequence
    )
    : data_buffer()
    , m_previous_out(point_out_previous)
    , m_script_signature(script_signature)
    , m_sequence(sequence)
{
    // ...
}

transaction_in::transaction_in(
    sha256 hash_previous_tx, std::uint32_t out,
    script script_signature,
    const std::uint32_t & sequence
    )
    : data_buffer()
    , m_previous_out(point_out(hash_previous_tx, out))
    , m_script_signature(script_signature)
    , m_sequence(sequence)
{
    // ...
}

void transaction_in::encode()
{
    encode(*this);
}

void transaction_in::encode(data_buffer & buffer) const
{
    /**
     * Write the previous out.
     */
    buffer.write_point_out(
        std::make_pair(m_previous_out.get_hash(), m_previous_out.n())
    );
    
    /**
     * Write the m_script_public_key size var_int.
     */
    buffer.write_var_int(m_script_signature.size());
    
    if (m_script_signature.size() > 0)
    {
        /**
         * Write the m_script_signature.
         */
        buffer.write_bytes(
            reinterpret_cast<const char *> (&m_script_signature[0]),
            m_script_signature.size()
        );
    }
    
    /**
     * Write the sequence.
     */
    buffer.write_uint32(m_sequence);
}

void transaction_in::decode()
{
    decode(*this);
}

void transaction_in::decode(data_buffer & buffer)
{
    /**
     * Read the point out.
     */
    auto pnt_out = buffer.read_point_out();
    
    /**
     * The previous out.
     */
    m_previous_out = point_out(pnt_out.first, pnt_out.second);

    /**
     * Read the var_int.
     */
    auto len = buffer.read_var_int();
    
    /**
     * Read the script.
     */
    auto bytes = buffer.read_bytes(len);
    
    /**
     * Read the script signature.
     */
    m_script_signature.insert(
        m_script_signature.begin(), bytes.begin(), bytes.end()
    );

    /**
     * The sequence.
     */
    m_sequence = buffer.read_uint32();
}

std::string transaction_in::to_string() const
{
    std::string ret;
    
    ret += "transaction_in(";
    
    ret += m_previous_out.to_string();
    
    if (m_previous_out.is_null())
    {
        ret += ", coinbase " + utility::hex_string(m_script_signature);
    }
    else
    {
        ret +=
            ", script signature = " +
            m_script_signature.to_string().substr(0, 24)
        ;
    }
    if (m_sequence != std::numeric_limits<std::uint32_t>::max())
    {
        ret += ", sequence = " + std::to_string(m_sequence);
    }
    
    ret += ")";
    
    return ret;
}

bool transaction_in::is_final() const
{
    return m_sequence == std::numeric_limits<std::uint32_t>::max();
}

point_out & transaction_in::previous_out()
{
    return m_previous_out;
}

const point_out & transaction_in::previous_out() const
{
    return m_previous_out;
}

void transaction_in::set_script_signature(const script & val)
{
    m_script_signature = val;
}

script & transaction_in::script_signature()
{
    return m_script_signature;
}

const script & transaction_in::script_signature() const
{
    return m_script_signature;
}

void transaction_in::set_sequence(const std::uint32_t & val)
{
    m_sequence = val;
}

const std::uint32_t & transaction_in::sequence() const
{
    return m_sequence;
}
