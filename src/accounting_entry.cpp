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

#include <coin/accounting_entry.hpp>
#include <coin/constants.hpp>
#include <coin/wallet.hpp>

using namespace coin;

accounting_entry::accounting_entry()
    : m_credit_debit(0)
    , m_time(0)
    , m_order_position(-1)
    , m_entry_number(0)
{
    // ...
}

void accounting_entry::encode()
{
    encode(*this);
}

void accounting_entry::encode(
    data_buffer & buffer, const bool & encode_version
    )
{
    if (encode_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(constants::version_client);
    }
    
    /**
     * Write the credit debit.
     */
    buffer.write_int64(m_credit_debit);
    
    /**
     * Write the time.
     */
    buffer.write_int64(m_time);
    
    /**
     * Write the other account.
     */
    buffer.write_var_int(m_other_account.size());
    buffer.write_bytes(m_other_account.data(), m_other_account.size());

    wallet::write_order_position(m_order_position, m_value);

    /**
     * Build the comment and extra.
     */
    if ((m_value.size() > 0 && extra_.size() > 0))
    {
        data_buffer buffer_extra;
        
        buffer_extra.write_byte('\0');

        buffer_extra.write_var_int(m_value.size());
        
        for (auto & i : m_value)
        {
            buffer_extra.write_var_int(i.first.size());
            
            buffer_extra.write_bytes(i.first.data(), i.first.size());
            
            buffer_extra.write_var_int(i.second.size());

            buffer_extra.write_bytes(i.second.data(), i.second.size());
        }
        
        buffer_extra.write_bytes(&extra_[0], extra_.size());
        
        m_comment.append(buffer_extra.data(), buffer_extra.size());
    }

    /**
     * Write the comment.
     */
    buffer.write_var_int(m_comment.size());
    buffer.write_bytes(m_comment.data(), m_comment.size());

    auto separator_pos = m_comment.find("\0", 0, 1);

    if (std::string::npos != separator_pos)
    {
        m_comment.erase(separator_pos);
    }
    
    m_value.erase("n");
}

void accounting_entry::decode()
{
    decode(*this);
}

void accounting_entry::decode(data_buffer & buffer, const bool & decode_version)
{
    if (decode_version)
    {
        /**
         * Read the version.
         */
        buffer.read_uint32();
    }
    
    /**
     * Read the credit debit.
     */
    m_credit_debit = buffer.read_int64();
    
    /**
     * Read the time.
     */
    m_time = buffer.read_int64();
    
    /**
     * Read the other account.
     */
    m_other_account.resize(buffer.read_var_int());
    buffer.read_bytes(
        const_cast<char *> (m_other_account.data()), m_other_account.size()
    );
    
    /**
     * Read the comment.
     */
    m_comment.resize(buffer.read_var_int());
    buffer.read_bytes(const_cast<char *> (m_comment.data()), m_comment.size());

    auto separator_pos = m_comment.find("\0", 0, 1);
    
    m_value.clear();
    
    /**
     * Read the comment extra.
     */
    if (separator_pos != std::string::npos)
    {
        data_buffer buffer_extra(
            m_comment.data() + (separator_pos + 1),
            m_comment.size() - (separator_pos + 1)
        );
        
        auto len_extra = buffer_extra.read_var_int();
        
        for (auto i = 0; i < len_extra; i++)
        {
            std::string first;
            
            first.resize(buffer_extra.read_var_int());
            
            buffer_extra.read_bytes(
                const_cast<char *> (first.data()), first.size()
            );

            std::string second;
            
            second.resize(buffer_extra.read_var_int());
            
            buffer_extra.read_bytes(
                const_cast<char *> (second.data()), second.size()
            );
            
            m_value.insert(std::make_pair(first, second));
        }
        
        extra_ = std::vector<char> (
            buffer_extra.data(), buffer_extra.data() + buffer_extra.size()
        );
    }

    wallet::read_order_position(m_order_position, m_value);

    if (std::string::npos != separator_pos)
    {
        m_comment.erase(separator_pos);
    }
    
    m_value.erase("n");
}

void accounting_entry::set_null()
{
    m_credit_debit = 0;
    m_time = 0;
    m_account.clear();
    m_other_account.clear();
    m_comment.clear();
    m_order_position = -1;
}

const std::int64_t & accounting_entry::credit_debit() const
{
    return m_credit_debit;
}

const std::int64_t & accounting_entry::time() const
{
    return m_time;
}

std::string & accounting_entry::account()
{
    return m_account;
}

const std::string & accounting_entry::account() const
{
    return m_account;
}

const std::string & accounting_entry::other_account() const
{
    return m_other_account;
}

const std::string & accounting_entry::comment() const
{
    return m_comment;
}

const std::map<std::string, std::string> & accounting_entry::value() const
{
    return m_value;
}

void accounting_entry::set_order_position(const std::int64_t & val)
{
    m_order_position = val;
}

const std::int64_t & accounting_entry::order_position() const
{
    return m_order_position;
}

void accounting_entry::set_entry_number(const std::uint64_t & value)
{
    m_entry_number = value;
}

const std::uint64_t & accounting_entry::entry_number() const
{
    return m_entry_number;
}
