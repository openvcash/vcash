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

#include <coin/alert_unsigned.hpp>

using namespace coin;

alert_unsigned::alert_unsigned()
    : m_version(current_version)
    , m_relay_until(0)
    , m_expiration(0)
    , m_id(0)
    , m_cancel(0)
    , m_minimum_version(0)
    , m_maximum_version(0)
    , m_priority(0)
{
    set_null();
}

void alert_unsigned::encode()
{
    encode(*this);
}

void alert_unsigned::encode(data_buffer & buffer)
{
    buffer.write_int32(m_version);
    buffer.write_int64(m_relay_until);
    buffer.write_int64(m_expiration);
    buffer.write_int32(m_id);
    buffer.write_int32(m_cancel);
    
    buffer.write_var_int(m_cancels.size());
    
    for (auto & i : m_cancels)
    {
        buffer.write_int32(i);
    }
    
    buffer.write_int32(m_minimum_version);
    buffer.write_int32(m_maximum_version);
    
    buffer.write_var_int(m_sub_versions.size());
    
    for (auto & i : m_sub_versions)
    {
        buffer.write_var_int(i.size());
        buffer.write_bytes(i.data(), i.size());
    }
    
    buffer.write_int32(m_priority);
    
    buffer.write_var_int(m_comment.size());
    buffer.write_bytes(m_comment.data(), m_comment.size());
    
    buffer.write_var_int(m_status.size());
    buffer.write_bytes(m_status.data(), m_status.size());
    
    buffer.write_var_int(m_reserved.size());
    buffer.write_bytes(m_reserved.data(), m_reserved.size());
}

bool alert_unsigned::decode()
{
    return decode(*this);
}

bool alert_unsigned::decode(data_buffer & buffer)
{
    m_version = buffer.read_int32();
    m_relay_until = buffer.read_int64();
    m_expiration = buffer.read_int64();
    m_id = buffer.read_int32();
    m_cancel = buffer.read_int32();
    
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        for (auto i = 0; i < len; i++)
        {
            auto cancel = buffer.read_int32();
            
            m_cancels.insert(cancel);
        }
    }
    
    m_minimum_version = buffer.read_int32();
    m_maximum_version = buffer.read_int32();
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        for (auto i = 0; i < len; i++)
        {
            auto len_sub_version = buffer.read_var_int();
            
            if (len_sub_version > 0)
            {
                std::string sub_version(len_sub_version, 0);
            
                buffer.read_bytes(
                    const_cast<char *> (sub_version.data()), sub_version.size()
                );
            
                m_sub_versions.insert(sub_version);
            }
        }
    }
    
    m_priority = buffer.read_int32();
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_comment.resize(len);
        
        buffer.read_bytes(
            const_cast<char *> (m_comment.data()), m_comment.size()
        );
    }
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_status.resize(len);
        
        buffer.read_bytes(
            const_cast<char *> (m_status.data()), m_status.size()
        );
    }
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_reserved.resize(len);
        
        buffer.read_bytes(
            const_cast<char *> (m_reserved.data()), m_reserved.size()
        );
    }
    
    return true;
}

void alert_unsigned::set_null()
{
    m_version = current_version;
    m_relay_until = 0;
    m_expiration = 0;
    m_id = 0;
    m_cancel = 0;
    m_cancels.clear();
    m_minimum_version = 0;
    m_maximum_version = 0;
    m_sub_versions.clear();
    m_priority = 0;
    m_comment.clear();
    m_status.clear();
    m_reserved.clear();
}

void alert_unsigned::set_version(const std::int32_t & val)
{
    m_version = val;
}

const std::int32_t & alert_unsigned::version() const
{
    return m_version;
}

void alert_unsigned::set_relay_until(const std::int32_t & val)
{
    m_relay_until = val;
}

const std::int64_t & alert_unsigned::relay_until() const
{
    return m_relay_until;
}

void alert_unsigned::set_expiration(const std::int32_t & val)
{
    m_expiration = val;
}

const std::int64_t & alert_unsigned::expiration() const
{
    return m_expiration;
}

const std::int32_t & alert_unsigned::id() const
{
    return m_id;
}

void alert_unsigned::set_cancel(const std::int32_t & val)
{
    m_cancel = val;
}

const std::int32_t & alert_unsigned::cancel() const
{
    return m_cancel;
}

const std::set<std::int32_t> & alert_unsigned::cancels() const
{
    return m_cancels;
}

void alert_unsigned::set_minimum_version(const std::int32_t & val)
{
    m_minimum_version = val;
}

const std::int32_t & alert_unsigned::minimum_version() const
{
    return m_minimum_version;
}

void alert_unsigned::set_maximum_version(const std::int32_t & val)
{
    m_maximum_version = val;
}

const std::int32_t & alert_unsigned::maximum_version() const
{
    return m_maximum_version;
}

const std::set<std::string> & alert_unsigned::sub_versions() const
{
    return m_sub_versions;
}

const std::int32_t & alert_unsigned::priority() const
{
    return m_priority;
}

void alert_unsigned::set_comment(const std::string & val)
{
    m_comment = val;
}

const std::string & alert_unsigned::comment() const
{
    return m_comment;
}

void alert_unsigned::set_status(const std::string & val)
{
    m_status = val;
}

const std::string & alert_unsigned::status() const
{
    return m_status;
}

const std::string & alert_unsigned::reserved() const
{
    return m_reserved;
}

std::string alert_unsigned::to_string() const
{
    std::string ret;
    
    ret += "alert_unsigned(\n";
    
    ret += "\tversion = " + std::to_string(m_version);
    ret += "\trelay until = " + std::to_string(m_relay_until);
    ret += "\texpiration = " + std::to_string(m_expiration);
    ret += "\tid = " + std::to_string(m_id);
    ret += "\tcancel = " + std::to_string(m_cancel);
    
    ret += "\tcancels = ";
    
    for (auto & i : m_cancels)
    {
        ret += std::to_string(i) + " ";
    }
    
    ret += "\n";
    
    ret += "\tminimum version = " + std::to_string(m_minimum_version);
    ret += "\tmaximum version = " + std::to_string(m_maximum_version);
    
    ret += "\tsub versions = ";
    
    for (auto & i : m_sub_versions)
    {
        ret += "\"" + i + "\"";
    }
    
    ret += "\n";
    
    ret += "\tpriority = " + std::to_string(m_priority);
    
    ret += "\ncomment = \"" + m_comment + "\"\n";
    ret += "\nstatus = \"" + m_status + "\"\n";
    ret += "\nreserved = \"" + m_reserved + "\"\n";
    
    ret += ")\n";
    
    return ret;
}
