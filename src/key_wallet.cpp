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

#include <coin/constants.hpp>
#include <coin/key_wallet.hpp>

using namespace coin;

key_wallet::key_wallet(const std::int64_t & expires)
    : m_time_created(expires ? std::time(0) : 0)
    , m_time_expires(expires)
{
    // ...
}

void key_wallet::encode()
{
    encode(*this);
}

void key_wallet::encode(data_buffer & buffer)
{
    /**
     * Write the version.
     */
    buffer.write_uint32(constants::version_client);
    
    /**
     * Write the private key length.
     */
    buffer.write_var_int(m_key_private.size());
    
    /**
     * Write the private key.
     */
    if (m_key_private.size() > 0)
    {
        buffer.write_bytes(
            reinterpret_cast<const char *>(&m_key_private[0]),
            m_key_private.size()
        );
    }
    
    /**
     * Write the time created.
     */
    buffer.write_int64(m_time_created);
    
    /**
     * Write the time expires.
     */
    buffer.write_int64(m_time_expires);
    
    /**
     * Write the comment length.
     */
    buffer.write_var_int(m_comment.size());
    
    /**
     * Write the comment.
     */
    if (m_comment.size() > 0)
    {
        buffer.write_bytes(m_comment.data(), m_comment.size());
    }
}

void key_wallet::decode()
{
    decode(*this);
}

void key_wallet::decode(data_buffer & buffer)
{
    /**
     * Read the version.
     */
    buffer.read_uint32();
    
    /**
     * Read the private key length.
     */
    auto len = buffer.read_var_int();

    if (len > 0)
    {
        /**
         * Read the private key.
         */
        m_key_private.reserve(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *> (&m_key_private[0]), m_key_private.size()
        );
    }
    
    /**
     * Read the time created.
     */
    m_time_created = buffer.read_int64();
    
    /**
     * Read the time expires.
     */
    m_time_expires = buffer.read_int64();
    
    /**
     * Read the comment length.
     */
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        /**
         * Read the comment.
         */
        m_comment.reserve(len);
        
        buffer.read_bytes(
            const_cast<char *> (m_comment.data()), m_comment.size()
        );
    }
}

const key::private_t & key_wallet::key_private() const
{
    return m_key_private;
}
