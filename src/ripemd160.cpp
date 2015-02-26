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

#include <cstring>
#include <stdexcept>

#include <openssl/ripemd.h>

#include <coin/ripemd160.hpp>

using namespace coin;

ripemd160::ripemd160()
{
    std::fill(m_digest.begin(), m_digest.end(), 0);
}

ripemd160::ripemd160(const ripemd160 & other)
    : m_digest(other.digest())
{
    // ...
}

ripemd160::ripemd160(const std::uint8_t * buf, const std::size_t & len)
{
    RIPEMD160(buf, len, &m_digest[0]);
}

ripemd160::ripemd160(const digest_t & digest)
{
    m_digest = digest;
}

ripemd160::ripemd160(const std::vector<std::uint8_t> & value)
{
    if (value.size() == digest_length)
    {
        std::memcpy(&m_digest[0], &value[0], digest_length);
    }
    else
    {
        throw std::runtime_error("value is too large");
    }
}

ripemd160::digest_t ripemd160::hash(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    digest_t ret;
    
    RIPEMD160(buf, len, &ret[0]);
    
    return ret;
}

std::string ripemd160::to_string() const
{
    std::vector<char> ret(m_digest.size() * 2 + 1);
    
    for (auto i = 0; i < sizeof(m_digest); i++)
    {
        sprintf(
            &ret[0] + i * 2, "%02x", ((std::uint8_t *)&m_digest)
            [sizeof(m_digest) - i - 1]
        );
    }
    
    return std::string(&ret[0], &ret[0] + m_digest.size() * 2);
}

bool ripemd160::is_empty() const
{
    for (auto & i : m_digest)
    {
        if (i != 0)
        {
            return false;
        }
    }
    
    return true;
}

void ripemd160::clear()
{
    std::fill(m_digest.begin(), m_digest.end(), 0);
}

ripemd160::digest_t & ripemd160::digest()
{
    return m_digest;
}

const ripemd160::digest_t & ripemd160::digest() const
{
    return m_digest;
}
