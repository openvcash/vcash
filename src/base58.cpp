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

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include <coin/base58.hpp>
#include <coin/big_number.hpp>
#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/sha256.hpp>

using namespace coin;

static const char * g_base58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
;

/**
 * Encode a byte sequence as a base58 encoded string.
 */
inline std::string encode_base58(
    const std::uint8_t * ptr_begin, const std::uint8_t * ptr_end
    )
{
    big_number::context pctx;

    big_number bn58 = 58;
    big_number bn0 = 0;

    /**
     * Convert big endian data to little endian. Insert an extra zero at the
     * end to make sure the bug_number will interpret as a positive integer.
     */
    std::vector<std::uint8_t> tmp(ptr_end - ptr_begin + 1, 0);
    std::reverse_copy(ptr_begin, ptr_end, tmp.begin());

    /**
     * Convert little endian data to big_number.
     */
    big_number bn;
    bn.set_vector(tmp);

    /**
     * Convert big_number to std::string.
     */
    std::string str;

    /**
     * Reserve 138% to be safe.
     */
    str.reserve((ptr_end - ptr_begin) * 138 / 100 + 1);
    
    big_number dv;
    big_number rem;
    
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
        {
            throw std::runtime_error("BN_div failed");
        }
        
        bn = dv;
        
        unsigned int c = static_cast<unsigned int> (rem.get_ulong());
        
        str += g_base58[c];
    }

    /**
     * Leading zeroes encoded as base58 zeros.
     */
    for (const auto * p = ptr_begin; p < ptr_end && *p == 0; p++)
    {
        str += g_base58[0];
    }
    
    /**
     * Convert little endian std::string to big endian std::string.
     */
    std::reverse(str.begin(), str.end());
    
    return str;
}

/**
 * Encode a byte vector as a base58-encoded string.
 */
inline std::string encode_base58(const std::vector<std::uint8_t> & value)
{
    return encode_base58(&value[0], &value[0] + value.size());
}

/**
 * Decode a base58-encoded string into byte vector.
 */
inline bool decode_base58(const char * str, std::vector<std::uint8_t> & value)
{
    big_number::context pctx;
    
    value.clear();
    
    big_number bn58 = 58;
    big_number bn = 0;
    big_number bn_char;
    
    while (isspace(*str))
    {
        str++;
    }
    
    /**
     * Convert big endian string to big_number.
     */
    for (const char *  p = str; *p; p++)
    {
        const char * p1 = strchr(g_base58, *p);
        
        if (p1 == 0)
        {
            while (isspace(*p))
            {
                p++;
            }
            
            if (*p != '\0')
            {
                return false;
            }
            
            break;
        }
        
        bn_char.set_ulong(p1 - g_base58);
        
        if (!BN_mul(&bn, &bn, &bn58, pctx))
        {
            throw std::runtime_error("BN_mul failed");
        }
        
        bn += bn_char;
    }

    /**
     * Get big_numeber as little endian data.
     */
    auto tmp = bn.get_vector();

    /**
     * Trim off sign byte if present.
     */
    if (tmp.size() >= 2 && tmp.end()[-1] == 0 && tmp.end()[-2] >= 0x80)
    {
        tmp.erase(tmp.end()-1);
    }
    
    /**
     * Restore leading zeros.
     */
    int leading_zeros = 0;
    
    for (const char* p = str; *p == g_base58[0]; p++)
    {
        leading_zeros++;
    }
    
    value.assign(leading_zeros + tmp.size(), 0);

    /*
     * Convert little endian data to big endian.
     */
    std::reverse_copy(
        tmp.begin(), tmp.end(), value.end() - tmp.size()
    );
    
    return true;
}

/**
 * Decode a base58-encoded string into byte vector.
 */
inline bool decode_base58(
    const std::string & str, std::vector<std::uint8_t> & value
    )
{
    return decode_base58(str.c_str(), value);
}

/**
 * Encode a byte vector to a base58-encoded string, including checksum.
 */
inline std::string encode_base58_check(const std::vector<std::uint8_t> & value)
{
    /**
     * Add 4-byte hash check to the end.
     */
    std::vector<std::uint8_t> vch(value);
    
    auto hash = hash::sha256d(&value[0], value.size());
    
    vch.insert(vch.end(), &hash[0], &hash[0] + 4);
    
    return encode_base58(vch);
}

/**
 * Decode a base58-encoded string that includes a checksum, into byte vector.
 */
inline bool decode_base58_check(
    const char * str, std::vector<std::uint8_t> & value
    )
{
    if (!decode_base58(str, value))
    {
        return false;
    }
    
    if (value.size() < 4)
    {
        value.clear();
        
        return false;
    }
    
    auto hash = hash::sha256d(&value[0], value.size() - 4);

    if (std::memcmp(&hash[0], &value[value.size() - 4], 4) != 0)
    {
        value.clear();
        
        return false;
    }
    
    value.resize(value.size() - 4);
    
    return true;
}

base58::base58()
    : m_version(0)
{
    // ...
}

base58::~base58()
{
    if (m_data.size() > 0)
    {
        std::memset(&m_data[0], 0, m_data.size());
    }
}

void base58::set_data(
    const int & version, const char * buf, const std::size_t & len
    )
{
    m_version = version;
    
    m_data.resize(len);
    
    if (m_data.size() > 0)
    {
        std::memcpy(&m_data[0], buf, len);
    }
}

void base58::set_data(
    const int & version, const char * ptr_begin, const char * ptr_end
    )
{
    set_data(version, ptr_begin, ptr_end - ptr_begin);
}

bool base58::set_string(const std::string & value)
{
    std::vector<std::uint8_t> vchTemp;
    
    decode_base58_check(value.c_str(), vchTemp);
    
    if (vchTemp.empty())
    {
        m_data.clear();
        m_version = 0;
        return false;
    }
    
    m_version = vchTemp[0];

    m_data.resize(vchTemp.size() - 1);
    
    if (m_data.size() > 0)
    {
        std::memcpy(&m_data[0], &vchTemp[1], m_data.size());
    }
    
    std::memset(&vchTemp[0], 0, vchTemp.size());
    
    return true;
}

const std::string base58::to_string() const
{
    std::vector<std::uint8_t> vch(1, m_version);
    
    vch.insert(vch.end(), m_data.begin(), m_data.end());
    
    return encode_base58_check(vch);
}

int base58::compare_to(const base58 & b58) const
{
    if (m_version < b58.m_version)
    {
        return -1;
    }
    
    if (m_version > b58.m_version)
    {
        return 1;
    }
    
    if (m_data < b58.m_data)
    {
        return -1;
    }
    
    if (m_data > b58.m_data)
    {
        return 1;
    }
    
    return 0;
}

const std::uint8_t & base58::version() const
{
    return m_version;
}

std::vector<std::uint8_t> & base58::data()
{
    return m_data;
}
