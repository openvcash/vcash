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

#include <cstdint>
#include <vector>

#include <boost/algorithm/string.hpp>

#include <database/query.hpp>
#include <database/utility.hpp>

using namespace database;

query::query(const std::string & val)
    : m_str(val)
{
    auto i = val.find("&");
    
    if (i != std::string::npos)
    {
        std::vector<std::string> pairs1;
        boost::split(pairs1, val, boost::is_any_of("&"));
        
        for (auto & i : pairs1)
        {
            std::vector<std::string> pairs2;
            
            boost::split(pairs2, i, boost::is_any_of("="));
            
            if (pairs2.size() != 2)
            {
                continue;
            }
            
            m_pairs[pairs2[0]] = uri_decode(pairs2[1]);
        }
    }
    else
    {
        std::vector<std::string> pairs2;
        
        boost::split(pairs2, val, boost::is_any_of("="));
        
        if (pairs2.size() == 2)
        {
            m_pairs[pairs2[0]] = uri_decode(pairs2[1]);
        }
    }
    
    for (auto & i : m_pairs)
    {
        if (i.first.size() == 0 || i.second.size() == 0)
        {
            continue;
        }

        /**
         * Skip "private" terms.
         */
        if (utility::string::starts_with(i.first, "_"))
        {
            continue;
        }

        /**
         * Insert the pair.
         */
        m_pairs_public.insert(std::make_pair(i.first, i.second));
    }
}

const std::string & query::str() const
{
    return m_str;
}

std::map<std::string, std::string> & query::pairs()
{
    return m_pairs;
}

std::map<std::string, std::string> & query::pairs_public()
{
    return m_pairs_public;
}

const std::int8_t g_hex_2_dec[256] =
{
    /*       0  1  2  3   4  5  6  7   8  9  A  B   C  D  E  F */
    /* 0 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 1 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 2 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 3 */  0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
    
    /* 4 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 5 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 6 */ -1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 7 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    
    /* 8 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* 9 */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* A */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* B */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    
    /* C */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* D */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* E */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
    /* F */ -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1
};
    
std::string query::uri_decode(const std::string & sSrc)
{
    // Note from RFC1630:  "Sequences which start with a percent sign
    // but are not followed by two hexadecimal characters (0-9, A-F) are reserved
    // for future extension"
    
    const std::uint8_t * pSrc = (const std::uint8_t *)sSrc.c_str();
	const int SRC_LEN = sSrc.length();
    const std::uint8_t * SRC_END = pSrc + SRC_LEN;
    const std::uint8_t * SRC_LAST_DEC = SRC_END - 2;   // last decodable '%' 

    std::unique_ptr<char> pStart(new char[SRC_LEN]);
    
    char * pEnd = pStart.get();

    while (pSrc < SRC_LAST_DEC)
	{
		if (*pSrc == '%')
        {
            char dec1, dec2;
            if (-1 != (dec1 = g_hex_2_dec[*(pSrc + 1)])
                && -1 != (dec2 = g_hex_2_dec[*(pSrc + 2)]))
            {
                *pEnd++ = (dec1 << 4) + dec2;
                pSrc += 3;
                continue;
            }
        }

        *pEnd++ = *pSrc++;
	}

    // the last 2- chars
    while (pSrc < SRC_END)
    {
        *pEnd++ = *pSrc++;
    }

	return std::string(pStart.get(), pEnd);
}

const char g_safe[256] =
{
    /* 0 1 2 3  4 5 6 7  8 9 A B  C D E F */
    /* 0 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 1 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 2 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 3 */ 1,1,1,1, 1,1,1,1, 1,1,0,0, 0,0,0,0,
    /* 4 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* 5 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,
    /* 6 */ 0,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    /* 7 */ 1,1,1,1, 1,1,1,1, 1,1,1,0, 0,0,0,0,
    /* 8 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* 9 */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* A */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* B */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* C */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* D */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* E */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    /* F */ 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

std::string query::uri_encode(const std::string & val)
{
    const char dec_2_hex[16 + 1] = "0123456789ABCDEF";
    const std::uint8_t * ptr_src = (const std::uint8_t *)val.c_str();
    const int len_src = val.length();
    std::unique_ptr<char> ptr_start(new char[len_src * 3]);
    char * ptr_end = ptr_start.get();
    const std::uint8_t * const ptr_src_end = ptr_src + len_src;

    for (; ptr_src < ptr_src_end; ++ptr_src)
	{
		if (g_safe[*ptr_src])
        {
            *ptr_end++ = *ptr_src;
        }
        else
        {
            *ptr_end++ = '%';
            *ptr_end++ = dec_2_hex[*ptr_src >> 4];
            *ptr_end++ = dec_2_hex[*ptr_src & 0x0F];
        }
	}

    return std::string((char *)ptr_start.get(), (char *)ptr_end);
}
