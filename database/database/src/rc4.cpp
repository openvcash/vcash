/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#include <cassert>
#include <cstdio>
#include <cstring>

#include <database/logger.hpp>
#include <database/rc4.hpp>

using namespace database;

#define S_SWAP(a, b) do { \
    unsigned char t = sbox[a]; sbox[a] = sbox[b]; sbox[b] = t; \
} while(0)

static void rc4_skip(
    const char * key, const std::size_t & key_len,
    const std::size_t & skip_bytes, char * buf, const std::size_t & len
    )
{
	unsigned i, j, kpos;
	std::uint8_t sbox[256], *pos;

	for (i = 0; i < 256; i++)
    {
		sbox[i] = i;
    }
    
	j = 0, kpos = 0;
	
    for (i = 0; i < 256; i++)
    {
		j = (j + sbox[i] + key[kpos]) & 0xff;
		
        kpos++;
		
        if (kpos >= key_len)
        {
			kpos = 0;
        }
		
        S_SWAP(i, j);
	}

	i = j = 0;

	for (unsigned k = 0; k < skip_bytes; k++)
    {
		i = (i + 1) & 0xff;
		j = (j + sbox[i]) & 0xff;
		S_SWAP(i, j);
	}
    
	pos = (unsigned char *)buf;

	for (unsigned k = 0; k < len; k++)
    {
		i = (i + 1) & 0xff;
		j = (j + sbox[i]) & 0xff;
		S_SWAP(i, j);
		*pos++ ^= sbox[(sbox[i] + sbox[j]) & 0xff];
	}
}

rc4::rc4()
{
    // ...
}

rc4::~rc4()
{
    // ...
}

void rc4::set_key(const std::string & key)
{
   key_ = key;
}

void rc4::crypt(char * buf, const std::size_t & len)
{
    if (key_.empty())
    {
        log_error("RC4 crypt failed, empty key.");
    }
    else
    {
        rc4_skip(key_.c_str(), key_.size(), 0, buf, len);
    }
}

int rc4::run_test()
{
    char str[] = "This is a test for the rc4 cipher.";
    
    std::size_t len = strlen(str);
    
    rc4 ctx1, ctx2;
    
    ctx1.set_key("x9HehRBG7C6V7V1294cJYzryPgobo28r");
    ctx2.set_key("x9HehRBG7C6V7V1294cJYzryPgobo28r");
    
	printf("Plain text: %s \n", str);
    
	ctx1.crypt(str, len);
	
    printf("Encoded string: %s \n", str);
	
    ctx2.crypt(str, len);
	
    printf("Decoded string: %s \n", str);

    return 0;
}
