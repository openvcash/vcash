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

#include <openssl/rand.h>

#include <coin/endian.hpp>
#include <coin/hash.hpp>
#include <coin/ripemd160.hpp>

using namespace coin;

std::array<std::uint8_t, sha256::digest_length> hash::sha256d(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    std::array<std::uint8_t, 32> one, two;
    
    one = sha256::hash(buf, len);
    
    two = sha256::hash(&one[0], one.size());

    return two;
}

std::array<std::uint8_t, sha256::digest_length> hash::sha256d(
    const std::uint8_t * begin, const std::uint8_t * end
    )
{
    static std::uint8_t blank[1];

    sha256 one;
    
    one.update(
        (begin == end ? blank : &begin[0]),
        (end - begin) * sizeof(begin[0])
    );
    one.final();
    
    std::array<std::uint8_t, 32> two = sha256::hash(
        one.digest(), sha256::digest_length
    );

    return two;
}

std::array<std::uint8_t, sha256::digest_length> hash::sha256d(
    const std::uint8_t * p1begin, const std::uint8_t * p1end,
    const std::uint8_t * p2begin, const std::uint8_t * p2endn
    )
{
    static std::uint8_t blank[1];

    sha256 one;
    
    one.update(
        (p1begin == p1end ? blank : &p1begin[0]),
        (p1end - p1begin) * sizeof(p1begin[0])
    );
    one.update(
        (p2begin == p2endn ? blank : &p2begin[0]),
        (p2endn - p2begin) * sizeof(p2begin[0])
    );
    
    one.final();
    
    std::array<std::uint8_t, 32> two = sha256::hash(
        one.digest(), sha256::digest_length
    );

    return two;
}

std::uint32_t hash::sha256d_checksum(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    /**
     * Calculate the digest using sha256d.
     */
    auto digest = sha256d(buf, len);
    
    return *reinterpret_cast<std::uint32_t *>(&digest[0]);
}


std::array<std::uint8_t, 20> hash::sha256_ripemd160(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    std::array<std::uint8_t, 32> one = sha256::hash(buf, len);

    std::array<std::uint8_t, 20> two = ripemd160::hash(&one[0], one.size());
    
    return two;
}

sha256 hash::sha256_random()
{
    sha256 ret;
    
    RAND_bytes(ret.digest(), sha256::digest_length);
    
    return ret;
}

std::array<std::uint8_t, whirlpool::digest_length / 2> hash::whirlpoolx(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    std::array<std::uint8_t, whirlpool::digest_length / 2> ret;
    
    auto digest = whirlpool::hash(buf, len);

	for (auto i = 0; i < (whirlpool::digest_length / 2); i++)
	{
        ret[i] =
            digest[i] ^ digest[i + ((whirlpool::digest_length / 2) / 2)]
        ;
	}
    
    return ret;
}

std::uint64_t hash::to_uint64(
    const std::uint8_t * buf, const std::size_t & n
    )
{
    return buf[2 * n] | (std::uint64_t)buf[2 * n + 1] << 32;
}