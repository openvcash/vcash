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

#include <cassert>

#include <boost/asio.hpp>

#include <openssl/rand.h>

#include <coin/hash.hpp>
#include <coin/ripemd160.hpp>
#include <coin/utility.hpp>

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

    SHA256_CTX ctx;
    
    sha256 one;
    
    one.init(ctx);
    
    one.update(
        ctx, (begin == end ? blank : &begin[0]),
        (end - begin) * sizeof(begin[0])
    );
    
    one.final(ctx);
    
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

    SHA256_CTX ctx;
    
    sha256 one;
    
    one.init(ctx);
    
    one.update(
        ctx, (p1begin == p1end ? blank : &p1begin[0]),
        (p1end - p1begin) * sizeof(p1begin[0])
    );
    
    one.update(
        ctx, (p2begin == p2endn ? blank : &p2begin[0]),
        (p2endn - p2begin) * sizeof(p2begin[0])
    );
    
    one.final(ctx);
    
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

std::array<std::uint8_t, blake256::digest_length> hash::blake2568round(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    return blake256::hash(buf, len);
}

inline std::uint32_t ROTL32(const std::uint32_t & x, const std::int8_t & r)
{
    return x << r | x >> (32 - r);
}

std::uint32_t hash::murmur3(
    const std::uint32_t & seed, const std::uint8_t * buf,
    const std::size_t & len
    )
{
    std::uint32_t ret = seed;
    
    if (len > 0)
    {
        const std::uint32_t & c1 = 0xcc9e2d51;
        const std::uint32_t & c2 = 0x1b873593;
        
        const std::int32_t & block_count = static_cast<std::int32_t> (len) / 4;
        
        auto ptr_blocks =
            reinterpret_cast<const std::uint32_t *>(buf + block_count * 4)
        ;
        
        for (auto i = -block_count; i; i++)
        {
            std::uint32_t k1 = ptr_blocks[i];
            
            k1 *= c1;
            k1 = ROTL32(k1, 15);
            k1 *= c2;
            
            ret ^= k1;
            ret = ROTL32(ret, 13);
            ret = ret * 5 + 0xe6546b64;
        }
        
        auto ptr_tail =
            reinterpret_cast<const std::uint8_t *> (buf + block_count * 4)
        ;
        
        std::uint32_t k1 = 0;

        switch (len & 3)
        {
            case 3:
                k1 ^= ptr_tail[2] << 16;
            case 2:
                k1 ^= ptr_tail[1] << 8;
            case 1:
                k1 ^= ptr_tail[0];
            default:
            {
                // ...
            }
            break;
        }
        
        k1 *= c1;
        k1 = ROTL32(k1, 15);
        k1 *= c2;
        ret ^= k1;
    }
    
    ret ^= len;
    ret ^= ret >> 16;
    ret *= 0x85ebca6b;
    ret ^= ret >> 13;
    ret *= 0xc2b2ae35;
    ret ^= ret >> 16;
    
    return ret;
}

std::uint64_t hash::to_uint64(
    const std::uint8_t * buf, const std::size_t & n
    )
{
    return buf[2 * n] | (std::uint64_t)buf[2 * n + 1] << 32;
}

int hash::run_test()
{
    auto from_hex = utility::from_hex("");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0x00000000);
    
    from_hex = utility::from_hex("");
    
    assert(murmur3(0xFBA4C795, from_hex.data(), from_hex.size()) == 0x6a396f08);
    
    from_hex = utility::from_hex("");
    
    assert(murmur3(0xffffffff, from_hex.data(), from_hex.size()) == 0x81f16f39);
    
    from_hex = utility::from_hex("00");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0x514e28b7);
    
    from_hex = utility::from_hex("00");
    
    assert(murmur3(0xFBA4C795, from_hex.data(), from_hex.size()) == 0xea3f0b17);
    
    from_hex = utility::from_hex("ff");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xfd6cf10d);
    
    from_hex = utility::from_hex("0011");

    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0x16c6b7ab);
    
    from_hex = utility::from_hex("001122");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0x8eb51c3d);
    
    from_hex = utility::from_hex("00112233");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xb4471bf8);
    
    from_hex = utility::from_hex("0011223344");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xe2301fa8);
    
    from_hex = utility::from_hex("001122334455");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xfc2e4a15);
    
    from_hex = utility::from_hex("00112233445566");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xb074502c);
    
    from_hex = utility::from_hex("0011223344556677");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0x8034d2a0);
    
    from_hex = utility::from_hex("001122334455667788");
    
    assert(murmur3(0x00000000, from_hex.data(), from_hex.size()) == 0xb4698def);
    
    printf("hash::murmur3 passed tests\n");
    
    return 0;
}
