/* libsodium: hash_sha256.c, v0.4.5 2014/04/16 */
/*
 * Copyright 2005,2007,2009 Colin Percival. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cassert>
#include <memory>

#include <coin/sha256.hpp>

using namespace coin;

sha256::sha256()
{
    std::memset(m_digest, 0, sizeof(m_digest));
}

sha256::sha256(std::uint64_t b)
{
    std::memset(m_digest, 0, sizeof(m_digest));
    
    *reinterpret_cast<std::uint32_t *>(&m_digest[0]) =
        static_cast<std::uint32_t> (b)
    ;
    
    *reinterpret_cast<std::uint32_t *>(&m_digest[0] + sizeof(std::uint32_t)) =
        static_cast<std::uint32_t> (b >> 32)
    ;
}

sha256::sha256(const std::string & hex)
{
    std::memset(m_digest, 0, sizeof(m_digest));
    
    auto psz = hex.c_str();

    while (isspace(*psz))
    {
        psz++;
    }

    if (psz[0] == '0' && tolower(psz[1]) == 'x')
    {
        psz += 2;
    }

    static const std::uint8_t phexdigit[256] =
    {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,
        0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0, 0, 0, 0, 0,0xa, 0xb, 0xc, 0xd,
        0xe, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    
    const char * pbegin = psz;
    
    while (phexdigit[(std::uint8_t)*psz] || *psz == '0')
    {
        psz++;
    }
    
    psz--;
    
    std::uint8_t * p1 = (std::uint8_t *)&m_digest;
    std::uint8_t * pend = p1 + digest_length * 4;
    
    while (psz >= pbegin && p1 < pend)
    {
        *p1 = phexdigit[(std::uint8_t)*psz--];
    
        if (psz >= pbegin)
        {
            *p1 |= (phexdigit[(std::uint8_t)*psz--] << 4);
            p1++;
        }
    }
}

sha256::sha256(const std::uint8_t * buf, const std::size_t & len)
{
    SHA256_CTX ctx;
    
    init(ctx);
    update(ctx, buf, len);
    final(ctx);
}

sha256 sha256::from_digest(const std::uint8_t * digest)
{
    sha256 ret;
    
    std::memcpy(ret.digest(), digest, digest_length);
    
    return ret;
}

void sha256::init(SHA256_CTX & ctx)
{
    SHA256_Init(&ctx);
}

void sha256::final(SHA256_CTX & ctx)
{
    SHA256_Final(m_digest, &ctx);
}

void sha256::update(
    SHA256_CTX & ctx, const std::uint8_t * buf, std::size_t len
    )
{
    SHA256_Update(&ctx, buf, len);
}

std::array<std::uint8_t, sha256::digest_length> sha256::hash(
    const std::uint8_t * buf, const std::size_t & len
    )
{
    std::array<std::uint8_t, digest_length> ret;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final(&ret[0], &ctx);

    return ret;
}

std::string sha256::to_string() const
{
    char ret[sha256::digest_length * 2 + 1];
    
    for (auto i = 0; i < sizeof(m_digest); i++)
    {
        sprintf(
            ret + i * 2, "%02x", ((std::uint8_t *)&m_digest)
            [sizeof(m_digest) - i - 1]
        );
    }
    
    return std::string(ret, ret + sha256::digest_length * 2);
}

std::uint64_t sha256::to_uint64(const std::uint32_t & index) const
{
    auto ptr = reinterpret_cast<const std::uint32_t *>(m_digest);
    
    return ptr[2 * index] | (std::uint64_t)ptr[2 * index + 1] << 32;
}

bool sha256::is_empty() const
{
    for (auto i = 0; i < digest_length; i++)
    {
        if (m_digest[i] != 0)
        {
            return false;
        }
    }
    
    return true;
}

void sha256::clear()
{
    std::memset(m_digest, 0, sizeof(m_digest));
}

std::uint8_t * sha256::digest()
{
    return m_digest;
}

const std::uint8_t * sha256::digest() const
{
    return m_digest;
}
