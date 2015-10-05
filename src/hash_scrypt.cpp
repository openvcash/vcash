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

#include <cstdlib>

#include <coin/data_buffer.hpp>
#include <coin/hash_scrypt.hpp>
#include <coin/pbkdf2.hpp>

#if (defined _MSC_VER || defined __linux__)
#include <coin/scrypt.hpp>
#else
#if (defined __x86_64__ || defined _M_X64 || defined _M_AMD64)

#define SCRYPT_3WAY 1
#define SCRYPT_BUFFER_SIZE (3 * 131072 + 63)

extern "C" int scrypt_best_throughput();
extern "C" void scrypt_core(
    std::uint32_t * X, std::uint32_t * V
);
extern "C" void scrypt_core_2way(
    std::uint32_t * X, std::uint32_t * Y, std::uint32_t * V
);
extern "C" void scrypt_core_3way(
    std::uint32_t * X, std::uint32_t * Y, std::uint32_t * Z, std::uint32_t * V
);

#else

#define SCRYPT_BUFFER_SIZE (131072 + 63)
extern  "C" void scrypt_core(std::uint32_t * X, std::uint32_t * V);

#endif
#endif // _MSC_VER

namespace coin {

void * scrypt_buffer_alloc()
{
    return malloc(SCRYPT_BUFFER_SIZE);
}

static void scrypt(
    const void * input, std::size_t inputlen, std::uint32_t * res,
    void * scratchpad
    )
{
    std::uint32_t * V;
    std::uint32_t X[32];
    V = (std::uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    pbkdf2::SHA256(
        (const std::uint8_t *)input, inputlen, (const std::uint8_t *)input,
        block::header_length, 1, (std::uint8_t *)X, 128
    );

    scrypt_core(X, V);

    pbkdf2::SHA256(
        (const std::uint8_t *)input, inputlen, (std::uint8_t *)X, 128, 1,
        (std::uint8_t *)res, 32
    );
}

void hash_scrypt(
    const void * input, std::size_t inputlen, std::uint32_t *res,
    void * scratchpad
    )
{
    return scrypt(input, inputlen, res, scratchpad);
}

#ifdef SCRYPT_3WAY
static void scrypt_2way(
    const void *input1, const void *input2, size_t input1len,
    size_t input2len, uint32_t *res1, uint32_t *res2, void *scratchpad
    )
{
    uint32_t *V;
    uint32_t X[32], Y[32];
    V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    pbkdf2::SHA256((const uint8_t*)input1, input1len, (const uint8_t*)input1, input1len, 1, (uint8_t *)X, 128);
    pbkdf2::SHA256((const uint8_t*)input2, input2len, (const uint8_t*)input2, input2len, 1, (uint8_t *)Y, 128);

    scrypt_core_2way(X, Y, V);

    pbkdf2::SHA256((const uint8_t*)input1, input1len, (uint8_t *)X, 128, 1, (uint8_t*)res1, 32);
    pbkdf2::SHA256((const uint8_t*)input2, input2len, (uint8_t *)Y, 128, 1, (uint8_t*)res2, 32);
}

static void scrypt_3way(const void *input1, const void *input2, const void *input3,
   size_t input1len, size_t input2len, size_t input3len, uint32_t *res1, uint32_t *res2, uint32_t *res3,
   void *scratchpad)
{
    uint32_t *V;
    uint32_t X[32], Y[32], Z[32];
    V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

    pbkdf2::SHA256((const uint8_t*)input1, input1len, (const uint8_t*)input1, input1len, 1, (uint8_t *)X, 128);
    pbkdf2::SHA256((const uint8_t*)input2, input2len, (const uint8_t*)input2, input2len, 1, (uint8_t *)Y, 128);
    pbkdf2::SHA256((const uint8_t*)input3, input3len, (const uint8_t*)input3, input3len, 1, (uint8_t *)Z, 128);

    scrypt_core_3way(X, Y, Z, V);

    pbkdf2::SHA256((const uint8_t*)input1, input1len, (uint8_t *)X, 128, 1, (uint8_t*)res1, 32);
    pbkdf2::SHA256((const uint8_t*)input2, input2len, (uint8_t *)Y, 128, 1, (uint8_t*)res2, 32);
    pbkdf2::SHA256((const uint8_t*)input3, input3len, (uint8_t *)Z, 128, 1, (uint8_t*)res3, 32);
}
#endif

std::uint32_t scanhash_scrypt(
    block::header_t * pdata, void * scratchbuf,
    std::uint32_t max_nonce, std::uint32_t & hash_count,
    void * result, block::header_t * res_header
    )
{
    hash_count = 0;

    block::header_t data = *pdata;
    
    std::uint32_t hash[8];
    std::uint8_t * hashc = reinterpret_cast<std::uint8_t *> (&hash);

#ifdef SCRYPT_3WAY
    block::header_t data2 = *pdata;
    
    std::uint32_t hash2[8];
    std::uint8_t * hashc2 = reinterpret_cast<std::uint8_t *> (&hash2);

    block::header_t data3 = *pdata;
    
    std::uint32_t hash3[8];
    std::uint8_t * hashc3 = reinterpret_cast<std::uint8_t *> (&hash3);

    auto throughput = scrypt_best_throughput();
#endif

    std::uint32_t n = 0;

    while (1)
    {
        data.nonce = n++;
#ifdef SCRYPT_3WAY
        if (throughput >= 2 && n < max_nonce)
        {
            data2.nonce = n++;
            
            if (throughput >= 3)
            {
                data3.nonce = n++;
                
                data_buffer buffer, buffer2, buffer3;
                
                buffer.write_uint32(data.version);
                buffer.write_sha256(data.hash_previous_block);
                buffer.write_sha256(data.hash_merkle_root);
                buffer.write_uint32(data.timestamp);
                buffer.write_uint32(data.bits);
                buffer.write_uint32(data.nonce);

                assert(buffer.size() == block::header_length);
    
                buffer2.write_uint32(data2.version);
                buffer2.write_sha256(data2.hash_previous_block);
                buffer2.write_sha256(data2.hash_merkle_root);
                buffer2.write_uint32(data2.timestamp);
                buffer2.write_uint32(data2.bits);
                buffer2.write_uint32(data2.nonce);

                assert(buffer2.size() == block::header_length);
                
                buffer3.write_uint32(data3.version);
                buffer3.write_sha256(data3.hash_previous_block);
                buffer3.write_sha256(data3.hash_merkle_root);
                buffer3.write_uint32(data3.timestamp);
                buffer3.write_uint32(data3.bits);
                buffer3.write_uint32(data3.nonce);

                assert(buffer3.size() == block::header_length);
                
                scrypt_3way(
                    buffer.data(), buffer2.data(), buffer3.data(), 80, 80, 80,
                    hash, hash2, hash3, scratchbuf
                );
                
                hash_count += 3;

                if (hashc3[31] == 0 && hashc3[30] == 0)
                {
                    std::memcpy(result, hash3, 32);
                    
                    res_header = reinterpret_cast<block::header_t *>(&data3);

                    return data3.nonce;
                }
            }
            else
            {
                data_buffer buffer, buffer2;
                
                buffer.write_uint32(data.version);
                buffer.write_sha256(data.hash_previous_block);
                buffer.write_sha256(data.hash_merkle_root);
                buffer.write_uint32(data.timestamp);
                buffer.write_uint32(data.bits);
                buffer.write_uint32(data.nonce);

                assert(buffer.size() == block::header_length);
    
                buffer2.write_uint32(data2.version);
                buffer2.write_sha256(data2.hash_previous_block);
                buffer2.write_sha256(data2.hash_merkle_root);
                buffer2.write_uint32(data2.timestamp);
                buffer2.write_uint32(data2.bits);
                buffer2.write_uint32(data2.nonce);

                assert(buffer2.size() == block::header_length);
                
                scrypt_2way(
                    buffer.data(), buffer2.data(), 80, 80, hash, hash2,
                    scratchbuf
                );
                
                hash_count += 2;
            }

            if (hashc2[31] == 0 && hashc2[30] == 0)
            {
                std::memcpy(result, hash2, 32);

                return data2.nonce;
            }
        }
        else
        {
            data_buffer buffer;
            
            buffer.write_uint32(data.version);
            buffer.write_sha256(data.hash_previous_block);
            buffer.write_sha256(data.hash_merkle_root);
            buffer.write_uint32(data.timestamp);
            buffer.write_uint32(data.bits);
            buffer.write_uint32(data.nonce);

            assert(buffer.size() == block::header_length);
            
            scrypt(buffer.data(), 80, hash, scratchbuf);
            
            hash_count += 1;
        }
#else
        data_buffer buffer;
        
        buffer.write_uint32(data.version);
        buffer.write_sha256(data.hash_previous_block);
        buffer.write_sha256(data.hash_merkle_root);
        buffer.write_uint32(data.timestamp);
        buffer.write_uint32(data.bits);
        buffer.write_uint32(data.nonce);

        assert(buffer.size() == block::header_length);
        
        scrypt(buffer.data(), 80, hash, scratchbuf);
        
        hash_count += 1;
#endif
        if (hashc[31] == 0 && hashc[30] == 0)
        {
            std::memcpy(result, hash, 32);

            return data.nonce;
        }

        if (n >= max_nonce)
        {
            hash_count = 0xffff + 1;
            
            break;
        }
    }

    return static_cast<std::uint32_t> (-1);
}

} // namespace coin
