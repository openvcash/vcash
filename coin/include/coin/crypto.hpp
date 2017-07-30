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

#ifndef COIN_CRYPTO_HPP
#define COIN_CRYPTO_HPP

#include <cassert>
#include <cstdint>
#include <locale>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <boost/uuid/sha1.hpp>

namespace coin {

    class crypto
    {
        public:

            /**
             * Generates a random string.
             * @param len The length of the string to be generated.
             */
            static std::string random_string(const std::size_t & len)
            {
                std::string ret;
                
                static const std::string chars =
                    "abcdefghijklmnopqrstuvwxyz"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                ;
            
                static std::random_device rd;
                static std::mt19937_64 mt(rd());
                
                std::uniform_int_distribution<std::size_t> dist(
                    0, chars.size() - 1
                );

                for (auto i = 0 ; i < len; ++i )
                {
                    ret += chars[dist(mt)] ;
                }
                
                return ret;
            }
        
            /**
             * Performs base64 encoding.
             * @param buf
             * @param len
             */
            static std::string base64_encode(
                const uint8_t * buf, const std::size_t & len
                )
            {
                static const char b64_forward_table[65] =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                    "0123456789+/"
                ;
                std::string bindata((char *)buf, len);

                if (
                    bindata.size() > (
                    std::numeric_limits<std::string::size_type>::max() / 4u) * 3u
                    )
                {
                    throw std::runtime_error(
                        "String is too large for base64 encoding."
                        );
                }

                const std::size_t binlen = bindata.size();
                
                /**
                 * Pad the end with '='.
                 */
                std::string ret((((binlen + 2) / 3) * 4), '=');
                
                std::size_t outpos = 0;
                int bits_collected = 0;
                unsigned int accumulator = 0;
                
                const std::string::const_iterator binend = bindata.end();

                for (
                    std::string::const_iterator i = bindata.begin();
                    i != binend; ++i
                    )
                {
                    accumulator = (accumulator << 8) | (*i & 0xffu);
                    bits_collected += 8;
                    
                    while (bits_collected >= 6)
                    {
                        bits_collected -= 6;
                        ret[outpos++] = b64_forward_table[
                            (accumulator >> bits_collected) & 0x3fu
                        ];
                    }
                }
               
                if (bits_collected > 0)
                {
                    assert(bits_collected < 6);
                    accumulator <<= 6 - bits_collected;
                    ret[outpos++] = b64_forward_table[accumulator & 0x3fu];
                }
               
                assert(outpos >= (ret.size() - 2));
                assert(outpos <= ret.size());
                
                return ret;
            }

            /**
             * Performs base64 decoding.
             * @param buf
             * @param len
             */
            static std::string base64_decode(
                const char * buf, const std::size_t & len
                )
            {
                static const char b64_reverse_table[128] =
                {
                   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
                   52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
                   64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
                   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
                   64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
                };
            
                std::string ascdata(buf, len);
                
                std::string ret;
                int bits_collected = 0;
                unsigned int accumulator = 0;

                for (
                    std::string::const_iterator i = ascdata.begin();
                    i != ascdata.end(); ++i
                    )
                {
                    const int c = *i;
                    
                    /**
                     * Skip whitespace and padding.
                     */
                    if (isspace(c) || c == '=')
                    {
                        continue;
                    }
                    
                    if ((c > 127) || (c < 0) || (b64_reverse_table[c] > 63))
                    {
                        throw std::runtime_error("Illegal characters");
                    }
                    
                    accumulator = (accumulator << 6) | b64_reverse_table[c];
                    bits_collected += 6;
                    
                    if (bits_collected >= 8)
                    {
                        bits_collected -= 8;
                        ret += (char)((accumulator >> bits_collected) & 0xffu);
                    }
                }
               
                return ret;
            }

            /**
             * Calculates the HMAC-512 of the value given key.
             * @Param key The key.
             * @param value The value.
             */
            static std::string hmac_sha512(
                const std::string & key, const std::string & value
                )
            {
                std::uint8_t * digest = HMAC(
                    EVP_sha512(), key.data(), static_cast<int> (key.size()),
                    (std::uint8_t *)value.data(), value.size(), NULL, NULL
                );

                char hex[(64 * 2) + 1];
                
                for(auto i = 0; i < 64; i++)
                {
                     sprintf(&hex[i * 2], "%02x", (std::uint32_t)digest[i]);
                }
                
                return std::string(hex, 64 * 2);
            }
        
            /**
             * Calculates the HMAC-512 of the value given key.
             * @param value The key.
             * @Param key The value.
             */
            static std::vector<std::uint8_t> hmac_sha512(
                const std::vector<std::uint8_t> & key,
                const std::vector<std::uint8_t> & value
                )
            {
                std::uint8_t * digest = HMAC(
                    EVP_sha512(), &key[0], static_cast<int> (key.size()),
                    &value[0], value.size(), NULL, NULL
                );
                
                return std::vector<std::uint8_t> (digest, digest + 64);
            }
        
        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_CRYPTO_HPP
