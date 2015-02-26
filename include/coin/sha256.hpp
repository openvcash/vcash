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

#ifndef COIN_SHA256_HPP
#define COIN_SHA256_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

extern "C"
{
    #include <openssl/sha.h>
}

namespace coin {

    /**
     * Implements sha256.
     */
    class sha256
    {
        public:
        
            /**
             * The digest length.
             */
            enum { digest_length = 32 };
        
            /**
             * The block length.
             */
            enum { block_length = 64 };

            /**
             * Constructor
             */
            sha256();
        
            /**
             * Constructor
             */
            sha256(std::uint64_t b);
        
            /**
             * Constructor
             * @param hex The hex.
             */
            sha256(const std::string & hex);
        
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            sha256(
                const std::uint8_t * buf, const std::size_t & len
            );
        
            /**
             * Creates a sha256 from a digest.
             * @param digest The digest.
             */
            static sha256 from_digest(const std::uint8_t * digest);
        
            /**
             * init
             */
            void init();
        
            /**
             * final
             */
            void final();

            /**
             * update
             * @param buf The buf.
             * @param len The length.
             */
            void update(
                const std::uint8_t * buf, std::size_t len
            );
        
            /**
             * Performs a hash operation.
             * @param buf The buffer.
             * @param len The length.
             */
            static std::array<std::uint8_t, digest_length> hash(
                const std::uint8_t * buf, const std::size_t & len
            );

            /**
             * The string representation.
             */
            std::string to_string() const;
    
            /**
             * The 64-bit representation from index.
             * @param index The index.
             */
            std::uint64_t to_uint64(const std::uint32_t & index = 0) const;

            /**
             * If true it is empty.
             */
            bool is_empty() const;
        
            /**
             * Clears
             */
            void clear();
        
            /**
             * The digest.
             */
            std::uint8_t * digest();
        
            /**
             * The digest.
             */
            const std::uint8_t * digest() const;
        
            /**
             * operator ~
             */
            const sha256 operator ~ () const
            {
                sha256 ret;
                
                auto ptr1 = reinterpret_cast<std::uint32_t *>(ret.m_digest);
                auto ptr2 = reinterpret_cast<const std::uint32_t *>(m_digest);
                
                for (
                    auto i = 0; i < digest_length  / sizeof(std::uint32_t); i++
                    )
                {
                    ptr1[i] = ~ptr2[i];
                }
                
                return ret;
            }
    
            /**
             * operator =
             */
            sha256 & operator = (const sha256 & b)
            {
                std::memcpy(m_digest, b.digest(), sha256::digest_length);
             
                std::memcpy(&context_, &b.context_, sizeof(context_));
                
                return *this;
            }
    
            /**
             * operator <
             */
            friend inline bool operator < (const sha256 & a, const sha256 & b)
            {
                for (
                    int i = digest_length / sizeof(std::uint32_t) - 1;
                    i >= 0; i--
                    )
                {
                    auto ptr1 =
                        reinterpret_cast<const std::uint32_t *>(a.m_digest)
                    ;
                    auto ptr2 =
                        reinterpret_cast<const std::uint32_t *>(b.m_digest)
                    ;
                    
                    if (ptr1[i] < ptr2[i])
                    {
                        return true;
                    }
                    else if (ptr1[i] > ptr2[i])
                    {
                        return false;
                    }
                }

                return false;
            }

            /**
             * operator >
             */
            friend inline bool operator > (const sha256 & a, const sha256 & b)
            {
                for (
                    int i = digest_length / sizeof(std::uint32_t) - 1;
                    i >= 0; i--
                    )
                {
                    auto ptr1 =
                        reinterpret_cast<const std::uint32_t *>(a.m_digest)
                    ;
                    auto ptr2 =
                        reinterpret_cast<const std::uint32_t *>(b.m_digest)
                    ;
                    
                    if (ptr1[i] > ptr2[i])
                    {
                        return true;
                    }
                    else if (ptr1[i] < ptr2[i])
                    {
                        return false;
                    }
                }
                
                return false;
            }
        
            /**
             * operator <
             */
            friend inline bool operator <= (const sha256 & a, const sha256 & b)
            {
                for (
                    int i = digest_length / sizeof(std::uint32_t) - 1;
                    i >= 0; i--
                    )
                {
                    auto ptr1 =
                        reinterpret_cast<const std::uint32_t *>(a.m_digest)
                    ;
                    auto ptr2 =
                        reinterpret_cast<const std::uint32_t *>(b.m_digest)
                    ;
                    
                    if (ptr1[i] < ptr2[i])
                    {
                        return true;
                    }
                    else if (ptr1[i] > ptr2[i])
                    {
                        return false;
                    }
                }
                
                return true;
            }
    
            /**
             * operator >>=
             */
            sha256 & operator >>= (std::uint32_t shift)
            {
                sha256 a(*this);
                
                auto ptr1 = reinterpret_cast<std::uint32_t *>(m_digest);
                auto ptr2 = reinterpret_cast<std::uint32_t *>(a.m_digest);
                
                for (int i = 0; i < digest_length / sizeof(std::uint32_t); i++)
                {
                    ptr1[i] = 0;
                }
        
                int k = shift / 32;
                
                shift = shift % 32;
                
                for (int i = 0; i < digest_length / sizeof(std::uint32_t); i++)
                {
                    if (i - k - 1 >= 0 && shift != 0)
                    {
                        ptr1[i - k - 1] |= (ptr2[i] << (32 - shift));
                    }
                    
                    if (i - k >= 0)
                    {
                        ptr1[i - k] |= (ptr2[i] >> shift);
                    }
                }
                
                return *this;
            }

            /**
             * operator ==
             */
            friend inline bool operator == (const sha256 & a, const sha256 & b)
            {
                for (auto i = 0; i < digest_length / sizeof(std::uint32_t); i++)
                {
                    auto ptr1 =
                        reinterpret_cast<const std::uint32_t *>(a.m_digest)
                    ;
                    auto ptr2 =
                        reinterpret_cast<const std::uint32_t *>(b.m_digest)
                    ;
                
                    if (ptr1[i] != ptr2[i])
                    {
                        return false;
                    }
                }
                
                return true;
            }
        
            /**
             * operator ^=
             */
            sha256 & operator ^= (const sha256 & b)
            {
                for (auto i = 0; i < digest_length / sizeof(std::uint32_t); i++)
                {
                    auto ptr1 =
                        reinterpret_cast<std::uint32_t *>(m_digest)
                    ;
                    auto ptr2 =
                        reinterpret_cast<const std::uint32_t *>(b.m_digest)
                    ;
                
                    ptr1[i] ^= ptr2[i];
                }

                return *this;
            }
        
            /**
             * operator ^
             */
            friend inline const sha256 operator ^ (
                const sha256 & a, const sha256 & b
                )
            {
                return sha256(a) ^= b;
            }

            /**
             * operator ==
             */
            friend inline bool operator == (
                const sha256 & a, const std::uint64_t & b
                )
            {
                std::uint32_t part1 = *((std::uint32_t *)(&a.m_digest[0]));
                
                if (part1 != static_cast<std::uint32_t> (b))
                {
                    return false;
                }
                
                std::uint32_t part2 = *((std::uint32_t *)(
                    &a.m_digest[sizeof(std::uint32_t)])
                );
                
                if (part2 != (unsigned int)(b >> 32))
                {
                    return false;
                }
                
                for (
                    auto i = sizeof(std::uint64_t);
                    i < digest_length  - sizeof(std::uint64_t); i++
                    )
                {
                    if (a.m_digest[i] != 0)
                    {
                        return false;
                    }
                }
                
                return true;
            }
        
            /**
             * operator !=
             */
            friend inline bool operator != (const sha256 & a, const sha256 & b)
            {
                return (!(a == b));
            }
        
        private:
        
            /**
             * The digest.
             */
            std::uint8_t m_digest[digest_length];

        protected:
        
            /**
             * The context.
             */
            SHA256_CTX context_;
    };
    
    inline const sha256 operator >> (const sha256 & a, unsigned int shift)
    {
        return sha256(a) >>= shift;
    }

} // namespace coin

#endif // COIN_SHA256_HPP
