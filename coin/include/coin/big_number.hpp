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

#ifndef COIN_BIG_NUMBER_HPP
#define COIN_BIG_NUMBER_HPP

#include <cstdint>
#include <stdexcept>
#include <vector>

#include <openssl/bn.h>

#include <coin/sha256.hpp>

namespace coin {

    class data_buffer;
    
    /**
     * Implements a big number.
     */
    class big_number : public BIGNUM
    {
        public:
        
            /**
             * Implements a context.
             */
            class context
            {
                public:
                
                    /**
                     * Constructor
                     */
                    context()
                        : m_bn_ctx(BN_CTX_new())
                    {
                        // ...
                    }
                
                    /**
                     * Destructor
                     */
                    ~context()
                    {
                        if (m_bn_ctx)
                        {
                            BN_CTX_free(m_bn_ctx);
                        }
                    }
                
                    /**
                     * operator BN_CTX *
                     */
                    operator BN_CTX * ()
                    {
                        return m_bn_ctx;
                    }
                
                    /**
                     * operator *
                     */
                    BN_CTX & operator * ()
                    {
                        return *m_bn_ctx;
                    }
                
                    /**
                     * operator &
                     */
                    BN_CTX ** operator & ()
                    {
                        return &m_bn_ctx;
                    }

                    /**
                     * operator !
                     */
                    bool operator ! ()
                    {
                        return m_bn_ctx == 0;
                    }
    
                private:
                
                    /**
                     * The BN_CTX.
                     */
                    BN_CTX * m_bn_ctx;
            
                protected:
                
                    /**
                     * operator =
                     */
                    BN_CTX * operator = (BN_CTX * other)
                    {
                        return m_bn_ctx = other;
                    }
            };
        
            /**
             * Constructor
             */
            big_number();
        
            /**
             * Copy Constructor
             */
            big_number(const big_number & b);

            /**
             * Constructor
             */
            big_number(std::int8_t n);
        
            /**
             * Constructor
             */
            big_number(std::int16_t n);
        
            /**
             * Constructor
             */
            big_number(std::int32_t n);
        
            /**
             * Constructor
             */
            big_number(std::int64_t n);
        
            /**
             * Constructor
             */
            big_number(std::uint8_t n);
        
            /**
             * Constructor
             */
            big_number(std::uint16_t n);
        
            /**
             * Constructor
             */
            big_number(std::uint32_t n);
        
            /**
             * Constructor
             */
            big_number(std::uint64_t n);
        
            /**
             * Constructor
             */
            explicit big_number(sha256 n);

            /**
             * Constructor
             */
            explicit big_number(const std::vector<std::uint8_t> & vch);
    
            /**
             * Constructor
             */
            explicit big_number(const std::string & hex);
        
            /**
             * Destructor
             */
            ~big_number();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);
        
            /**
             * operator =
             */
            big_number & operator = (const big_number & b)
            {
                if (!BN_copy((BIGNUM *)this, (BIGNUM *)&b))
                {
                    throw std::runtime_error("BN_copy failed");
                }
                return (*this);
            }
        
            /**
             * operator !
             */
            bool operator ! () const
            {
                return BN_is_zero(this);
            }

            /**
             * operator +=
             */
            big_number & operator += (const big_number & b)
            {
                if (!BN_add((BIGNUM *)this, (BIGNUM *)this, (BIGNUM *)&b))
                {
                    throw std::runtime_error("BN_add failed");
                }
                
                return *this;
            }

            /**
             * operator -=
             */
            big_number & operator -= (const big_number & b)
            {
                *this = *this - b;
                return *this;
            }

            /**
             * operator *=
             */
            big_number & operator *= (const big_number & b)
            {
                context pctx;
                
                if (!BN_mul((BIGNUM *)this, (BIGNUM *)this, (BIGNUM *)&b, pctx))
                {
                    throw std::runtime_error("BN_mul failed");
                }
                
                return *this;
            }

            /**
             * operator /=
             */
            big_number & operator /= (const big_number & b)
            {
                *this = *this / b;
                return *this;
            }

            /**
             * operator %=
             */
            big_number & operator %= (const big_number & b)
            {
                *this = *this % b;
                return *this;
            }

            /**
             * operator <<=
             */
            big_number & operator <<= (unsigned int shift)
            {
                if (!BN_lshift((BIGNUM *)this, (BIGNUM *)this, shift))
                {
                    throw std::runtime_error("BN_lshift failed");
                }
                
                return *this;
            }

            /**
             * operator >>=
             */
            big_number & operator >>= (unsigned int shift)
            {
                big_number a = 1;
                
                a <<= shift;
                
                if (BN_cmp((BIGNUM *)&a, (BIGNUM *)this) > 0)
                {
                    *this = 0;
                    return *this;
                }

                if (!BN_rshift((BIGNUM *)this, (BIGNUM *)this, shift))
                {
                    throw std::runtime_error("BN_rshift failed");
                }
                
                return *this;
            }

            /**
             * operator ++
             */
            big_number & operator ++ ()
            {
                if (!BN_add((BIGNUM *)this, (BIGNUM *)this, BN_value_one()))
                {
                    throw std::runtime_error("BN_add failed");
                }
                
                return *this;
            }

            /**
             * operator ++
             */
            const big_number operator ++ (int)
            {
                const big_number ret = *this;
                ++(*this);
                return ret;
            }

            /**
             * operator --
             */
            big_number & operator -- ()
            {
                big_number r;
                
                if (!BN_sub((BIGNUM *)&r, (BIGNUM *)this, BN_value_one()))
                {
                    throw std::runtime_error("BN_sub failed");
                }
                
                *this = r;
                
                return *this;
            }

            /**
             * operator --
             */
            const big_number operator -- (int)
            {
                const big_number ret = *this;
                
                --(*this);
                
                return ret;
            }
        
            /**
             * BN_is_zero
             */
            bool is_zero() const;
        
            /**
             * Sets ulong.
             * @param n The value.
             */
            void set_ulong(unsigned long n);
        
            /**
             * Gets a ulong.
             */
            unsigned long get_ulong() const;
        
            /**
             * Gets a uint.
             */
            unsigned int get_uint() const;
        
            /**
             * Gets an int.
             */
            int get_int() const;
        
            /**
             * Sets in64.
             * @param val The value.
             */
            void set_int64(std::int64_t val);
        
            /**
             * Gets a uint64.
             */
            std::uint64_t get_uint64();
        
            /**
             * Sets uint64.
             * @param val The value.
             */
            void set_uint64(std::uint64_t val);
        
            /**
             * Sets sha256.
             * @param val The sha256.
             */
            void set_sha256(sha256 val);
        
            /**
             * Gets a sha256 hash.
             */
            sha256 get_sha256();
        
            /**
             * Sets the vector.
             * @param val The vector.
             */
            void set_vector(const std::vector<std::uint8_t> & val);
        
            /**
             * Gets the vector.
             */
            std::vector<std::uint8_t> get_vector() const;
        
            /**
             * Sets the vector without reversing the input.
             */
            void set_vector_no_reverse(
                const std::vector<std::uint8_t> & bytes
            );
        
            /**
             * Gets the vector without reversing the output.
             */
            std::vector<std::uint8_t> get_vector_no_reverse() const;
    
            /**
             * Sets compact.
             * @param val The value.
             */
            big_number & set_compact(unsigned int val);
        
            /**
             * Gets compact.
             */
            unsigned int get_compact() const;
        
            /**
             * Set's from hex.
             * @param str The std::string.
             */
            void set_hex(const std::string & str);
        
            /**
             * Converts to an std::string.
             * @param base The base.
             */
            std::string to_string(int base = 10) const;
        
            /**
             * Gets the hexadecimal std::string representation.
             */
            std::string get_hex() const;

            /**
             * operator -
             */
            friend inline const big_number operator - (
                const big_number & a, const big_number & b
            );
        
            /**
             * operator /
             */
            friend inline const big_number operator / (
                const big_number & a, const big_number & b
            );
        
            /**
             * operator %
             */
            friend inline const big_number operator % (
                const big_number & a, const big_number & b
            );
        
        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
    /**
     * operator +
     * @param a The lhs big_number.
     * @param b The rhs big_number.
     */
    inline const big_number operator + (
        const big_number & a, const big_number & b
        )
    {
        big_number r;
        
        if (!BN_add(&r, &a, &b))
        {
            throw std::runtime_error("BN_add failed");
        }
        
        return r;
    }

    /**
     * operator -
     */
    inline const big_number operator - (
        const big_number & a, const big_number & b
        )
    {
        big_number r;
        
        if (!BN_sub(&r, &a, &b))
        {
            throw std::runtime_error("BN_sub failed");
        }
        
        return r;
    }

    /**
     * operator -
     */
    inline const big_number operator - (const big_number & a)
    {
        big_number r(a);
        
        BN_set_negative(&r, !BN_is_negative(&r));
        
        return r;
    }

    /**
     * operator *
     */
    inline const big_number operator * (
        const big_number & a, const big_number & b
        )
    {
        big_number::context pctx;
        big_number r;
        
        if (!BN_mul(&r, &a, &b, pctx))
        {
            throw std::runtime_error("BN_mul failed");
        }
        return r;
    }

    /**
     * operator /
     */
    inline const big_number operator / (
        const big_number & a, const big_number & b
        )
    {
        big_number::context pctx;
        big_number r;
        
        if (!BN_div(&r, NULL, &a, &b, pctx))
        {
            throw std::runtime_error("BN_div failed");
        }
        return r;
    }

    /**
     * operator %
     */
    inline const big_number operator % (
        const big_number & a, const big_number & b
        )
    {
        big_number::context pctx;
        big_number r;
        
        if (!BN_mod(&r, &a, &b, pctx))
        {
            throw std::runtime_error("BN_div failed");
        }
        return r;
    }

    /**
     * operator <<
     */
    inline const big_number operator << (
        const big_number & a, unsigned int shift
        )
    {
        big_number r;
        
        if (!BN_lshift(&r, &a, shift))
        {
            throw std::runtime_error("BN_lshift failed");
        }
        
        return r;
    }

    /**
     * operator >>
     */
    inline const big_number operator >> (
        const big_number & a, unsigned int shift
        )
    {
        big_number r = a;
        r >>= shift;
        return r;
    }

    /**
     * operator ==
     */
    inline bool operator == (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) == 0;
    }

    /**
     * operator !=
     */
    inline bool operator != (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) != 0;
    }

    /**
     * operator <=
     */
    inline bool operator <= (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) <= 0;
    }

    /**
     * operator >=
     */
    inline bool operator >= (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) >= 0;
    }

    /**
     * operator <
     */
    inline bool operator < (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) < 0;
    }

    /**
     * operator >
     */
    inline bool operator > (const big_number & a, const big_number & b)
    {
        return BN_cmp(&a, &b) > 0;
    }

} // namespace coin

#endif // COIN_BIG_NUMBER_HPP
