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

#ifndef COIN_HD_ECDSA_HPP
#define COIN_HD_ECDSA_HPP

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace coin {
    
    /**
     * Implements ECDSA routines for Deterministic key generation.
     */
    namespace hd_ecdsa {
    
        /**
         * Implements an ECDSA key.
         */
        class key
        {
            public:
            
                /**
                 * EC_KEY_regenerate_key
                 * @param eckey The EC_KEY.
                 * @param priv_key The BIGNUM.
                 */
                bool static EC_KEY_regenerate_key(
                    EC_KEY * eckey, BIGNUM * priv_key
                    )
                {
                    if (eckey == 0)
                    {
                        return false;
                    }
                    
                    const EC_GROUP * group = EC_KEY_get0_group(eckey);

                    auto ret = false;
                    
                    EC_POINT * pub_key = 0;
                    
                    BN_CTX * ctx = BN_CTX_new();
                    
                    if (ctx == 0)
                    {
                        goto done;
                    }

                    pub_key = EC_POINT_new(group);
                    
                    if (pub_key == 0)
                    {
                        goto done;
                    }

                    if (
                        !EC_POINT_mul(group, pub_key, priv_key, 0, 0, ctx)
                        )
                    {
                        goto done;
                    }

                    EC_KEY_set_private_key(eckey, priv_key);
                    EC_KEY_set_public_key(eckey, pub_key);

                    ret = true;

                    done:
                
                    if (pub_key)
                    {
                        EC_POINT_free(pub_key);
                    }
                    
                    if (ctx)
                    {
                        BN_CTX_free(ctx);
                    }
                    
                    return ret;
                }

                /**
                 * Constructor
                 */
                key()
                    : m_EC_KEY(0)
                    , m_key_is_set(false)
                {
                    m_EC_KEY = EC_KEY_new_by_curve_name(NID_secp256k1);
                    
                    if (m_EC_KEY == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_KEY_new_by_curve_name failed."
                        );
                    }
                    
                    EC_KEY_set_conv_form(
                        m_EC_KEY, POINT_CONVERSION_COMPRESSED
                    );
                }
            
                /**
                 * Destructor
                 */
                ~key()
                {
                    if (m_EC_KEY)
                    {
                        EC_KEY_free(m_EC_KEY), m_EC_KEY = 0;
                    }
                }
            
                /**
                 * Set's the private key.
                 * @param val The std::vector<std::uint8_t>.
                 */
                EC_KEY * set_private_key(const std::vector<std::uint8_t> & val)
                {
                    BIGNUM * bn = BN_bin2bn(&val[0], val.size(), NULL);
                    
                    if (bn == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": BN_bin2bn failed."
                        );
                    }

                    auto success = EC_KEY_regenerate_key(m_EC_KEY, bn);
                    
                    BN_clear_free(bn);
                    
                    if (success == false)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_KEY_set_private_key failed."
                        );
                    }
                    
                    m_key_is_set = true;
                    
                    return m_EC_KEY;
                }
            
                /**
                 * Set's the public key.
                 * @param val The std::vector<std::uint8_t>.
                 */
                EC_KEY * set_public_key(const std::vector<std::uint8_t> & val)
                {
                    if (val.size() == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": val is empty."
                        );
                    }

                    const auto * in = &val[0];
                    
                    if (!o2i_ECPublicKey(&m_EC_KEY, &in, val.size()))
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": o2i_ECPublicKey failed."
                        );
                    }
                    
                    m_key_is_set = true;
                    
                    return m_EC_KEY;
                }
            
                /**
                 * Get's the public key.
                 * @param is_compressed If true it is compressed.
                 */
                std::vector<std::uint8_t> get_public_key(
                    const bool & is_compressed = true
                    ) const
                {
                    if (m_key_is_set == false)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": key is not set."
                        );
                    }

                    if (is_compressed == false)
                    {
                        EC_KEY_set_conv_form(
                            m_EC_KEY, POINT_CONVERSION_UNCOMPRESSED
                        );
                    }
                    
                    auto size = i2o_ECPublicKey(m_EC_KEY, NULL);
                    
                    if (size == 0)
                    {
                        if (is_compressed == false)
                        {
                            EC_KEY_set_conv_form(
                                m_EC_KEY, POINT_CONVERSION_COMPRESSED
                            );
                        }
                        
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": i2o_ECPublicKey failed."
                        );
                    }

                    std::vector<std::uint8_t> ret(size, 0);
                    
                    auto * out = &ret[0];
                    
                    if (i2o_ECPublicKey(m_EC_KEY, &out) != size)
                    {
                        if (is_compressed == false)
                        {
                            EC_KEY_set_conv_form(
                                m_EC_KEY, POINT_CONVERSION_COMPRESSED
                            );
                        }
                        
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": i2o_ECPublicKey returned unexpected size."
                        );
                    }

                    if (is_compressed == false)
                    {
                        EC_KEY_set_conv_form(
                            m_EC_KEY, POINT_CONVERSION_COMPRESSED
                        );
                    }
                    
                    return ret;
                }
    
            private:
            
                /**
                 * The EC_KEY.
                 */
                EC_KEY * m_EC_KEY;
            
                /**
                 * If true the key is set.
                 */
                bool m_key_is_set;
    
            protected:
            
                // ...
        };
        
        /**
         * Implements an ECDSA point.
         */
        class point
        {
            public:
            
                /**
                 * Constructor
                 */
                point()
                    : m_group(0)
                    , m_point(0)
                    , m_ctx(0)
                {
                    /**
                     * Initialize
                     */
                    initialize();
                }
            
                /**
                 * Constructor
                 * @param other The point.
                 */
                point(const point & other)
                    : m_group(0)
                    , m_point(0)
                    , m_ctx(0)
                {
                    /**
                     * Initialize
                     */
                    initialize();
                    
                    if (!EC_GROUP_copy(m_group, other.m_group))
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_GROUP_copy failed."
                        );
                    }
                    
                    if (!EC_POINT_copy(m_point, other.m_point))
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_POINT_copy failed."
                        );
                    }
                }
            
                /**
                 * Constructor
                 * @param bytes The std::vector<std::uint8_t>.
                 */
                point(const std::vector<std::uint8_t> & bytes)
                    : m_group(0)
                    , m_point(0)
                    , m_ctx(0)
                {
                    /**
                     * Initialize
                     */
                    initialize();
                    
                    /**
                     * Set the bytes.
                     */
                    set_bytes(bytes);
                }
            
                /**
                 * Destructor
                 */
                ~point()
                {
                    if (m_point)
                    {
                        EC_POINT_free(m_point), m_point = 0;
                    }
                    
                    if (m_group)
                    {
                        EC_GROUP_free(m_group), m_group = 0;
                    }
                    
                    if (m_ctx)
                    {
                        BN_CTX_free(m_ctx), m_ctx = 0;
                    }
                }

                /**
                 * operator =
                 */
                point & operator = (const point & rhs)
                {
                    if (!EC_GROUP_copy(m_group, rhs.m_group))
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_GROUP_copy failed."
                        );
                    }
                    
                    if (!EC_POINT_copy(m_point, rhs.m_point))
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_POINT_copy failed."
                        );
                    }

                    return *this;
                }

                /**
                 * Sets the bytes.
                 * @param val The bytes.
                 */
                void set_bytes(const std::vector<std::uint8_t> & val)
                {
                    std::string err;

                    EC_POINT * result = 0;

                    BIGNUM * bn = BN_bin2bn(&val[0], val.size(), 0);
                    
                    if (bn == 0)
                    {
                        err = "BN_bin2bn failed.";
                        
                        goto failed;
                    }

                    result = EC_POINT_bn2point(m_group, bn, m_point, m_ctx);
                    
                    if (result == 0)
                    {
                        err = "EC_POINT_bn2point failed.";
                        
                        goto failed;
                    }

                    failed:
                    
                    if (bn)
                    {
                        BN_clear_free(bn);
                    }

                    if (err.size() > 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": " + err
                        );
                    }
                }
            
                /**
                 * The bytes.
                 */
                const std::vector<std::uint8_t> bytes() const
                {
                    std::vector<std::uint8_t> ret(33);

                    std::string err;

                    BIGNUM * result = 0;

                    BIGNUM * bn = BN_new();
                    
                    if (bn == 0)
                    {
                        err = "BN_new failed.";
                       
                        goto failed;
                    }

                    result = EC_POINT_point2bn(
                        m_group, m_point, POINT_CONVERSION_COMPRESSED,
                        bn, m_ctx
                    );
                    
                    if (result == 0)
                    {
                        err = "EC_POINT_point2bn failed.";
                    
                        goto failed;
                    }

                    assert(BN_num_bytes(bn) == 33);
                    
                    BN_bn2bin(bn, &ret[0]);

                    failed:
                    
                    if (bn)
                    {
                        BN_clear_free(bn);
                    }

                    if (err.size() > 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": " + err
                        );
                    }

                    return ret;
                }

                /**
                 * operator +=
                 * @param rhs The point.
                 */
                point & operator += (const point & rhs)
                {
                    if (
                        !EC_POINT_add(m_group, m_point, m_point, rhs.m_point,
                        m_ctx)
                        )
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": EC_POINT_add failed."
                        );
                    }
                    
                    return *this;
                }
            
                /**
                 * operator *=
                 * @param rhs The std::vector<std::uint8_t>.
                 */
                point & operator *= (const std::vector<std::uint8_t> & rhs)
                {
                    BIGNUM * bn = BN_bin2bn(&rhs[0], rhs.size(), 0);
                    
                    if (bn == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": BN_bin2bn failed."
                        );
                    }

                    auto result = EC_POINT_mul(
                        m_group, m_point, 0, m_point, bn, m_ctx
                    );
                    
                    BN_clear_free(bn);

                    if (result == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_POINT_mul failed."
                        );
                    }

                    return *this;
                }

                /**
                 * operator +
                 * @param rhs The point.
                 */
                const point operator + (const point & rhs) const
                {
                    return point(*this) += rhs;
                }
            
                /**
                 * operator *
                 * @param rhs The std::vector<std::uint8_t>.
                 */
                const point operator * (
                    const std::vector<std::uint8_t> & rhs
                    ) const
                {
                    return point(*this) *= rhs;
                }

                /**
                 * EC_POINT_mul
                 * @param n The std::vector<std::uint8_t>.
                 */
                void generator_mul(const std::vector<std::uint8_t> & n)
                {
                    BIGNUM * bn = BN_bin2bn(&n[0], n.size(), 0);
                    
                    if (bn == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": BN_bin2bn failed."
                        );
                    }

                    auto result = EC_POINT_mul(
                        m_group, m_point, bn, m_point, BN_value_one(), m_ctx
                    );
                    
                    BN_clear_free(bn);

                    if (result == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) +
                            ": EC_POINT_mul failed."
                        );
                    }
                }

                /**
                 * EC_POINT_mul
                 * @param n The std::vector<std::uint8_t>.
                 */
                void set_generator_mul(const std::vector<std::uint8_t> & n)
                {
                    BIGNUM * bn = BN_bin2bn(&n[0], n.size(), 0);
                    
                    if (bn == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": BN_bin2bn failed."
                        );
                    }

                    auto result = EC_POINT_mul(
                        m_group, m_point, bn, 0, 0, m_ctx
                    );
                    
                    BN_clear_free(bn);

                    if (result == 0)
                    {
                        throw std::runtime_error(
                            std::string(__FUNCTION__) + ": EC_POINT_mul failed."
                        );
                    }
                }

                /**
                 * EC_POINT_is_at_infinity
                 */
                bool is_at_infinity() const
                {
                    return EC_POINT_is_at_infinity(m_group, m_point);
                }
            
                /**
                 * EC_POINT_set_to_infinity
                 */
                void set_to_infinity()
                {
                    EC_POINT_set_to_infinity(m_group, m_point);
                }

                /**
                 * The EC_GROUP.
                 */
                const EC_GROUP * getGroup() const
                {
                    return m_group;
                }
            
                /**
                 * The EC_POINT.
                 */
                const EC_POINT * getPoint() const
                {
                    return m_point;
                }

            private:
            
                /**
                 * The EC_GROUP.
                 */
                EC_GROUP * m_group;
            
                /**
                 * The EC_POINT.
                 */
                EC_POINT * m_point;
            
                /**
                 * The BN_CTX.
                 */
                BN_CTX * m_ctx;
            
            protected:
            
                /**
                 * Performs initialisation.
                 */
                void initialize()
                {
                    std::string err;

                    m_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
                    
                    m_point = 0, m_ctx = 0;
                    
                    if (m_group == 0)
                    {
                        err = "EC_KEY_new_by_curve_name failed.";
                        
                        goto failed;
                    }

                    m_point = EC_POINT_new(m_group);
                    
                    if (m_point == 0)
                    {
                        err = "EC_POINT_new failed.";
                        
                        goto failed;
                    }

                    m_ctx = BN_CTX_new();
                    
                    if (m_ctx == 0)
                    {
                        err = "BN_CTX_new failed.";
                        
                        goto failed;
                    }

                    return;

                    failed:
                
                    if (m_group)
                    {
                        EC_GROUP_free(m_group), m_group = 0;
                    }
                    
                    if (m_point)
                    {
                        EC_POINT_free(m_point), m_point = 0;
                    }

                    throw std::runtime_error(
                        std::string(__FUNCTION__) + ": " + err
                    );
                }
        };
    
    } // namespace hd_ecdsa

} // namespace coin

#endif // COIN_HD_ECDSA_HPP
