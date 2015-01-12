/*
 * Copyright (c) 2013-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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
#include <stdexcept>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/logger.hpp>

using namespace coin;

int EC_KEY_regenerate_key(EC_KEY * eckey, BIGNUM * priv_key)
{
    int ok = 0;
    
    BN_CTX * ctx = 0;
    EC_POINT * pub_key = 0;

    if (eckey == 0)
    {
        return 0;
    }
    
    const EC_GROUP * group = EC_KEY_get0_group(eckey);

    if ((ctx = BN_CTX_new()) == 0)
    {
        goto err;
    }
    
    pub_key = EC_POINT_new(group);

    if (pub_key == 0)
    {
        goto err;
    }
    
    if (!EC_POINT_mul(group, pub_key, priv_key, 0, 0, ctx))
    {
        goto err;
    }
    
    EC_KEY_set_private_key(eckey, priv_key);
    EC_KEY_set_public_key(eckey, pub_key);

    ok = 1;

err:

    if (pub_key)
    {
        EC_POINT_free(pub_key);
    }
    
    if (ctx != 0)
    {
        BN_CTX_free(ctx);
    }
    
    return ok;
}

int ECDSA_SIG_recover_key_GFp(
    EC_KEY * eckey, ECDSA_SIG * ecsig, const std::uint8_t * msg,
    int msglen, int recid, int check
    )
{
    if (!eckey)
    {
        return 0;
    }
    
    int ret = 0;
    
    BN_CTX * ctx = 0;
    BIGNUM * x = 0;
    BIGNUM * e = 0;
    BIGNUM * order = 0;
    BIGNUM * sor = 0;
    BIGNUM * eor = 0;
    BIGNUM * field = 0;
    EC_POINT * R = 0;
    EC_POINT * O = 0;
    EC_POINT * Q = 0;
    BIGNUM * rr = 0;
    BIGNUM * zero = 0;
    int n = 0;
    int i = recid / 2;

    const EC_GROUP * group = EC_KEY_get0_group(eckey);
    
    if ((ctx = BN_CTX_new()) == 0)
    {
        ret = -1;
        
        goto err;
    }
    
    BN_CTX_start(ctx);
    
    order = BN_CTX_get(ctx);
    
    if (!EC_GROUP_get_order(group, order, ctx))
    {
        ret = -2;
        
        goto err;
    }
    
    x = BN_CTX_get(ctx);
    
    if (!BN_copy(x, order))
    {
        ret = -1;
        
        goto err;
    }
    
    if (!BN_mul_word(x, i))
    {
        ret = -1;
        
        goto err;
    }
    
    if (!BN_add(x, x, ecsig->r))
    {
        ret = -1;
        
        goto err;
    }
    
    field = BN_CTX_get(ctx);
    
    if (!EC_GROUP_get_curve_GFp(group, field, 0, 0, ctx))
    {
        ret = -2;
        
        goto err;
    }
    
    if (BN_cmp(x, field) >= 0)
    {
        ret = 0;
        
        goto err;
    }
    if ((R = EC_POINT_new(group)) == 0)
    {
        ret = -2;
        
        goto err;
    }
    
    if (
        !EC_POINT_set_compressed_coordinates_GFp(group, R, x, recid % 2, ctx)
        )
    {
        ret = 0;
        
        goto err;
    }
    
    if (check)
    {
        if ((O = EC_POINT_new(group)) == 0)
        {
            ret = -2;
            
            goto err;
        }

        if (!EC_POINT_mul(group, O, 0, R, order, ctx))
        {
            ret = -2;
            
            goto err;
        }
        
        if (!EC_POINT_is_at_infinity(group, O))
        {
            ret = 0;
            
            goto err;
        }
    }
    
    if ((Q = EC_POINT_new(group)) == 0)
    {
        ret = -2;
        
        goto err;
    }
    
    n = EC_GROUP_get_degree(group);
    
    e = BN_CTX_get(ctx);
    
    if (!BN_bin2bn(msg, msglen, e))
    {
        ret = -1;
        
        goto err;
    }
    
    if (8 * msglen > n)
    {
        BN_rshift(e, e, 8-(n & 7));
    }
    
    zero = BN_CTX_get(ctx);
    
    if (!BN_zero(zero))
    {
        ret = -1;
        
        goto err;
    }
    
    if (!BN_mod_sub(e, zero, e, order, ctx))
    {
        ret = -1;
        
        goto err;
    }
    
    rr = BN_CTX_get(ctx);
    
    if (!BN_mod_inverse(rr, ecsig->r, order, ctx))
    {
        ret= -1;
        
        goto err;
    }
    
    sor = BN_CTX_get(ctx);
    
    if (!BN_mod_mul(sor, ecsig->s, rr, order, ctx))
    {
        ret = -1;
        
        goto err;
    }
    
    eor = BN_CTX_get(ctx);
    
    if (!BN_mod_mul(eor, e, rr, order, ctx))
    {
        ret = -1;
        
        goto err;
    }
    
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx))
    {
        ret = -2;
        
        goto err;
    }
    
    if (!EC_KEY_set_public_key(eckey, Q))
    {
        ret = -2;
        
        goto err;
    }

    ret = 1;

err:
    if (ctx)
    {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    
    if (R != 0)
    {
        EC_POINT_free(R);
    }
    
    if (O != 0)
    {
        EC_POINT_free(O);
    }
    
    if (Q != 0)
    {
        EC_POINT_free(Q);
    }
    
    return ret;
}

key::key()
    : m_EC_KEY(0)
    , m_set(false)
    , m_compressed(false)
{
    reset();
}

key::key(const key & other)
    : m_EC_KEY(EC_KEY_dup(other.m_EC_KEY))
    , m_set(other.m_set)
    , m_compressed(other.m_compressed)
{
    if (m_EC_KEY == 0)
    {
        throw std::runtime_error("EC_KEY_dup failed");
    }
}

key::~key()
{
    if (m_EC_KEY)
    {
        EC_KEY_free(m_EC_KEY);
    }
}

key & key::operator = (const key & other)
{
    if (!EC_KEY_copy(m_EC_KEY, other.m_EC_KEY))
    {
        throw std::runtime_error("EC_KEY_copy failed");
    }
    
    m_set = other.m_set;
    m_compressed = other.m_compressed;
    
    return *this;
}

void key::reset()
{
   if (m_EC_KEY != 0)
    {
        EC_KEY_free(m_EC_KEY);
    }
    
    m_EC_KEY = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    if (m_EC_KEY == 0)
    {
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    }
    
    m_set = false;
    m_compressed = false;
}

bool key::is_null() const
{
    return m_set == false;
}

bool key::is_compressed() const
{
    return m_compressed;
}

void key::make_new_key(const bool & compressed)
{
    if (!EC_KEY_generate_key(m_EC_KEY))
    {
        throw std::runtime_error("EC_KEY_generate_key failed");
    }
    
    if (m_compressed)
    {
        set_compressed_public_key();
    }
    
    m_set = true;
}

bool key::set_private_key(const private_t & value)
{
    const auto * ptr_value = &value[0];
    
    if (
        d2i_ECPrivateKey(&m_EC_KEY, &ptr_value, value.size())
        )
    {
        /** 
         * Double check.
         */
        if (EC_KEY_check_key(m_EC_KEY))
        {
            m_set = true;
            
            return true;
        }
    }

    /**
     * If value is bad d2i_ECPrivateKey can leave m_EC_KEY pointing to invalid
     * memory. Just leak memory instead of freeing it.
     */
    m_set = 0;
    
    reset();
    
    return false;
}

bool key::set_secret(
    const secret_t & value, const bool & compressed
    )
{
    EC_KEY_free(m_EC_KEY);
    
    m_EC_KEY = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    if (m_EC_KEY == 0)
    {
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    }
    
    if (value.size() != 32)
    {
        throw std::runtime_error("secret must be 32 bytes");
    }
    
    BIGNUM * bn = BN_bin2bn(&value[0], 32, BN_new());
    
    if (bn == 0)
    {
        throw std::runtime_error("BN_bin2bn failed");
    }
    
    if (!EC_KEY_regenerate_key(m_EC_KEY, bn))
    {
        BN_clear_free(bn);
        
        throw std::runtime_error("EC_KEY_regenerate_key failed");
    }
    
    BN_clear_free(bn);
    
    m_set = true;
    
    if (compressed || m_compressed)
    {
        set_compressed_public_key();
    }
    
    return true;
}

key::secret_t key::get_secret(bool & compressed) const
{
    secret_t ret(32);
    
    const BIGNUM * bn = EC_KEY_get0_private_key(m_EC_KEY);
    
    auto num_bytes = BN_num_bytes(bn);
    
    if (bn == 0)
    {
        throw std::runtime_error("EC_KEY_get0_private_key failed");
    }
    
    auto n = BN_bn2bin(bn, &ret[32 - num_bytes]);
    
    if (n != num_bytes)
    {
        throw std::runtime_error("BN_bn2bin failed");
    }
    
    compressed = m_compressed;
    
    return ret;
}

key::private_t key::get_private_key() const
{
    auto size = i2d_ECPrivateKey(m_EC_KEY, 0);
    
    if (size == 0)
    {
        throw std::runtime_error("i2d_ECPrivateKey failed");
    }
    
    private_t ret(size, 0);
    
    auto * ptr = &ret[0];
    
    if (i2d_ECPrivateKey(m_EC_KEY, &ptr) != size)
    {
        throw std::runtime_error("i2d_ECPrivateKey returned unexpected size");
    }
    
    return ret;
}

bool key::set_public_key(const key_public & value)
{
    const auto * ptr = &value.bytes()[0];
    
    if (o2i_ECPublicKey(&m_EC_KEY, &ptr, value.bytes().size()))
    {
        m_set = true;
        
        if (value.bytes().size() == 33)
        {
            set_compressed_public_key();
        }
        
        return true;
    }
    
    m_EC_KEY = 0;
    
    reset();
    
    return false;
}

key_public key::get_public_key() const
{
    auto size = i2o_ECPublicKey(m_EC_KEY, 0);
    
    if (!size)
    {
        throw std::runtime_error("i2o_ECPublicKey failed");
    }
    
    std::vector<std::uint8_t> pub_key(size, 0);
    
    std::uint8_t * pbegin = &pub_key[0];
    
    if (i2o_ECPublicKey(m_EC_KEY, &pbegin) != size)
    {
        throw std::runtime_error("i2o_ECPublicKey returned unexpected size");
    }
    
    return key_public(pub_key);
}

bool key::sign(const sha256 & h, std::vector<std::uint8_t> & signature)
{
    unsigned int size = ECDSA_size(m_EC_KEY);
    
    signature.resize(size);

    if (
        !ECDSA_sign(0, h.digest(), sha256::digest_length, &signature[0],
        &size, m_EC_KEY)
        )
    {
        signature.clear();
        
        return false;
    }
    
    signature.resize(size);
    
    return true;
}

bool key::sign_compact(
    const sha256 & h, std::vector<std::uint8_t> & signature
    )
{
    bool ret = false;
    
    ECDSA_SIG * sig = ECDSA_do_sign(
        h.digest(), sha256::digest_length, m_EC_KEY
    );
    
    if (sig == 0)
    {
        return false;
    }
    
    signature.clear();
    signature.resize(65, 0);
    
    auto bits_r = BN_num_bits(sig->r);
    auto bits_s = BN_num_bits(sig->s);
    
    if (bits_r <= 256 && bits_s <= 256)
    {
        int id_rec = -1;
        
        for (auto i = 0; i < 4; i++)
        {
            key key_rec;
            
            key_rec.m_set = true;
            
            if (m_compressed)
            {
                key_rec.set_compressed_public_key();
            }
            
            if (
                ECDSA_SIG_recover_key_GFp(key_rec.m_EC_KEY,
                sig, h.digest(), sha256::digest_length,
                i, 1) == 1
                )
            {
                if (key_rec.get_public_key() == get_public_key())
                {
                    id_rec = i;
                    
                    break;
                }
            }
        }

        if (id_rec == -1)
        {
            throw std::runtime_error("unable to construct recoverable key");
        }
        
        signature[0] = id_rec + 27 + (m_compressed ? 4 : 0);
        
        BN_bn2bin(sig->r, &signature[33 - (bits_r + 7) / 8]);
        BN_bn2bin(sig->s, &signature[65 - (bits_s + 7) / 8]);
        
        ret = true;
    }
    
    ECDSA_SIG_free(sig);
    
    return ret;
}

bool key::set_compact_signature(
    const sha256 & h, const std::vector<std::uint8_t> & signature
    )
{
    if (signature.size() != 65)
    {
        return false;
    }
    
    int v = signature[0];
    
    if (v < 27 || v >= 35)
    {
        return false;
    }
    
    ECDSA_SIG * sig = ECDSA_SIG_new();
    
    BN_bin2bn(&signature[1], 32, sig->r);
    BN_bin2bn(&signature[33], 32, sig->s);

    EC_KEY_free(m_EC_KEY);
    
    m_EC_KEY = EC_KEY_new_by_curve_name(NID_secp256k1);
    
    if (v >= 31)
    {
        set_compressed_public_key();
        
        v -= 4;
    }
    
    if (
        ECDSA_SIG_recover_key_GFp(m_EC_KEY, sig, h.digest(),
        sha256::digest_length, v - 27, 0) == 1
        )
    {
        m_set = true;
        
        ECDSA_SIG_free(sig);
        
        return true;
    }
    
    return false;
}

bool key::verify(
    const sha256 & h, const std::vector<std::uint8_t> & signature
    )
{
    bool ret = false;
    
    if (signature.size() > 0)
    {
        auto ptr_signature = &signature[0];
        
        ECDSA_SIG * ecdsa_sig = 0;
        
        /**
         * Make sure that the signature looks like a valid signature before
         * sending it to OpenSSL (like in the test cases).
         */
        if (
            (ecdsa_sig = d2i_ECDSA_SIG(
            0, &ptr_signature, signature.size())) != 0
            )
        {
            std::uint8_t * pp = 0;
            
            auto len = i2d_ECDSA_SIG(ecdsa_sig, &pp);
            
            ECDSA_SIG_free(ecdsa_sig), ecdsa_sig = 0;
            
            if (pp && len > 0)
            {
                ret = ECDSA_verify(
                    0, h.digest(), sha256::digest_length, pp, len, m_EC_KEY
                ) == 1;
                
                OPENSSL_free(pp), pp = 0;
            }
        }
    }
    
    return ret;
}

bool key::verify_compact(
    const sha256 & h, const std::vector<std::uint8_t> & signature
    )
{
    key k;
    
    if (k.set_compact_signature(h, signature) == false)
    {
        return false;
    }
    
    if (get_public_key() != k.get_public_key())
    {
        return false;
    }
    
    return true;
}

bool key::is_valid()
{
    if (m_set == false)
    {
        return false;
    }
    
    if (!EC_KEY_check_key(m_EC_KEY))
    {
        return false;
    }
    
    bool compressed;
    
    secret_t s = get_secret(compressed);
    
    key k;
    
    k.set_secret(s, compressed);
    
    return get_public_key() == k.get_public_key();
}

void key::set_compressed_public_key()
{
    EC_KEY_set_conv_form(m_EC_KEY, POINT_CONVERSION_COMPRESSED);
    
    m_compressed = true;
}

