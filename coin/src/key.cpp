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
#include <stdexcept>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <coin/android.hpp>
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
    
    if (compressed)
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
    
    if (bn == 0)
    {
        throw std::runtime_error("EC_KEY_get0_private_key failed");
    }
    
    auto num_bytes = BN_num_bytes(bn);
    
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
    
    int nBitsR = BN_num_bits(sig->r);
    int nBitsS = BN_num_bits(sig->s);
    
    if (nBitsR <= 256 && nBitsS <= 256)
    {
        int nRecId = -1;
        
        for (auto i = 0; i < 4; i++)
        {
            key keyRec;
            
            keyRec.m_set = true;
            
            if (m_compressed)
            {
                keyRec.set_compressed_public_key();
            }
            
            if (
                ECDSA_SIG_recover_key_GFp(keyRec.m_EC_KEY,
                sig, h.digest(), sha256::digest_length,
                i, 1) == 1
                )
            {
                if (keyRec.get_public_key() == get_public_key())
                {
                    nRecId = i;
                    break;
                }
            }
        }

        if (nRecId == -1)
        {
            ECDSA_SIG_free(sig);

            throw std::runtime_error("unable to construct recoverable key");
        }
        
        signature[0] = nRecId + 27 + (m_compressed ? 4 : 0);
        
        BN_bn2bin(sig->r, &signature[33 - (nBitsR + 7) / 8]);
        BN_bn2bin(sig->s, &signature[65 - (nBitsS + 7) / 8]);
        
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

    ECDSA_SIG_free(sig);
    
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

    return get_public_key() == k.get_public_key();
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

#include <coin/address.hpp>
#include <coin/destination.hpp>
#include <coin/secret.hpp>

int key::run_test()
{
    log_test("Testing class key.");

    secret s1, s2, s3, s4, s5;

    assert(s1.set_string("7gP7i2F9nKhDbjx5qgoy14ar8nSc7MqFs4p3kZq8DHAovP5TQvv"));
    assert(s2.set_string("7gHopFmzZvTppKdUnUfCGXWu62MEFa2ZVTYcURoDkwRb1EJb4Ci"));
    assert(s3.set_string("WUpcc4VTm3WWcLa8MtiJBGpPsMa1y4wzbypf9HuQqCNJ6Hqgauex"));
    assert(s4.set_string("WURBdaDb6JyQ3sE1dj5ajXgxuAxHVJmtQcAXa4T1JwDX5kXoC9og"));

    /**
     * A bad address.
     */
    assert(!s5.set_string("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"));
    
    key k1, k2, k3, k4;
    
    bool compressed;
    
    secret_t secret1  = s1.get_secret(compressed);
    
    assert(compressed == false);
    
    secret_t secret2  = s2.get_secret(compressed);
    
    assert(compressed == false);
    
    secret_t secret1C = s3.get_secret(compressed);
    
    assert(compressed == true);
    
    secret_t secret2C = s4.get_secret(compressed);
    
    assert(compressed == true);

    k1.set_secret(secret1, false);
    k2.set_secret(secret2, false);
    k3.set_secret(secret1C, true);
    k4.set_secret(secret2C, true);
    
    address
        a1(k1.get_public_key().get_id()), a2(k2.get_public_key().get_id()),
        a1c(k3.get_public_key().get_id()), a2c(k4.get_public_key().get_id())
    ;
    
    log_test("class address var a1 " << a1.to_string());
    log_test("class address var a2 " << a2.to_string());
    log_test("class address var a1c " << a1c.to_string());
    log_test("class address var a2c " << a2c.to_string());

    assert("ViTU88LacykhqctosDe7qQiYieoRapugmn" == a1.to_string());
    assert("VbGoy26u8CHru1pDQQwRAsFbBxGMfkAh1w" == a2.to_string());
    assert("VmRSdA11YnTSFP389tFAQjq8Lj1D9xWQHB" == a1c.to_string());
    assert("VucpF5NMepUcQXjDa4Pf9yZHRiNLyTUAKX" == a2c.to_string());
    
    assert(secret1 == secret1C);
    assert(secret2 == secret2C);
    
    assert(a1.get() == destination::tx_t(k1.get_public_key().get_id()));
    assert(a2.get() == destination::tx_t(k2.get_public_key().get_id()));
    assert(a1c.get() == destination::tx_t(k3.get_public_key().get_id()));
    assert(a2c.get() == destination::tx_t(k4.get_public_key().get_id()));

    for (auto i = 0; i < 16; i++)
    {
        std::string msg = "Top Secret Test #" + std::to_string(i) + ".";

        sha256 hash_msg = sha256(
            reinterpret_cast<const std::uint8_t *> (msg.c_str()), msg.size()
        );

        /**
         * Normal Signatures.
         */
        std::vector<std::uint8_t> sign1, sign2, sign1c, sign2c;

        assert(k1.sign(hash_msg, sign1));
        assert(k2.sign(hash_msg, sign2));
        assert(k3.sign(hash_msg, sign1c));
        assert(k4.sign(hash_msg, sign2c));

        assert(k1.verify(hash_msg, sign1));
        assert(!k1.verify(hash_msg, sign2));
        assert(k1.verify(hash_msg, sign1c));
        assert(!k1.verify(hash_msg, sign2c));

        assert(!k2.verify(hash_msg, sign1));
        assert(k2.verify(hash_msg, sign2));
        assert(!k2.verify(hash_msg, sign1c));
        assert(k2.verify(hash_msg, sign2c));

        assert(k3.verify(hash_msg, sign1));
        assert(!k3.verify(hash_msg, sign2));
        assert(k3.verify(hash_msg, sign1c));
        assert(!k3.verify(hash_msg, sign2c));

        assert(!k4.verify(hash_msg, sign1));
        assert(k4.verify(hash_msg, sign2));
        assert(!k4.verify(hash_msg, sign1c));
        assert(k4.verify(hash_msg, sign2c));

        /**
         * Compact signatures with key recovery.
         */
        std::vector<std::uint8_t> csign1, csign2, csign1c, csign2c;

        assert(k1.sign_compact(hash_msg, csign1));
        assert(k2.sign_compact(hash_msg, csign2));
        assert(k3.sign_compact(hash_msg, csign1c));
        assert(k4.sign_compact(hash_msg, csign2c));

        key rkey1, rkey2, rkey1C, rkey2c;

        assert(rkey1.set_compact_signature(hash_msg, csign1));
        assert(rkey2.set_compact_signature(hash_msg, csign2));
        assert(rkey1C.set_compact_signature(hash_msg, csign1c));
        assert(rkey2c.set_compact_signature(hash_msg, csign2c));

        assert(rkey1.get_public_key()  == k1.get_public_key());
        assert(rkey2.get_public_key()  == k2.get_public_key());
        assert(rkey1C.get_public_key() == k3.get_public_key());
        assert(rkey2c.get_public_key() == k4.get_public_key());
    }
    
    log_test("Done testing class key.");
    
    return 0;
}
