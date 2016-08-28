/*
 * Copyright (c) 2013-2016 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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
#include <iostream>
#include <stdexcept>
#include <sstream>

#include <coin/address.hpp>
#include <coin/base58.hpp>
#include <coin/big_number.hpp>
#include <coin/hd_ecdsa.hpp>
#include <coin/hd_keychain.hpp>
#include <coin/logger.hpp>

using namespace coin;

std::uint32_t hd_keychain::g_private_version = private_version;
std::uint32_t hd_keychain::g_public_version = public_version;

/**
 * The curve order.
 */
static const big_number g_curve_order(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
);

hd_keychain::hd_keychain()
{
    // ...
}

hd_keychain::hd_keychain(
    const std::vector<std::uint8_t> & key,
    const std::vector<std::uint8_t> & chain_code,
    const std::uint32_t & child_num, const std::uint32_t & parent_fingerprint,
    const std::uint32_t & depth
    )
    : m_depth(depth)
    , m_parent_fingerprint(parent_fingerprint)
    , m_child_count(child_num)
    , m_chain_code(chain_code)
    , m_key(key)
{
    if (m_chain_code.size() != 32)
    {
        throw std::runtime_error("Invalid chain code.");
    }

    if (m_key.size() == 32)
    {
        big_number n;
        
        n.set_vector_no_reverse(m_key);
        
        if (n >= g_curve_order || n.is_zero())
        {
            throw std::runtime_error("Invalid key.");
        }

        std::vector<std::uint8_t> private_key;
        
        private_key.push_back(0x00);
        private_key.insert(private_key.end(), m_key.begin(), m_key.end());
        
        m_key = private_key;
    }
    else if (m_key.size() == 33)
    {
        try
        {
            hd_ecdsa::point K(m_key);
        }
        catch (...)
        {
            throw std::runtime_error("Invalid key.");
        }
    }
    else
    {
        throw std::runtime_error("Invalid key.");
    }

    m_version = is_private() ? g_private_version : g_public_version;
    
    update_public_key();

    m_is_valid = true;
}

hd_keychain::hd_keychain(const std::vector<std::uint8_t> & extkey)
{
    if (extkey.size() != 78)
    {
        throw std::runtime_error("Invalid extended key length.");
    }

    m_version =
        ((std::uint32_t)extkey[0] << 24) |
        ((std::uint32_t)extkey[1] << 16) |
        ((std::uint32_t)extkey[2] << 8) |
        (std::uint32_t)extkey[3]
    ;
    
    m_depth = extkey[4];
    
    m_parent_fingerprint =
        ((std::uint32_t)extkey[5] << 24) |
        ((std::uint32_t)extkey[6] << 16) |
        ((std::uint32_t)extkey[7] << 8) |
        (std::uint32_t)extkey[8]
    ;
    
    m_child_count =
        ((std::uint32_t)extkey[9] << 24) |
        ((std::uint32_t)extkey[10] << 16) |
        ((uint32_t)extkey[11] << 8) |
        (uint32_t)extkey[12]
    ;
    
    m_chain_code.assign(extkey.begin() + 13, extkey.begin() + 45);
    
    m_key.assign(extkey.begin() + 45, extkey.begin() + 78);

    update_public_key();

    m_is_valid = true;
}

hd_keychain::hd_keychain(const hd_keychain & other)
{
    m_is_valid = other.m_is_valid;
    
    if (m_is_valid == true)
    {
        m_version = other.m_version;
        m_depth = other.m_depth;
        m_parent_fingerprint = other.m_parent_fingerprint;
        m_child_count = other.m_child_count;
        m_chain_code = other.m_chain_code;
        m_key = other.m_key;
        
        update_public_key();
    }
}

hd_keychain & hd_keychain::operator = (const hd_keychain & rhs)
{
    m_is_valid = rhs.m_is_valid;
    
    if (m_is_valid == true)
    {
        m_version = rhs.m_version;
        m_depth = rhs.m_depth;
        m_parent_fingerprint = rhs.m_parent_fingerprint;
        m_child_count = rhs.m_child_count;
        m_chain_code = rhs.m_chain_code;
        m_key = rhs.m_key;
        
        update_public_key();
    }
    
    return *this;
}

bool hd_keychain::operator == (const hd_keychain & rhs) const
{
    return
        m_is_valid && rhs.m_is_valid && m_version == rhs.m_version &&
        m_depth == rhs.m_depth &&
        m_parent_fingerprint == rhs.m_parent_fingerprint &&
        m_child_count == rhs.m_child_count &&
        m_chain_code == rhs.m_chain_code && m_key == rhs.m_key
    ;
}

bool hd_keychain::operator != (const hd_keychain & rhs) const
{
    return !(*this == rhs);
}

void hd_keychain::set_is_valid(const bool & val)
{
    m_is_valid = val;
}

const bool hd_keychain::is_valid() const
{
    return m_is_valid;
}

const bool hd_keychain::is_private() const
{
    return m_key.size() == 33 && m_key[0] == 0x00;
}

const std::vector<std::uint8_t> hd_keychain::extended_key() const
{
    std::vector<std::uint8_t> ret;

    ret.push_back((std::uint32_t)m_version >> 24);
    ret.push_back(((std::uint32_t)m_version >> 16) & 0xff);
    ret.push_back(((std::uint32_t)m_version >> 8) & 0xff);
    ret.push_back((std::uint32_t)m_version & 0xff);

    ret.push_back(m_depth);

    ret.push_back((std::uint32_t)m_parent_fingerprint >> 24);
    ret.push_back(((std::uint32_t)m_parent_fingerprint >> 16) & 0xff);
    ret.push_back(((std::uint32_t)m_parent_fingerprint >> 8) & 0xff);
    ret.push_back((std::uint32_t)m_parent_fingerprint & 0xff);

    ret.push_back((std::uint32_t)m_child_count >> 24);
    ret.push_back(((std::uint32_t)m_child_count >> 16) & 0xff);
    ret.push_back(((std::uint32_t)m_child_count >> 8) & 0xff);
    ret.push_back((std::uint32_t)m_child_count & 0xff);

    ret.insert(ret.end(), m_chain_code.begin(), m_chain_code.end());
    ret.insert(ret.end(), m_key.begin(), m_key.end());

    return ret;
}

void hd_keychain::set_version(const std::uint32_t & val)
{
    m_version = val;
}

const std::uint32_t & hd_keychain::version() const
{
    return m_version;
}

void hd_keychain::set_depth(const std::uint8_t & val)
{
    m_depth = val;
}

const std::uint8_t & hd_keychain::depth() const
{
    return m_depth;
}

void hd_keychain::set_parent_fingerprint(const std::uint32_t & val)
{
    m_parent_fingerprint = val;
}

const std::uint32_t & hd_keychain::parent_fingerprint() const
{
    return m_parent_fingerprint;
}

void hd_keychain::set_child_count(const std::uint32_t & val)
{
    m_child_count = val;
}

const std::uint32_t & hd_keychain::child_count() const
{
    return m_child_count;
}

void hd_keychain::set_chain_code(const std::vector<std::uint8_t> & val)
{
    m_chain_code = val;
}

const std::vector<std::uint8_t> & hd_keychain::chain_code() const
{
    return m_chain_code;
}

void hd_keychain::set_key(const std::vector<std::uint8_t> & val)
{
    m_key = val;
}

const std::vector<std::uint8_t> & hd_keychain::key() const
{
    return m_key;
}

std::vector<std::uint8_t> hd_keychain::privkey() const
{
    if (is_private() == true)
    {
        return std::vector<std::uint8_t> (m_key.begin() + 1, m_key.end());
    }

    return std::vector<std::uint8_t> ();
}

void hd_keychain::set_pubkey(const std::vector<std::uint8_t> & val)
{
    m_pubkey = val;
}

const std::vector<std::uint8_t> & hd_keychain::pubkey() const
{
    return m_pubkey;
}

std::vector<std::uint8_t> hd_keychain::uncompressed_pubkey() const
{
    hd_ecdsa::key k;
    
    k.set_public_key(m_pubkey);
    
    return k.get_public_key(false);
}

std::vector<std::uint8_t> hd_keychain::get_hash() const
{
    auto digest = hash::sha256_ripemd160(&m_pubkey[0], m_pubkey.size());
    
    return std::vector<std::uint8_t> (&digest[0], &digest[0] + digest.size());
}

std::uint32_t hd_keychain::fingerprint() const
{
    auto digest = get_hash();
    
    return
        (std::uint32_t)digest[0] << 24 | (std::uint32_t)digest[1] << 16 |
        (std::uint32_t)digest[2] << 8 | (std::uint32_t)digest[3]
    ;
}

std::vector<std::uint8_t> hd_keychain::full_hash() const
{
    std::vector<std::uint8_t> data(m_pubkey);
    
    data.insert(data.end(), m_chain_code.begin(), m_chain_code.end());

    auto digest = hash::sha256_ripemd160(&data[0], data.size());
    
    return std::vector<std::uint8_t> (&digest[0], &digest[0] + digest.size());
}

hd_keychain hd_keychain::get_public() const
{
    if (m_is_valid == false)
    {
        throw std::runtime_error(
            std::string(__FUNCTION__) + ": invalid hd_keychain"
        );
    }

    hd_keychain ret;
    
    ret.set_is_valid(m_is_valid);

    ret.set_version(g_public_version);
    
    ret.set_depth(m_depth);
    
    ret.set_parent_fingerprint(m_parent_fingerprint);
    
    ret.set_child_count(m_child_count);
    
    ret.set_chain_code(m_chain_code);
    
    ret.set_key(m_pubkey);
    
    ret.set_pubkey(m_pubkey);
    
    return ret;
}

hd_keychain hd_keychain::get_child(const std::uint32_t & index) const
{
    if (m_is_valid == false)
    {
        throw std::runtime_error(
            std::string(__FUNCTION__) + ": invalid hd_keychain"
        );
    }
    
    bool priv_derivation = 0x80000000 & index;
    
    if (is_private() == false && priv_derivation)
    {
        throw std::runtime_error(
            std::string(__FUNCTION__) +
            ": tried to derive private key on public key."
        );
    }

    hd_keychain ret;
    
    ret.set_is_valid(false);

    std::vector<std::uint8_t> data;
    
    data.insert(
        data.end(), (priv_derivation ? m_key : m_pubkey).begin(),
        (priv_derivation ? m_key : m_pubkey).end()
    );
    data.push_back(index >> 24);
    data.push_back((index >> 16) & 0xff);
    data.push_back((index >> 8) & 0xff);
    data.push_back(index & 0xff);

    auto digest = crypto::hmac_sha512(m_chain_code, data);
    
    std::vector<std::uint8_t> l32(digest.begin(), digest.begin() + 32);
    
    big_number i_l;
    
    i_l.set_vector_no_reverse(l32);
    
    auto foo1 = i_l.get_hex();
    auto foo2 = g_curve_order.get_hex();
    
    if (i_l >= g_curve_order)
    {
        throw std::runtime_error(
            std::string(__FUNCTION__) + ": invalid hd_keychain"
        );
    }

    if (is_private() == true)
    {
        big_number k;
        
        k.set_vector_no_reverse(m_key);
        
        k += i_l;
        k %= g_curve_order;
        
        if (k.is_zero() == true)
        {
            throw std::runtime_error(
                std::string(__FUNCTION__) + ": invalid hd_keychain"
            );
        }

        auto child_key = k.get_vector_no_reverse();
        
        std::vector<std::uint8_t> padded_key(33 - child_key.size(), 0);
        
        padded_key.insert(
            padded_key.end(),  child_key.begin(), child_key.end()
        );
        
        ret.set_key(padded_key);
        
        ret.update_public_key();
    }
    else
    {
        hd_ecdsa::point point_k;
        
        point_k.set_bytes(m_pubkey);
        
        point_k.generator_mul(l32);
        
        if (point_k.is_at_infinity())
        {
            throw std::runtime_error(
                std::string(__FUNCTION__) + ": invalid hd_keychain"
            );
        }

        ret.set_key(point_k.bytes());
        
        ret.set_pubkey(point_k.bytes());
    }

    ret.set_version(m_version);
    
    ret.set_depth(m_depth + 1);
    
    ret.set_parent_fingerprint(fingerprint());
    
    ret.set_child_count(index);
    
    ret.m_chain_code.assign(digest.begin() + 32, digest.end());

    ret.set_is_valid(true);
    
    return ret;
}

hd_keychain hd_keychain::get_child(const std::string & path) const
{
    if (path.size() == 0)
    {
        throw std::runtime_error(
            std::string(__FUNCTION__) + ": invalid hd_keychain"
        );
    }

    std::vector<uint32_t> paths;

    std::size_t i = 0;
    
    std::uint64_t n = 0;
    
    while (i < path.size())
    {
        char c = path[i];
        
        if (c >= '0' && c <= '9')
        {
            n *= 10;
            n += (std::uint32_t)(c - '0');
            
            if (n >= 0x80000000)
            {
                throw std::runtime_error(
                    std::string(__FUNCTION__) + ": invalid hd_keychain"
                );
            }
            
            i++;
            
            if (i >= path.size())
            {
                paths.push_back((std::uint32_t)n);
            }
        }
        else if (c == '\'')
        {
            if (i + 1 < path.size())
            {
                if (
                    (i + 2 >= path.size()) || (path[i + 1] != '/') ||
                    (path[i + 2] < '0') || (path[i + 2] > '9')
                    )
                {
                    throw std::runtime_error(
                        std::string(__FUNCTION__) + ": invalid hd_keychain"
                    );
                }
            }
            
            n |= 0x80000000;
            
            paths.push_back((std::uint32_t)n);
            
            n = 0;
            
            i += 2;
        }
        else if (c == '/')
        {
            if (i + 1 >= path.size() || path[i + 1] < '0' || path[i + 1] > '9')
            {
                throw std::runtime_error(
                    std::string(__FUNCTION__) + ": invalid hd_keychain"
                );
            }
            
            paths.push_back((std::uint32_t)n);
            
            n = 0;
            
            i++;
        }
        else
        {
            throw std::runtime_error(
                std::string(__FUNCTION__) + ": invalid hd_keychain"
            );
        }
    }

    hd_keychain ret(*this);
    
    for (auto i : paths)
    {
        ret = ret.get_child(i);
    }
    
    return ret;
}

hd_keychain hd_keychain::get_child_node(
    const std::uint32_t & index, const bool & private_derivation
    ) const
{
    std::uint32_t mask = private_derivation ? 0x80000000ull : 0x00000000ull;
    
    return get_child(mask).get_child(index);
}

std::vector<std::uint8_t> hd_keychain::get_private_signing_key(
    const std::uint32_t & index
    ) const
{
    assert(index != 0);

    return get_child(index).privkey();
}

std::vector<std::uint8_t> hd_keychain::get_public_signing_key(
    const std::uint32_t & index, const bool & compressed
    ) const
{
    assert(index != 0);
    
    return
        compressed ? get_child(index).pubkey() :
        get_child(index).uncompressed_pubkey()
    ;
}

void hd_keychain::set_versions(
    const std::uint32_t & private_version,
    const std::uint32_t & public_version
    )
{
    g_private_version = private_version;
    
    g_public_version = public_version;
}

std::string hd_keychain::to_string() const
{
    std::stringstream ss;
    
    ss << "hd_keychain: " << std::endl;
    ss << "\tversion: " << std::hex << m_version << std::endl;
    ss << "\tdepth: " << static_cast<std::int32_t> (depth()) << std::endl;
    ss << "\tparent_fingerprint: " << m_parent_fingerprint << std::endl;
    ss << "\tchild_num: " << m_child_count << std::endl;
    ss << "\tchain_code: " << utility::hex_string(m_chain_code) << std::endl;
    ss << "\tkey: " << utility::hex_string(m_key) << std::endl;
    ss << "\thash: " << utility::hex_string(get_hash()) << std::endl;
    
    return ss.str();
}

void hd_keychain::update_public_key()
{
    if (is_private() == true)
    {
        hd_ecdsa::key key_curve;
        
        key_curve.set_private_key(
            std::vector<std::uint8_t> (m_key.begin() + 1, m_key.end())
        );
        
        m_pubkey = key_curve.get_public_key();
    }
    else
    {
        m_pubkey = m_key;
    }
}

inline std::uint32_t test_p(const std::uint32_t & i)
{
    return 0x80000000 | i;

}

inline bool test_is_p(const std::uint32_t & i)
{
    return 0x80000000 & i;
}

std::string test_s(const std::uint32_t & i)
{
    std::stringstream ss;
    
    ss << (0x7fffffff & i);
    
    if (test_is_p(i))
    {
        ss << "'";
    }
    
    return ss.str();
}

void test_show_key(const hd_keychain & keychain)
{
    auto extended_key = keychain.extended_key();

    base58 b58;
    
    b58.set_data(
        constants::test_net ? 111 : 0,
        reinterpret_cast<char *> (&extended_key[0]), extended_key.size()
    );
    
    std::cout <<
        "  * ext " << (keychain.is_private() ? "prv" : "pub") << ": " <<
        b58.to_string(false) <<
    std::endl;
}

void test_show_step(
    const std::string & chainname, const hd_keychain & public_hd_keychain,
    const hd_keychain & private_hd_keychain
    )
{
    std::cout << "* [" << chainname << "]" << std::endl;
    
    test_show_key(public_hd_keychain);
    
    test_show_key(private_hd_keychain);
}

int hd_keychain::run_test()
{
#if 1
    const std::vector<std::uint8_t> seed =
        utility::from_hex("000102030405060708090a0b0c0d0e0f")
    ;
    
    const std::uint32_t chain[] =
    {
        test_p(0), 1, test_p(2), 2, 1000000000
    };
#else
    const std::vector<std::uint8_t> seed =
        utility::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab"
        "7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754"
        "514e4b484542")
    ;
    
    const std::uint32_t chain[] =
    {
        0, test_p(2147483647), 1, test_p(2147483646), 2
    };
#endif
    const auto chain_length = sizeof(chain) / sizeof(std::uint32_t);

    try
    {
        hd_keychain::set_versions(0x0488ADE4, 0x0488B21E);

        std::cout << "Seed: " << utility::hex_string(seed) << std::endl;

        hd_keychain::seed hd_seed(seed);
        
        auto k = hd_seed.get_master_key();
        auto c = hd_seed.get_master_chain_code();

        std::stringstream chainname;
        
        chainname << "Chain m";

        hd_keychain prv(k, c);
        
        hd_keychain pub = prv.get_public();

        test_show_step(chainname.str(), pub, prv);

        hd_keychain parentpub;

        for (auto k = 0; k < chain_length; k++)
        {
            chainname << "/" << test_s(chain[k]);

            if (test_is_p(chain[k]) == false)
            {
                parentpub = pub;
            }

            prv = prv.get_child(chain[k]);
            
            assert(prv.is_valid());

            pub = prv.get_public();
            
            assert(pub.is_valid());

            if (test_is_p(chain[k]) == false)
            {
                auto parentpubChild = parentpub.get_child(chain[k]);
                
                assert(pub == parentpubChild);
            }

            test_show_step(chainname.str(), pub, prv);
        }

        return 0;
    }
    catch (const std::exception & e)
    {
        std::cout << "Error: " << e.what() << std::endl;
    }
    
    return 0;
}
