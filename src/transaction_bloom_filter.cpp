/*
 * Copyright (c) 2013-2016 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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

#include <cassert>
#include <cmath>

#include <coin/data_buffer.hpp>
#include <coin/hash.hpp>
#include <coin/script.hpp>
#include <coin/secret.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_in.hpp>
#include <coin/transaction_out.hpp>
#include <coin/transaction_bloom_filter.hpp>
#include <coin/types.hpp>
#include <coin/utility.hpp>

/**
 * LN2SQUARED
 */
static const double LN2SQUARED =
    0.4804530139182014246671025263266649717305529515945455
;

/**
 * LN2
 */
static const double LN2 =
    0.6931471805599453094172321214581765680755001343602552
;

using namespace coin;

transaction_bloom_filter::transaction_bloom_filter()
    : m_is_full(true)
    , m_is_empty(false)
    , m_hash_funcs(0)
    , m_tweak(0)
    , m_flags(0)
{
    // ...
}

transaction_bloom_filter::transaction_bloom_filter(
    const std::uint32_t & elements, const double & fprate,
    const std::uint32_t & tweak, const std::uint8_t & flags
    )
    : m_data(std::min(static_cast<std::uint32_t> (
        -1 / LN2SQUARED * elements * std::log(fprate)),
        static_cast<std::uint32_t> (max_bloom_filter_size * 8)) / 8)
    , m_is_full(false)
    , m_is_empty(false)
    , m_hash_funcs(std::min(static_cast<std::uint32_t> (
        m_data.size() * 8 / elements * LN2),
        static_cast<std::uint32_t> (max_hash_funcs)))
    , m_tweak(tweak)
    , m_flags(flags)
{
    // ...
}

void transaction_bloom_filter::encode(data_buffer & buffer) const
{
    buffer.write_var_int(m_data.size());
    buffer.write_bytes(
        reinterpret_cast<const char *> (&m_data[0]), m_data.size()
    );
    buffer.write_uint32(m_hash_funcs);
    buffer.write_uint32(m_tweak);
    buffer.write_uint8(m_flags);
}

bool transaction_bloom_filter::decode(data_buffer & buffer)
{
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_data.resize(len);
        
        buffer.read_bytes(reinterpret_cast<char *> (&m_data[0]), m_data.size());
    }
    
    m_hash_funcs = buffer.read_uint32();
    
    m_tweak = buffer.read_uint32();
    
    m_flags = buffer.read_uint8();
    
    return true;
}

inline std::uint32_t transaction_bloom_filter::hash(
    const std::uint32_t & hashes, const std::vector<std::uint8_t> & data
    ) const
{
    return hash::murmur3(
        hashes * 0xFBA4C795 + m_tweak, &data[0], data.size()) %
        (m_data.size() * 8
    );
}

void transaction_bloom_filter::insert(
    const std::vector<std::uint8_t> & pub_key
    )
{
    if (m_is_full == false)
    {
        for (auto i = 0; i < m_hash_funcs; i++)
        {
            auto index = hash(i, pub_key);

            m_data[index >> 3] |= (1 << (7 & index));
        }
        
        m_is_empty = false;
    }
}

void transaction_bloom_filter::insert(const point_out & out_point)
{
    /**
     * Copy the point_out.
     */
    auto out_point_copy = out_point;
    
    /**
     * Clear the point_out.
     */
    out_point_copy.clear();
    
    /**
     * Encode the point_out.
     */
    out_point_copy.encode();
    
    insert(
        std::vector<std::uint8_t> (out_point_copy.data(),
        out_point_copy.data() + out_point_copy.size())
    );
}

void transaction_bloom_filter::insert(const sha256 & h)
{
    insert(
        std::vector<std::uint8_t> (
        h.digest(), h.digest() + sha256::digest_length)
    );
}

bool transaction_bloom_filter::contains(
    const std::vector<std::uint8_t> & pub_key
    ) const
{
    if (m_is_full)
    {
        return true;
    }
    else
    {
        if (m_is_empty)
        {
            return false;
        }
        else
        {
            for (auto i = 0; i < m_hash_funcs; i++)
            {
                auto index = hash(i, pub_key);

                if (!(m_data[index >> 3] & (1 << (7 & index))))
                {
                    return false;
                }
            }
        }
    }
    
    return true;
}

bool transaction_bloom_filter::contains(const point_out & out_point) const
{
    /**
     * Copy the point_out.
     */
    auto out_point_copy = out_point;
    
    /**
     * Clear the point_out.
     */
    out_point_copy.clear();
    
    /**
     * Encode the point_out.
     */
    out_point_copy.encode();
    
    return contains(
        std::vector<std::uint8_t>(out_point_copy.data(),
        out_point_copy.data() + out_point_copy.size())
    );
}

bool transaction_bloom_filter::contains(const sha256 & h) const
{
    return contains(
        std::vector<std::uint8_t>(
        h.digest(), h.digest() + sha256::digest_length)
    );
}

void transaction_bloom_filter::clear()
{
    m_data.assign(m_data.size(), 0);
    
    m_is_full = false, m_is_empty = true;
}

bool transaction_bloom_filter::is_within_size_constraints() const
{
    return
        m_data.size() <= max_bloom_filter_size &&
        m_hash_funcs <= max_hash_funcs
    ;
}

bool transaction_bloom_filter::is_relevant_and_update(const transaction & tx)
{
    auto found = false;
    
    if (m_is_full)
    {
        return true;
    }
    
    if (m_is_empty)
    {
        return false;
    }
    
    const auto & h = tx.get_hash();
    
    if (contains(h) == true)
    {
        found = true;
    }

    for (auto i = 0; i < tx.transactions_out().size(); i++)
    {
        const auto & tx_out = tx.transactions_out()[i];

        auto it = tx_out.script_public_key().begin();
        
        std::vector<std::uint8_t> data;
        
        while (it < tx_out.script_public_key().end())
        {
            script::op_t opcode;
            
            if (tx_out.script_public_key().get_op(it, opcode, data) == false)
            {
                break;
            }
            
            if (data.size() != 0 && contains(data))
            {
                found = true;
                
                if ((m_flags & update_mask) == update_all)
                {
                    insert(point_out(h, i));
                }
                else if ((m_flags & update_mask) == update_p2pubkey_only)
                {
                    types::tx_out_t type;
                    
                    std::vector< std::vector<std::uint8_t> > solutions;
                    
                    if (
                        script::solver(tx_out.script_public_key(), type,
                        solutions) && (type ==  types::tx_out_pubkey ||
                        type == types::tx_out_multisig)
                        )
                    {
                        insert(point_out(h, i));
                    }
                }
                
                break;
            }
        }
    }

    if (found)
    {
        return true;
    }
    
    for (auto & i : tx.transactions_in())
    {
        if (contains(i.previous_out()) == true)
        {
            return true;
        }
        
        auto it = i.script_signature().begin();
        
        std::vector<std::uint8_t> data;
        
        while (it < i.script_signature().end())
        {
            script::op_t opcode;
            
            if (i.script_signature().get_op(it, opcode, data) == false)
            {
                break;
            }
            
            if (data.size() != 0 && contains(data) == true)
            {
                return true;
            }
        }
    }
    
    return false;
}

void transaction_bloom_filter::update_empty_full()
{
    auto full = true;
    auto empty = true;
    
    for (auto i = 0; i < m_data.size(); i++)
    {
        full &= m_data[i] == 0xff;
        empty &= m_data[i] == 0;
    }
    
    m_is_full = full;
    m_is_empty = empty;
}

int transaction_bloom_filter::run_test()
{
    transaction_bloom_filter filter1(
        3, 0.01, 0, transaction_bloom_filter::update_all
    );
    
    auto val = utility::from_hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
    
    filter1.insert(val);
    
    assert(filter1.contains(val));
    
    printf("transaction_bloom_filter: Check 1 Passed\n");
    
    val = utility::from_hex("19108ad8ed9bb6274d3980bab5a85c048f0950c8");
    
    assert(!filter1.contains(val));
    
    printf("transaction_bloom_filter: Check 2 Passed\n");
    
    val = utility::from_hex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee");
    
    filter1.insert(val);
    
    assert(filter1.contains(val));
    
    printf("transaction_bloom_filter: Check 3 Passed\n");
    
    val = utility::from_hex("b9300670b4c5366e95b2699e8b18bc75e5f729c5");
    
    filter1.insert(val);
    
    assert(filter1.contains(val));
    
    printf("transaction_bloom_filter: Check 4 Passed\n");
    
    coin::data_buffer buffer;
    
    filter1.encode(buffer);
    
    auto tmp = utility::from_hex("03614e9b050000000000000001");
    
    std::vector<char> expected(tmp.size());

    for (auto i = 0; i < tmp.size(); i++)
    {
        expected[i] = (char)tmp[i];
    }

    for (auto i = 0; i < tmp.size(); i++)
    {
        if (expected[i] != buffer.data()[i])
        {
            printf("transaction_bloom_filter: Filter mismatch %d\n", i);
        }
        else
        {
            printf("transaction_bloom_filter: Filter match %d\n", i);
        }
    }
    
    printf("transaction_bloom_filter: Check 5 Passed\n");
    
    tmp = utility::from_hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
    
    assert(filter1.contains(tmp));
    
    printf("transaction_bloom_filter: Check 6 Passed\n");
    
    filter1.clear();

    assert(!filter1.contains(tmp));
    
    printf("transaction_bloom_filter: Check 7 Passed\n");
    
    /**
     * Tweak = 100.
     */
    
    transaction_bloom_filter filter2(
        3, 0.01, 2147483649UL, transaction_bloom_filter::update_all
    );
    
    val = utility::from_hex("99108ad8ed9bb6274d3980bab5a85c048f0950c8");
    
    filter2.insert(val);
    
    assert(filter2.contains(val));
    
    printf("transaction_bloom_filter: Check 8 Passed\n");
    
    val = utility::from_hex("19108ad8ed9bb6274d3980bab5a85c048f0950c8");
    
    assert(!filter2.contains(val));
    
    printf("transaction_bloom_filter: Check 9 Passed\n");
    
    val = utility::from_hex("b5a2c786d9ef4658287ced5914b37a1b4aa32eee");
    
    filter2.insert(val);
    
    assert(filter2.contains(val));
    
    printf("transaction_bloom_filter: Check 10 Passed\n");
    
    val = utility::from_hex("b9300670b4c5366e95b2699e8b18bc75e5f729c5");
    
    filter2.insert(val);
    
    assert(filter2.contains(val));
    
    printf("transaction_bloom_filter: Check 11 Passed\n");
    
    buffer.clear();
    
    filter2.encode(buffer);
    
    tmp = utility::from_hex("03ce4299050000000100008001");
    
    expected = std::vector<char> (tmp.size());

    for (auto i = 0; i < tmp.size(); i++)
    {
        expected[i] = (char)tmp[i];
    }

    for (auto i = 0; i < tmp.size(); i++)
    {
        if (expected[i] != buffer.data()[i])
        {
            printf("transaction_bloom_filter: Filter mismatch %d\n", i);
        }
        else
        {
            printf("transaction_bloom_filter: Filter match %d\n", i);
        }
    }
    
    printf("transaction_bloom_filter: Check 12 Passed\n");

    std::string secret_key =
        "WTdKLEiqXFnypm99qddgQRJLnWwaKH7LSrgBdBgbcRVJJL3mNhBn"
    ;
    
    secret s;
    
    assert(s.set_string(secret_key));

    bool compressed;
    
    auto key_secret = s.get_secret(compressed);
    
    key k;
    
    k.set_secret(key_secret, compressed);
    
    auto pub_key = k.get_public_key();
    
    std::vector<std::uint8_t> pub_key_bytes(
        pub_key.bytes().begin(), pub_key.bytes().end()
    );

    transaction_bloom_filter filter3(
        2, 0.001, 0, transaction_bloom_filter::update_all
    );
    
    filter3.insert(pub_key_bytes);
    
    auto hash = pub_key.get_id();
    
    filter3.insert(
        std::vector<std::uint8_t> (&hash.digest()[0],
        &hash.digest()[0] + ripemd160::digest_length)
    );

    buffer.clear();
    
    filter3.encode(buffer);

    tmp = utility::from_hex("038fc16b080000000000000001");
    
    expected = std::vector<char> (tmp.size());

    for (auto i = 0; i < tmp.size(); i++)
    {
        expected[i] = (char)tmp[i];
    }
    
    for (auto i = 0; i < tmp.size(); i++)
    {
        if (expected[i] != buffer.data()[i])
        {
            printf("transaction_bloom_filter: Filter mismatch %d\n", i);
        }
        else
        {
            printf("transaction_bloom_filter: Filter match %d\n", i);
        }
    }
    
    printf("transaction_bloom_filter: Check 13 Passed\n");
    
    return 0;
}
