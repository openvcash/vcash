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
#include <cmath>

#include <coin/data_buffer.hpp>
#include <coin/hash.hpp>
#include <coin/point_out.hpp>
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
        std::vector<std::uint8_t> (out_point_copy.data(),
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
    
    transaction tx;
    
    /**
     * Tx ID: 2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac
     */
    tmp = utility::from_hex("0100000009f0f556012dbf3865b09a8ec76c7a94239dc42df3458f63af3197a76edf7da29b43f95c01010000008b48304502201e1847d73ebf8e2762ffeaf71ad760b82df223a6ae73eaff2c7a6189cd516d88022100e574269ef71ec9f6c11f5bb51fe8c06283d63a2518e633cd79fe0e215cb06f590141045cfb58bf2cde0dea18413fd97ea98349a51d303d6baeab00536ebb02da2205d39f1b568913c5443a2f9db57dedd355e38cacc3b33fd1502a22059dfbad668afbffffffff02cc6d9026000000001976a914b0828b96cc3adc502911b5de4c4ddcc3e23c716488ac40420f00000000001976a9145365aeb2ae680ae2c18522d26f33acdb3884ef6988ac00000000"
    );
    
    buffer.clear();
    
    buffer.write_bytes(reinterpret_cast<const char *> (&tmp[0]), tmp.size());
    
    tx.decode(buffer);

    /**
     * Tx ID: af1fe7d7c9b5abc1df57e0438bb523af1097be748c3248ac160a1ab154efb82e
     */
    tmp = utility::from_hex("01000000c5f1f55601aceaca8b9b93ff0c35af177edf3b8f0c61337d52b7a9f5ec09db55ee51b16023010000006b48304502207dab2f956042b278bfc28f0f995a3257b31a6c38062d54b006651bfd6e297846022100b97124afbab6c9d9ba7d6bb3cb842044f1366d88736df5e4b72e93c4940cdae5012103f61929f6a32fda609602f532bcbf3967e4b1a52996df2e212b0274d3e8638c5affffffff02ac840100000000001976a9149becef0b1317539d8c0be8415cd866cc3a00682388aca0bb0d00000000001976a914538d91f1856fef39665107f09b133917ea92a14388ac00000000"
    );
    
    transaction tx_spending;
    
    buffer.clear();
    
    buffer.write_bytes(reinterpret_cast<const char *> (&tmp[0]), tmp.size());
    
    tx_spending.decode(buffer);
    
    transaction_bloom_filter filter4(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Tx ID: 2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac
     * @note https://explorer.v.cash/api/getrawtransaction?txid=2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac&decrypt=1
     */
    filter4.insert(
        sha256("2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac")
    );
    
    assert(filter4.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 14 Passed\n");

    transaction_bloom_filter filter5(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * The Tx ID that will be byte reversed.
     */
    std::string tx_id_reversed =
        "2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac"
    ;
    
    std::reverse(tx_id_reversed.begin(), tx_id_reversed.end());
    
    for (auto it = tx_id_reversed.begin(); it != tx_id_reversed.end(); it += 2)
    {
        std::swap(it[0], it[1]);
    }

    /**
     * Tx ID: 2360b151ee55db09ecf5a9b7527d33610c8f3bdf7e17af350cff939b8bcaeaac
     */
    filter5.insert(utility::from_hex(tx_id_reversed));
    
    assert(filter5.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 15 Passed\n");
    
    transaction_bloom_filter filter6(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Input signature.
     */
    
    filter6.insert(utility::from_hex(
        "304502201e1847d73ebf8e2762ffeaf71ad760b82df223a6ae73eaff2c7a6189cd516"
        "d88022100e574269ef71ec9f6c11f5bb51fe8c06283d63a2518e633cd79fe0e215cb0"
        "6f5901")
    );
    
    assert(filter6.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 16 Passed\n");
    
    transaction_bloom_filter filter7(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert public key.
     */
    
    filter7.insert(utility::from_hex(
        "5365aeb2ae680ae2c18522d26f33acdb3884ef69")
    );
    
    assert(filter7.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 17 Passed\n");

    transaction_bloom_filter filter8(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert output address.
     */
    
    filter8.insert(utility::from_hex(
        "5365aeb2ae680ae2c18522d26f33acdb3884ef69")
    );
    
    assert(filter8.is_relevant_and_update(tx));
    assert(filter8.is_relevant_and_update(tx_spending));
    
    printf("transaction_bloom_filter: Check 18 Passed\n");
    
    transaction_bloom_filter filter9(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert output address.
     */
    
    filter9.insert(utility::from_hex(
        "b0828b96cc3adc502911b5de4c4ddcc3e23c7164")
    );
    
    assert(filter9.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 19 Passed\n");
    
    transaction_bloom_filter filter10(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert output point_out.
     * 015cf9439ba27ddf6ea79731af638f45f32dc49d23947a6cc78e9ab06538bf2d
     */

    filter10.insert(
        point_out(sha256(
        "015cf9439ba27ddf6ea79731af638f45f32dc49d23947a6cc78e9ab06538bf2d"), 1)
    );
    
    assert(filter10.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 20 Passed\n");
    
    transaction_bloom_filter filter11(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert output point_out from raw data.
     * 015cf9439ba27ddf6ea79731af638f45f32dc49d23947a6cc78e9ab06538bf2d
     */
    
    point_out previous_out(sha256(
        "015cf9439ba27ddf6ea79731af638f45f32dc49d23947a6cc78e9ab06538bf2d"), 1
    );

    std::vector<std::uint8_t> data(32 + sizeof(std::uint32_t));
    
    std::memcpy(
        &data[0], previous_out.get_hash().digest(), sha256::digest_length
    );
    std::memcpy(&data[32], &previous_out.n(), sizeof(std::uint32_t));
 
    filter11.insert(data);
    
    assert(filter11.is_relevant_and_update(tx));
    
    printf("transaction_bloom_filter: Check 21 Passed\n");
    
    transaction_bloom_filter filter12(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert random Tx ID.
     * 00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436
     */

    filter12.insert(
        sha256(
        "00000009e784f32f62ef849763d4f45b98e07ba658647343b915ff832b110436")
    );
    
    assert(filter12.is_relevant_and_update(tx) == false);
    
    printf("transaction_bloom_filter: Check 22 Passed\n");
    
    transaction_bloom_filter filter13(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert random address.
     * 0000006d2965547608b9e15d9032a7b9d64fa431
     */

    filter13.insert(
        utility::from_hex("0000006d2965547608b9e15d9032a7b9d64fa431")
    );
    
    assert(filter13.is_relevant_and_update(tx) == false);
    
    printf("transaction_bloom_filter: Check 23 Passed\n");
    
    transaction_bloom_filter filter14(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert random point_out.
     * 90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b
     */

    filter14.insert(
        point_out(sha256(
        "90c122d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 2)
    );
    
    assert(filter14.is_relevant_and_update(tx) == false);
    
    printf("transaction_bloom_filter: Check 24 Passed\n");
    
    
    transaction_bloom_filter filter15(
        10, 0.000001, 0, transaction_bloom_filter::update_all
    );
    
    /**
     * Insert random point_out.
     * 000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b
     */

    filter15.insert(
        point_out(sha256(
        "000000d70786e899529d71dbeba91ba216982fb6ba58f3bdaab65e73b7e9260b"), 0)
    );
    
    assert(filter15.is_relevant_and_update(tx) == false);
    
    printf("transaction_bloom_filter: Check 25 Passed\n");

    return 0;
}
