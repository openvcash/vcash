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
#include <mutex>

#include <coin/block_merkle.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/script.hpp>
#include <coin/transaction.hpp>
#include <coin/wallet.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

globals::globals()
    : m_strand(m_io_service)
    , m_state(state_none)
#if (defined __ANDROID__ || defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , m_operation_mode(protocol::operation_mode_client)
#else
    , m_operation_mode(protocol::operation_mode_peer)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
    , m_debug(true)
    , m_is_client_spv(false)
    , m_version_nonce(0)
    , m_best_block_height(-1)
    , m_block_index_fbbh_last(0)
    , m_time_best_received(0)
    , m_transactions_updated(0)
    , m_peer_block_counts(5, 0)
    , m_transaction_fee(constants::min_tx_fee)
    , m_wallet_unlocked_mint_only(false)
    , m_last_coin_stake_search_interval(0)
    , m_option_rescan(false)
    , m_last_block_transactions(0)
    , m_last_block_size(0)
    , m_money_supply(0)
    , m_coinbase_flags(new script())
    , m_zerotime_depth(zerotime::depth)
    , m_zerotime_answers_minimum(zerotime::answers_minimum)
    , m_spv_active_tcp_connection_identifier(0)
    , m_spv_best_block_height(-1)
    , m_spv_use_getblocks(false)
    , m_spv_time_wallet_created(std::time(0))
    , m_db_private(false)
{
    /**
     * P2SH (BIP16 support) can be removed eventually.
     */
    auto p2sh = "/P2SH/";

    *m_coinbase_flags << std::vector<std::uint8_t>(p2sh, p2sh + strlen(p2sh));
}

globals & globals::instance()
{
    static globals g_globals;
    
    static std::recursive_mutex g_recursive_mutex;
    
    std::lock_guard<std::recursive_mutex> l1(g_recursive_mutex);
    
    return g_globals;
}

void globals::set_operation_mode(const protocol::operation_mode_t & val)
{
    m_operation_mode = val;
}

protocol::operation_mode_t & globals::operation_mode()
{
    return m_operation_mode;
}

script & globals::coinbase_flags()
{
    return *m_coinbase_flags;
}

void globals::set_zerotime_depth(const std::uint8_t & val)
{
    m_zerotime_depth = val;
}

const std::uint8_t & globals::zerotime_depth() const
{
    return m_zerotime_depth;
}

void globals::set_zerotime_answers_minimum(const std::uint8_t & val)
{
    m_zerotime_answers_minimum = val;
}

const std::uint8_t & globals::zerotime_answers_minimum() const
{
    return m_zerotime_answers_minimum;
}

void globals::set_spv_active_tcp_connection_identifier(
    const std::uint32_t & val
    )
{
    m_spv_active_tcp_connection_identifier = val;
}

const std::uint32_t & globals::spv_active_tcp_connection_identifier() const
{
    return m_spv_active_tcp_connection_identifier;
}

std::map<sha256, std::unique_ptr<block_merkle> > & globals::spv_block_merkles()
{
    return m_spv_block_merkles;
}

void globals::set_spv_block_last(const block_merkle & val)
{
    m_spv_block_last.reset(new block_merkle(val));
}

void globals::set_spv_block_last(const std::unique_ptr<block_merkle> & val)
{
    if (val)
    {
        m_spv_block_last.reset(new block_merkle(*val));
    }
    else
    {
        m_spv_block_last.reset();
    }
}

const std::unique_ptr<block_merkle> & globals::spv_block_last() const
{
    if (
        m_spv_block_last &&
        m_spv_block_last->height() > m_spv_best_block_height
        )
    {
        m_spv_best_block_height = m_spv_block_last->height();
    }
    
    return m_spv_block_last;
}

std::map<sha256, std::unique_ptr<block_merkle> > &
    globals::spv_block_merkle_orphans()
{
    return m_spv_block_merkle_orphans;
}

void globals::set_spv_block_orphan_last(const block_merkle & val)
{
    m_spv_block_orphan_last.reset(new block_merkle(val));
}

const std::unique_ptr<block_merkle> & globals::spv_block_orphan_last() const
{
    return m_spv_block_orphan_last;
}

void globals::set_spv_best_block_height(const std::int32_t & value)
{
    m_spv_best_block_height = value;
}

const std::int32_t & globals::spv_best_block_height() const
{
    return m_spv_best_block_height;
}

const std::unique_ptr<transaction_bloom_filter> &
    globals::spv_transaction_bloom_filter() const
{
    return m_spv_transaction_bloom_filter;
}

std::vector<sha256> globals::spv_block_locator_hashes()
{
    std::vector<sha256> ret;

    std::int32_t step = 1, start = 0;
    
    const auto * block_last = globals::instance().spv_block_last().get();

    while (block_last && block_last->height() > 0)
    {
        ret.push_back(block_last->get_hash());

        /**
         * Exponentially larger steps back.
         */
        for (auto i = 0; block_last && i < step; i++)
        {
            block_last =
                m_spv_block_merkles[block_last->block_header(
                ).hash_previous_block].get()
            ;
        }
        
        if (++start > 10)
        {
            step *= 2;
        }
    }

    ret.push_back(
        (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
    );

    return ret;
}

void globals::set_spv_use_getblocks(const bool & val)
{
    m_spv_use_getblocks = val;
}

const bool & globals::spv_use_getblocks() const
{
    return m_spv_use_getblocks;
}

void globals::set_spv_time_wallet_created(const std::time_t & val)
{
    m_spv_time_wallet_created = val;
}

const std::time_t globals::spv_time_wallet_created() const
{
    /**
     * Return t - one day.
     */
    return m_spv_time_wallet_created - 1 * 24 * 60 * 60;
}

std::map<sha256, std::vector<transaction> > &
    globals::spv_block_merkle_orphan_transactions()
{
    return m_spv_block_merkle_orphan_transactions;
}

void globals::set_db_private(const bool & val)
{
    m_db_private = val;
}

const bool & globals::db_private() const
{
    return m_db_private;
}

void globals::spv_reset_bloom_filter()
{
    /**
     * The number of elements (keys or point_out's).
     */
    std::uint32_t elements = 0;
    
    if (m_wallet_main->is_crypted() == true)
    {
        elements += m_wallet_main->crypted_keys().size();
    }
    else
    {
        elements += m_wallet_main->keys().size();
    }
    
    /**
     * A random value to add to the seed value in the hash function used by
     * the bloom filter.
     */
    auto tweak = static_cast<std::uint32_t> (std::rand());

    /**
     * Allocate the (SPV) transaction_bloom_filter.
     */
    m_spv_transaction_bloom_filter.reset(
        new transaction_bloom_filter(elements, spv_false_positive_rate(),
        tweak, transaction_bloom_filter::update_all)
    );
    
    if (m_wallet_main)
    {
        if (m_wallet_main->is_crypted() == true)
        {
            /**
             * Iterate all keys.
             */
            for (auto & i : m_wallet_main->crypted_keys())
            {
                auto pub_key = i.second.first;

                auto hash = pub_key.get_id();
                
                m_spv_transaction_bloom_filter->insert(
                    std::vector<std::uint8_t> (&hash.digest()[0],
                    &hash.digest()[0] + ripemd160::digest_length)
                );
                
                log_info(
                    "Reset bloom filter for (crypted) address " <<
                    address(hash).to_string() << "."
                );
            }
        }
        else
        {
            /**
             * Iterate all keys.
             */
            for (auto & i : m_wallet_main->keys())
            {
                const auto & key_id = i.first;
                
                key k;
                
                if (m_wallet_main->get_key(key_id, k) == true)
                {
                    auto compressed = false;
                    
                    auto s = k.get_secret(compressed);
                    
                    if (m_wallet_main->address_book().count(key_id) > 0)
                    {
                        k.set_secret(s, compressed);
                        
                        auto pub_key = k.get_public_key();

                        auto hash = pub_key.get_id();
                        
                        m_spv_transaction_bloom_filter->insert(
                            std::vector<std::uint8_t> (&hash.digest()[0],
                            &hash.digest()[0] + ripemd160::digest_length)
                        );
                        
                        log_info(
                            "Reset bloom filter for address " <<
                            address(key_id).to_string() << "."
                        );
                    }
                    else
                    {
                        k.set_secret(s, compressed);
                        
                        auto pub_key = k.get_public_key();

                        auto hash = pub_key.get_id();
                        
                        m_spv_transaction_bloom_filter->insert(
                            std::vector<std::uint8_t> (&hash.digest()[0],
                            &hash.digest()[0] + ripemd160::digest_length)
                        );
                        
                        log_info(
                            "Reset bloom filter for address " <<
                            address(key_id).to_string() << "."
                        );
                    }
                }
            }
        }
    }

    /**
     * :TODO: UTXO's
     */
}

const double globals::spv_false_positive_rate() const
{
    return 0.00005;
}
