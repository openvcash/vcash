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

#include <chrono>
#include <future>
#include <stdexcept>

#include <boost/lexical_cast.hpp>

#include <coin/account.hpp>
#include <coin/accounting_entry.hpp>
#include <coin/address.hpp>
#include <coin/block_locator.hpp>
#include <coin/coin_control.hpp>
#include <coin/constants.hpp>
#include <coin/crypter.hpp>
#include <coin/db_env.hpp>
#include <coin/hash.hpp>
#include <coin/kernel.hpp>
#include <coin/key_reserved.hpp>
#include <coin/key_pool.hpp>
#include <coin/logger.hpp>
#include <coin/random.hpp>
#include <coin/reward.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/time.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/wallet.hpp>

using namespace coin;

wallet::wallet()
    : m_wallet_version(feature_base)
    , m_wallet_version_max(feature_base)
    , m_order_position_next(0)
    , m_master_key_max_id(0)
    , stack_impl_(0)
    , m_is_file_backed(true)
    , resend_transactions_timer_(globals::instance().io_service())
    , time_last_resend_(0)
{
    // ...
}

wallet::wallet(stack_impl & impl)
    : m_wallet_version(feature_base)
    , m_wallet_version_max(feature_base)
    , m_order_position_next(0)
    , m_master_key_max_id(0)
    , stack_impl_(&impl)
    , m_is_file_backed(true)
    , resend_transactions_timer_(globals::instance().io_service())
    , time_last_resend_(0)
{
    // ...
}

void wallet::start()
{
    /**
     * Start the resend transactions timer.
     */
    resend_transactions_timer_.expires_from_now(std::chrono::seconds(300));
    resend_transactions_timer_.async_wait(globals::instance().strand().wrap(
        std::bind(&wallet::resend_transactions_tick, this,
        std::placeholders::_1))
    );
    
    for (auto & i : m_address_book)
    {
        /**
         * Allocate the info.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet.address_book";

        /**
         * Set the value.
         */
        status["value"] = "new";
        
        /**
         * Set the wallet.transaction.hash.
         */
        status["wallet.address_book.address"] =
            address(i.first).to_string()
        ;
        
        /**
         * Set the wallet.transaction.hash.
         */
        status["wallet.address_book.name"] = i.second;
        
        if (stack_impl_)
        {
            /**
             * Callback on new or updated transaction.
             */
            stack_impl_->get_status_manager()->insert(status);
        }
    }
}

void wallet::stop()
{
    resend_transactions_timer_.cancel();
}

void wallet::flush()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    auto reference_count = 0;

    auto it = stack_impl::get_db_env()->file_use_counts().begin();

    while (it != stack_impl::get_db_env()->file_use_counts().end())
    {
        reference_count += it->second;
        
        it++;
    }

    if (reference_count == 0)
    {
        auto it = stack_impl::get_db_env()->file_use_counts().find(
            "wallet.dat"
        );
        
        if (it != stack_impl::get_db_env()->file_use_counts().end())
        {
            log_info("Wallet is flushing to disk.");

            stack_impl::get_db_env()->close_Db("wallet.dat");
            
            stack_impl::get_db_env()->checkpoint_lsn("wallet.dat");

            stack_impl::get_db_env()->file_use_counts().erase(it++);
            
            log_info("Wallet flushed to disk.");
        }
    }
}

bool wallet::encrypt(const std::string & passphrase)
{
    if (passphrase.size() == 0)
    {
        log_error("Wallet failed to encrypt, empty passphrase.");
        
        return false;
    }
    
    if (is_crypted())
    {
        log_error("Wallet failed to encrypt, already encrypted.");
        
        return false;
    }
    
    return do_encrypt(passphrase);
}

bool wallet::unlock(const std::string & passphrase)
{
    if (is_locked())
    {
        crypter c;
        
        types::keying_material_t master_key;

        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        for (auto & i : m_master_keys)
        {
            if (
                c.set_key_from_passphrase(passphrase, i.second.salt(),
                i.second.derive_iterations(),
                i.second.derivation_method()) == false
                )
            {
                return false;
            }

            if (c.decrypt(i.second.crypted_key(), master_key) == false)
            {
                return false;
            }
            
            if (key_store_crypto::unlock(master_key) == true)
            {
                return true;
            }
        }
    }

    return false;
}

bool wallet::can_support_feature(const feature_t & value)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_wallet_version_max >= value;
}

key_public wallet::generate_new_key()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Check if the key can be compressed.
     */
    bool compressed = can_support_feature(feature_comprpubkey);

    /**
     * Increase the uncertainty about the RNG state.
     */
    random::openssl_RAND_add();
    
    /**
     * Allocate the key.
     */
    key k;
    
    /**
     * Make the key.
     */
    k.make_new_key(compressed);

    /**
     * Compressed public keys were introduced in version 0.6.0.
     */
    if (compressed)
    {
        set_min_version(feature_comprpubkey);
    }
    
    /**
     * Try to add the key.
     */
    if (add_key(k) == false)
    {
        throw std::runtime_error(
            "wallet::generate_new_key() : add_key failed"
        );
    }
    
    return k.get_public_key();
}

bool wallet::load_key(const key & k)
{
    return key_store_crypto::add_key(k);
}

bool wallet::load_minimum_version(const std::int32_t & version)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_wallet_version = version;
    
    m_wallet_version_max = std::max(
        m_wallet_version_max, m_wallet_version
    );
    
    return true;
}

bool wallet::add_key(const key & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (key_store_crypto::add_key(val) == false)
    {
        return false;
    }
    
    if (m_is_file_backed == false)
    {
        return true;
    }
    
    if (is_crypted() == false)
    {
        return db_wallet("wallet.dat").write_key(
            val.get_public_key(), val.get_private_key()
        );
    }
    
    return true;
}

bool wallet::add_crypted_key(
    const key_public & pub_key, const std::vector<std::uint8_t> & crypted_secret
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (key_store_crypto::add_crypted_key(pub_key, crypted_secret) == false)
    {
        return false;
    }
    
    if (m_is_file_backed == false)
    {
        return true;
    }

    if (m_db_wallet_encryption)
    {
        return
            m_db_wallet_encryption->write_crypted_key(pub_key, crypted_secret)
        ;
    }
    else
    {
        return
            db_wallet("wallet.dat").write_crypted_key(pub_key, crypted_secret)
        ;
    }
    
    return false;
}

bool wallet::load_crypted_key(
    const key_public & pub_key, const std::vector<std::uint8_t> & crypted_secret
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    set_min_version(feature_walletcrypt);
    
    return key_store_crypto::add_crypted_key(pub_key, crypted_secret);
}

bool wallet::add_c_script(const script & script_redeem)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (key_store_crypto::add_c_script(script_redeem) == false)
    {
        return false;
    }
    
    if (m_is_file_backed == false)
    {
        return true;
    }
    
    return
        db_wallet("wallet.dat").write_c_script(hash::sha256_ripemd160(
        &script_redeem[0], script_redeem.size()), script_redeem)
    ;
}

bool wallet::load_c_script(const script & script_redeem)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return key_store_crypto::add_c_script(script_redeem);
}

std::int64_t wallet::increment_order_position_next(
    db_wallet * ptr_wallet_db
    ) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = m_order_position_next++;
    
    if (ptr_wallet_db)
    {
        ptr_wallet_db->write_orderposnext(m_order_position_next);
    }
    else
    {
        db_wallet("wallet.dat").write_orderposnext(m_order_position_next);
    }
    
    return ret;
}

bool wallet::new_key_pool()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    db_wallet wallet_db("wallet.dat");
    
    /**
     * Remove the old keys from the pool.
     */
    for (auto & i : m_key_pool)
    {
        wallet_db.erase_pool(i);
    }
    
    /**
     * Clear the old keys.
     */
    m_key_pool.clear();

    if (is_locked() == false)
    {
        /**
         * Get the number of keys.
         */
        auto target_size = 0;
        
        if (stack_impl_)
        {
            target_size =
                std::max(
                stack_impl_->get_configuration().wallet_keypool_size(), 0)
            ;
        }
        
        for (int i = 0; i < target_size; i++)
        {
            auto index = i + 1;
            
            /**
             * Create a new key pool with a new key.
             */
            key_pool pool(generate_new_key());
            
            /**
             * Write the new pool to the wallet.
             */
            wallet_db.write_pool(index, pool);
            
            m_key_pool.insert(index);
        }
        
        log_debug(
            "Wallet, created new key pool, wrote " << target_size << " keys."
        );
        
        return true;
    }
    
    return false;
}

bool wallet::top_up_key_pool()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);

    if (is_locked())
    {
        return false;
    }
    
    db_wallet wallet_db("wallet.dat");

    /**
     * Top up (off) the key pool.
     */
    auto target_size = 0;
    
    if (stack_impl_)
    {
        target_size =
            std::max(
            stack_impl_->get_configuration().wallet_keypool_size(), 0)
        ;
    }

    while (m_key_pool.size() < (target_size + 1))
    {
        std::int64_t end = 1;
        
        if (m_key_pool.size() > 0)
        {
            end = *(--m_key_pool.end()) + 1;
        }
        
        key_pool pool(generate_new_key());
        
        if (wallet_db.write_pool(end, pool) == false)
        {
            throw std::runtime_error(
                "wallet::top_up_key_pool() : writing generated key failed"
            );
        }
    
        m_key_pool.insert(end);
        
        log_info(
            "Wallet toping off key pool, added " << end <<
            ", size = " << m_key_pool.size() << "."
        );
    }

    return true;
}

void wallet::reserve_key_from_key_pool(
    std::int64_t & index, key_pool & keypool
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    index = -1;
    
    keypool.set_key_public(key_public());

    if (is_locked() == false)
    {
        top_up_key_pool();
    }
    
    /**
     * Get the oldest key.
     */
    if (m_key_pool.size() == 0)
    {
        return;
    }
    
    db_wallet wallet_db("wallet.dat");
    
    index = *m_key_pool.begin();
    
    m_key_pool.erase(m_key_pool.begin());
    
    if (wallet_db.read_pool(index, keypool) == false)
    {
        throw std::runtime_error(
            "wallet::reserve_key_from_key_pool() : read failed"
        );
    }
    
    if (have_key(keypool.get_key_public().get_id()) == false)
    {
        throw std::runtime_error(
            "wallet::reserve_key_from_key_pool() : unknown key in key pool"
        );
    }
    
    assert(keypool.get_key_public().is_valid());
    
    /**
     * -printkeypool
     */
    log_none("Wallet reserved key " << index << " from pool.");
}

void wallet::keep_key(const std::int64_t & index)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Remove from key pool.
     */
    if (m_is_file_backed)
    {
        db_wallet wallet_db("wallet.dat");
        
        wallet_db.erase_pool(index);
    }
    
    log_debug("Wallet key pool keep key " << index << ".");
}

void wallet::return_key(const std::int64_t & index)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Return to the key_pool.
     */
    m_key_pool.insert(index);

    log_none("Wallet key pool return key " << index << ".");
}

bool wallet::get_key_from_pool(key_public & result, const bool & allow_reuse)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t index = 0;

    /**
     * Allocate the key_pool.
     */
    key_pool pool;
    
    reserve_key_from_key_pool(index, pool);
    
    if (index == -1)
    {
        if (allow_reuse && m_key_public_default.is_valid())
        {
            result = m_key_public_default;
            
            return true;
        }
        
        if (is_locked())
        {
            return false;
        }
        
        result = generate_new_key();
        
        return true;
    }
    
    keep_key(index);
    
    result = pool.get_key_public();

    return true;
}

bool wallet::is_from_me(const transaction & tx) const
{
    return get_debit(tx) > 0;
}

bool wallet::is_mine(const transaction & tx) const
{
    for (auto & i : tx.transactions_out())
    {
        if (is_mine(i))
        {
            return true;
        }
    }
    return false;
}

bool wallet::is_mine(const transaction_in & tx_in) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
        
    auto it = m_transactions.find(tx_in.previous_out().get_hash());

    if (it != m_transactions.end())
    {
        const auto & prev = it->second;
        
        if (tx_in.previous_out().n() < prev.transactions_out().size())
        {
            if (is_mine(prev.transactions_out()[tx_in.previous_out().n()]))
            {
                return true;
            }
        }
    }

    return false;
}

bool wallet::is_mine(const transaction_out & tx_out) const
{
    return script::is_mine(*this, tx_out.script_public_key());
}

std::int64_t wallet::get_debit(const transaction & tx) const
{
    std::int64_t ret = 0;
    
    for (auto & i : tx.transactions_in())
    {
        ret += get_debit(i);
        
        if (utility::money_range(ret) == false)
        {
            throw std::runtime_error("value out of range");
        }
    }
    
    return ret;
}

std::int64_t wallet::get_debit(const transaction_in & tx_in) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
        
    auto it = m_transactions.find(tx_in.previous_out().get_hash());

    if (it != m_transactions.end())
    {
        const auto & prev = it->second;

        if (tx_in.previous_out().n() < prev.transactions_out().size())
        {
            if (is_mine(prev.transactions_out()[tx_in.previous_out().n()]))
            {
                return
                    prev.transactions_out()[tx_in.previous_out().n()].value()
                ;
            }
        }
    }

    return 0;
}

std::int64_t wallet::get_credit(const transaction_out & tx_out) const
{
    if (utility::money_range(tx_out.value()) == false)
    {
        throw std::runtime_error(
            "wallet::get_credit() : value out of range"
        );
    }
    
    return is_mine(tx_out) ? tx_out.value() : 0;
}

std::int64_t wallet::get_credit(const transaction & tx) const
{
    std::int64_t ret = 0;
    
    for (auto & i : tx.transactions_out())
    {
        ret += get_credit(i);
        
        if (utility::money_range(ret) == false)
        {
            throw std::runtime_error(
                "wallet::get_credit() : value out of range"
            );
        }
    }
    
    return ret;
}

bool wallet::is_change(const transaction_out & tx_out) const
{
    destination::tx_t address;

    if (
        script::extract_destination(tx_out.script_public_key(), address) &&
        script::is_mine(*this, address)
        )
    {
        if (m_address_book.count(address) == 0)
        {
            return true;
        }
    }
    return false;
}

void wallet::set_best_chain(const block_locator & value)
{
    db_wallet("wallet.dat").write_bestblock(value);
}

db_wallet::error_t wallet::load_wallet(bool & first_run)
{
    db_wallet::error_t ret = db_wallet::error_load_ok;

    if (m_is_file_backed == false)
    {
        return ret;
    }
    else
    {
        first_run = false;
        
        ret = db_wallet("wallet.dat", "cr+").load(*this);
        
        if (ret == db_wallet::error_need_rewrite)
        {
            globals::instance().io_service().post(
                globals::instance().strand().wrap(
                [this]()
            {
                if (db::rewrite("\x04pool"))
                {

                    m_key_pool.clear();
                    
                    /**
                     * The key pool cannot be topped off here because we are
                     * locked.
                     */
                }
            }));
        }
    }
    
    if (ret != db_wallet::error_load_ok)
    {
        return ret;
    }
    
    first_run = m_key_public_default.is_valid() == false;
    
    /**
     * Flush the wallet database by posting to the boost::asio::io_service.
     */
    globals::instance().io_service().post(
        globals::instance().strand().wrap(
        [this]()
    {
        flush();
    }));
    
    return ret;
}

void wallet::on_transaction_updated(const sha256 & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Only notify UI if this transaction is in this wallet.
     */
    auto it = m_transactions.find(val);
    
    if (it != m_transactions.end())
    {
        transaction_wallet & wtx = it->second;
        
        /**
         * Allocate the info.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet.transaction";

        /**
         * Set the value.
         */
        status["value"] = "updated";
        
        /**
         * Set the wallet.transaction.hash.
         */
        status["wallet.transaction.hash"] = val.to_string();
        
        /**
         * Set the wallet.transaction.in_main_chain.
         */
        status["wallet.transaction.in_main_chain"] =
            std::to_string(wtx.is_in_main_chain())
        ;
        
        /**
         * Set the wallet.transaction.is_from_me.
         */
        status["wallet.transaction.is_from_me"] =
            std::to_string(wtx.is_from_me())
        ;
        
        /**
         * Set the wallet.transaction.confirmations.
         */
        status["wallet.transaction.confirmations"] =
            std::to_string(wtx.get_depth_in_main_chain())
        ;
        
        /**
         * Set the wallet.transaction.confirmed.
         */
        status["wallet.transaction.confirmed"] =
            std::to_string(wtx.is_confirmed())
        ;
        
        /**
         * Set the wallet.transaction.credit.
         */
        status["wallet.transaction.credit"] =
            std::to_string(wtx.get_credit(true))
        ;
        
        /**
         * Set the wallet.transaction.debit.
         */
        status["wallet.transaction.debit"] =
            std::to_string(wtx.get_debit())
        ;
        
        /**
         * Set the wallet.transaction.net.
         */
        status["wallet.transaction.net"] =
            std::to_string(wtx.get_credit(true) - wtx.get_debit())
        ;
        
        /**
         * Set the wallet.transaction.time.
         */
        status["wallet.transaction.time"] = std::to_string(wtx.time());
        
        if (wtx.is_coin_stake())
        {
            /**
             * Set the wallet.transaction.coin_stake.
             */
            status["wallet.transaction.coin_stake"] = "1";
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] = std::to_string(
                -wtx.get_debit()
            );
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.value_out"] = std::to_string(
                wtx.get_value_out()
            );
            
            /**
             * Set the wallet.transaction.type.
             */
            status["wallet.transaction.type"] = "stake";
        }
        else if (wtx.is_coin_base())
        {
            /**
             * Set the wallet.transaction.coin_base.
             */
            status["wallet.transaction.coin_base"] = "1";
            
            std::int64_t credit = 0;
            
            /**
             * Since this is a coin base transaction we only add the first value
             * from the first transaction out.
             */
            for (auto & j : wtx.transactions_out())
            {
                if (
                    globals::instance().wallet_main(
                    )->is_mine(j)
                    )
                {
                    credit += j.value();
                    
                    break;
                }
            }
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] = std::to_string(credit);
            
            /**
             * Set the wallet.transaction.type.
             */
            status["wallet.transaction.type"] = "mined";
        }
    
        if (stack_impl_)
        {
            /**
             * Callback on new or updated transaction.
             */
            stack_impl_->get_status_manager()->insert(status);
        }
    }
}

void wallet::on_inventory(const sha256 & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    auto it = m_request_counts.find(val);

    if (it != m_request_counts.end())
    {
        it->second++;
    }
}

bool wallet::erase_from_wallet(const sha256 & val) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_transactions.erase(val) > 0)
    {
        db_wallet("wallet.dat").erase_tx(val);
    }
    
    return true;
}

void wallet::erase_transactions()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
   for (auto & i : m_transactions)
   {
        db_wallet("wallet.dat").erase_tx(i.first);
   }
   
   m_transactions.clear();
}

std::int32_t wallet::scan_for_transactions(
    const std::shared_ptr<block_index> & index_start, const bool & update
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int32_t ret = 0;
    
    auto index = index_start;
    
    while (index)
    {
        block blk;
        
        blk.read_from_disk(index, true);
        
        for (auto & i : blk.transactions())
        {
            if (add_to_wallet_if_involving_me(i, &blk, update))
            {
                ret++;
            }
        }
        
        index = index->block_index_next();
    }
    
    return ret;
}

void wallet::reaccept_wallet_transactions()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    db_tx tx_db("r");
    
    bool repeat = true;
    
    while (repeat)
    {
        if (globals::instance().state() >= globals::state_stopping)
        {
            log_debug(
                "Wallet reaccept transactions is aborting, state >= "
                "state_stopping."
            );
            
            break;
        }
        
        repeat = false;
        
        std::vector<transaction_position> tx_missing;
        
        for (auto & i : m_transactions)
        {
            auto & wtx = i.second;
            
            if (
                (wtx.is_coin_base() && wtx.is_spent(0)) ||
                (wtx.is_coin_stake() && wtx.is_spent(1))
                )
            {
                continue;
            }

            transaction_index tx_index;
            
            bool updated = false;
            
            if (tx_db.read_transaction_index(wtx.get_hash(), tx_index))
            {
                /**
                 * Update spent if a transaction got spent somewhere else by a
                 * copy of wallet.dat.
                 */
                if (tx_index.spent().size() != wtx.transactions_out().size())
                {
                    log_debug(
                        "Wallet, reaccept wallet transactions "
                        "tx_index.spent().size() = " <<
                        tx_index.spent().size() <<
                        " != wtx.transactions_out().size()  " <<
                        wtx.transactions_out().size() << "."
                    );
                    
                    continue;
                }
                
                for (auto i = 0; i < tx_index.spent().size(); i++)
                {
                    if (wtx.is_spent(i))
                    {
                        continue;
                    }
                    
                    if (
                        tx_index.spent()[i].is_null() == false &&
                        is_mine(wtx.transactions_out()[i])
                        )
                    {
                        wtx.mark_spent(i);
                        
                        updated = true;
                        
                        tx_missing.push_back(tx_index.spent()[i]);
                    }
                }
                
                if (updated)
                {
                    log_debug(
                        "Wallet, reaccept wallet transactions found spent "
                        "coin " << utility::format_money(wtx.get_credit()) <<
                        ", hash = " << wtx.get_hash().to_string() << "."
                    );
                    
                    wtx.mark_dirty();
                    
                    wtx.write_to_disk();
                }
            }
            else
            {
                /**
                 * Re-accept any txes of ours that aren't already in a block.
                 */
                if ((wtx.is_coin_base() || wtx.is_coin_stake()) == false)
                {
                    try
                    {
                        wtx.accept_wallet_transaction(tx_db);
                    }
                    catch (std::exception & e)
                    {
                        log_error(
                            "Wallet, reaccept transactions, "
                            "accept transaction failed, what = " <<
                            e.what() << "."
                        );
                    }
                }
            }
        }
        
        if (tx_missing.size() > 0)
        {
            if (scan_for_transactions(stack_impl::get_block_index_genesis()))
            {
                /**
                 * Found missing transactions: re-do re-accept.
                 */
                repeat = true;
            }
        }
    }
}

void wallet::fix_spent_coins(
    std::int32_t & mismatch_spent, std::int64_t & balance_in_question,
    const bool & check_only
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    mismatch_spent = 0;
    
    balance_in_question = 0;
    
    std::vector<transaction_wallet *> coins;
    
    coins.reserve(m_transactions.size());
    
    for (auto & i : m_transactions)
    {
        coins.push_back(&i.second);
    }
    
    db_tx txdb("r");
    
    for (auto & i : coins)
    {
        /**
         * Find the corresponding transaction index.
         */
        transaction_index tx_index;
        
        /**
         * Read the transaction index.
         */
        if (txdb.read_transaction_index(i->get_hash(), tx_index) == false)
        {
            continue;
        }
        
        for (auto n = 0; n < i->transactions_out().size(); n++)
        {
            if (
                is_mine(i->transactions_out()[n]) && i->is_spent(n) &&
                (tx_index.spent().size() <= n || tx_index.spent()[n].is_null())
                )
            {
                log_info(
                    "Wallet, fix spent coins found lost coin " <<
                    utility::format_money(i->transactions_out()[n].value()) <<
                    ":" << i->get_hash().to_string() << "[" << n << "], " <<
                    (check_only ? "repair not attempted" : "repairing") << "."
                );
                
                mismatch_spent++;
                
                balance_in_question += i->transactions_out()[n].value();
                
                if (check_only == false)
                {
                    i->mark_unspent(n);
                    
                    i->write_to_disk();
                }
            }
            else if (
                is_mine(i->transactions_out()[n]) && i->is_spent(n) == false &&
                (tx_index.spent().size() > n &&
                tx_index.spent()[n].is_null() == false)
                )
            {
                log_info(
                    "Wallet, fix spent coins found spent coin " <<
                    utility::format_money(i->transactions_out()[n].value()) <<
                    i->get_hash().to_string() << "[" << n << "], " <<
                    (check_only ? "repair not attempted" : "repairing") << "."
                );
                
                mismatch_spent++;
                
                balance_in_question += i->transactions_out()[n].value();
                
                if (check_only == false)
                {
                    i->mark_spent(n);
                    
                    i->write_to_disk();
                }
            }
        }
    }
}

void wallet::disable_transaction(const transaction & tx) const
{
    if (tx.is_coin_stake() == false || is_from_me(tx) == false)
    {
        return;
    }
    
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    for (auto & i : tx.transactions_in())
    {
        auto it = m_transactions.find(i.previous_out().get_hash());
        
        if (it != m_transactions.end())
        {
            auto & prev = it->second;
            
            if (
                i.previous_out().n() < prev.transactions_out().size() &&
                is_mine(prev.transactions_out()[i.previous_out().n()]
                )
                )
            {
                prev.mark_unspent(i.previous_out().n());
                
                prev.write_to_disk();
            }
        }
    }
}

bool wallet::add_to_wallet_if_involving_me(
    const transaction & tx, block * blk, const bool & update
    )
{
    auto hash = tx.get_hash();
    
    std::lock_guard<std::recursive_mutex> l1(mutex_);

    bool existed = m_transactions.count(hash);

    if (existed && update == false)
    {
        return false;
    }
    
    if (existed || is_mine(tx) || is_from_me(tx))
    {
        transaction_wallet wtx(this, tx);
        
        /**
         * Get merkle branch if transaction was found in a block.
         */
        if (blk)
        {
            wtx.set_merkle_branch(blk);
        }
        
        return add_to_wallet(wtx);
    }
    else
    {
        update_spent(tx);
    }
    
    return false;
}

wallet::tx_items_t wallet::ordered_tx_items(
    std::list<accounting_entry> & entries, const std::string & account
    ) const
{
    db_wallet wallet_db("wallet.dat");

    /**
     * Get all transaction_wallet's and account_entry's into a sorted-by-order
     * multimap.
     */
    tx_items_t tx_ordered;

    /**
     * Maintaining indices in the database of (account, time) --> txid and
     * (account, time) --> acentry would make this much faster for applications
     * that do this a lot.
     */
    for (auto it = m_transactions.begin(); it != m_transactions.end(); ++it)
    {
        auto wtx = &it->second;
        
        tx_ordered.insert(
            std::make_pair(wtx->order_position(), tx_pair_t(wtx, 0))
        );
    }
    
    entries.clear();
    
    wallet_db.list_account_credit_debit(account, entries);

    for (auto & i : entries)
    {
        tx_ordered.insert(std::make_pair(i.order_position(), tx_pair_t(0, &i)));
    }

    return tx_ordered;
}

void wallet::update_spent(const transaction & tx) const
{
    /**
     * Anytime a signature is successfully verified, it's proof the out point
     * is spent. Update the wallet spent flag if it doesn't know due to
     * wallet.dat being restored from backup or the user making copies of
     * wallet.dat.
     */

    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    for (auto & i : tx.transactions_in())
    {
        auto it = m_transactions.find(i.previous_out().get_hash());
        
        if (it != m_transactions.end())
        {
            auto & wtx = it->second;
            
            if (i.previous_out().n() >= wtx.transactions_out().size())
            {
                log_error(
                    "Wallet, update spent failed, bad wallet transaction " <<
                    wtx.get_hash().to_string().substr(0, 10) << "."
                );
            }
            else if (
                wtx.is_spent(i.previous_out().n()) &&
                is_mine(wtx.transactions_out()[i.previous_out().n()]) == false
                )
            {
                log_debug(
                    "Wallet, update found spent coin " <<
                    utility::format_money(wtx.get_credit()) << ":" <<
                    wtx.get_hash().to_string().substr(0, 10) <<
                    "."
                );

                wtx.mark_spent(i.previous_out().n());
                
                wtx.write_to_disk();
                
                /**
                 * Allocate the info.
                 */
                std::map<std::string, std::string> status;
                
                /**
                 * Set the type.
                 */
                status["type"] = "wallet.transaction";

                /**
                 * Set the value.
                 */
                status["value"] = "updated";
                
                /**
                 * Set the wallet.transaction.hash.
                 */
                status["wallet.transaction.hash"] =
                    i.previous_out().to_string()
                ;
                
                if (stack_impl_)
                {
                    /**
                     * Callback on new or updated transaction.
                     */
                    stack_impl_->get_status_manager()->insert(status);
                }
            }
        }
    }
}

bool wallet::add_to_wallet(const transaction_wallet & wtx_in)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    auto h = wtx_in.get_hash();
    
    /**
     * Try to insert.
     */
    auto ret = m_transactions.insert(std::make_pair(h, wtx_in));

    auto & wtx = ret.first->second;

    /**
     * Bind the wallet.
     */
    wtx.bind_wallet(*this);
    
    bool inserted_new = ret.second;
    
    if (inserted_new)
    {
        wtx.set_time_received(
            static_cast<std::uint32_t> (time::instance().get_adjusted())
        );
        
        wtx.set_order_position(increment_order_position_next());

        wtx.set_time_smart(wtx.time_received());
     
        if (wtx.block_hash() != 0)
        {
            if (globals::instance().block_indexes().count(wtx_in.block_hash()))
            {
                auto latest_now = wtx.time_received();
                
                std::uint32_t latest_entry = 0;

                /**
                 * Tolerate times up to the last timestamp in the wallet not
                 * more than 5 minutes into the future.
                 */
                std::int64_t latest_tolerated = latest_now + 300;
                
                std::list<accounting_entry> acentries;
                
                auto tx_ordered = ordered_tx_items(acentries);
                
                for (
                    auto it = tx_ordered.rbegin(); it != tx_ordered.rend(); ++it
                    )
                {
                    const auto ptr_wtx = it->second.first;
                    
                    if (ptr_wtx == &wtx)
                    {
                        continue;
                    }
                    
                    const accounting_entry * pacentry = it->second.second;
                    
                    std::int64_t time_smart;
                    
                    if (ptr_wtx)
                    {
                        time_smart = ptr_wtx->time_smart();
                        
                        if (!time_smart)
                        {
                            time_smart = ptr_wtx->time_received();
                        }
                    }
                    else
                    {
                        time_smart = pacentry->time();
                    }
                    
                    if (time_smart <= latest_tolerated)
                    {
                        latest_entry = static_cast<std::uint32_t> (time_smart);
                        
                        if (time_smart > latest_now)
                        {
                            latest_now = static_cast<std::uint32_t> (time_smart);
                        }
                        
                        break;
                    }
                }

                auto & block_time = m_transactions[wtx_in.block_hash()].time();
                
                wtx.set_time_smart(std::max(
                    latest_entry, std::min(block_time, latest_now))
                );
            }
            else
            {
                log_debug(
                    "Wallet, add to found " <<
                    wtx_in.get_hash().to_string().substr(0, 10) <<
                    " in block " <<
                    wtx_in.block_hash().to_string().substr(0, 10) << "."
                );
            }
        }
    }
    
    bool updated = false;
    
    if (inserted_new == false)
    {
        /**
         * Merge.
         */
        if (wtx_in.block_hash() != 0 && wtx_in.block_hash() != wtx.block_hash())
        {
            wtx.set_block_hash(wtx_in.block_hash());
            
            updated = true;
        }
        
        if (
            wtx_in.index() != -1 &&
            (wtx_in.merkle_branch() != wtx.merkle_branch() ||
            wtx_in.index() != wtx.index())
            )
        {
            wtx.set_merkle_branch(wtx_in.merkle_branch());
            
            wtx.set_index(wtx_in.index());
            
            updated = true;
        }
        
        if (wtx_in.is_from_me() && wtx_in.is_from_me() != wtx.is_from_me())
        {
            wtx.set_is_from_me(wtx_in.is_from_me());
            
            updated = true;
        }
        
        updated |= wtx.update_spent(wtx_in.spent());
    }
    
    log_debug(
        "Wallet, add to, incoming = " <<
        wtx_in.get_hash().to_string().substr(0, 10) <<
        (inserted_new ? " new" : " ") << (updated ? "update" : "") << "."
    );

    /**
     * Write to disk.
     */
    if (inserted_new || updated)
    {
        if (wtx.write_to_disk() == false)
        {
            return false;
        }
    }
    
#if (defined COIN_USE_GUI && COIN_USE_GUI)
    // ...
#else
        /**
         * If default receiving address gets used, replace it with a new one.
         */
        script script_default_key;
    
        script_default_key.set_destination(m_key_public_default.get_id());
    
        for (auto & i : wtx.transactions_out())
        {
            if (i.script_public_key() == script_default_key)
            {
                key_public new_default_key;
                
                if (get_key_from_pool(new_default_key, false))
                {
                    set_key_public_default(new_default_key, true);
                    
                    set_address_book_name(m_key_public_default.get_id(), "");
                }
            }
        }
#endif // COIN_USE_GUI
    
    /**
     * Since add_to_wallet is called directly for self-originating
     * transactions, check for consumption of our own coins.
     */
    update_spent(wtx);

    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, wtx, updated]()
    {
        /**
         * Allocate the info.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet.transaction";

        /**
         * Set the value.
         */
        status["value"] = (updated ? "updated" : "new");
       
        /**
         * Set the wallet.transaction.is_from_me.
         */
        status["wallet.transaction.is_from_me"] =
            std::to_string(wtx.is_from_me())
        ;
        
        /**
         * Set the wallet.transaction.hash.
         */
        status["wallet.transaction.hash"] = wtx.get_hash().to_string();
        
        /**
         * Set the wallet.transaction.in_main_chain.
         */
        status["wallet.transaction.in_main_chain"] = std::to_string(
            wtx.is_in_main_chain()
        );
        
        /**
         * Set the wallet.transaction.confirmations.
         */
        status["wallet.transaction.confirmations"] =
            std::to_string(wtx.get_depth_in_main_chain())
        ;
        
        /**
         * Set the wallet.transaction.confirmed.
         */
        status["wallet.transaction.confirmed"] =
            std::to_string(wtx.is_confirmed())
        ;
        
        /**
         * Set the wallet.transaction.credit.
         */
        status["wallet.transaction.credit"] =
            std::to_string(wtx.get_credit(true))
        ;
        
        /**
         * Set the wallet.transaction.debit.
         */
        status["wallet.transaction.debit"] = std::to_string(wtx.get_debit());
        
        /**
         * Set the wallet.transaction.net.
         */
        status["wallet.transaction.net"] =
            std::to_string(wtx.get_credit(true) - wtx.get_debit())
        ;
        
        /**
         * Set the wallet.transaction.time.
         */
        status["wallet.transaction.time"] = std::to_string(wtx.time());
        
        if (wtx.is_coin_stake())
        {
            /**
             * Set the wallet.transaction.coin_stake.
             */
            status["wallet.transaction.coin_stake"] = "1";
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] =
                std::to_string(-wtx.get_debit())
            ;
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.value_out"] = std::to_string(
                wtx.get_value_out()
            );
            
            /**
             * Set the wallet.transaction.type.
             */
            status["wallet.transaction.type"] = "stake";
        }
        else if (wtx.is_coin_base())
        {
            /**
             * Set the wallet.transaction.coin_base.
             */
            status["wallet.transaction.coin_base"] = "1";
            
            std::int64_t credit = 0;
            
            /**
             * Since this is a coin base transaction we only add the first value
             * from the first transaction out.
             */
            for (auto & j : wtx.transactions_out())
            {
                if (
                    globals::instance().wallet_main(
                    )->is_mine(j)
                    )
                {
                    credit += j.value();
                    
                    break;
                }
            }
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] = std::to_string(credit);
            
            /**
             * Set the wallet.transaction.type.
             */
            status["wallet.transaction.type"] = "mined";
        }
        
        if (stack_impl_)
        {
            /**
             * Callback on new or updated transaction.
             */
            stack_impl_->get_status_manager()->insert(status);
        }
        
        /**
         * Notify an external script when a wallet transaction comes in or is
         * updated.
         * Call -walletnotify and run command replacing %s with
         * wtx_in.get_hash().to_string().
         */
     }));
    
    return true;
}

void wallet::mark_dirty()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    for (auto & i : m_transactions)
    {
        i.second.mark_dirty();
    }
}

bool wallet::set_address_book_name(
    const destination::tx_t & addr, const std::string & name
    ) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    log_info(
        "Wallet is setting address book " <<
        address(addr).to_string() << " to " << name << "."
    );
    
    auto it = m_address_book.find(addr);
    
    bool is_new = false;
    
    if (it == m_address_book.end())
    {
        is_new = true;
    }
    
    m_address_book[addr] = name;
    
    /**
     * Callback that the address book has changed.
     */
    
    /**
     * Allocate the info.
     */
    std::map<std::string, std::string> status;
    
    /**
     * Set the type.
     */
    status["type"] = "wallet.address_book";

    /**
     * Set the value.
     */
    status["value"] = "new";
    
    /**
     * Set the wallet.transaction.hash.
     */
    status["wallet.address_book.address"] =
        address(addr).to_string()
    ;
    
    /**
     * Set the wallet.transaction.hash.
     */
    status["wallet.address_book.name"] = name;
    
    if (stack_impl_)
    {
        /**
         * Callback on new or updated transaction.
         */
        stack_impl_->get_status_manager()->insert(status);
    }
    
    if (m_is_file_backed == false)
    {
        return false;
    }
    
    return db_wallet("wallet.dat").write_name(address(addr).to_string(), name);
}

bool wallet::set_key_public_default(
    const key_public & value, const bool & write_to_disk
    ) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (write_to_disk)
    {
        if (m_is_file_backed)
        {
            if (db_wallet("wallet.dat").write_defaultkey(value) == false)
            {
                return false;
            }
        }
    }
    
    m_key_public_default = value;
    
    return true;
}

const key_public & wallet::key_public_default() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_key_public_default;
}

std::set<std::int64_t> & wallet::get_key_pool()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_key_pool;
}

std::map<std::uint32_t, key_wallet_master> & wallet::master_keys()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_master_keys;
}

void wallet::set_master_key_max_id(const std::uint32_t & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_master_key_max_id = val;
}

const std::uint32_t & wallet::master_key_max_id() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_master_key_max_id;
}

const bool & wallet::is_file_backed() const
{
    return m_is_file_backed;
}

bool wallet::set_min_version(
    feature_t version, db_wallet * ptr_db_wallet,
    const bool & explicit_upgrade
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_wallet_version >= version)
    {
        return true;
    }
    
    /**
     * When doing an explicit upgrade, if we pass the max version permitted,
     * upgrade all the way
     */
    if (explicit_upgrade && version > m_wallet_version_max)
    {
        version = feature_latest;
    }
    
    m_wallet_version = version;

    if (version > m_wallet_version_max)
    {
        m_wallet_version_max = version;
    }
    
    if (m_is_file_backed)
    {
        auto ptr =
            ptr_db_wallet ?
            ptr_db_wallet : std::make_shared<db_wallet> ("wallet.dat").get()
        ;
        
        if (m_wallet_version > 40000)
        {
            ptr->write_minversion(m_wallet_version);
        }
    }

    return true;
}

bool wallet::set_max_version(const std::int32_t & version)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Cannot downgrade below current version.
     */
    if (m_wallet_version > version)
    {
        return false;
    }
    
    m_wallet_version_max = version;

    return true;
}

std::int32_t wallet::get_version()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_wallet_version;
}

std::int64_t wallet::get_balance() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = 0;

    for (auto & i : m_transactions)
    {
        const auto & coin = i.second;
        
        if (coin.is_final() && coin.is_confirmed())
        {
            ret += coin.get_available_credit();
        }
    }

    return ret;
}

std::int64_t wallet::get_unconfirmed_balance() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = 0;

    for (auto & i : m_transactions)
    {
        const auto & coin = i.second;
        
        if (coin.is_final() == false || coin.is_confirmed() == false)
        {
            ret += coin.get_available_credit();
        }
    }
    
    return ret;
}

std::int64_t wallet::get_immature_balance() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = 0;

    for (auto & i : m_transactions)
    {
        const auto & coin = i.second;
        
        if (
            coin.is_coin_base() && coin.get_blocks_to_maturity() > 0 &&
            coin.is_in_main_chain()
            )
        {
            ret += get_credit(coin);
        }
    }
    
    return ret;
}

std::int64_t wallet::get_stake() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = 0;

    for (auto & i : m_transactions)
    {
        const auto & coin = i.second;
    
        if (
            coin.is_coin_stake() && coin.get_blocks_to_maturity() > 0 &&
            coin.get_depth_in_main_chain() > 0
            )
        {
            ret += get_credit(coin);
        }
    }
    
    return ret;
}

std::int64_t wallet::get_new_mint() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    std::int64_t ret = 0;
    
    for (auto & i : m_transactions)
    {
        const auto & coin = i.second;
        
        if (
            coin.is_coin_base() && coin.get_blocks_to_maturity() > 0 &&
            coin.get_depth_in_main_chain() > 0)
        {
            ret += get_credit(coin);
        }
    }
    return ret;
}

bool wallet::select_coins(
    const std::int64_t & target_value,
    const std::uint32_t & spend_time,
    std::set< std::pair<transaction_wallet,
    std::uint32_t> > & coins_out, std::int64_t & value_out,
    const std::shared_ptr<coin_control> & control
    ) const
{
    std::vector<output> coins;
    
    available_coins(coins, true, control);

    if (control && control->has_selected())
    {
        for (auto & out : coins)
        {
            value_out +=
                out.get_transaction_wallet().transactions_out()[
                out.get_i()].value()
            ;
            
            coins_out.insert(
                std::make_pair(out.get_transaction_wallet(), out.get_i())
            );
        }
        
        return value_out >= target_value;
    }

    return (
        select_coins_min_conf(target_value, spend_time, 1, 6, coins,
        coins_out, value_out) || select_coins_min_conf(target_value,
        spend_time, 1, 1, coins, coins_out, value_out) ||
        select_coins_min_conf(target_value, spend_time, 0, 1, coins,
        coins_out, value_out)
    );
}

bool wallet::create_transaction(
    const std::vector< std::pair<script, std::int64_t> > & scripts,
    transaction_wallet & tx_new, key_reserved & reserved_key,
    std::int64_t & fee_out, const std::shared_ptr<coin_control> & control
    )
{
    std::int64_t value = 0;
    
    for (auto & s : scripts)
    {
        if (value < 0)
        {
            log_debug(
                "Wallet, create transaction failed, value " << value <<
                " is less than 0."
            );
            
            return false;
        }
        
        value += s.second;
    }
    
    if (scripts.size() == 0 || value < 0)
    {
        log_debug("Wallet, create transaction failed, no scripts or value.")

        return false;
    }
    
    tx_new.bind_wallet(*this);
    
    db_tx tx_db("r");
    
    fee_out = globals::instance().transaction_fee();
    
    for (;;)
    {
        tx_new.transactions_in().clear();
        tx_new.transactions_out().clear();
        
        /**
         * Of course it is from me :-).
         */
        tx_new.set_is_from_me(true);

        std::int64_t total_value = value + fee_out;
        
        double priority = 0;
        
        /**
         * The transaction outs to the payees.
         */
        for (auto & s : scripts)
        {
            tx_new.transactions_out().push_back(
                transaction_out(s.second, s.first)
            );
        }
        
        /**
         * Choose coins to use.
         */
        std::set<
            std::pair<transaction_wallet, std::uint32_t>
        > coins;
        
        std::int64_t value_in = 0;
        
        if (
            select_coins(total_value, tx_new.time(),
            coins, value_in, control) == false
            )
        {
            log_debug(
                "Wallet, create transaction failed, select coins failed."
            );

            return false;
        }
        
        for (auto & i : coins)
        {
            std::int64_t credit =
                i.first.transactions_out()[i.second].value()
            ;
            
            priority +=
                static_cast<double> (credit) * i.first.get_depth_in_main_chain()
            ;
        }

        std::int64_t change = value_in - value - fee_out;
        
        /**
         * If sub-cent change is required then the fee must be raised to at
         * least constants::min_tx_fee or until the change becomes zero.
         */
        if (
            fee_out < constants::min_tx_fee && change > 0 &&
            change < constants::cent
            )
        {
            std::int64_t move_to_fee =
                std::min(change, constants::min_tx_fee - fee_out)
            ;
            
            /**
             * Decrement the change.
             */
            change -= move_to_fee;
            
            /**
             * Increment the fee.
             */
            fee_out += move_to_fee;
        }

        /**
         * Sub-cent change is moved to fee (ppcoin).
         */
        if (change > 0 && change < constants::min_txout_amount)
        {
            fee_out += change;
            
            change = 0;
        }

        if (change > 0)
        {
            /**
             * Allocate an out to ourself.
             */
            script script_change;
            
            /**
             * Send change to custom address (coin control),
             * otherwise send change to a newly generated address.
             */
            if (
                control &&
                !boost::get<destination::none>(&control->destination_change())
                )
            {
                script_change.set_destination(control->destination_change());
            }
            else
            {
                /**
                 * Reserve a new key/pair.
                 */
                script_change.set_destination(
                    reserved_key.get_reserved_key().get_id()
                );
            }
            
            /**
             * Insert change txn at random position.
             */
            auto position =
                tx_new.transactions_out().begin() +
                random::uint32(static_cast<std::uint32_t> (
                tx_new.transactions_out().size()))
            ;
            
            tx_new.transactions_out().insert(
                position, transaction_out(change, script_change)
            );
        }
        else
        {
            reserved_key.return_key();
        }
        
        /**
         * Fill out the inputs.
         */
        for (auto & i : coins)
        {
            tx_new.transactions_in().push_back(
                transaction_in(i.first.get_hash(), i.second)
            );
        }
        
        /**
         * Sign the transaction.
         */
        auto n = 0;
        
        for (auto & i : coins)
        {
            if (
                script::sign_signature(*this, i.first, tx_new, n++) == false
                )
            {
                log_debug(
                    "Wallet, create transaction failed, sign signature failed."
                );
                
                return false;
            }
        }
        
        data_buffer buffer;
        
        tx_new.encode(buffer);
        
        /**
         * Get the length of the transaction in bytes.
         */
        auto len = buffer.size();
        
        /**
         * Make sure the transaction is not too big.
         */
        if (len >= constants::max_block_size_gen / 5)
        {
            log_debug("Wallet, create transaction failed, too big.");
            
            return false;
        }
        
        /**
         * Calculate the transaction priority.
         */
        priority /= len;

        /**
         * Check that enough fee is included.
         */
        std::int64_t pay_fee =
            globals::instance().transaction_fee() *
            (1 + (std::int64_t)len / 1000)
        ;
        
        std::int64_t min_fee = tx_new.get_minimum_fee(
            1, false, types::get_minimum_fee_mode_send, len
        );

        if (fee_out < std::max(pay_fee, min_fee))
        {
            fee_out = std::max(pay_fee, min_fee);
            
            continue;
        }

        /**
         * Add the supporting transactions.
         */
        tx_new.add_supporting_transactions(tx_db);
        
        /**
         * Set the time received is the same time as the transaction.
         */
        tx_new.set_time_received_is_tx_time(true);

        break;
    }

    return true;
}

bool wallet::create_transaction(
    const script & script_pub_key, const std::int64_t & value,
    transaction_wallet & tx_new, key_reserved & reserved_key,
    std::int64_t & fee_out, const std::shared_ptr<coin_control> & control
    )
{
    std::vector< std::pair<script, std::int64_t> > scripts;
    
    scripts.push_back(std::make_pair(script_pub_key, value));

    return create_transaction(scripts, tx_new, reserved_key, fee_out, control);
}

bool wallet::get_transaction(
    const sha256 & hash_tx, transaction_wallet & wtx_out
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    auto it = m_transactions.find(hash_tx);

    if (it != m_transactions.end())
    {
        wtx_out = it->second;
        
        return true;
    }

    return false;
}

std::pair<bool, std::string> wallet::commit_transaction(
    transaction_wallet & wtx_new, key_reserved & reserve_key
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    log_debug(
        "Wallet is committing transaction " << wtx_new.to_string() << "."
    );
    
    /**
     * Allocate the db_wallet.
     */
    std::unique_ptr<db_wallet> unused(
        m_is_file_backed ? new db_wallet("wallet.dat", "r") : 0
    );

    /**
     * Take a key/pair from key pool so it won't be used again.
     */
    reserve_key.keep_key();

    /**
     * Add transaction to wallet.
     */
    add_to_wallet(wtx_new);

    /**
     * Mark old coins as spent.
     */
    for (auto & i : wtx_new.transactions_in())
    {
        transaction_wallet & tx = m_transactions[i.previous_out().get_hash()];
        
        /**
         * Bind the wallet.
         */
        tx.bind_wallet(*this);
        
        /**
         * Mark spent.
         */
        tx.mark_spent(i.previous_out().n());
        
        /**
         * Write the transaction to disk.
         */
        tx.write_to_disk();
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status type.
         */
        status["type"] = "wallet.transaction";
        
        /**
         * Set the status value.
         */
        status["value"] = "updated";

        /**
         * Set the wallet.transaction.hash.
         */
        status["wallet.transaction.hash"] = tx.get_hash().to_string();

        /**
         * Set the wallet.transaction.in_main_chain.
         */
        status["wallet.transaction.in_main_chain"] = std::to_string(
            tx.is_in_main_chain()
        );
        
        /**
         * Set the wallet.transaction.is_from_me.
         */
        status["wallet.transaction.is_from_me"] =
            std::to_string(tx.is_from_me())
        ;
        
        /**
         * Set the wallet.transaction.confirmations.
         */
        status["wallet.transaction.confirmations"] =
            std::to_string(tx.get_depth_in_main_chain())
        ;
        
        /**
         * Set the wallet.transaction.confirmed.
         */
        status["wallet.transaction.confirmed"] =
            std::to_string(tx.is_confirmed())
        ;
        
        /**
         * Set the wallet.transaction.credit.
         */
        status["wallet.transaction.credit"] = std::to_string(
            tx.get_credit(true)
        );

        /**
         * Set the wallet.transaction.debit.
         */
        status["wallet.transaction.debit"] =
            std::to_string(tx.get_debit())
        ;
        
        /**
         * Set the wallet.transaction.net.
         */
        status["wallet.transaction.net"] =
            std::to_string(tx.get_credit(true) - tx.get_debit())
        ;

        /**
         * Set the wallet.transaction.time.
         */
        status["wallet.transaction.time"] = std::to_string(tx.time());

        if (tx.is_coin_stake())
        {
            /**
             * Set the wallet.transaction.coin_stake.
             */
            status["wallet.transaction.coin_stake"] = "1";
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] =
                std::to_string(-tx.get_debit())
            ;
        }
        else if (tx.is_coin_base())
        {
            /**
             * Set the wallet.transaction.coin_base.
             */
            status["wallet.transaction.coin_base"] = "1";
            
            std::int64_t credit = 0;
            
            /**
             * Since this is a coin base transaction we only add the first value
             * from the first transaction out.
             */
            for (auto & j : tx.transactions_out())
            {
                if (
                    globals::instance().wallet_main(
                    )->is_mine(j)
                    )
                {
                    credit += j.value();
                    
                    break;
                }
            }
            
            /**
             * Set the wallet.transaction.credit.
             */
            status["wallet.transaction.credit"] = std::to_string(credit);
            
            /**
             * Set the wallet.transaction.type.
             */
            status["wallet.transaction.type"] = "mined";
        }
        
        if (stack_impl_)
        {
            /**
             * Callback
             */
            stack_impl_->get_status_manager()->insert(status);
        }
    }
    
    if (m_is_file_backed)
    {
        /**
         * Deallocate
         */
        unused.reset();
    }
    
    /**
     * Track how many getdata requests our transaction gets.
     */
    m_request_counts[wtx_new.get_hash()] = 0;

    auto ret = wtx_new.accept_to_memory_pool();

    /**
     * Accept to the transaction_pool.
     */
    if (ret.first == false)
    {
        /**
         * The transaction has been signed and recorded, something bad happened.
         */
        
        log_error(
            "Wallet, commit transaction failed, transaction is not valid."
        );

        return std::make_pair(false, ret.second);
    }
    
    if (stack_impl_)
    {
        /**
         * Relay the wallet transaction.
         */
        wtx_new.relay_wallet_transaction(
            stack_impl_->get_tcp_connection_manager()
        );
        
        return std::make_pair(true, "");
    }
    
    return std::make_pair(false, "null stack_impl");
}

bool wallet::create_coin_stake(
    const key_store & keystore, const std::uint32_t & bits,
    const std::int64_t search_interval, transaction & tx_new
    )
{
    /**
     * The split and combine thresholds should not be adjusted for
     * security reasons.
     */
    enum { stake_split_age = 60 * 60 * 24 * 30 };
	
    auto index = utility::get_last_block_index(
        stack_impl::get_block_index_best(), false
    );
    
    std::int64_t combine_threshold = 0;
	
    if (index->block_index_previous())
	{
    	combine_threshold = reward::get_proof_of_work(
            index->height(), constants::min_tx_fee,
            index->block_index_previous()->get_block_hash()) / 3
        ;
    }
    
    big_number target_per_coin_day;
    
    target_per_coin_day.set_compact(bits);

    tx_new.transactions_in().clear();
    tx_new.transactions_out().clear();
    
    script script_empty;
    
    script_empty.clear();
    
    tx_new.transactions_out().push_back(transaction_out(0, script_empty));
    
    /**
     * Choose the coins to use.
     */
    std::int64_t balance = get_balance();
    std::int64_t reserve_balance = 0;

    /**
     * -reservebalance
     */
    if (0)
    {
        log_error(
            "Wallet failed to create coin stake, invalid reserve balance."
        );
        
        return false;
    }
    
    if (balance <= reserve_balance)
    {
        return false;
    }
    
    std::set< std::pair<transaction_wallet, std::uint32_t> > coins;
    
    std::vector<transaction_wallet> previous_wtxs;
    
    std::int64_t value_in = 0;
    
    if (
        select_coins(balance - reserve_balance, tx_new.time(), coins,
        value_in) == false
        )
    {
        return false;
    }
    
    if (coins.empty())
    {
        return false;
    }
    
    std::int64_t credit = 0;
    
    script script_pub_key_kernel;

    for (auto & pcoin : coins)
    {
        db_tx tx_db("r");
        
        transaction_index tx_index;
			
        if (
            tx_db.read_transaction_index(pcoin.first.get_hash(),
            tx_index) == false
            )
        {
            continue;
        }

        /**
         * Allocate the block.
         */
        block blk;

        /**
         * Read the block from disk, excluding the transactions.
         */
        if (
            blk.read_from_disk(tx_index.get_transaction_position().file_index(),
            tx_index.get_transaction_position().block_position(), false) ==
            false
            )
        {
            continue;
        }

        static int max_stake_search_interval = 60;
		
        /**
         * Check the minimum age.
         */
        if (
            blk.header().timestamp + constants::min_stake_age >
            tx_new.time() - max_stake_search_interval
            )
        {
            continue;
        }
        
        bool kernel_found = false;
        
        for (
            auto n = 0 ; n < std::min(search_interval,
            static_cast<std::int64_t> (max_stake_search_interval)) &&
            kernel_found == false && (globals::instance().state() ==
            globals::state_started); n++
            )
        {
            sha256 hash_proof_of_stake = 0;
            
            auto prevout_stake = point_out(
                pcoin.first.get_hash(), pcoin.second
            );
            
            if (
                kernel::check_stake_kernel_hash(bits, blk,
                tx_index.get_transaction_position().tx_position() -
                tx_index.get_transaction_position().block_position(),
                pcoin.first, prevout_stake, tx_new.time() - n,
                hash_proof_of_stake)
                )
            {
                if (globals::instance().debug())
                {
                    log_debug("Wallet, create coin stake found kernel.");
                }
                
                std::vector< std::vector<std::uint8_t> > solutions;
                
                types::tx_out_t which_type;
                
                script script_pub_key_out;
                
                script_pub_key_kernel =
                    pcoin.first.transactions_out()[
                    pcoin.second].script_public_key()
                ;
                
                if (
                    script::solver(script_pub_key_kernel, which_type,
                    solutions) == false
                    )
                {
                    if (globals::instance().debug())
                    {
                        log_debug(
                            "Wallet, create coin stake failed to parse kernel."
                        );
                    }
                    
                    break;
                }
                
                if (globals::instance().debug())
                {
                    log_debug(
                        "Wallet, create coin stake parsed kernel type = " <<
                        which_type << "."
                    );
                }
                
                if (
                    which_type != types::tx_out_pubkey &&
                    which_type != types::tx_out_pubkeyhash
                    )
                {
                    if (globals::instance().debug())
                    {
                        log_debug(
                            "Wallet, create coin stake no support for kernel "
                            "type = " << which_type << "."
                        );
                    }
                    
                    break;
                }
                
                if (which_type == types::tx_out_pubkeyhash)
                {
                    key k;

                    if (keystore.get_key(ripemd160(solutions[0]), k) == false)
                    {
                        if (globals::instance().debug())
                        {
                            log_debug(
                                "Wallet, create coin stake failed to get key "
                                "for kernel type = " << which_type << "."
                            );
                        }
                        
                        break;
                    }
                    
                    script_pub_key_out <<
                        k.get_public_key() << script::op_checksig
                    ;
                }
                else
                {
                    script_pub_key_out = script_pub_key_kernel;
                }
                
                tx_new.set_time(tx_new.time() - n);
                
                tx_new.transactions_in().push_back(
                    transaction_in(pcoin.first.get_hash(), pcoin.second)
                );
                
                credit += pcoin.first.transactions_out()[pcoin.second].value();

                previous_wtxs.push_back(pcoin.first);
                
                tx_new.transactions_out().push_back(
                    transaction_out(0, script_pub_key_out)
                );
                
                if (blk.header().timestamp + stake_split_age > tx_new.time())
                {
                    tx_new.transactions_out().push_back(
                        transaction_out(0, script_pub_key_out)
                    );
                }
                
                if (globals::instance().debug())
                {
                    log_debug(
                        "Wallet, create coin stake added kernel type = " <<
                        which_type << "."
                    );
                }
                
                kernel_found = true;
                
                break;
            }
        }
        
        if (
            kernel_found ||
            globals::instance().state() != globals::state_started
            )
        {
            break;
        }
    }

    if (credit == 0 || credit > balance - reserve_balance)
	{
        return false;
	}

    for (auto & pcoin : coins)
    {
        /**
         * Try to add more inputs.
         */
        if (
            tx_new.transactions_out().size() == 2 &&
            ((pcoin.first.transactions_out()[
            pcoin.second].script_public_key() == script_pub_key_kernel ||
            pcoin.first.transactions_out()[pcoin.second].script_public_key() ==
            tx_new.transactions_out()[1].script_public_key()))
            && pcoin.first.get_hash() !=
            tx_new.transactions_in()[0].previous_out().get_hash()
            )
        {
            /**
             * Stop adding more inputs if there are already too many inputs.
             */
            if (tx_new.transactions_in().size() >= 100)
            {
                break;
            }
            
            /**
             * Stop adding inputs if the value is already significant.
             */
            if (credit > combine_threshold)
            {
                break;
            }
            
            /**
             * Stop adding inputs if we have reached the reserve balance.
             */
            if (
                credit + pcoin.first.transactions_out()[
                pcoin.second].value() > balance - reserve_balance
                )
            {
                break;
            }
            
            /**
             * Don't add significant additional input.
             */
            if (
                pcoin.first.transactions_out()[
                pcoin.second].value() > combine_threshold
                )
            {
                continue;
            }
            
            /**
             * Don't add input that is still too young.
             */
            if (pcoin.first.time() + constants::min_stake_age > tx_new.time())
            {
                continue;
            }
            
            tx_new.transactions_in().push_back(
                transaction_in(pcoin.first.get_hash(), pcoin.second)
            );
            
            credit += pcoin.first.transactions_out()[pcoin.second].value();
            
            previous_wtxs.push_back(pcoin.first);
        }
    }
    
    /**
     * Calculate the coin age reward.
     */
    std::uint64_t coin_age;
    
    db_tx tx_db("r");
    
    index = utility::get_last_block_index(
        stack_impl::get_block_index_best(), false
    );

    if (tx_new.get_coin_age(tx_db, coin_age) == false)
    {
        log_error("Wallet, create coin stake failed to calculate coin age.");
    
        return false;
    }
    
    credit += reward::get_proof_of_stake(
        coin_age, bits, tx_new.time(), index->height()
    );

    std::int64_t min_fee = 0;
    
    for (;;)
    {
        /**
         * Put the output amount into the transaction.
         */
        if (tx_new.transactions_out().size() == 3)
        {
            tx_new.transactions_out()[1].set_value(
                ((credit - min_fee) / 2 / constants::cent) * constants::cent
            );
            tx_new.transactions_out()[2].set_value(
                credit - min_fee - tx_new.transactions_out()[1].value()
            );
        }
        else
        {
            tx_new.transactions_out()[1].set_value(credit - min_fee);
        }
        
        /**
         * Generate the signature.
         */
        int n = 0;
        
        for (auto & pcoin : previous_wtxs)
        {
            if (script::sign_signature(*this, pcoin, tx_new, n++) == false)
            {
                log_error(
                    "Wallet, create coin stake failed, unable to sign."
                );
                
                return false;
            }
        }

        data_buffer buffer;
        
        tx_new.encode(buffer);
        
        /**
         * Enforce the size limit.
         */
        if (buffer.size() >= constants::max_block_size_gen / 5)
        {
            log_error(
                "Wallet, create coin stake failed, exceeded coinstake "
                "size limit."
            );
        
            return false;
        }
        
        /**
         * Validate the fee is correct.
         */
        if (min_fee < tx_new.get_minimum_fee() - constants::min_tx_fee)
        {
            min_fee = tx_new.get_minimum_fee() - constants::min_tx_fee;
            
            continue;
        }
        else
        {
            /**
             * -printfee
             */
            if (globals::instance().debug())
            {
                log_debug(
                    "Wallet, create coin stake, fee = " <<
                    utility::format_money(min_fee) << "."
                );
            }
            
            break;
        }
    }

    return true;
}

std::pair<bool, std::string> wallet::send_money(
    const script & script_pub_key, const std::int64_t & value,
    const transaction_wallet & wtx_new
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Allocate the reserve_key so that it is not copied and survives the
     * boost::asio::io_service::post operation.
     */
    auto reserve_key = std::make_shared<key_reserved> (*this);
    
    std::int64_t fee_required;

    if (is_locked())
    {
        log_error(
            "Wallet, send money failed, wallet locked, unable to create "
            "transaction."
        );
        
        return std::make_pair(
            false, "wallet locked, unable to create transaction"
        );
    }
    
    if (globals::instance().wallet_unlocked_mint_only())
    {
        log_error(
            "Wallet, send money failed, wallet unlocked for minting only, "
            "unable to create transaction."
        );
        
        return std::make_pair(
            false,
            "wallet unlocked for minting only, unable to create transaction"
        );
    }
    
    if (
        create_transaction(script_pub_key, value,
        *const_cast<transaction_wallet *> (&wtx_new), *reserve_key,
        fee_required) == false
        )
    {
        if (value + fee_required > get_balance())
        {
            log_error(
                "Wallet, send money failed, create transaction failed, "
                "insufficient funds, fee required = " <<
                utility::format_money(fee_required) << "."
            );
            
            return std::make_pair(
                false, "failed to create transaction, insufficient funds"
            );
        }
        else
        {
            log_error("Wallet, send money failed, create transaction failed.");
            
            return std::make_pair(false, "failed to create transaction");
        }
    }

    /**
     * Commit the transaction.
     */
    auto ret_pair = commit_transaction(
        *const_cast<transaction_wallet *> (&wtx_new), *reserve_key
    );
    
    /**
     * Commit the transaction.
     */
    if (ret_pair.first == false)
    {
        log_error(
            "Wallet, send money failed, commit transaction failed, "
            "wallet may need a rescan."
        );
        
        return std::make_pair(ret_pair.first, ret_pair.second);
    }

    return std::make_pair(true, "");
}

std::pair<bool, std::string> wallet::send_money_to_destination(
    const destination::tx_t & address, const std::int64_t & value,
    const transaction_wallet & wtx_new
    )
{
    if (value <= 0)
    {
        log_error(
            "Wallet, send money to destination failed, invalid amount."
        );
    
        return std::make_pair(false, "invalid amount");
    }
    
    if (value + globals::instance().transaction_fee() > get_balance())
    {
        log_error(
            "Wallet, send money to destination  failed, "
            "insufficient funds = " << utility::format_money(value) <<
            ", fee required = " <<
            utility::format_money(globals::instance().transaction_fee()) <<
            ", balance = " << get_balance() << "."
        );
    
        return std::make_pair(false, "insufficient funds");
    }
    
    script script_pub_key;
    
    script_pub_key.set_destination(address);

    return send_money(script_pub_key, value, wtx_new);
}

void wallet::available_coins(
    std::vector<output> & coins, const bool & only_confirmed,
    const std::shared_ptr<coin_control> & control
    ) const
{
    coins.clear();

    for (auto & i : m_transactions)
    {
        const transaction_wallet & coin = i.second;

        if (coin.is_final() == false)
        {
            continue;
        }
        
        if (only_confirmed && coin.is_confirmed() == false)
        {
            continue;
        }
        
        if (coin.is_coin_base() && coin.get_blocks_to_maturity() > 0)
        {
            continue;
        }
        
        if (coin.is_coin_stake() && coin.get_blocks_to_maturity() > 0)
        {
            continue;
        }
        
        for (auto j = 0; j < coin.transactions_out().size(); j++)
        {
            if (
                coin.is_spent(j) == false &&
                is_mine(coin.transactions_out()[j]) &&
                coin.transactions_out()[j].value() > 0 &&
                (control == 0 || control->has_selected() == false ||
                control->is_selected(i.first, j))
                )
             {
                coins.push_back(
                    output(coin, j, coin.get_depth_in_main_chain())
                );
            }
        }
    }
}

bool wallet::select_coins_min_conf(
    std::int64_t target_value, std::uint32_t spend_time,
    std::int32_t conf_mine, std::int32_t conf_theirs,
    std::vector<output> coins,
    std::set< std::pair<transaction_wallet, std::uint32_t> > & coins_out,
    std::int64_t & value_out
    ) const
{
    coins_out.clear();
    
    value_out = 0;

    /**
     * The list of values less than target.
     */
    std::pair<
        std::int64_t, std::pair<transaction_wallet, std::uint32_t>
    > coin_lowest_larger;
    
    /**
     * Set the first value to it's maximum.
     */
    coin_lowest_larger.first = std::numeric_limits<std::int64_t>::max();
    
    /**
     * The values.
     */
    std::vector<std::pair< std::int64_t,
        std::pair<transaction_wallet, std::uint32_t> >
    > values;
    
    std::int64_t total_lower = 0;

    /**
     * Shuffle the coins.
     */
    std::random_shuffle(coins.begin(), coins.end(), random::uint32);

    for (auto & output : coins)
    {
        const transaction_wallet & ref_coin = output.get_transaction_wallet();

        if (
            output.get_depth() <
            (ref_coin.is_from_me() ? conf_mine : conf_theirs)
            )
        {
            continue;
        }
        
        int i = output.get_i();

        /**
         * The timestamp must not exceed the spend time (ppcoin).
         */
        if (ref_coin.time() > spend_time)
        {
            continue;
        }
        
        auto n = ref_coin.transactions_out()[i].value();

        auto coin = std::make_pair(n, std::make_pair(ref_coin, i));

        if (n == target_value)
        {
            coins_out.insert(coin.second);
            
            value_out += coin.first;
            
            return true;
        }
        else if (n < target_value + constants::cent)
        {
            values.push_back(coin);
            
            total_lower += n;
        }
        else if (n < coin_lowest_larger.first)
        {
            coin_lowest_larger = coin;
        }
    }

    if (total_lower == target_value)
    {
        for (auto i = 0; i < values.size(); ++i)
        {
            coins_out.insert(values[i].second);
            
            value_out += values[i].first;
        }
        
        return true;
    }

    if (total_lower < target_value)
    {
        if (coin_lowest_larger.second.first.is_null())
        {
            return false;
        }
        
        coins_out.insert(coin_lowest_larger.second);
        
        value_out += coin_lowest_larger.first;
        
        return true;
    }

    /**
     * Value comparator.
     */
    struct compare_value_only
    {
        bool operator()(
            const std::pair<std::int64_t,
            std::pair<transaction_wallet, std::uint32_t> > & t1,
            const std::pair<std::int64_t,
            std::pair<transaction_wallet, std::uint32_t> > & t2
            ) const
        {
            return t1.first < t2.first;
        }
    };
    
    /**
     * Solve subset sum by stochastic approximation.
     */
    std::sort(values.rbegin(), values.rend(), compare_value_only());
    
    std::vector<char> bests;
    
    std::int64_t best_count;

    /**
     * Calcualte the best (approximate) subset.
     */
    approximate_best_subset(
        values, total_lower, target_value, bests, best_count, 1000
    );
    
    if (
        best_count != target_value &&
        total_lower >= target_value + constants::cent
        )
    {
        approximate_best_subset(
            values, total_lower, target_value + constants::cent,
            bests, best_count, 1000
        );
    }
    
    /**
     * If we have a bigger coin return it.
    */
    if (
        coin_lowest_larger.second.first.is_null() == false &&
        ((best_count != target_value && best_count <
        target_value + constants::cent) ||
        coin_lowest_larger.first <= best_count)
        )
    {
        coins_out.insert(coin_lowest_larger.second);
        value_out += coin_lowest_larger.first;
    }
    else
    {
        for (auto i = 0; i < values.size(); i++)
        {
            if (bests[i])
            {
                coins_out.insert(values[i].second);
                value_out += values[i].first;
            }
        }
        
        /**
         * -printpriority
         */
        if (globals::instance().debug())
        {
            std::stringstream ss;
            
            ss << "Wallet is selecting coins, best subset: ";
            
            for (auto i = 0; i < values.size(); i++)
            {
                if (bests[i])
                {
                    ss << utility::format_money(values[i].first);
                }
            }
            
            ss << "total: \n" << utility::format_money(best_count);
            
            log_debug(ss.str());
        }
    }

    return true;
}

void wallet::approximate_best_subset(
    std::vector< std::pair< std::int64_t,
    std::pair<transaction_wallet, std::uint32_t> > > value,
    const std::int64_t & total_lower, const std::int64_t & target_value,
    std::vector<char> & bests, std::int64_t & best,
    const std::uint32_t & iterations
    )
{
    std::vector<char> included;

    bests.assign(value.size(), true);
    
    best = total_lower;

    for (
        int rep = 0; rep < iterations && best != target_value; rep++
        )
    {
        included.assign(value.size(), false);
        
        std::int64_t total = 0;
        
        bool reached_target = false;
        
        for (int pass = 0; pass < 2 && !reached_target; pass++)
        {
            for (auto i = 0; i < value.size(); i++)
            {
                if (pass == 0 ? std::rand() % 2 : !included[i])
                {
                    total += value[i].first;
                    
                    included[i] = true;
                    
                    if (total >= target_value)
                    {
                        reached_target = true;
                        
                        if (total < best)
                        {
                            best = total;
                            bests = included;
                        }
                        
                        total -= value[i].first;
                        
                        included[i] = false;
                    }
                }
            }
        }
    }
}

std::map<sha256, transaction_wallet> & wallet::transactions()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions;
}

const std::map<sha256, transaction_wallet> & wallet::transactions() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions;
}

std::map<sha256, std::int32_t> & wallet::request_counts()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_request_counts;
}

std::map<destination::tx_t, std::string> & wallet::address_book()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_address_book;
}

const std::map<destination::tx_t, std::string> & wallet::address_book() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_address_book;
}

void wallet::set_order_position_next(const std::int64_t & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_order_position_next = val;
}

const std::int64_t & wallet::order_position_next() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_order_position_next;
}

void wallet::read_order_position(
    std::int64_t & order_position,
    std::map<std::string, std::string> & value
    )
{
    if (value.count("n") == 0)
    {
        order_position = -1;
        
        return;
    }
    
    order_position = boost::lexical_cast<std::int64_t> (value["n"]);
}

void wallet::write_order_position(
    const std::int64_t & order_position,
    std::map<std::string, std::string> & value
    )
{
    if (order_position != -1)
    {
        value["n"] = std::to_string(order_position);
    }
}

std::int64_t wallet::get_account_balance(
    db_wallet & wallet_db, const std::string & account_name,
    const std::size_t & minimum_depth
    )
{
    std::int64_t balance = 0;

    auto transactions =
        globals::instance().wallet_main()->transactions()
    ;

    /**
     * Sum up all of the transactions.
     */
    for (auto & i : transactions)
    {
        const auto & wtx = i.second;
        
        if (wtx.is_final() == false)
        {
            continue;
        }
        
        std::int64_t generated, received, sent, fee;
        
        wtx.get_account_amounts(account_name, generated, received, sent, fee);

        if (
            received != 0 && wtx.get_depth_in_main_chain() >= minimum_depth
            )
        {
            balance += received;
        }
        
        balance += generated - sent - fee;
    }
    
    /**
     * Sum up credit and debit.
     */
    balance += wallet_db.get_account_credit_debit(account_name);

    return balance;
}

std::int64_t wallet::get_account_balance(
    const std::string & account_name, const std::size_t & minimum_depth
    )
{
    db_wallet wallet_db("wallet.dat");
    
    return get_account_balance(wallet_db, account_name, minimum_depth);
}

std::pair<bool, std::string> wallet::get_account_address(
    wallet & w, const std::string & name, address & addr_out
    )
{
    db_wallet wallet_db("wallet.dat");

    account account;
    
    wallet_db.read_account(name, account);

    /**
     * First check if the key has been used.
     */
    bool was_used = false;

    if (account.get_key_public().is_valid())
    {
        script s;
        
        s.set_destination(account.get_key_public().get_id());
        
        auto it = w.transactions().begin();
        
        for (
            ; it != w.transactions().end() &&
            account.get_key_public().is_valid(); ++it
            )
        {
            const auto & wtx = it->second;
            
            for (auto & i : wtx.transactions_out())
            {
                if (i.script_public_key() == s)
                {
                    was_used = true;
                    
                    break;
                }
            }
        }
    }

    /**
     * If the public key is not valid or it was used then generate a new key.
     */
    if (account.get_key_public().is_valid() == false || was_used)
    {
        if (w.get_key_from_pool(account.get_key_public(), false) == false)
        {
            return std::make_pair(
                false, "keypool is empty, needs refill"
            );
        }

        w.set_address_book_name(account.get_key_public().get_id(), name);
        
        wallet_db.write_account(name, account);
    }

    addr_out = address(account.get_key_public().get_id());
    
    return std::make_pair(true, "");
}

void wallet::resend_transactions_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        if (stack_impl_)
        {
            if (
                utility::is_initial_block_download() == false &&
                stack_impl_->get_tcp_connection_manager(
                )->tcp_connections().size() > 0 &&
                globals::instance().time_best_received() >= time_last_resend_
                )
            {
                /**
                 * Set the time of the last resend to now.
                 */
                time_last_resend_ = std::time(0);
                
                db_tx tx_db("r");
                
                /**
                 * Sort by time.
                 */
                std::multimap<std::uint32_t, transaction_wallet *> sorted;
                
                for (auto & item : m_transactions)
                {
                    auto & wtx = item.second;
                    
                    /**
                     * Allow time for the transaction to have been put into a
                     * block.
                     */
                    if (
                        globals::instance().time_best_received() -
                        static_cast<std::int64_t> (wtx.time_received()) >
                        constants::work_and_stake_target_spacing
                        )
                    {
                        sorted.insert(
                            std::make_pair(wtx.time_received(), &wtx)
                        );
                    }
                }
                
                for (auto & item : sorted)
                {
                    auto & wtx = *item.second;

                    try
                    {
                        /**
                         * Check the transaction.
                         */
                        if (wtx.check())
                        {
                            /**
                             * Relay the transaction to all connected peers.
                             */
                            wtx.relay_wallet_transaction(
                                tx_db, stack_impl_->get_tcp_connection_manager()
                            );
                        }
                        else
                        {
                            log_error(
                                "Wallet, resend transactions failed, check "
                                "failed for transaction " <<
                                wtx.get_hash().to_string() << "."
                            );
                        }
                    }
                    catch (std::exception & e)
                    {
                        log_debug(
                            "Wallet, resend transactions failed, what = " <<
                            e.what() << "."
                        );
                    }
                }
            }
        }
        
        /**
         * Start the timer again after a random time interval.
         */
        resend_transactions_timer_.expires_from_now(
            std::chrono::seconds(random::uint16_random_range(300, 1200))
        );
        resend_transactions_timer_.async_wait(globals::instance().strand().wrap(
            std::bind(&wallet::resend_transactions_tick, this,
            std::placeholders::_1))
        );
    }
}

bool wallet::do_encrypt(const std::string & passphrase)
{
    if (is_crypted())
    {
        log_error("Wallet tried to encrypt but is already encrypted.");
        
        return false;
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        /**
         * The master key.
         */
        types::keying_material_t master_key;
        
        /**
         * RAND_add
         */
        random::openssl_RAND_add();

        /**
         * Allocate the master key.
         */
        master_key.resize(crypter::wallet_key_size);
        
        /**
         * Generate the master key.
         */
        RAND_bytes(&master_key[0], crypter::wallet_key_size);

        key_wallet_master master_key_wallet;

        /**
         * RAND_add
         */
        random::openssl_RAND_add();
        
        /**
         * Allocate the master key wallet's salt.
         */
        master_key_wallet.salt().resize(crypter::wallet_salt_size);
        
        /**
         * Generate the master key wallet.
         */
        RAND_bytes(&master_key_wallet.salt()[0], crypter::wallet_salt_size);
        
        /**
         * Allocate the crypter.
         */
        crypter c;
        
        /**
         * Get the milliseconds since epoch.
         */
        auto time_start = std::chrono::duration_cast<
            std::chrono::milliseconds> (
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        /**
         * Set the key from the passphrase.
         */
        c.set_key_from_passphrase(
            passphrase, master_key_wallet.salt(), 25000,
            master_key_wallet.derivation_method()
        );

        /**
         * Set the derive iterations.
         */
        master_key_wallet.set_derive_iterations(
            2500000 / (static_cast<double> ((std::chrono::duration_cast<
            std::chrono::milliseconds> (std::chrono::system_clock::now(
            ).time_since_epoch()).count() - time_start)))
        );

        /**
         * Set the start time.
         */
        time_start = std::chrono::duration_cast<
            std::chrono::milliseconds> (
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        
        /**
         * Set the key from the passphrase.
         */
        c.set_key_from_passphrase(
            passphrase, master_key_wallet.salt(),
            master_key_wallet.derive_iterations(),
            master_key_wallet.derivation_method()
        );
        
        /**
         * Set the derive iterations.
         */
        master_key_wallet.set_derive_iterations(
            (master_key_wallet.derive_iterations() +
            master_key_wallet.derive_iterations() * 100 /
            (static_cast<double> ((std::chrono::duration_cast<
            std::chrono::milliseconds> (std::chrono::system_clock::now(
            ).time_since_epoch()).count() - time_start)))) / 2
        );

        if (master_key_wallet.derive_iterations() < 25000)
        {
            master_key_wallet.set_derive_iterations(25000);
        }
        
        log_debug(
            "Wallet is encrypting with " <<
            master_key_wallet.derive_iterations() << " derive iterations."
        );

        /**
         * Set the key from the passphrase.
         */
        if (
            c.set_key_from_passphrase(passphrase, master_key_wallet.salt(),
            master_key_wallet.derive_iterations(),
            master_key_wallet.derivation_method()) == false
            )
        {
            return false;
        }
        
        /**
         * Encrypt the master key.
         */
        if (c.encrypt(master_key, master_key_wallet.crypted_key()) == false)
        {
            return false;
        }

        m_master_keys[++m_master_key_max_id] = master_key_wallet;
        
        if (m_is_file_backed)
        {
            m_db_wallet_encryption = std::make_shared<db_wallet> ("wallet.dat");
            
            if (m_db_wallet_encryption->txn_begin() == false)
            {
                return false;
            }
            
            m_db_wallet_encryption->write_master_key(
                m_master_key_max_id, master_key_wallet
            );
        }

        /** 
         * Encrypt the keys.
         */
        if (encrypt_keys(master_key) == false)
        {
            if (m_is_file_backed)
            {
                m_db_wallet_encryption->txn_abort();
            }
            
            log_error(
                "Wallet encrypting keys failed, restart to load the "
                "unencrypted wallet."
            );
            
            return false;
        }

        /**
         * Set the minimum version.
         */
        set_min_version(feature_walletcrypt, m_db_wallet_encryption.get(), true);

        if (m_is_file_backed)
        {
            if (m_db_wallet_encryption->txn_commit() == false)
            {
                log_error(
                    "Wallet encrypting transaction commit failed, restart to "
                    "load the unencrypted wallet."
                );
                
                return false;
            }
            
            m_db_wallet_encryption.reset();
        }

        /**
         * Lock the wallet.
         */
        lock();
        
        /**
         * Unlock the wallet.
         */
        unlock(passphrase);
        
        /**
         * Mark old keys as used and generate new ones.
         */
        new_key_pool();
        
        /**
         * Lock the wallet.
         */
        lock();

        /**
         * Rewrite the dat file to remove any database remains of clear-text key
         * material. The original data will still exist on the hard drive on some
         * operating systems since this is not a secure wipe of the disk's bits.
         */
        db::rewrite("wallet.dat");
    }
    
    return true;
}
