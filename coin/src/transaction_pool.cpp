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

#include <stdexcept>

#include <coin/constants.hpp>
#include <coin/logger.hpp>
#include <coin/stack_impl.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

transaction_pool::transaction_pool()
    : m_transactions_updated(0)
{
    // ...
}

transaction_pool & transaction_pool::instance()
{
    static transaction_pool g_transaction_pool;
    
    return g_transaction_pool;
}

std::pair<bool, std::string> transaction_pool::accept(
    db_tx & dbtx, transaction & tx, bool * missing_inputs
    )
{
    if (missing_inputs)
    {
        *missing_inputs = false;
    }
    
    /**
     * Check the transaction.
     */
    if (tx.check() == false)
    {
        return std::make_pair(false, "check transaction failed");
    }
    
    /**
     * Coinbase is only valid in a block, not as a loose transaction.
     */
    if (tx.is_coin_base())
    {
        return std::make_pair(false, "coin base as individual transaction");
    }
    
    /**
     * Coinstake is only valid in a block, not as a loose transaction.
     */
    if (tx.is_coin_stake())
    {
        return std::make_pair(false, "coin stake as individual transaction");
    }
    
    /**
     * Only work on non standard transactions when on test net.
     */
    if (constants::test_net == false && tx.is_standard() == false)
    {
        return std::make_pair(false, "nonstandard transaction type");
    }
    
    /**
     * Do we already have it.
     */
    auto hash = tx.get_hash();

    std::lock_guard<std::recursive_mutex> l1(mutex_);
        
    if (m_transactions.count(hash) > 0)
    {
        log_debug("Transaction pool failed to accept, hash already found.");
        
        return std::make_pair(false, "hash already found");
    }
    
    if (dbtx.contains_transaction(hash))
    {
        log_error(
            "Transaction pool failed to accept, db tx contains transaction."
        );
        
        return std::make_pair(false, "db tx contains transaction.");
    }
    
    /**
     * ZeroTime transaction checking.
     */
    if (globals::instance().is_zerotime_enabled())
    {
        /**
         * Check for a zerotime_lock conflict.
         */
        if (zerotime::instance().has_lock_conflict(tx))
        {
            log_error(
                "Transaction pool failed to accept, zerotime lock conflict."
            );
            
            return std::make_pair(false, "zerotime lock conflict.");
        }
    }
    
    /**
     * Check for conflicts with in-memory transactions.
     */
    transaction * tx_old = 0;
    
    for (auto i = 0; i < tx.transactions_in().size(); i++)
    {
        auto outpoint = tx.transactions_in()[i].previous_out();
        
        if (m_transactions_next.count(outpoint) > 0)
        {
#if 1
            log_error(
                "Transaction pool failed to accept, replacement "
                "transaction disabled."
            );
            
            /**
             * Disable replacement feature (disabled in reference
             * implementation).
             */
            return std::make_pair(false, "replacement transaction disabled");
#endif
            /**
             * Allow replacing with a newer version of the same transaction.
             */
            if (i != 0)
            {
                log_error(
                    "Transaction pool failed to accept, replacement "
                    " i != 0."
                );
            
                return std::make_pair(false, "replacement i != 0");
            }
            
            tx_old = const_cast<transaction *> (
                &m_transactions_next[outpoint].get_transaction()
            );
            
            if (tx_old->is_final())
            {
                log_error(
                    "Transaction pool failed to accept, replacement "
                    "transaction old is final."
                );
            
                return std::make_pair(
                    false, "replacement transaction old is final"
                );
            }
            
            if (tx.is_newer_than(*tx_old) == false)
            {
                log_error(
                    "Transaction pool failed to accept, replacement "
                    "transaction is not newer."
                );
            
                return std::make_pair(
                    false, "replacement transaction is not newer"
                );
            }
            
            for (auto & i : tx.transactions_in())
            {
                auto outpoint = i.previous_out();
                
                if (
                    m_transactions_next.count(outpoint) == 0 ||
                    &m_transactions_next[outpoint].get_transaction() != tx_old
                    )
                {
                    log_error(
                        "Transaction pool failed to accept, replacement "
                        "transaction != tx_old."
                    );
            
                    return std::make_pair(
                        false, "replacement transaction != tx_old"
                    );
                }
            }
            
            break;
        }
    }
    
    /**
     * We always check the inputs.
     */
    bool check_inputs = true;
    
    if (check_inputs)
    {
        transaction::previous_t inputs;
        
        std::map<sha256, transaction_index> unused;
        
        bool invalid = false;
        
        if (
            tx.fetch_inputs(dbtx, unused, false, false, inputs,
            invalid) == false
            )
        {
            if (invalid)
            {
                log_error(
                    "Transaction pool found invalid transaction " <<
                    hash.to_string().substr(0, 10) << "."
                );
                
                return std::make_pair(
                    false, "found invalid transaction"
                );
            }
            
            if (missing_inputs)
            {
                *missing_inputs = true;
            }
            
            return std::make_pair(false, "failed to fetch inputs");
        }
        
        /**
         * Check for non-standard pay-to-script-hash in inputs.
         */
        if (
            tx.are_inputs_standard(inputs) == false &&
            constants::test_net == false
            )
        {
            log_error(
                "Transaction pool accept failed, nonstandard transaction input."
            );
            
            return std::make_pair(false, "nonstandard transaction input");
        }
        
        /**
         * @note If you modify this code to accept non-standard transactions,
         * then you should add code here to check that the transaction does a
         * reasonable number of ECDSA signature verifications.
         */

        auto fees = tx.get_value_in(inputs) - tx.get_value_out();
        
        /**
         * Allocate a buffer to contain the encoded transaction.
         */
        data_buffer buffer;
        
        /**
         * Clear the transaction's buffer.
         */
        tx.clear();
    
        /**
         * Encode the transaction into the buffer.
         */
        tx.encode(buffer);
    
        /**
         * Get the transaction size.
         */
        auto tx_size = buffer.size();

        /**
         * Don't accept it if it can't get into a block.
         */
        auto tx_min_fee = tx.get_minimum_fee(
            1000, false, types::get_minimum_fee_mode_relay, tx_size
        );

        if (fees < tx_min_fee)
        {
            log_error(
                "Transaction pool accept failed, not enough fees " <<
                hash.to_string() << ", " << fees << "<" <<  tx_min_fee
            );

            return std::make_pair(false, "not enough fees");
        }

        /**
         * Rate-limit free transactions. This mitigates 'penny-flooding'.
         */
        if (fees < constants::min_relay_tx_fee)
        {
            static std::mutex g_m;
            static double g_free_count;
            static std::int64_t g_time_last;
            auto now = std::time(0);

            std::lock_guard<std::mutex> l1(g_m);
            
            /**
             * Use an exponentially decaying ~10-minute window.
             */
            g_free_count *= std::pow(
                1.0 - 1.0 / 600.0, static_cast<double> ((now - g_time_last))
            );
            
            g_time_last = now;
            
            /**
             * The limitfreerelay is a thousand-bytes-per-minute.
             */
            enum { limitfreerelay = 15 };
            
            if (
                g_free_count > limitfreerelay * 10 * 1000 &&
                wallet_manager::instance().is_from_me(tx) == false
                )
            {
                log_error(
                    "Transaction pool accept failed, free transaction "
                    "rejected by rate limiter."
                );
            
                return std::make_pair(
                    false, "free transaction rejected by rate limiter"
                );
            }
            
            log_debug(
                "Transaction pool rate limit free count = " <<
                g_free_count << " => " << g_free_count + tx_size << "."
            );

            g_free_count += tx_size;
        }
        
        /**
         * Check against previous transactions. This is done last to help
         * prevent CPU exhaustion denial-of-service attacks.
         */
        if (
            tx.connect_inputs(dbtx, inputs, unused,
            transaction_position(1, 1, 1), stack_impl::get_block_index_best(),
            false, false) == false
            )
        {
            log_debug(
                "Transaction pool connect inputs failed " <<
                hash.to_string().substr(0, 10) << "."
            );
            
            return std::make_pair(false, "connect inputs failed");
        }
    }
    
    /**
     * Store transaction in memory.
     */
    if (tx_old)
    {
        log_debug(
            "Transaction pool is replacing tx " <<
            tx_old->get_hash().to_string() << " with new version."
        );
        
        remove(*tx_old);
    }
    
    add_unchecked(hash, tx);
    
    /**
     * Are we sure this is ok when loading transactions?
     */
    if (tx_old)
    {
        wallet_manager::instance().erase_from_wallets(tx_old->get_hash());
    }

    log_debug(
        "Transacton pool accepted " << hash.to_string().substr(0, 10) <<
        ", pool size = " << m_transactions.size() << "."
    );

    return std::make_pair(true, "");
}

std::pair<bool, std::string> transaction_pool::acceptable(transaction & tx)
{
    /**
     * Check the transaction.
     */
    if (tx.check() == false)
    {
        return std::make_pair(false, "check transaction failed");
    }
    
    /**
     * Coinbase is only valid in a block, not as a loose transaction.
     */
    if (tx.is_coin_base())
    {
        return std::make_pair(false, "coin base as individual transaction");
    }
    
    /**
     * Coinstake is only valid in a block, not as a loose transaction.
     */
    if (tx.is_coin_stake())
    {
        return std::make_pair(false, "coin stake as individual transaction");
    }
    
    /**
     * Do we already have it.
     */
    auto hash = tx.get_hash();

    std::lock_guard<std::recursive_mutex> l1(mutex_);
        
    if (m_transactions.count(hash) > 0)
    {
        return std::make_pair(false, "hash already found");
    }
    
    /**
     * Check for conflicts with in-memory transactions.
     */
    for (auto i = 0; i < tx.transactions_in().size(); i++)
    {
        auto outpoint = tx.transactions_in()[i].previous_out();
        
        if (m_transactions_next.count(outpoint) > 0)
        {
            /**
             * Disable replacement feature (disabled in reference
             * implementation).
             */
            return std::make_pair(false, "replacement transaction disabled");
        }
    }

    db_tx txdb("r");
    
    /**
     * We always check the inputs.
     */
    bool check_inputs = true;
    
    if (check_inputs)
    {
        transaction::previous_t inputs;
        
        std::map<sha256, transaction_index> unused;
        
        bool invalid = false;
        
        if (
            tx.fetch_inputs(txdb, unused, false, false, inputs,
            invalid) == false
            )
        {
            if (invalid)
            {
                return std::make_pair(
                    false, "found invalid transaction"
                );
            }
            
            return std::make_pair(false, "failed to fetch inputs");
        }
        
        /**
         * Check against previous transactions.
         */
        if (
            tx.connect_inputs(txdb, inputs, unused,
            transaction_position(1, 1, 1), stack_impl::get_block_index_best(),
            false, false, true, false) == false
            )
        {
            return std::make_pair(false, "connect inputs failed");
        }
    }
    
    return std::make_pair(true, "");
}
        
bool transaction_pool::remove(transaction & tx)
{
    auto hash = tx.get_hash();
    
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_transactions.count(hash) > 0)
    {
        for (auto & i : tx.transactions_in())
        {
            m_transactions_next.erase(i.previous_out());
        }
        
        m_transactions.erase(hash);
        
        m_transactions_updated++;
    }

    return true;
}
        
void transaction_pool::clear()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_transactions.clear();
    m_transactions_next.clear();
    
    ++m_transactions_updated;
}
        
void transaction_pool::query_hashes(std::vector<sha256> & transaction_ids)
{
    transaction_ids.clear();

    transaction_ids.reserve(m_transactions.size());
    
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    for (auto & i : m_transactions)
    {
        transaction_ids.push_back(i.first);
    }
}

std::size_t transaction_pool::size()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions.size();
}

bool transaction_pool::exists(const sha256 & hash)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions.count(hash) > 0;
}

transaction & transaction_pool::lookup(const sha256 & hash)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);

    return m_transactions[hash];
}

const std::map<point_out, point_in> &
    transaction_pool::transactions_next() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions_next;
}

std::map<sha256, transaction> & transaction_pool::transactions()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions;
}

std::uint32_t & transaction_pool::transactions_updated()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_transactions_updated;
}

bool transaction_pool::add_unchecked(const sha256 & hash, transaction & tx)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_transactions[hash] = tx;
    
    for (auto i = 0; i < tx.transactions_in().size(); i++)
    {
        m_transactions_next[
            tx.transactions_in()[i].previous_out()
        ] = point_in(m_transactions[hash], i);
    }
    
    m_transactions_updated++;
    
    return true;
}
