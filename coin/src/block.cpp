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

#include <algorithm>
#include <set>
#include <sstream>

#include <boost/format.hpp>

#include <coin/big_number.hpp>
#include <coin/block.hpp>
#include <coin/block_orphan.hpp>
#include <coin/block_index.hpp>
#include <coin/block_index_disk.hpp>
#include <coin/block_locator.hpp>
#include <coin/constants.hpp>
#include <coin/db_tx.hpp>
#include <coin/file.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/incentive.hpp>
#include <coin/kernel.hpp>
#include <coin/key_reserved.hpp>
#include <coin/key_store.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/point_out.hpp>
#include <coin/reward.hpp>
#include <coin/script_checker_queue.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/time.hpp>
#include <coin/transaction_in.hpp>
#include <coin/transaction_out.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/utility.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

block::block()
    : data_buffer()
{
    set_null();
}

void block::encode(const bool & block_header_only)
{
    encode(*this, block_header_only);
}

void block::encode(data_buffer & buffer, const bool & block_header_only)
{
    buffer.write_uint32(m_header.version);
    buffer.write_sha256(m_header.hash_previous_block);
    buffer.write_sha256(m_header.hash_merkle_root);
    buffer.write_uint32(m_header.timestamp);
    buffer.write_uint32(m_header.bits);
    buffer.write_uint32(m_header.nonce);
    
    /**
     * Connect block depends on the transactions following the header to
     * generate the transaction position.
     */
    if (block_header_only)
    {
        // ...
    }
    else
    {
        buffer.write_var_int(m_transactions.size());
        
        for (auto & i : m_transactions)
        {
            i.encode(buffer);
        }
        
        buffer.write_var_int(m_signature.size());
        
        if (m_signature.size() > 0)
        {
            buffer.write_bytes(
                reinterpret_cast<const char *>(&m_signature[0]),
                m_signature.size()
            );
        }
    }
}

bool block::decode(const bool & block_header_only)
{
    return decode(*this, block_header_only);
}

bool block::decode(data_buffer & buffer, const bool & block_header_only)
{
    m_header.version = buffer.read_uint32();
    m_header.hash_previous_block = buffer.read_sha256();
    m_header.hash_merkle_root = buffer.read_sha256();
    m_header.timestamp = buffer.read_uint32();
    m_header.bits = buffer.read_uint32();
    m_header.nonce = buffer.read_uint32();
    
    log_none(
        "version = " << m_header.version << ", timestamp = " <<
        m_header.timestamp << ", bits = " << m_header.bits <<
        ", nonce = " << m_header.nonce
    );
    
    if (block_header_only)
    {
        // ...
    }
    else
    {
        /**
         * Read the number of transactions.
         */
        auto number_transactions = buffer.read_var_int();
        
        /**
         * Decode the transactions.
         */
        for (auto i = 0; i < number_transactions; i++)
        {
            /**
             * Allocate the transaction.
             */
            transaction tx;
            
            /**
             * Decode the transaction.
             */
            tx.decode(buffer);
            
            /**
             * Retain the transaction.
             */
            m_transactions.push_back(tx);
        }
        
        /**
         * Read the var_int.
         */
        auto len = buffer.read_var_int();
        
        if (len > 0)
        {
            /**
             * Read the signature.
             */
            auto bytes = buffer.read_bytes(len);
            
            /**
             * Insert the signature.
             */
            m_signature.insert(
                m_signature.begin(), bytes.begin(), bytes.end()
            );
        }
    }
    
    return true;
}

void block::set_null()
{
    m_header.version = current_version;
    m_header.hash_previous_block.clear();
    m_header.hash_merkle_root.clear();
    m_header.nonce = 0;
    m_header.bits = 0;
    m_header.nonce = 0;
    m_transactions.clear();
    m_signature.clear();
    m_merkle_tree.clear();
}

bool block::is_null() const
{
    return m_header.bits == 0;
}

sha256 block::get_hash() const
{
    sha256 ret;
    
    std::uint32_t * ptr = reinterpret_cast<std::uint32_t *>(ret.digest());
    
    data_buffer buffer;
    
    buffer.write_uint32(m_header.version);
    buffer.write_sha256(m_header.hash_previous_block);
    buffer.write_sha256(m_header.hash_merkle_root);
    buffer.write_uint32(m_header.timestamp);
    buffer.write_uint32(m_header.bits);
    buffer.write_uint32(m_header.nonce);

    assert(buffer.size() == header_length);

    /**
     * Use whirlpool for blocks less than version 5.
     */
    auto use_whirlpool = m_header.version < 5;
    
    if (use_whirlpool == true)
    {
        auto digest = hash::whirlpoolx(
            reinterpret_cast<std::uint8_t *>(buffer.data()), buffer.size()
        );
        
        std::memcpy(ptr, &digest[0], digest.size());
    }
    else
    {
        auto digest = hash::blake2568round(
            reinterpret_cast<std::uint8_t *>(buffer.data()), buffer.size()
        );
        
        std::memcpy(ptr, &digest[0], digest.size());
    }

    return ret;
}

sha256 block::get_hash_genesis()
{
    static const sha256 ret(
        "15e96604fbcf7cd7e93d072a06f07ccfe1f8fd0099270a075c761c447403a783"
    );

    return ret;
}

sha256 block::get_hash_genesis_test_net()
{
    static const sha256 ret(
        "de32fadf1f12e666f783c529e7764d49950541d6571a6080a9242cd7dc595c65"
    );

    return ret;
}

std::int64_t block::get_size()
{
    std::int64_t ret = 0;
    
    /**
     * Allocate a temporary buffer to determine the size of the block in bytes.
     */
    data_buffer buffer;
    
    /**
     * Encode ourselves into the buffer.
     */
    encode(buffer);
    
    ret = buffer.size();
    
    /**
     * Return the buffer size.
     */
    return ret;
}

block::header_t & block::header()
{
    return m_header;
}

const block::header_t & block::header() const
{
    return m_header;
}

std::vector<transaction> & block::transactions()
{
    return m_transactions;
}

std::vector<std::uint8_t> & block::signature()
{
    return m_signature;
}

void block::update_time(block_index & previous)
{
    m_header.timestamp = std::max(
        m_header.timestamp,
        static_cast<std::uint32_t> (time::instance().get_adjusted())
    );
}

block block::create_genesis()
{
    /**
     * Genesis block creation.
     */
    std::string timestamp_quote =
        "December 22, 2014 - New York Times calls for Cheney, "
        "Bush officials to be investigated and prosecuted for "
        "torture."
    ;
    
    /**
     * Allocate a new transaction.
     */
    transaction tx_new;
    
    /**
     * Set the transaction time to the time of the start of the
     * chain.
     */
    tx_new.set_time(constants::chain_start_time);
    
    /**
     * Allocate one input.
     */
    tx_new.transactions_in().resize(1);
    
    /**
     * Allocate one output.
     */
    tx_new.transactions_out().resize(1);

    /**
     * Create the script signature.
     */
    auto script_signature =
        script() << 486604799 << big_number(9999) <<
        std::vector<std::uint8_t>(
        (const std::uint8_t *)timestamp_quote.c_str(),
        (const std::uint8_t *)timestamp_quote.c_str() +
        timestamp_quote.size()
    );

    /**
     * Set the script signature on the input.
     */
    tx_new.transactions_in()[0].set_script_signature(
        script_signature
    );
    
    /**
     * Set the output to empty.
     */
    tx_new.transactions_out()[0].set_empty();

    /**
     * Allocate the genesis block.
     */
    block blk;
    
    /**
     * Add the transactions.
     */
    blk.transactions().push_back(tx_new);
    
    /**
     * There is no previous block.
     */
    blk.header().hash_previous_block = 0;
    
    /**
     * Build the merkle tree.
     */
    blk.header().hash_merkle_root = blk.build_merkle_tree();
    
    /**
     * Set the header version.
     */
    blk.header().version = 1;
    
    /**
     * Set the header timestamp.
     */
    blk.header().timestamp = constants::chain_start_time;
    
    /**
     * Set the header bits.
     */
    blk.header().bits =
        constants::proof_of_work_limit.get_compact()
    ;
    
    assert(blk.header().bits == 504365055);
    
    /**
     * The test network uses a different genesis block by using a
     * different nonce.
     */
    if (constants::test_net == true)
    {
        /**
         * Set the header nonce.
         */
        blk.header().nonce =
            constants::chain_start_time - 10000 + 1
        ;
    }
    else
    {
        /**
         * Set the header nonce.
         */
        blk.header().nonce = constants::chain_start_time - 10000;
    }

    /**
     * Print the block.
     */
    blk.print();

    log_debug(
        "Block hash = " << blk.get_hash().to_string() << "."
    );
    log_debug(
        "Block header hash merkle root = " <<
        blk.header().hash_merkle_root.to_string() << "."
    );
    log_debug(
        "Block header time = " << blk.header().timestamp << "."
    );
    log_debug(
        "Block header nonce = " << blk.header().nonce << "."
    );

    /**
     * Check the merkle root hash.
     */
    assert(
        blk.header().hash_merkle_root ==
        sha256("e6dc22fdcfcbffccb14cacfab0f0af67721d38f2929d8344cb"
        "1635ac400e2e68")
        
    );
    
    /**
     * Check the genesis block hash.
     */
    assert(
        blk.get_hash() ==
        (constants::test_net ? block::get_hash_genesis_test_net() :
        block::get_hash_genesis())
    );
    
    return blk;
}

std::shared_ptr<block> block::create_new(
    const std::shared_ptr<wallet> & w, const bool & proof_of_stake
    )
{
    static std::mutex g_mutex;
    
    std::lock_guard<std::mutex> l1(g_mutex);
    
    /**
     * Allocate a block.
     */
    auto ret = std::make_shared<block> ();
    
    /**
     * Allocate a key_reserved.
     */
    key_reserved reserved_key(*w);
    
    /**
     * Allocate a new (coinbase) transaction.
     */
    transaction tx_new;
    
    tx_new.transactions_in().resize(1);
    tx_new.transactions_in()[0].previous_out().set_null();
    tx_new.transactions_out().resize(1);
    tx_new.transactions_out()[0].script_public_key() <<
        reserved_key.get_reserved_key() << script::op_checksig
    ;
    
    /**
     * Create incentive transaction.
     */
    if (
        proof_of_stake == false &&
        globals::instance().is_incentive_enabled() == true
        )
    {
        auto index_previous = stack_impl::get_block_index_best();

        if (
            index_previous &&
            incentive::instance().get_key().is_null() == false
            )
        {
            if (
                incentive::instance().winners().count(
                index_previous->height() + 1) > 0
                )
            {
                tx_new.transactions_out().resize(2);

                script script_incentive;

                auto wallet_address =
                    incentive::instance().winners()[
                    index_previous->height() + 1].second
                ;
                
                address addr;
                
                if (addr.set_string(wallet_address) == true)
                {
                    script_incentive.set_destination(addr.get());
                    
                    tx_new.transactions_out()[1].script_public_key() =
                        script_incentive
                    ;

                    tx_new.transactions_out()[1].set_value(0);

                    destination::tx_t dest;
                    
                    if (
                        script::extract_destination(
                        script_incentive, dest) == true
                        )
                    {
                        address addr(dest);
                    
                        log_info(
                            "Block creating new incentive transaction for " <<
                            addr.to_string().substr(0, 8)<< "."
                        );
                    }
                }
            }
        }
    }
    
    /**
     * Add our (coinbase) transaction as the first transaction.
     */
    ret->transactions().push_back(tx_new);

    /**
     * Calculate the largest block we're willing to create.
     * -blockmaxsize
    */
    auto max_size = block::get_maximum_size_median220() / 4;
    
    /**
     * Limit to betweeen 1000 and block::get_maximum_size_median220()
     * - 1000 for sanity.
     */
    max_size = std::max(
        static_cast<std::size_t> (1000),
        std::min((block::get_maximum_size_median220() - 1000), max_size)
    );

    /**
     * How much of the block should be dedicated to high-priority transactions,
     * included regardless of the fees they pay.
     * -blockprioritysize
     */
    auto priority_size = 27000;
    
    priority_size = std::min(max_size, static_cast<std::size_t> (priority_size));

    /**
     * Minimum block size you want to create; block will be filled with free
     * transactions until there are no more or the block reaches this size:
     * -blockminsize
     */
    auto min_size = 0;
    
    min_size = std::min(max_size, static_cast<std::size_t> (min_size));
    
    /**
     * -mintxfee
     */
    std::int64_t min_transaction_fee = constants::min_tx_fee;

    /**
     * If coinstake is available add the coinstake transaction (ppcoin).
     */
    static std::int64_t last_coinstake_search_time =
        time::instance().get_adjusted()
    ;
    
    auto index_previous = stack_impl::get_block_index_best();
    
    /**
     * If the block to be created is Proof-of-Stake then try to create some
     * coin stake.
     */
    if (proof_of_stake)
    {
        ret->header().bits = utility::get_next_target_required(
            index_previous, true
        );
        
        transaction tx_coinstake;
        
        std::int64_t time_search = tx_coinstake.time();
        
        if (time_search > last_coinstake_search_time)
        {
            if (
                globals::instance().wallet_main()->create_coin_stake(
                *globals::instance().wallet_main(), ret->header().bits,
                time_search - last_coinstake_search_time, tx_coinstake)
                )
            {
                if (
                    tx_coinstake.time() >= std::max(
                    index_previous->get_median_time_past() + 1,
                    index_previous->time() - constants::max_clock_drift)
                    )
                {
                    ret->transactions()[0].transactions_out()[0].set_empty();
                    ret->transactions()[0].set_time(tx_coinstake.time());
                    
                    ret->transactions().push_back(tx_coinstake);
                }
            }
            
            globals::instance().set_last_coin_stake_search_interval(
                time_search - last_coinstake_search_time
            );
            
            last_coinstake_search_time = time_search;
        }
    }

    ret->header().bits = utility::get_next_target_required(
        index_previous, ret->is_proof_of_stake()
    );

    /**
     * Collect transactions pool entries into a block.
     */
    
    std::int64_t fees = 0;

    index_previous = stack_impl::get_block_index_best();
    
    db_tx tx_db("r");

    /**
     * The priority of order in which to process transactions.
     */
    std::list< std::shared_ptr<block_orphan> > orphans;
    
    std::map<
        sha256, std::vector< std::shared_ptr<block_orphan> >
    > dependencies;

    std::vector< std::tuple<double, double, transaction *> > priorities;
    
    priorities.reserve(transaction_pool::instance().size());

    /**
     * Get the transaction_pool transactions.
     */
    auto transactions = transaction_pool::instance().transactions();
    
    for (auto it = transactions.begin(); it != transactions.end(); ++it)
    {
        auto & tx = it->second;
        
        if (tx.is_coin_base() || tx.is_coin_stake() || tx.is_final() == false)
        {
            continue;
        }
        
        std::shared_ptr<block_orphan> ptr_orphan;
        
        double priority = 0;
        
        std::int64_t total_in = 0;
        
        bool is_missing_inputs = false;
        
        for (auto & tx_in : tx.transactions_in())
        {
            transaction tx_previous;
            
            transaction_index tx_index;
            
            if (
                tx_previous.read_from_disk(tx_db, tx_in.previous_out(),
                tx_index) == false
                )
            {
                /**
                 * This should never be reached.
                 */
                if (transactions.count(tx_in.previous_out().get_hash()) == 0)
                {
                    log_error(
                        "Block, create new, transaction pool item is "
                        "missing input."
                    );
#if 0
                    /**
                     * :JC: When issue 5267 is fixed uncomment this.
                     * TODO: https://github.com/bitcoin/bitcoin/pull/5267
                     */
                    if (globals::instance().debug())
                    {
                        assert("transaction is missing input" == 0);
                    }
#endif
                    is_missing_inputs = true;
                    
                    if (ptr_orphan)
                    {
                        orphans.pop_back();
                    }
                    
                    break;
                }

                if (ptr_orphan == 0)
                {
                    orphans.push_back(std::make_shared<block_orphan> (tx));
                    
                    ptr_orphan = orphans.back();
                }
                
                dependencies[tx_in.previous_out().get_hash()].push_back(
                    ptr_orphan
                );
                
                ptr_orphan->dependencies().insert(
                    tx_in.previous_out().get_hash()
                );
                
                total_in += 
                    transactions[tx_in.previous_out().get_hash()
                    ].transactions_out()[tx_in.previous_out().n()].value()
                ;
                
                continue;
            }
            
            std::int64_t value_in = tx_previous.transactions_out()[
                tx_in.previous_out().n()
            ].value();
            
            total_in += value_in;

            auto conf = tx_index.get_depth_in_main_chain();
            
            priority += static_cast<double> (value_in) * conf;
        }
        
        if (is_missing_inputs)
        {
            continue;
        }
        
        /**
         * priority = sum(value * age) / transaction size
         */
        
        data_buffer buffer;
        
        tx.encode(buffer);
    
        auto tx_size = buffer.size();
    
        priority /= tx_size;

        double fee_per_kilobyte =  double(
            total_in - tx.get_value_out()) / (double(tx_size) / 1000.0
        );

        if (ptr_orphan)
        {
            ptr_orphan->set_priority(priority);
            
            ptr_orphan->set_fee_per_kilobyte(fee_per_kilobyte);
        }
        else
        {
            priorities.push_back(
                std::make_tuple(priority, fee_per_kilobyte, &it->second)
            );
        }
    }

    /**
     * Collect the transactions into block.
     */
    
    std::map<sha256, transaction_index> test_pool;
    
    std::int64_t block_size = 1000;
    
    std::uint64_t block_tx = 0;
    
    auto block_sig_ops = 100;
    
    bool sorted_by_fee = (priority_size <= 0);

    transaction_fee_priority_compare comparer(sorted_by_fee);
    
    std::make_heap(priorities.begin(), priorities.end(), comparer);

    while (priorities.size() > 0)
    {
        double priority = std::get<0> (priorities.front());
        
        double fee_per_kilobyte = std::get<1> (priorities.front());
        
        transaction & tx = *std::get<2>(priorities.front());

        std::pop_heap(priorities.begin(), priorities.end(), comparer);
        
        priorities.pop_back();

        data_buffer buffer;
        
        tx.encode(buffer);
        
        auto tx_size = buffer.size();

        if (block_size + tx_size >= block::get_maximum_size_median220())
        {
            continue;
        }
        
        auto sig_ops = tx.get_legacy_sig_op_count();
        
        if (block_sig_ops + sig_ops >= block::get_maximum_size_median220() / 50)
        {
            continue;
        }
        
        if (
            tx.time() > time::instance().get_adjusted() ||
            (ret->is_proof_of_stake() &&
            tx.time() > ret->transactions()[1].time())
            )
        {
            continue;
        }
        
        /**
         * Simplify transaction fee - allow free = false (ppcoin).
         */
        std::int64_t min_fee = tx.get_minimum_fee(
            static_cast<std::uint32_t> (block_size), false,
            types::get_minimum_fee_mode_block
        );

        if (
            sorted_by_fee && (fee_per_kilobyte < min_transaction_fee) &&
            (block_size + tx_size >= min_size)
            )
        {
            continue;
        }

        if (
            sorted_by_fee == false &&
            ((block_size + tx_size >= priority_size) ||
            (priority < constants::coin * 144 / 250))
            )
        {
            sorted_by_fee = true;
            
            comparer = transaction_fee_priority_compare(sorted_by_fee);
            
            std::make_heap(priorities.begin(), priorities.end(), comparer);
        }

        std::map<sha256, transaction_index> test_pool_copy(test_pool);
        
        std::map<sha256, std::pair<transaction_index, transaction> > inputs;
        
        bool invalid;
        
        if (
            tx.fetch_inputs(tx_db, test_pool_copy, false, true, inputs,
            invalid) == false
            )
        {
            continue;
        }
        
        std::int64_t transaction_fees =
            tx.get_value_in(inputs) - tx.get_value_out()
        ;
        
        if (transaction_fees < min_fee)
        {
            continue;
        }
        
        sig_ops += tx.get_p2sh_sig_op_count(inputs);

        if (block_sig_ops + sig_ops >= block::get_maximum_size_median220() / 50)
        {
            continue;
        }
        
        if (
            tx.connect_inputs(tx_db, inputs, test_pool_copy,
            transaction_position(1, 1, 1), index_previous, false, true) == false
            )
        {
            continue;
        }

        test_pool_copy[tx.get_hash()] = transaction_index(
            transaction_position(1, 1, 1),
            static_cast<std::uint32_t> (tx.transactions_out().size())
        );
        
        std::swap(test_pool, test_pool_copy);

        ret->transactions().push_back(tx);
        
        block_size += tx_size;
        
        ++block_tx;
        
        block_sig_ops += sig_ops;
        
        fees += transaction_fees;

        /**
         * -printpriority;
         */
        if (globals::instance().debug() && false)
        {
            log_debug(
                "Block, create new, priority = " << priority <<
                ", fee_per_kilobyte = " << fee_per_kilobyte <<
                ", hash(tx id) = " << tx.get_hash().to_string() << "."
            );
        }

        /**
         * Add the transactions that depend on this one to the priority queue.
         */
        sha256 hash = tx.get_hash();
        
        if (dependencies.count(hash) > 0)
        {
            for (auto & i : dependencies[hash])
            {
                if (!i->dependencies().empty())
                {
                    i->dependencies().erase(hash);
                    
                    if (i->dependencies().empty())
                    {
                        priorities.push_back(
                            std::make_tuple(static_cast<double> (
                            i->priority()), static_cast<double> (
                            i->fee_per_kilobyte()),
                            const_cast<transaction *> (&i->get_transaction()))
                        );
                        
                        std::push_heap(
                            priorities.begin(), priorities.end(), comparer
                        );
                    }
                }
            }
        }
    }

    /**
     * Set the number of transactions in the last block transaction.
     */
    globals::instance().set_last_block_transactions(block_tx);
    
    /**
     * Set the last block size.
     */
    globals::instance().set_last_block_size(block_size);

    /**
     * -printpriority
     */
    if (globals::instance().debug())
    {
        log_debug("Block, create new total size = " << block_size << ".");
    }
    
    if (ret->is_proof_of_work() == true)
    {
        if (
            globals::instance().is_incentive_enabled() == true &&
            incentive::instance().get_key().is_null() == false &&
            incentive::instance().winners().count(
            index_previous->height() + 1) > 0
            )
        {
            auto value = reward::get_proof_of_work(
                index_previous->height() + 1, fees,
                index_previous->get_block_hash()
            );
            
            auto value_incentive =
                static_cast<std::uint64_t> (value * (
                incentive::instance().get_percentage(
                index_previous->height() + 1) / 100.0f))
            ;

            ret->transactions()[0].transactions_out()[0].set_value(
                value - value_incentive
            );
            
            if (tx_new.transactions_out().size() > 1)
            {
                ret->transactions()[0].transactions_out()[1].set_value(
                    value_incentive
                );
            }
        }
        else
        {
            ret->transactions()[0].transactions_out()[0].set_value(
                reward::get_proof_of_work(index_previous->height() + 1, fees,
                index_previous->get_block_hash())
            );
        }
    }
    
    /**
     * Fill in the block header.
     */
    ret->header().hash_previous_block = index_previous->get_block_hash();
    
    if (ret->is_proof_of_stake() == true)
    {
        ret->header().timestamp = ret->transactions()[1].time();
    }
    
    ret->header().timestamp = std::max(
        static_cast<std::uint32_t> (index_previous->get_median_time_past() + 1),
        static_cast<std::uint32_t> (ret->get_max_transaction_time())
    );
    
    ret->header().timestamp = std::max(
        static_cast<std::uint32_t> (ret->header().timestamp),
        static_cast<std::uint32_t> (index_previous->time() -
        constants::max_clock_drift)
    );
    
    if (ret->is_proof_of_work())
    {
        ret->update_time(*index_previous);
    }
    
    ret->header().nonce = 0;

    return ret;
}

bool block::disconnect_block(db_tx & tx_db, block_index * index)
{
    /**
     * Disconnect in reverse order.
     */
    for (
        std::int32_t i = static_cast<int> (m_transactions.size()) - 1;
        i >= 0; i--
        )
    {
        if (m_transactions[i].disconnect_inputs(tx_db) == false)
        {
            return false;
        }
    }
    
    /**
     * Update block index on disk without changing it in memory. The memory
     * index structure will be changed after the database commits.
     */
    if (index->block_index_previous())
    {
        block_index_disk previous(*index->block_index_previous());

        /**
         * Set the next hash to null.
         */
        previous.set_hash_next(0);
        
        if (tx_db.write_blockindex(previous) == false)
        {
            log_error("Block, disconnect failed, write block index failed");
            
            return false;
        }
    }

    /**
     * Clean up wallet after disconnecting coinstake (ppcoin).
     */
    for (auto & i : m_transactions)
    {
        wallet_manager::instance().sync_with_wallets(i, this, false, false);
    }
    
    return true;
}

bool block::connect_block(
    db_tx & tx_db, block_index * pindex, const bool  & check_only
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not connecting because state != state_started.");
    
        return false;
    }
    
    try
    {
        /**
         * Check it again in case a previous version let a bad block in.
         * jc: Is this crap needed anymore?
         */
        if (check_block(0, check_only == false, check_only == false) == false)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }
    
    bool enforce_bip30 = true;
    
    bool strict_pay_to_script_hash = true;

    /**
     * Possible issue here: it doesn't know the version.
     */
    std::uint32_t tx_pos;
    
    if (check_only)
    {
        /**
         * Since we're just checking the block and not actually connecting it,
         * it might not (and probably shouldn't) be on the disk to get the
         * transaction from.
         */
        tx_pos = 1;
    }
    else
    {
        block tmp;
        
        tmp.encode();
        
        tx_pos = static_cast<std::uint32_t> (
            pindex->block_position() + tmp.size() -
            (2 * utility::get_var_int_size(0)) +
            utility::get_var_int_size(m_transactions.size()))
        ;
    }

    std::map<sha256, transaction_index> queued_changes;
  
    /**
     * Allocate the script_checker_queue:context.
     */
    script_checker_queue::context script_checker_queue_context;
    
    std::int64_t fees = 0;
    std::int64_t value_in = 0;
    std::int64_t value_out = 0;
    
    std::uint32_t sig_ops = 0;
    
    for (auto & i : m_transactions)
    {
        auto hash_tx = i.get_hash();
        
        if (enforce_bip30)
        {
            transaction_index tx_index_old;
            
            if (tx_db.read_transaction_index(hash_tx, tx_index_old))
            {
                for (auto & j : tx_index_old.spent())
                {
                    if (j.is_null())
                    {
                        return false;
                    }
                }
            }
        }
        
        sig_ops += i.get_legacy_sig_op_count();
        
        if (sig_ops > block::get_maximum_size_median220() / 50)
        {
            log_error("Block connect block failed, too many sigops.");
            
            return false;
        }
        
        transaction_position tx_position_this(
            pindex->file(), pindex->block_position(), tx_pos
        );
        
        if (check_only == false)
        {
            data_buffer tmp;
        
            i.encode(tmp);
        
            tx_pos += tmp.size();
        }
        
        transaction::previous_t inputs;
        
        if (i.is_coin_base())
        {
            value_out += i.get_value_out();
        }
        else
        {
            bool invalid;
            
            if (
                i.fetch_inputs(tx_db, queued_changes, true, false,
                inputs, invalid) == false
                )
            {
                return false;
            }
            
            if (strict_pay_to_script_hash)
            {
                /**
                 * Add in sigops done by pay-to-script-hash inputs; this is to
                 * prevent a "rogue miner" from creating an
                 * incredibly-expensive-to-validate block.
                 */
                sig_ops += i.get_p2sh_sig_op_count(inputs);
                
                if (sig_ops > block::get_maximum_size_median220() / 50)
                {
                    log_error("Block connect failed, too many sig ops.");
                    
                    return false;
                }
            }

            std::int64_t tx_value_in = i.get_value_in(inputs);
            std::int64_t tx_value_out = i.get_value_out();
            
            value_in += tx_value_in;
            value_out += tx_value_out;
            
            if (i.is_coin_stake() == false)
            {
                fees += tx_value_in - tx_value_out;
            }
            
            /**
             * Allocate container to hold all scripts to be verified by the
             * script_checker_queue.
             */
            std::vector<script_checker> script_checker_checks;

            if (
                i.connect_inputs(tx_db, inputs, queued_changes,
                tx_position_this, pindex, true, false,
                strict_pay_to_script_hash, true,
                &script_checker_checks) == false
                )
            {
                return false;
            }
            
            /**
             * Insert the scripts to be check by the script_checker_queue.
             */
            script_checker_queue_context.insert(script_checker_checks);
        }

        queued_changes[hash_tx] = transaction_index(
            tx_position_this,
            static_cast<std::uint32_t> (i.transactions_out().size())
        );
    }
    
    /**
     * Wait for all scripts to be checked by the script_checker_queue.
     */
    if (script_checker_queue_context.sync_wait() == false)
    {
        log_error(
            "Block connect failed, one of the scripts failed validation."
        );
        
        return false;
    }
    
    /**
     * Track money supply (ppcoin).
     */
    
    /**
     * Set the mint.
     */
    pindex->set_mint(value_out - value_in + fees);
    
    /**
     * Set the money supply.
     */
    pindex->set_money_supply(
        (pindex->block_index_previous() ?
        pindex->block_index_previous()->money_supply() : 0) +
        value_out - value_in
    );

    /**
     * Update the money supply.
     */
    globals::instance().set_money_supply(pindex->money_supply());
    
    block_index_disk new_block_index(*pindex);
    
    if (tx_db.write_blockindex(new_block_index) == false)
    {
        log_error("Block connect failed, write_block_index for failed.");
        
        return false;
    }
    
    /**
     * Fees are not collected by miners as in bitcoin instead they are
     * destroyed to compensate the entire network (ppcoin).
     * -printcreation
     */
    log_none(
        "Block connect, destroy fees = " << utility::format_money(fees) << "."
    );

    if (check_only)
    {
        return true;
    }
    
    /**
     * Write queued tx_index changes.
     */
    for (
        auto it = queued_changes.begin(); it != queued_changes.end(); ++it
        )
    {
        if (tx_db.update_transaction_index(it->first, it->second) == false)
        {
            log_error("Block, connect failed, update_tx_index failed.");
            
            return false;
        }
    }

    sha256 hash_previous = 0;
    
    if (pindex->block_index_previous())
    {
        hash_previous = pindex->block_index_previous()->get_block_hash();
    }

    if (
        m_transactions[0].get_value_out() >
        reward::get_proof_of_work(pindex->height(), fees, hash_previous)
        )
    {
        return false;
    }

    /**
     * Update block index on disk without changing it in memory. The memory
     * index structure will be changed after the db commits.
     */
    if (pindex->block_index_previous())
    {
        block_index_disk previous(*pindex->block_index_previous());
        
        previous.set_hash_next(pindex->get_block_hash());
        
        if (tx_db.write_blockindex(previous) == false)
        {
            log_error("Block, connect failed, write_block_index failed.");
         
            return false;
        }
    }
    
    /**
     * Watch for transactions paying to me.
     */
    for (auto & i : m_transactions)
    {
        wallet_manager::instance().sync_with_wallets(i, this, true);
    }

    return true;
}

std::uint32_t block::get_stake_entropy_bit(const std::uint32_t & height) const
{
    /**
     * Take the last bit of the block hash as the entropy bit.
     */
    std::uint32_t entropy_bit = get_hash().to_uint64() & 1llu;
    
    log_none(
        "Block " << height << ", entropy bit = " << entropy_bit << "."
    );
    
    return entropy_bit;
}

bool block::is_proof_of_stake() const
{
    return m_transactions.size() > 1 && m_transactions[1].is_coin_stake();
}

bool block::is_proof_of_work() const
{
    return is_proof_of_stake() == false;
}

std::pair<point_out, std::uint32_t> block::get_proof_of_stake() const
{
    return
        is_proof_of_stake() ? std::make_pair(
        m_transactions[1].transactions_in()[0].previous_out(),
        m_transactions[1].time()) :
        std::make_pair(point_out(), static_cast<std::uint32_t> (0))
    ;
}

std::int64_t block::get_max_transaction_time() const
{
    std::int64_t ret = 0;
    
    for (auto & i : m_transactions)
    {
        ret = std::max(ret, (static_cast<std::int64_t>(i.time())));
    }

    return ret;
}

sha256 block::build_merkle_tree() const
{
    m_merkle_tree.clear();
    
    for (auto & i : m_transactions)
    {
        m_merkle_tree.push_back(i.get_hash());
    }
    
    int j = 0;
    
    for (auto size = m_transactions.size(); size > 1; size = (size + 1) / 2)
    {
        for (auto i = 0; i < size; i += 2)
        {
            auto i2 = std::min(static_cast<std::size_t> (i + 1), size - 1);

            m_merkle_tree.push_back(sha256::from_digest(&hash::sha256d(
                m_merkle_tree[j + i].digest(),
                m_merkle_tree[j + i].digest() + sha256::digest_length,
                m_merkle_tree[j + i2].digest(),
                m_merkle_tree[j + i2].digest() + sha256::digest_length)[0])
            );
        }
        
        j += size;
    }
    
    return m_merkle_tree.empty() ? 0 : m_merkle_tree.back();
}

bool block::check_block(
    const std::shared_ptr<tcp_connection> & connection, const bool & check_pow,
    const bool & check_merkle_root
    )
{
    /**
     * These are checks that are independent of context that can be verified
     * before saving an orphan block.
     */
    
    /**
     * Clear
     */
    clear();
    
    /**
     * Encode
     */
    encode();
    
    /**
     * Get the size.
     */
    auto length = size();
    
    /**
     * Clear
     */
    clear();
    
    /**
     * Check size limits.
     */
    if (
        m_transactions.size() == 0 ||
        m_transactions.size() > block::get_maximum_size_median220() ||
        length > block::get_maximum_size_median220()
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("size limits failed");
        
        return false;
    }

    /**
     * Check that the nonce is in range for the block type.
     */
    if (is_proof_of_stake() == true)
    {
        if (m_header.nonce != 0)
        {
            throw std::runtime_error("invalid nonce for proof of stake");
            
            return false;
        }
    }
    else if (is_proof_of_work() == true)
    {
        if (m_header.nonce == 0)
        {
            throw std::runtime_error("invalid nonce for proof of work");
            
            return false;
        }
    }

    /**
     * Check that the proof of work matches claimed amount.
     */
    if (
        check_pow && is_proof_of_work() &&
        check_proof_of_work(get_hash(), m_header.bits) == false
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(50);
        }
        
        throw std::runtime_error("proof of work failed");
     
        return false;
    }

    /**
     * Check the timestamp.
     */
    if (
        m_header.timestamp >
        time::instance().get_adjusted() + constants::max_clock_drift
        )
    {
        throw std::runtime_error("block timestamp too far in the future");
     
        return false;
    }

    /**
     * The first transaction must be coinbase.
     */
    if (
        m_transactions.size() == 0 || m_transactions[0].is_coin_base() == false
        )
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error(
            m_transactions.size() == 0 ? "first tx is missing" :
            "first tx is not coinbase"
        );
     
        return false;
    }
    
    for (auto i = 1; i < m_transactions.size(); i++)
    {
        if (m_transactions[i].is_coin_base())
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(100);
            }
            
            throw std::runtime_error("more than one coinbase");
         
            return false;
        }
    }
    
    /**
     * Only the second transaction can be the optional coinbase.
     */
    for (auto i = 2; i < m_transactions.size(); i++)
    {
        if (m_transactions[i].is_coin_stake())
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(100);
            }
            
            throw std::runtime_error("coinstake in wrong position");
         
            return false;
        }
    }

    /**
     * If the block is proof-of-stake the coinbase output must be empty.
     */
    if (is_proof_of_stake())
    {
        if (
            m_transactions[0].transactions_out().size() != 1 ||
            m_transactions[0].transactions_out()[0].is_empty() == false
            )
        {
            throw std::runtime_error(
                "coinbase output not empty for proof-of-stake block"
            );
         
            return false;
        }
    }
#if 0 /** Commented out in the original code. */
    /**
     * Check the coinbase timestamp.
     */
    if (
        m_header.timestamp > m_transactions[0].time() +
        constants::max_clock_drift
        )
    {
        log_error(
            "Block failed to check coinbase timestamp because it "
            "is too early."
        );
         
        return false;
    }
#endif
    /**
     * Check coinstake timestamp.
     */
    if (is_proof_of_stake())
    {
        if (
            kernel::check_coin_stake_timestamp(
            m_header.timestamp, m_transactions[1].time()) == false
            )
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(50);
            }
            
            throw std::runtime_error("coinstake timestamp violation");
             
            return false;
        }
    }

    /**
     * ZeroTime transaction checking.
     */
    if (globals::instance().is_zerotime_enabled())
    {
        if (utility::is_initial_block_download() == false)
        {
            for (auto & i : m_transactions)
            {
                if (i.is_coin_base() || i.is_coin_stake())
                {
                    continue;
                }
                else if (zerotime::instance().has_lock_conflict(i))
                {
                    /**
                     * Set the Denial-of-Service score for the connection.
                     */
                    if (connection)
                    {
                        connection->set_dos_score(connection->dos_score() + 1);
                    }
                    
                    throw std::runtime_error("zerotime lock conflict");
                    
                    return false;
                }
            }
        }
    }

    /**
     * Incentive block checking.
     */
    if (globals::instance().is_incentive_enabled() == true)
    {
        if (is_proof_of_work() == true)
        {
            if (utility::is_initial_block_download() == false)
            {
                if (m_transactions.size() > 0)
                {
                    auto index_previous = stack_impl::get_block_index_best();
                    
                    /**
                     * The incentive enforcement block number.
                     */
                    enum { incentive_enforcement = (constants::test_net ?
                        600 : 220000)
                    };

                    if (
                        index_previous &&
                        index_previous->height() + 1 >= incentive_enforcement
                        )
                    {
                        if (
                            incentive::instance().winners().count(
                            index_previous->height() + 1) > 0
                            )
                        {
                            /**
                             * There must be at least two outputs.
                             */
                            if (
                                m_transactions[0].transactions_out().size() > 1
                                )
                            {
                                /**
                                 * Get the value.
                                 */
                                auto value = reward::get_proof_of_work(
                                    index_previous->height() + 1, 0,
                                    index_previous->get_block_hash()
                                );
                                
                                /**
                                 * Get the incentive value.
                                 */
                                std::int64_t value_incentive =
                                    value * (incentive::instance(
                                    ).get_percentage(
                                    index_previous->height() + 1) / 100.0f
                                );

                                /**
                                 * Get their incentive value.
                                 */
                                auto their_incentive_value =
                                    m_transactions[0].transactions_out()[
                                    1].value()
                                ;

                                if (their_incentive_value >= value_incentive)
                                {
                                    log_info(
                                        "Block got incentive reward "
                                        "(VALID VALUE)."
                                    );
                                    
                                    /**
                                     * Get the winner for this height.
                                     */
                                    auto winner =
                                        incentive::instance().winners()[
                                        index_previous->height() + 1
                                    ].second;
                                    
                                    if (winner.size() > 0)
                                    {
                                       /**
                                        * Check winners against address.
                                        */
                                        auto script_public_key =
                                            m_transactions[0
                                            ].transactions_out()[
                                            1].script_public_key()
                                        ;
                                        
                                        destination::tx_t dest_tx;

                                        if (
                                            script::extract_destination(
                                            script_public_key, dest_tx) == true
                                            )
                                        {
                                            auto addr = address(
                                                dest_tx).to_string()
                                            ;
     
                                            if (winner == addr)
                                            {
                                                log_info(
                                                    "Block got incentive reward"
                                                    " (VALID WINNER) " <<
                                                    winner << ":" << addr << "."
                                                );
                                            }
                                            else
                                            {
                                                if (
                                                    incentive::instance(
                                                    ).runners_up().count(
                                                    index_previous->height() + 1
                                                    ) > 0
                                                    )
                                                {
                                                    /**
                                                     * Get the runners up.
                                                     */
                                                    auto runners_up =
                                                        incentive::instance(
                                                        ).runners_up()[
                                                        index_previous->height()
                                                        + 1]
                                                    ;
                                                    
                                                    if (runners_up.size() > 0)
                                                    {
                                                        auto found = false;
                                                        
                                                        for (
                                                            auto & i :
                                                            runners_up
                                                            )
                                                        {
                                                            if (i == addr)
                                                            {
                                                                log_info(
                                                                    "Block got "
                                                                    "incentive "
                                                                    "reward "
                                                                    "(VALID "
                                                                    "RUNNERSUP) "
                                                                    << i << ":"
                                                                    << addr <<
                                                                    "."
                                                                );
                                                                
                                                                found = true;
                                                                
                                                                break;
                                                            }
                                                        }
                                                        
                                                        /**
                                                         * If we have no
                                                         * matching winner
                                                         * and no runners up we
                                                         * we will accept the
                                                         * questionable reward
                                                         * but increase the
                                                         * node's ban score.
                                                         */
                                                        if (found == false)
                                                        {
                                                            log_error(
                                                                "Block got "
                                                                "incentive "
                                                                "reward "
                                                                "(QUESTIONABLE "
                                                                "WINNER/"
                                                                "NORUNNERSUP) "
                                                                << winner << ":"
                                                                << addr << "."
                                                            );

                                                            if (index_previous->height() + 1 >= 705000)
                                                            {
#if 0
                                                                /**
                                                                 * Increment the
                                                                 * Denial-of-Service
                                                                 * score for the
                                                                 * connection.
                                                                 */
                                                                if (connection)
                                                                {
                                                                    connection->set_dos_score(
                                                                        connection->dos_score(
                                                                        ) + 1
                                                                    );
                                                                }
#endif
                                                                /**
                                                                 * Reject the
                                                                 * block.
                                                                 */
                                                                return false;
                                                            }
                                                            else
                                                            {
                                                                /**
                                                                 * Increment the
                                                                 * Denial-of-Service
                                                                 * score for the
                                                                 * connection.
                                                                 */
                                                                if (connection)
                                                                {
                                                                    connection->set_dos_score(
                                                                        connection->dos_score(
                                                                        ) + 1
                                                                    );
                                                                }
                                                                
                                                                /**
                                                                 * We accept the
                                                                 * block as valid
                                                                 * since we lack
                                                                 * consensus.
                                                                 */
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        /**
                                                         * We have no winner or
                                                         * runners up, therefore
                                                         * are a new node to the
                                                         * system, follow the
                                                         * longest chain.
                                                         */
                                                    }
                                                }
                                            }
                                        }
                                        else
                                        {
                                            /**
                                             * Increment the Denial-of-Service
                                             * score for the connection.
                                             */
                                            if (connection)
                                            {
                                                connection->set_dos_score(
                                                    connection->dos_score()
                                                    + 5
                                                );
                                            }
                                            
                                            /**
                                             * We failed to extract the
                                             * destination address found in the
                                             * block, reject and increase the
                                             * peers ban score.
                                             */
                                            return false;
                                        }
                                    }
                                    else
                                    {
                                        /**
                                         * We have no winners, follow the
                                         * longest chain.
                                         */
                                        log_info(
                                            "Block got incentive reward "
                                            "(LONGESTCHAIN)."
                                        );
                                    }
                                }
                                else
                                {
                                    log_info(
                                        "Got incentive reward(RAPED) NOT "
                                        "ENOUGH." << static_cast<double> (
                                        m_transactions[0].transactions_out()[
                                        0].value()) / constants::coin << ":" <<
                                        static_cast<double> (value) /
                                        constants::coin
                                    );
                                    
                                    /**
                                     * Set the Denial-of-Service score for the
                                     * connection.
                                     */
                                    if (connection)
                                    {
                                        connection->set_dos_score(
                                            connection->dos_score() + 1
                                        );
                                    }
                                    
                                    /**
                                     * There was not enough incentive value
                                     * found in the block, reject and increase
                                     * the peers ban score.
                                     */
                                    return false;
                                }
                            }
                            else
                            {
                                if (connection)
                                {
                                    try
                                    {
                                        if (
                                            auto t =
                                            connection->get_tcp_transport(
                                            ).lock()
                                            )
                                        {
                                            log_info(
                                                "Got incentive reward(RAPED) "
                                                "EMPTY from " << t->socket(
                                                ).remote_endpoint() << "."
                                            );
                                        }
                                    }
                                    catch (std::exception & e)
                                    {
                                        log_info(
                                            "Got incentive reward(RAPED) EMPTY "
                                            "what = " << e.what() << "."
                                        );
                                    }
                                }
                                else
                                {
                                    log_info(
                                        "Got incentive reward(RAPED) EMPTY "
                                        "from ???."
                                    );
                                }
#if 0
                                /**
                                 * Set the Denial-of-Service score for the
                                 * connection and reject the block.
                                 */
                                if (connection)
                                {
                                    connection->set_dos_score(
                                        connection->dos_score() + 1
                                    );
                                }
#endif
                                /**
                                 * There was no incentive transaction found in
                                 * the block, reject it.
                                 */
                                return false;
                            }
                        }
                        else
                        {
                            /**
                             * Follow the longest chain.
                             */
                        }
                    }
                    else
                    {
                        /**
                         * Follow the longest chain.
                         */
                    }
                }
            }
        }
    }

    /**
     * Check the transactions.
     */
    for (auto & i : m_transactions)
    {
        if (i.check() == false)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(connection->dos_score() + 1);
            }
            
            throw std::runtime_error("check_transaction failed");
             
            return false;
        }
        
        if (m_header.timestamp < i.time())
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(50);
            }
            
            throw std::runtime_error(
                "block timestamp earlier than transaction timestamp"
            );
             
            return false;
        }
    }

    /**
     * Check for duplicate tx id's. This is caught by connect_inputs, but
     * catching it earlier avoids a potential DoS attack.
     */
    std::set<sha256> unique_tx;

    for (auto & i : m_transactions)
    {
        unique_tx.insert(i.get_hash());
    }
    
    if (unique_tx.size() != m_transactions.size())
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("duplicate transaction");
         
        return false;
    }

    auto sig_ops = 0;
    
    for (auto & i : m_transactions)
    {
        sig_ops += i.get_legacy_sig_op_count();
    }
    
    if (sig_ops > block::get_maximum_size_median220() / 50)
    {
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("sig ops out-of-bounds");
        
        return false;
    }
    
    /**
     * Check merkle root.
     */
    if (check_merkle_root && m_header.hash_merkle_root != build_merkle_tree())
    {
        log_error(
            "Block merkle root mismatch " <<
            m_header.hash_merkle_root.to_string() << ":" <<
            build_merkle_tree().to_string() << ""
        );
        
        /**
         * Set the Denial-of-Service score for the connection.
         */
        if (connection)
        {
            connection->set_dos_score(100);
        }
        
        throw std::runtime_error("hash merkle root mismatch");
        
        return false;
    }

    /**
     * Skip ECDSA signature verification when checking blocks before the last
     * blockchain checkpoint.
     */
    if (
        globals::instance().best_block_height() >=
        checkpoints::instance().get_total_blocks_estimate()
        )
    {
        /**
         * Check the signature.
         */
        if (check_signature() == false)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            if (connection)
            {
                connection->set_dos_score(100);
            }
            
            throw std::runtime_error("bad block signature");
            
            return false;
        }
    }

    return true;
}

bool block::read_from_disk(
    const block_index * index, const bool & read_transactions
    )
{
    if (read_transactions == false)
    {
        *this = index->get_block_header();
        
        return true;
    }
    
    if (
        read_from_disk(index->file(), index->block_position(),
        read_transactions) == false
        )
    {
        return false;
    }
    
    if (get_hash() != index->get_block_hash())
    {
        throw std::runtime_error("get_hash doesn't match index");
        
        return false;
    }
    
    return true;
}

bool block::accept_block(
    const std::shared_ptr<tcp_connection_manager> & connection_manager
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_debug("Block, not accepting because state != state_started.");
    
        return false;
    }
    
    if (globals::instance().is_client_spv() == true)
    {
        log_debug("Block, not accepting because we are an SPV client.");
        
        return false;
    }
    
    auto hash_block = get_hash();
 
    /**
     * Check for duplicate.
     */
    if (globals::instance().block_indexes().count(hash_block) > 0)
    {
        log_error("Block, accept block failed, already in block indexes.");
    
        return false;
    }
    
    /**
     * Get the previous block index.
     */
    auto it = globals::instance().block_indexes().find(
        m_header.hash_previous_block
    );
    
    if (it == globals::instance().block_indexes().end())
    {
        log_error(
            "Block, accept block failed, previous block " <<
            m_header.hash_previous_block.to_string().substr(0, 20) <<
            " not found."
        );
    
        return false;
    }
    
    /**
     * Get the previous index.
     */
    auto index_previous = it->second;

    /**
     * Get the height.
     */
    auto height = index_previous->height() + 1;
    
    log_debug("Block, accept block, height = " << height << ".");
    
    /**
     * Pause Proof-of-Work for mobile Proof-of-Stake testing and development
     * of FPGA mining support.
     */
    
    /**
     * The block height at which to pause Proof-of-Work.
     */
    enum { block_height_pause_pow = 117833 };
    
    /**
     * The block height at which to resume Proof-of-Work.
     */
    enum { block_height_resume_pow = 136000 };
    
    /**
     * The block height at which to pause even Proof-of-Work blocks.
     */
    enum { block_height_pause_even_pow = 136400 };
    
    if (
        is_proof_of_work() &&
        (height > block_height_pause_pow && height < block_height_resume_pow)
        )
    {
        log_error(
            "Block, accept block failed, PoW is paused until block # " <<
            block_height_resume_pow << ", height = " <<  height << "."
        );
        
        return false;
    }

    if (
        is_proof_of_work() && (height >= block_height_resume_pow &&
        height < block_height_pause_even_pow)
        )
    {
        /**
         * When Proof-of-Work is mixed with Proof-of-Stake we see ~22% increase
         * in block generation as a result of variable timing. By only
         * accepting even Proof-of-Work blocks "back to back" block generation
         * will no longer occur from the same entity and the time variation
         * will be removed. This has the side-effect that it halts an
         * insta-mine attack attempt immediately.
         */
        if (height % 2 == 1)
        {
            log_debug("Block, accept block failed, height is not even.");
            
            return false;
        }
    }
    
    if (is_proof_of_work() && height > constants::pow_cutoff_block)
    {
        log_error(
            "Block, accept block failed, no PoW block allowed anymore, "
            "height = " <<  height << "."
        );
        
        return false;
    }
    
    auto bits = utility::get_next_target_required(
        index_previous, is_proof_of_stake()
    );

    /**
     * Check the proof-of-work or the proof-of-stake.
     */
    if (m_header.bits != bits)
    {
        log_error(
            "Block, accept block failed, incorrect " << (is_proof_of_work() ?
            "proof-of-work" : "proof-of-stake") << "."
        );
        
        return false;
    }

    /**
     * Check the timestamp against the previous index.
     */
    if (
        m_header.timestamp <= index_previous->get_median_time_past() ||
        m_header.timestamp +
        constants::max_clock_drift < index_previous->time()
        )
    {
        log_error(
            "Block, accept block failed, block's timestamp is too early."
        );
    
        return false;
    }
    
    /**
     * Check that all transactions are finalized.
     */
    for (auto & i : m_transactions)
    {
        if (i.is_final(height, m_header.timestamp) == false)
        {
            log_error(
                "Block, accept block failed, contains a non-final transaction."
            );
         
            return false;
        }
    }
    
    /**
     * Check that the block chain matches the known block chain up to a
     * checkpoint.
     */
    if (checkpoints::instance().check_hardened(height, hash_block) == false)
    {
        log_error(
            "Block, accept block failed, rejected by hardened checkpoint "
            "lock-in at " << height << "."
        );
    
        return false;
    }

    /**
     * Check that the block satisfies synchronized checkpoint (ppcoin).
     */
    if (checkpoints::instance().check_sync(hash_block, index_previous) == false)
    {
        /**
         * -nosynccheckpoints
         */
        auto nosynccheckpoints = false;
        
        if (nosynccheckpoints == false)
        {
            log_error(
                "Block, accept block failed, rejected by synchronized "
                "checkpoint."
            );
            
            return false;
        }
        else
        {
            log_warn(
                "Block, accept block failed, syncronized checkpoint "
                "violation detected, skipping."
            );
        }
    }
    
    /**
     * Reject block header version < 3 since 95% threshold on main network
     * and always on test network.
     */
    if (
        m_header.version < 3 &&
        ((constants::test_net == false && height > 14060) ||
        (constants::test_net && height > 0))
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 3."
        );
    
        return false;
    }
    
    /**
     * Reject block header version < 5 after block 310000.
     */
    if (
        m_header.version < 5 &&
        ((constants::test_net == false && height > 310000) ||
        (constants::test_net == true && height > 18))
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 5."
        );
    
        return false;
    }

    /**
     * Reject block header version < 6 after block 635000.
     */
    if (
        m_header.version < 6 &&
        ((constants::test_net == false && height > 635000) ||
        (constants::test_net == true && height > 30))
        )
    {
        log_error(
            "Block, accept block failed, rejected block header version < 6."
        );
    
        return false;
    }
    
    /**
     * Enforce rule that the coinbase starts with serialized block height.
     */
    script expect = script() << height;
    
    if (
        std::equal(expect.begin(), expect.end(),
        m_transactions[0].transactions_in()[0].script_signature().begin()
        ) == false
        )
    {
        log_error(
            "Block, accept block failed, block height mismatch in coinbase."
        );
    
        return false;
    }
    
    /**
     * Write block to history file.
     */
    
    /**
     * Allocate a temporary buffer to determine the size of the block in bytes.
     */
    data_buffer buffer;
    
    /**
     * Encode ourselves into the buffer.
     */
    encode(buffer);
    
    /**
     * Get the available disk space.
     */
    auto disk_available =
        utility::disk_info(filesystem::data_path()).available
    ;
    
    /**
     * Make sure we have enough disk space.
     */
    if (disk_available < buffer.size())
    {
        log_error(
            "Block, accept block failed, out of disk space, "
            "available = " << disk_available << "."
        );
        
        return false;
    }
    
    std::uint32_t file = -1;
    
    std::uint32_t block_position = 0;
    
    /**
     * Write the block to disk.
     */
    if (write_to_disk(file, block_position) == false)
    {
        log_error("Block, accept block failed, write_to_disk failed.");
        
        return false;
    }
    
    /**
     * Add the block to the index.
     */
    if (add_to_block_index(file, block_position) == false)
    {
        log_error("Block, accept block failed, add_to_block_index failed.");
        
        return false;
    }

    /**
     * Do not relay during initial download.
     */
    if (utility::is_initial_block_download() == false)
    {
        /**
         * Relay inventory.
         */
        if (globals::instance().hash_best_chain() == hash_block)
        {
            if (connection_manager)
            {
                auto connections = connection_manager->tcp_connections();
                
                for (auto & i : connections)
                {
                    if (auto connection = i.second.lock())
                    {
                        connection->send_inv_message(
                            inventory_vector::type_msg_block, hash_block
                        );
                    }
                }
            }
        }
    }

    /**
     * Check pending sync-checkpoint (ppcoin).
     */
    checkpoints::instance().accept_pending_sync_checkpoint(connection_manager);

    return true;
}

bool block::read_from_disk(
    const std::uint32_t & file_index, const std::uint32_t & block_position,
    const bool & read_transactions
    )
{
    set_null();

    auto f = file_open(file_index, block_position, "rb");
    
    if (f)
    {
        auto block_header_only = false;
        
        if (read_transactions == false)
        {
            block_header_only = true;
        }
        
        /**
         * Clear the buffer.
         */
        clear();

        /**
         * Set the file for decoding.
         */
        set_file(f);

        /**
         * Attempt to decode.
         */
        if (decode(block_header_only))
        {
            /**
             * Clear the buffer.
             */
            clear();
        
            /**
             * Close the file.
             */
            f->close();
            
            /**
             * Set the file to null.
             */
            set_file(nullptr);
        }
        else
        {
            /**
             * Set the file to null.
             */
            set_file(nullptr);
        
            return false;
        }
        
        /**
         * Check the header.
         */
        if (read_transactions)
        {
            if (is_proof_of_work())
            {
                if (check_proof_of_work(get_hash(), m_header.bits) == false)
                {
                    log_error(
                        "Block check proof of work failed, errors in "
                        "block header."
                    );
                    
                    return false;
                }
            }
        }
    }
    else
    {
        log_error("Block failed to open block file.");
        
        return false;
    }

    return true;
}

bool block::write_to_disk(
    std::uint32_t & file_number, std::uint32_t & block_position
    )
{
    /**
     * :TODO: Do not allow empty pruned block files to be created.
     */

    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not writing to disk because state != state_started.");
    
        return false;
    }
     
    /**
     * Open history file to append.
     */
    auto f = file_append(file_number);
    
    if (f)
    {
        /**
         * Allocate the buffer.
         */
        data_buffer buffer_block;
        
        /**
         * Encode the block into the buffer.
         */
        encode(buffer_block);
        
        /**
         * Get the size of the buffer.
         */
        std::uint32_t size = static_cast<std::uint32_t> (buffer_block.size());
        
        /**
         * Get the magic (message start).
         */
        std::uint32_t magic = message::header_magic();
        
        /**
         * Allocate the index buffer.
         */
        data_buffer buffer_index;
        
        /**
         * Write the magic (message start).
         */
        buffer_index.write_uint32(magic);
        
        /**
         * Write the encoded block size.
         */
        buffer_index.write_uint32(size);
        
        /**
         * Write the index header buffer.
         */
        f->write(buffer_index.data(), buffer_index.size());

        /**
         * Get the out position.
         */
        auto out_position = f->ftell();
        
        if (out_position < 0)
        {
            log_error("Block failed writing to disk, ftell failed");
            
            return false;
        }
        
        /**
         * Set the block position to the out position.
         */
        block_position = static_cast<std::uint32_t> (out_position);

        /**
         * Write the block buffer.
         */
        f->write(buffer_block.data(), buffer_block.size());

        /**
         * Flush
         */
        f->fflush();

        /**
         * Sync the file to disk.
         */
        if (
            utility::is_initial_block_download() == false ||
            (globals::instance().best_block_height() + 1) % 500 == 0
            )
        {
            f->fsync();
        }
    }
    else
    {
        log_error("Block failed writing to disk, file append failed.");
        
        return false;
    }

    return true;
}

bool block::set_best_chain(db_tx & tx_db, block_index * index_new)
{
    auto block_hash = get_hash();

    if (tx_db.txn_begin() == false)
    {
        log_error("Block, set best chain failed, txn_begin failed.");
        
        return false;
    }
    
    if (
        stack_impl::get_block_index_genesis() == 0 &&
        block_hash == (constants::test_net ?
        block::get_hash_genesis_test_net() : block::get_hash_genesis())
        )
    {
        tx_db.write_hash_best_chain(block_hash);
        
        if (tx_db.txn_commit() == false)
        {
            log_error("Block set best chain txn_commit failed.");
            
            return false;
        }
        
        stack_impl::set_block_index_genesis(index_new);
    }
    else if (
        m_header.hash_previous_block == globals::instance().hash_best_chain()
        )
    {
        if (set_best_chain_inner(tx_db, index_new) == false)
        {
            log_error("Block set best chain inner failed.");
            
            return false;
        }
    }
    else
    {
        /**
         * The first block in the new chain that will cause it to become the
         * new best chain.
         */
        auto index_intermediate = index_new;

        /**
         * List of blocks that need to be connected afterwards.
         */
        std::vector<block_index *> index_secondary;

        /**
         * Reorganization is costly in terms of database load because it works
         * in a single database transaction. We try to limit how much needs
         * to be done inside.
        */
        while (
            index_intermediate->block_index_previous() &&
            index_intermediate->block_index_previous()->chain_trust() >
            stack_impl::get_block_index_best()->chain_trust()
            )
        {
            index_secondary.push_back(index_intermediate);
            
            index_intermediate =
                index_intermediate->block_index_previous()
            ;
        }

        if (index_secondary.size() > 0)
        {
            log_debug(
                "Block set best chain is postponing " <<
                index_secondary.size() << " reconnects."
            );
        }
        
        /**
         * Switch to the new best branch.
         */
        if (db_tx::reorganize(tx_db, index_intermediate) == false)
        {
            tx_db.txn_abort();
            
            block::invalid_chain_found(index_new);

            log_error("Block set best chain failed, reorganize failed.");
            
            return false;
        }
        
        /**
         * Connect further blocks.
         */
        for (auto & i : index_secondary)
        {
            block blk;
            
            if (blk.read_from_disk(i) == false)
            {
                log_error(
                    "Block failed to set best chain, read_from_disk failed."
                );

                break;
            }
            
            if (tx_db.txn_begin() == false)
            {
                log_error(
                    "Block failed to set best chain, txn_begin failed."
                );
               
                break;
            }
            
            /**
             * Errors are no longer fatal, we still did a reorganization to a
             * new chain in a valid way.
             */
            if (blk.set_best_chain_inner(tx_db, i) == false)
            {
                break;
            }
        }
    }
    
    /**
     * Update best block in wallet (so we can detect restored wallets).
     */
    bool is_initial_download = utility::is_initial_block_download();
    
    if (is_initial_download == false)
    {
        /**
         * Notify wallets about a new best chain.
         */
        wallet_manager::instance().set_best_chain(block_locator(index_new));
    }
    
    /**
     * New best block.
     */
    globals::instance().set_hash_best_chain(block_hash);
    stack_impl::set_block_index_best(index_new);
    globals::instance().set_block_index_fbbh_last(0);
    globals::instance().set_best_block_height(
        stack_impl::get_block_index_best()->height()
    );
    stack_impl::get_best_chain_trust() = index_new->chain_trust();
    globals::instance().set_time_best_received(std::time(0));
    globals::instance().set_transactions_updated(
        globals::instance().transactions_updated() + 1
    );
    
    log_debug(
        "Block, set best chain, new best = " <<
        globals::instance().hash_best_chain().to_string() <<
        ", height = " << globals::instance().best_block_height() <<
        ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
        ", date = " << stack_impl::get_block_index_best()->time() << "."
    );

    if (globals::instance().best_block_height() % 500 == 0)
    {
        log_info(
            "Block, set best chain, new best = " <<
            globals::instance().hash_best_chain().to_string() <<
            ", height = " << globals::instance().best_block_height() <<
            ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
            ", date = " << stack_impl::get_block_index_best()->time() << "."
        );
    }
    
    log_debug(
        "Block, stake checkpoint = " <<
        stack_impl::get_block_index_best()->stake_modifier_checksum() << "."
    );

    /**
     * Check the version of the last 100 blocks to see if we need to upgrade.
     */
    if (utility::is_initial_block_download() == false)
    {
        auto blocks_upgraded = 0;
        
        auto index = stack_impl::get_block_index_best();
        
        for (auto i = 0; i < 100 && index != 0; i++)
        {
            if (index->version() > block::current_version)
            {
                ++blocks_upgraded;
            }
            
            index = index->block_index_previous();
        }
        
        if (blocks_upgraded > 0)
        {
            log_debug(
                "Block set best chain, " << blocks_upgraded <<
                " of last 100 blocks version " << block::current_version << "."
            );
        }
        
        if (blocks_upgraded > 100 / 2)
        {
            log_warn("Block detected obsolete version, upgrade required.");
        }
    }

    /*
     * -blocknotify
     */

    return true;
}

bool block::add_to_block_index(
    const std::uint32_t & file_index, const std::uint32_t & block_position
    )
{
    if (globals::instance().state() != globals::state_started)
    {
        log_error("Block, not adding to index because state != state_started.");
    
        return false;
    }
    
    /**
     * Check for duplicate.
     */
    auto hash_block = get_hash();
    
    if (globals::instance().block_indexes().count(hash_block) > 0)
    {
        log_error(
            "Block add to block index failed, " <<
            hash_block.to_string().substr(0, 20) << " already exists."
        );
        
        return false;
    }
    
    /**
     * Construct new block index.
     */
    auto index_new = new block_index(file_index, block_position, *this);
    
    if (index_new == 0)
    {
        log_error("Block add to block index failed, allocation failure.");
        
        return false;
    }
    
    index_new->set_hash_block(hash_block);
    
    auto it1 = globals::instance().block_indexes().find(
        m_header.hash_previous_block
    );
    
    if (it1 != globals::instance().block_indexes().end())
    {
        index_new->set_block_index_previous(it1->second);

        index_new->set_height(it1->second->height() + 1);
    }
    
    /**
     * Compute chain trust score (ppcoin).
     */
    index_new->set_chain_trust(
        (index_new->block_index_previous() ?
        index_new->block_index_previous()->chain_trust() : 0) +
        index_new->get_block_trust()
    );

    /**
     * Compute stake entropy bit for stake modifier (ppcoin).
     */
    if (
        index_new->set_stake_entropy_bit(
        get_stake_entropy_bit(index_new->height())) == false
        )
    {
        log_error(
            "Block, add to block index failed, set stake entriopy bit failed."
        );
        
        return false;
    }
    
    /**
     * Record Proof-of-Stake hash value (ppcoin).
     */
    if (index_new->is_proof_of_stake())
    {
        if (globals::instance().proofs_of_stake().count(hash_block) == 0)
        {
            log_error(
                "Block, add to block index failed, hash for proof of stake"
                " not found in map"
            );
            
            return false;
        }
        
        index_new->set_hash_proof_of_stake(
            globals::instance().proofs_of_stake()[hash_block]
        );
    }
    
    /**
     * Compute stake modifier (ppcoin).
     */
    std::uint64_t stake_modifier = 0;
    
    bool generated_stake_modifier = false;

    if (
        kernel::instance().compute_next_stake_modifier(block_position,
        index_new->block_index_previous(),
        stake_modifier, generated_stake_modifier) == false
        )
    {
        log_error(
            "Block, add to block index failed, compute stake modifier failed."
        );
    
        return false;
    }
    
    /**
     * Set the stake modifier.
     */
    index_new->set_stake_modifier(stake_modifier, generated_stake_modifier);
    
    /**
     * Set the stake modifier checksum.
     */
    index_new->set_stake_modifier_checksum(
        kernel::instance().get_stake_modifier_checksum(index_new)
    );

    if (
        kernel::instance().check_stake_modifier_checkpoints(
        index_new->height(), index_new->stake_modifier_checksum()) == false
        )
    {
        log_debug(
            "Block, add to block index failed, rejected by stake modifier "
            "checkpoint = " << index_new->height() << ", modifier = " <<
            stake_modifier << "."
        );
        
        return false;
    }
    
    /**
     * Add to the block indexes.
     */
    globals::instance().block_indexes().insert(
        std::make_pair(hash_block, index_new)
    );

    if (index_new->is_proof_of_stake())
    {
        stack_impl::get_seen_stake().insert(
            std::make_pair(index_new->previous_out_stake(),
            index_new->stake_time())
        );
    }

    /**
     * Write to disk block index.
     */
    db_tx tx_db;
    
    if (tx_db.txn_begin() == false)
    {
        return false;
    }
    
    /**
     * Write the blockindex.
     */
    tx_db.write_blockindex(block_index_disk(*index_new));
    
    if (tx_db.txn_commit() == false)
    {
        return false;
    }
    
    /**
     * Check if we have a new best chain.
     */
    if (index_new->chain_trust() > stack_impl::get_best_chain_trust())
    {
        /**
         * Set the new best chain.
         */
        if (set_best_chain(tx_db, index_new) == false)
        {
            return false;
        }
    }
    
    tx_db.close();

    if (index_new == stack_impl::get_block_index_best())
    {
        /**
         * The hash of the previous best coinbase.
         */
        static sha256 g_hash_previous_best_coinbase;
        
        /**
         * Inform the wallet that the transacton was updated.
         */
        wallet_manager::instance().on_transaction_updated(
            g_hash_previous_best_coinbase
        );
        
        g_hash_previous_best_coinbase = m_transactions[0].get_hash();
    }
    
    return true;
}

bool block::set_best_chain_inner(db_tx & tx_db, block_index * index_new)
{
    if (
        connect_block(tx_db, index_new) == false ||
        tx_db.write_hash_best_chain(get_hash()) == false
        )
    {
        tx_db.txn_abort();
        
        invalid_chain_found(index_new);
        
        return false;
    }
    
    if (tx_db.txn_commit() == false)
    {
        log_error("Block set best chain inner failed, txn_commit failed.");
        
        return false;
    }
    
    /**
     * Add to current best branch.
     */
    index_new->block_index_previous()->set_block_index_next(index_new);

    /**
     * Delete redundant memory transactions.
     */
    for (auto & i : m_transactions)
    {
        transaction_pool::instance().remove(i);
    }

    return true;
}

void block::invalid_chain_found(const block_index * index_new)
{
    if (index_new->chain_trust() > stack_impl::get_best_invalid_trust())
    {
        stack_impl::get_best_invalid_trust() = index_new->chain_trust();
        
        db_tx().write_best_invalid_trust(stack_impl::get_best_invalid_trust());
    }

    log_info(
        "Block, invalid chain found, invalid block = " <<
        index_new->get_block_hash().to_string().substr(0, 20) <<
        ", height = " << index_new->height() <<
        ", trust = " << index_new->chain_trust().to_string() <<
        ", date = " << index_new->time() << "."
    );

    log_info(
        "Block, invalid chain found, current block = " <<
        globals::instance().hash_best_chain().to_string().substr(0, 20) <<
        ", height = " << globals::instance().best_block_height() <<
        ", trust = " << stack_impl::get_best_chain_trust().to_string() <<
        ", date = " << stack_impl::get_block_index_best()->time() << "."
    );
}

bool block::sign(const key_store & store)
{
    std::vector< std::vector<std::uint8_t> > solutions;
    
    types::tx_out_t tx_out_which;

    if (is_proof_of_stake() == false)
    {
        for (auto i = 0; i < m_transactions[0].transactions_out().size(); i++)
        {
            const auto & txout = m_transactions[0].transactions_out()[i];

            if (
                script::solver(txout.script_public_key(), tx_out_which,
                solutions) == false
                )
            {
                continue;
            }
            
            if (tx_out_which == types::tx_out_pubkey)
            {
                auto & pub_key = solutions[0];
                
                key k;

                types::id_key_t addr;
                
                auto hash160 = hash::sha256_ripemd160(
                    &pub_key[0], pub_key.size()
                );
                
                std::memcpy(&addr.digest()[0], &hash160[0], hash160.size());
    
                if (store.get_key(addr, k) == false)
                {
                    continue;
                }
                
                if (k.get_public_key() != pub_key)
                {
                    continue;
                }
                
                if (k.sign(get_hash(), m_signature) == false)
                {
                    continue;
                }
                
                return true;
            }
        }
    }
    else
    {
        const auto & txout = m_transactions[1].transactions_out()[1];

        if (
            script::solver(txout.script_public_key(), tx_out_which,
            solutions) == false
            )
        {
            return false;
        }
        
        if (tx_out_which == types::tx_out_pubkey)
        {
            auto & pub_key = solutions[0];
            
            key k;

            types::id_key_t addr;
            
            auto hash160 = hash::sha256_ripemd160(
                &pub_key[0], pub_key.size()
            );
            
            std::memcpy(&addr.digest()[0], &hash160[0], hash160.size());

            if (store.get_key(addr, k) == false)
            {
                return false;
            }
            
            if (store.get_key(addr, k) == false)
            {
                return false;
            }
            
            if (k.get_public_key() != pub_key)
            {
                return false;
            }
            
            return k.sign(get_hash(), m_signature);
        }
    }

    log_error("Block, sign failed.");
    
    return false;
}

bool block::check_signature() const
{
    if (get_hash() == get_hash_genesis())
    {
        return m_signature.size() == 0;
    }

    std::vector< std::vector<std::uint8_t> > solutions;
    
    types::tx_out_t tx_out_type;

    if (is_proof_of_stake())
    {
        const auto & txout = m_transactions[1].transactions_out()[1];

        if (
            script::solver(txout.script_public_key(), tx_out_type,
            solutions) == false
            )
        {
            return false;
        }
        
        if (tx_out_type == types::tx_out_pubkey)
        {
            auto & pub_key = solutions[0];
            
            key k;
            
            if (k.set_public_key(pub_key) == false)
            {
                return false;
            }
            
            if (m_signature.size() == 0)
            {
                return false;
            }
            
            return k.verify(get_hash(), m_signature);
        }
    }
    else
    {
        for (auto i = 0; i < m_transactions[0].transactions_out().size(); i++)
        {
            const auto & txout = m_transactions[0].transactions_out()[i];

            if (
                !script::solver(txout.script_public_key(), tx_out_type,
                solutions)
                )
            {
                return false;
            }
            
            if (tx_out_type == types::tx_out_pubkey)
            {
                /**
                 * Verify
                 */
                auto & pub_key = solutions[0];
                
                key k;
                
                if (k.set_public_key(pub_key) == false)
                {
                    continue;
                }
                
                if (m_signature.size() == 0)
                {
                    continue;
                }
                
                if (k.verify(get_hash(), m_signature) == false)
                {
                    continue;
                }
                
                return true;
            }
        }
    }
    
    return false;
}

std::size_t block::get_maximum_size_median220()
{
    /**
     * (SPV) clients do not have a maximum block size.
     */
    if (globals::instance().is_client_spv() == true)
    {
        return std::numeric_limits<std::size_t>::max();
    }

    /**
     * Skip size limit on checking blocks before the last blockchain
     * checkpoint or during initial download.
     */
    if (
        globals::instance().best_block_height() <
        checkpoints::instance().get_total_blocks_estimate() ||
        utility::is_initial_block_download() == true
        )
    {
        return std::numeric_limits<std::size_t>::max();
    }
    
    /**
     * 128 Kilobytes
     */
    enum { minimum_maximum_size = 128000 };

    /**
     * The number of blocks to calculate the median over.
     */
    enum { blocks_to_go_back = 220 };
    
    /**
     * Get the last block_index.
     */
    const auto * index = stack_impl::get_block_index_best();
    
    static median_filter<std::size_t> g_median_filter(
        blocks_to_go_back, minimum_maximum_size
    );
    
    /**
     * Initialise the median_filter once.
     */
    if (g_median_filter.sorted().size() <= 1)
    {
        for (auto i = 0; i < blocks_to_go_back; i++)
        {
            g_median_filter.input(minimum_maximum_size);
        }
    }

    static block_index * g_block_index_last = 0;
    
    if (g_block_index_last != index)
    {
        g_block_index_last = const_cast<block_index *> (index);
        
        static std::recursive_mutex g_mutex_last_block_indexes;
        
        std::lock_guard<std::recursive_mutex> l1(g_mutex_last_block_indexes);

        static std::map<const block_index *, std::size_t> g_last_block_indexes;
        
        auto it = g_last_block_indexes.begin();
        
        while (it != g_last_block_indexes.end())
        {
            if (
                1 + globals::instance().best_block_height() -
                it->first->height() > blocks_to_go_back
                )
            {
                it = g_last_block_indexes.erase(it);
            }
            else
            {
                ++it;
            }
        }

        /**
         * Go back by what we want to be median size worth of blocks.
         */
        for (auto i = 0; index && i < blocks_to_go_back; i++)
        {
            if (g_last_block_indexes.count(index) > 0)
            {
                g_median_filter.input(g_last_block_indexes[index]);
            }
            else
            {
                /**
                 * Allocate the block.
                 */
                block blk;
                
                /**
                 * Read the block from disk.
                 */
                if (
                    blk.read_from_disk(index->file(),
                    index->block_position()) == true
                    )
                {
                    /**
                     * Encode to obtain the size in bytes.
                     */
                    blk.encode();

                    g_last_block_indexes[index] = blk.size();
                    
                    g_median_filter.input(blk.size());
                }
            }
            
            index = index->block_index_previous();
        }
    }

    /**
     * 768 Kilobytes
     */
    enum { maximum_byte_increase = 768000 };

    return std::max(
        static_cast<std::size_t> (minimum_maximum_size),
        static_cast<std::size_t> ((g_median_filter.median() <
        minimum_maximum_size ? minimum_maximum_size :
        g_median_filter.median()) + maximum_byte_increase)
    );
}

std::string block::get_file_path(const std::uint32_t & file_index)
{
    std::stringstream ss;
    
    std::string block_path = "blockchain/peer/";
    
    ss <<
        filesystem::data_path() << block_path <<
        boost::format("blk%04u.dat") % file_index
    ;

    return ss.str();
}

std::shared_ptr<file> block::file_open(
    const std::uint32_t & index, const std::uint32_t & position,
    const char * mode
    )
{
    if ((index < 1) || (index == (std::uint32_t)-1))
    {
        return std::shared_ptr<file> ();
    }
    else
    {
        auto ret = std::make_shared<file>();
        
        if (ret->open(get_file_path(index).c_str(), mode))
        {
            if (position != 0 && !strchr(mode, 'a') && !strchr(mode, 'w'))
            {
                if (ret->seek_set(position) != 0)
                {
                    ret->close();
                    
                    return std::shared_ptr<file> ();
                }
            }
        }
        else
        {
            return std::shared_ptr<file> ();
        }
        
        return ret;
    }
    
    return std::shared_ptr<file> ();
}

std::shared_ptr<file> block::file_append(std::uint32_t & index)
{
    index = 0;
    
    static std::uint32_t current_block_file = 1;
    
    for (;;)
    {
        if (auto f = file_open(current_block_file, 0, "ab"))
        {
            if (f->seek_end())
            {
                /**
                 * The default maximum size is 128 megabytes.
                 */
                std::size_t max_file_size = 128;
                
                max_file_size *= 1000000;

                if (ftell(f->get_FILE()) <= max_file_size)
                {
                    index = current_block_file;
                    
                    return f;
                }

                f->close();
                
                current_block_file++;
            }
            else
            {
                return std::shared_ptr<file> ();
            }
        }
        else
        {
            return std::shared_ptr<file> ();
        }
    }
    
    return std::shared_ptr<file> ();
}

bool block::check_proof_of_work(const sha256 & hash, const std::uint32_t & bits)
{
    /**
     * The genesis block does not use Proof-of-Work, instead a
     * hard-coded hash of it is used.
     */
    if (constants::test_net == true && hash == get_hash_genesis_test_net())
    {
        return true;
    }
    else if (hash == get_hash_genesis())
    {
        return true;
    }
    
    /**
     * Allocate the target
     */
    big_number target;
    
    /**
     * Set the compact bits.
     */
    target.set_compact(bits);

    /**
     * Check the range.
     */
    if (target <= 0 || target > constants::proof_of_work_limit)
    {
        throw std::runtime_error("number of bits below minimum work");

        return false;
    }
    
    /**
     * Allocate our target.
     */
    big_number target_ours;
    
    /**
     * Set the target sha256.
     */
    target_ours.set_sha256(hash);

    /**
     * Check the proof of work matches the claimed amount.
     */
    if (hash > target.get_sha256())
    {
        log_error(
            "Block check proof of work failed, hash doesn't match bits." <<
            hash.to_string() << ":" << target.get_sha256().to_string()
        );
        
        return false;
    }

    return true;
}

std::vector<sha256> block::get_merkle_branch(std::int32_t index) const
{
    if (m_merkle_tree.size() == 0)
    {
        build_merkle_tree();
    }
    
    std::vector<sha256> merkle_branch;
    
    int j = 0;
    
    for (
        auto size = m_transactions.size(); size > 1;
        size = (size + 1) / 2
        )
    {
        auto i = std::min(index ^ 1, static_cast<std::int32_t> (size - 1));
        
        merkle_branch.push_back(m_merkle_tree[j + i]);
        
        index >>= 1;
        
        j += size;
    }
    
    return merkle_branch;
}

sha256 block::check_merkle_branch(
    sha256 h, const std::vector<sha256> & merkle_branch,
    std::int32_t index
    )
{
    if (index == -1)
    {
        return 0;
    }
    
    for (auto & i : merkle_branch)
    {
        if (index & 1)
        {
            h = sha256::from_digest(&hash::sha256d(
                i.digest(), i.digest() + sha256::digest_length,
                h.digest(), h.digest() + sha256::digest_length)[0]
            );
        }
        else
        {
            h = sha256::from_digest(&hash::sha256d(
                h.digest(), h.digest() + sha256::digest_length,
                i.digest(), i.digest() + sha256::digest_length)[0]
            );
        }
        
        index >>= 1;
    }
    
    return h;
}

void block::print()
{
    std::stringstream ss_transactions;

    for (auto & i : m_transactions)
    {
        ss_transactions << " ";
        ss_transactions << i.to_string();
    }
    
    std::stringstream ss_merkle_tree;
    
    for (auto & i : m_merkle_tree)
    {
        ss_merkle_tree << " ";
        ss_merkle_tree << i.to_string().substr(0, 8);
    }
    
    log_debug(
        "Block, hash = " << get_hash().to_string() << ". version = " <<
        m_header.version << ", hash_previous_block = " <<
        m_header.hash_previous_block.to_string() << ", hash_merkle_root = " <<
        m_header.hash_merkle_root.to_string() << ", timestamp = " <<
        m_header.timestamp << ", bits = " << m_header.bits << ", nonce = " <<
        m_header.nonce << ", transactions = " << m_transactions.size() <<
        ", signature = " << (m_signature.size() > 0 ?
        utility::hex_string(m_signature.begin(), m_signature.end()) : "null") <<
        ", transactions = " << ss_transactions.str() <<
        ", merkle tree = " << ss_merkle_tree.str() << "."
    );
}

int block::run_test()
{
    auto f1 = block::file_open(1, 0, "rb");
    
    if (f1)
    {
        printf("block::run_test: test 1 passed!\n");
    }
    
    std::uint32_t index = 1;
    
    auto f2 = block::file_append(index);
    
    if (f2)
    {
        printf("block::run_test: test 2 passed!\n");
    }
    
    return 0;
}
