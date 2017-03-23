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

#include <chrono>
#include <iomanip>

#include <coin/block.hpp>
#include <coin/globals.hpp>
#include <coin/incentive.hpp>
#include <coin/key_reserved.hpp>
#include <coin/logger.hpp>
#include <coin/mining.hpp>
#include <coin/mining_manager.hpp>
#include <coin/random.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/utility.hpp>
#include <coin/wallet.hpp>

using namespace coin;

mining_manager::mining_manager(
    boost::asio::io_service & ios, stack_impl & owner
    )
    : m_state_pow(state_pow_none)
    , m_state_pos(state_pos_none)
    , m_hashes_per_second(0.0f)
    , m_hps_timer_start(0)
    , io_service_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
    , timer_pos_(ios)
{
    // ...
}

void mining_manager::start()
{
    /**
     * Start mining Proof-of-Stake.
     */
    start_proof_of_stake();

    auto args = stack_impl_.get_configuration().args();
    
    auto it = args.find("mine-cpu");
    
    if (it != args.end())
    {
        if (std::stoi(it->second) > 0)
        {
            /**
             * Start mining Proof-of-Work.
             */
            start_proof_of_work();
        }
    }
}

void mining_manager::stop()
{
    /**
     * Stop mining Proof-of-Stake.
     */
    stop_proof_of_stake();
    
    /**
     * Stop mining Proof-of-Work.
     */
    stop_proof_of_work();
}

void mining_manager::start_proof_of_work()
{
    std::lock_guard<std::mutex> l1(mutex_);

    if (
        m_state_pow < state_pow_starting ||
        m_state_pow == state_pow_stopped
        )
    {
        /**
         * Set the state.
         */
        m_state_pow = state_pow_starting;

        /**
         * Calculate the number of cores.
         */
        auto cores = std::max(
            static_cast<std::uint32_t> (1),
            std::thread::hardware_concurrency()
        );

        log_info(
            "Mining manager is adding " << cores << " Proof-of-Work threads."
        );
        
        for (auto i = 0; i < cores; i++)
        {
            auto thread = std::make_shared<std::thread> (
                std::bind(&mining_manager::loop, this)
            );
            
            /**
             * Retain the thread.
             */
            threads_.push_back(thread);
        }
        
        /**
         * Set the state.
         */
        m_state_pow = state_pow_started;
    }
}

void mining_manager::stop_proof_of_work()
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (m_state_pow == state_pow_started)
    {
        /**
         * Set the state.
         */
        m_state_pow = state_pow_stopping;
        
        /**
         * Join the threads.
         */
        for (auto & i : threads_)
        {
            try
            {
                if (i->joinable())
                {
                    i->join();
                }
            }
            catch (std::exception & e)
            {
                // ...
            }
        }
        
        /**
         * Set the hashes per second.
         */
        m_hashes_per_second = 0.0f;
        
        /**
         * Post the operation onto the boost::asio::io_service.
         */
        io_service_.post(strand_.wrap(
            [this]()
        {
            /**
             * Allocate the pairs.
             */
            std::map<std::string, std::string> pairs;
            
            /**
             * Set the pairs type.
             */
            pairs["type"] = "mining";
            
            /**
             * Set the pairs value.
             */
            pairs["value"] = "proof-of-work";

            /**
             * Set the pairs hash.
             */
            pairs["mining.hashes_per_second"] =
                std::to_string(m_hashes_per_second)
            ;

            /**
             * Callback
             */
            stack_impl_.get_status_manager()->insert(pairs);
        }));
        
        /**
         * Set the hps timer start.
         */
        m_hps_timer_start = 0;
        
        /**
         * Clear the threads.
         */
        threads_.clear();
        
        /**
         * Set the state.
         */
        m_state_pow = state_pow_stopped;
    }
}

void mining_manager::start_proof_of_stake()
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (stack_impl_.get_configuration().mining_proof_of_stake() == true)
    {
        if (
            m_state_pos < state_pos_starting ||
            m_state_pos == state_pos_stopped
            )
        {
            /**
             * Set the state.
             */
            m_state_pos = state_pos_starting;

            timer_pos_.expires_from_now(std::chrono::seconds(60));
            timer_pos_.async_wait(std::bind(
                &mining_manager::pos_tick, this, std::placeholders::_1)
            );

            /**
             * Set the state.
             */
            m_state_pos = state_pos_started;
        }
    }
    else
    {
        log_info(
            "Mining manager did not start Proof-of-Stake, disabled "
            "in configuration."
        );
    }
}

void mining_manager::stop_proof_of_stake()
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (m_state_pos == state_pos_started)
    {
        /**
         * Set the state.
         */
        m_state_pos = state_pos_stopping;

        timer_pos_.cancel();

        /**
         * Set the state.
         */
        m_state_pos = state_pos_stopped;
    }
}

const double & mining_manager::hashes_per_second() const
{
    return m_hashes_per_second;
}

void mining_manager::loop()
{
    key_reserved reserve_key(*globals::instance().wallet_main());
    
    std::uint32_t extra_nonce = 0;
    
    while (
        ((m_state_pow == state_pow_starting ||
        m_state_pow == state_pow_started)) &&
        globals::instance().state() == globals::state_started
        )
    {
        while (
            (utility::is_initial_block_download() ||
            stack_impl_.get_tcp_connection_manager(
            )->is_connected() == false) &&
            globals::instance().state() == globals::state_started
            
            )
        {
            log_debug(
                "Mining manager is waiting on the blockchain to download."
            );
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        while (
            globals::instance().wallet_main()->is_locked() &&
            globals::instance().state() == globals::state_started
            )
        {
            log_debug("Mining manager, wallet is locked.");
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        /**
         * Attempt to create a new block of transactions.
         */
        auto blk = block::create_new(
            globals::instance().wallet_main(), false
        );
        
        if (blk == 0)
        {
            return;
        }
        
        auto transactions_updated_last =
            globals::instance().transactions_updated()
        ;
        
        auto index_previous = stack_impl::get_block_index_best();
    
        increment_extra_nonce(blk, index_previous, extra_nonce);
        
        if (globals::instance().debug())
        {
            /**
             * Encode the block to determine the size.
             */
            data_buffer buffer;
            
            blk->encode(buffer);
            
            log_debug(
                "Mining manager, mining with " << blk->transactions().size() <<
                " transactions in block, bytes = " << buffer.size() << "."
            );
        }

        /**
         * Create the hash buffers.
         */
        char midstate_buf[32 + 16];
        char * midstate = utility::alignup<16> (midstate_buf);
        char data_buf[128 + 16];
        char * data = utility::alignup<16> (data_buf);
        char hash1_buf[64 + 16];
        char * hash1 = utility::alignup<16> (hash1_buf);

        mining::format_hash_buffers(blk, midstate, data, hash1);

        auto & block_time =
            *reinterpret_cast<std::uint32_t *> (data + 64 + 4)
        ;
        auto & block_nonce =
            *reinterpret_cast<std::uint32_t *> (data + 64 + 12)
        ;

        /**
         * Search for a solution.
         */
        auto start = std::time(0);
        auto hash_target =
            big_number().set_compact(blk->header().bits).get_sha256()
        ;

        /**
         * The maximum nonce.
         */
        std::uint32_t max_nonce = 0xffff0000;
        
        block::header_t res_header;
        
        sha256 result;

        /**
         * The hashing loop.
         */
        while (
            ((m_state_pow == state_pow_starting ||
            m_state_pow == state_pow_started)) &&
            globals::instance().state() == globals::state_started
            )
        {
            std::uint32_t hashes_done = 0;
            
            std::uint32_t nonce_found = 0;
            
            /**
             * If the current block version is less than 5 use whirlpool
             * otherwise use blake256.
             */
            if (block::current_version < 5)
            {
                nonce_found = mining::scan_hash_whirlpool(
                    &blk->header(), max_nonce, hashes_done, result.digest(),
                    &res_header
                );
            }
            else
            {
                nonce_found =
                    mining::scan_hash_blake256(
                    &blk->header(), max_nonce, hashes_done, result.digest(),
                    &res_header
                );
            }

            /**
             * Check if we have found a solution.
             */
            if (nonce_found != static_cast<std::uint32_t> (-1))
            {
                if (result <= hash_target)
                {
                    /**
                     * We found a solution.
                     */
                    blk->header().nonce = nonce_found;
                    
                    assert(result == blk->get_hash());

                    if (
                        blk->sign(*globals::instance().wallet_main()) == false
                        )
                    {
                        break;
                    }
                    
                    /**
                     * Check the work.
                     */
                    check_work(
                        blk, globals::instance().wallet_main(), reserve_key,
                        false
                    );
                    
                    break;
                }
            }

            log_none(
                "Mining manager performed " << hashes_done << " hashes."
            );

            hashes_done += 1;
            
            static std::int64_t g_hash_counter = 0;
            
            /**
             * Get the milliseconds since epoch.
             */
            auto milliseconds = std::chrono::duration_cast<
                std::chrono::milliseconds> (
                std::chrono::system_clock::now().time_since_epoch()
            ).count();

            if (m_hps_timer_start == 0)
            {
                m_hps_timer_start = milliseconds;
                
                g_hash_counter = 0;
            }
            else
            {
                g_hash_counter += hashes_done;
            }

            if (milliseconds - m_hps_timer_start > 4000)
            {
                m_hashes_per_second =
                    1000.0 * g_hash_counter /
                    (milliseconds - m_hps_timer_start)
                ;
                
                m_hps_timer_start = milliseconds;
                
                g_hash_counter = 0;
                
                enum { interval_log = 4 };
                
                static std::int64_t time_log;
                
                if (std::time(0) - time_log > interval_log)
                {
                    time_log = std::time(0);
                    
                    log_info(
                        "Mining manager " <<
                        std::fixed << std::setprecision(2) <<
                        m_hashes_per_second / 1000.0f << " KH/s."
                    );
                    
                    /**
                     * Post the operation onto the boost::asio::io_service.
                     */
                    io_service_.post(strand_.wrap([this]()
                    {
                        /**
                         * Allocate the pairs.
                         */
                        std::map<std::string, std::string> pairs;
                        
                        /**
                         * Set the pairs type.
                         */
                        pairs["type"] = "mining";
                        
                        /**
                         * Set the pairs value.
                         */
                        pairs["value"] = "proof-of-work";

                        /**
                         * Set the pairs hash.
                         */
                        pairs["mining.hashes_per_second"] =
                            std::to_string(m_hashes_per_second)
                        ;

                        /**
                         * Callback
                         */
                        stack_impl_.get_status_manager()->insert(pairs);
                    }));
                }
            }
            
            if (globals::instance().state() != globals::state_started)
            {
                break;
            }
            
            if (
                globals::instance().transactions_updated() !=
                transactions_updated_last && std::time(0) - start > 60
                )
            {
                break;
            }
            
            if (block_nonce >= 0xffff0000)
            {
                break;
            }
            
            if (index_previous != stack_impl::get_block_index_best())
            {
                break;
            }
            
            /**
             * Update the block.
             */
            
            /**
             * Update the timestamp.
             */
            blk->header().timestamp = std::max(
                static_cast<std::uint32_t> (
                index_previous->get_median_time_past() + 1),
                static_cast<std::uint32_t> (blk->get_max_transaction_time())
            );
            
            /**
             * Update the timestamp (again).
             */
            blk->header().timestamp = std::max(
                blk->header().timestamp,
                static_cast<std::uint32_t> (index_previous->time() -
                constants::max_clock_drift)
            );
            
            /** 
             * Update the time.
             */
            blk->update_time(*index_previous);
            
            block_time = utility::byte_reverse(blk->header().timestamp);

            if (
                blk->header().timestamp >=
                static_cast<std::uint32_t> (blk->transactions()[0].time() +
                constants::max_clock_drift)
                )
            {
                break;
            }
        }
    }
    
    log_debug(
        "Mining manager thread " << std::this_thread::get_id() << " stopped."
    );
}
void mining_manager::pos_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * Spawn a detached thread.
         */
        std::thread([this]()
        {
            auto start = std::chrono::system_clock::now();
            
            key_reserved reserve_key(*globals::instance().wallet_main());
            
            static std::uint32_t g_extra_nonce = 0;
            
            if (
                (m_state_pos == state_pos_starting ||
                m_state_pos == state_pos_started) &&
                globals::instance().state() == globals::state_started
                )
            {
                if (
                    stack_impl_.get_tcp_connection_manager(
                    )->active_tcp_connections() <
                    stack_impl_.get_tcp_connection_manager(
                    )->minimum_tcp_connections() &&
                    globals::instance().state() == globals::state_started
                    )
                {
                    log_info(
                        "Mining manager is waiting on more network "
                        "connections."
                    );
                }
                else if (
                    utility::is_initial_block_download() &&
                    globals::instance().state() == globals::state_started
                    )
                {
                    log_info(
                        "Mining manager is waiting on the blockchain "
                        "to download."
                    );
                }
                else if (
                    globals::instance().wallet_main()->is_locked() &&
                    globals::instance().state() == globals::state_started
                    )
                {
                    log_info("Mining manager, wallet is locked.");
                }
                else
                {
                    /**
                     * Attempt to create a new block of transactions.
                     */
                    auto blk = block::create_new(
                        globals::instance().wallet_main(), true
                    );
                    
                    if (blk)
                    {
                        if (globals::instance().debug())
                        {
                            /**
                             * Encode the block to determine the size.
                             */
                            data_buffer buffer;
                            
                            blk->encode(buffer);
                            
                            log_info(
                                "Mining manager, mining (pos) with " <<
                                blk->transactions().size() <<
                                " transactions in block, bytes = " <<
                                buffer.size() << "."
                            );
                        }
                        
                        auto index_previous =
                            stack_impl::get_block_index_best()
                        ;
                    
                        increment_extra_nonce(
                            blk, index_previous, g_extra_nonce
                        );

                        /**
                         * If proof-of-stake block found then process it.
                         */
                        if (blk->is_proof_of_stake())
                        {
                            if (
                                blk->sign(*globals::instance().wallet_main()
                                ) == false)
                            {
                                // ..
                            }
                            else
                            {
                                log_info(
                                    "Mining manager found Proof-of-Stake "
                                    "block " << blk->get_hash().to_string()
                                );

                                /**
                                 * Check the work.
                                 */
                                check_work(
                                    blk, globals::instance().wallet_main(),
                                    reserve_key, true
                                );
                            }
                        }
                    }
                }
            }
            
            std::chrono::duration<double> elapsed_seconds =
                std::chrono::system_clock::now() - start
            ;
            
            log_info(
                "Mining manager Proof-of-Stake took " <<
                elapsed_seconds.count() << " seconds."
            );

        }).detach();
        
        /**
         * Restart timer.
         */
        timer_pos_.expires_from_now(std::chrono::seconds(60));
        timer_pos_.async_wait(std::bind(
            &mining_manager::pos_tick, this, std::placeholders::_1)
        );
    }
}

void mining_manager::check_work(
    std::shared_ptr<block> & blk, const std::shared_ptr<wallet> & wallet,
    key_reserved & reserve_key, const bool & is_proof_of_stake
    )
{
    auto hash_block = blk->get_hash();
    
    auto hash_target = big_number().set_compact(
        blk->header().bits
    ).get_sha256();

    if (hash_block > hash_target && blk->is_proof_of_work())
    {
        log_error(
            "Mining manager check work failed, Proof-of-Work does not "
            "meet target."
        );
    
        return;
    }
    
    log_debug(
        "Mining manager found new block, hash = " << hash_block.to_string() <<
        ", target = " << hash_target.to_string() << ", value = " <<
        utility::format_money(
        blk->transactions()[0].transactions_out()[0].value()) << "."
    );
    
    /**
     * Print the block.
     */
    blk->print();

    /**
     * Check if we found a solution.
     */
    if (
        blk->header().hash_previous_block !=
        globals::instance().hash_best_chain()
        )
    {
        log_error("Mining manager block is stale, dropping.");
        
        return;
    }

    /**
     * Remove key from the pool.
     */
    reserve_key.keep_key();

    /**
     * Track the number of getdata requests this block gets.
     */
    wallet->request_counts()[blk->get_hash()] = 0;

    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, blk]()
    {
        /**
         * Process the block.
         */
        if (stack_impl_.process_block(0, blk) == false)
        {
            log_error("Mining manager failed to process block, not accepted.");
        }
        else
        {
            log_info("Mining manager processed block, accepted.");
            
            /**
             * If we are a client node broadcast the block to all connected
             * peers, otherwise an INV was sent in process_block above.
             */
            if (
                globals::instance().operation_mode() ==
                protocol::operation_mode_client
                )
            {
                auto connections =
                    stack_impl_.get_tcp_connection_manager(
                    )->tcp_connections()
                ;
                
                for (auto & i : connections)
                {
                    if (auto connection = i.second.lock())
                    {
                        connection->send_block_message(*blk);
                    }
                }
            }
        }
    }));
}

void mining_manager::increment_extra_nonce(
    std::shared_ptr<block> & blk, block_index * index_previous,
    std::uint32_t & extra_nonce
    )
{
    static sha256 hash_previous;
    
    if (hash_previous != blk->header().hash_previous_block)
    {
        extra_nonce = 0;
        
        hash_previous = blk->header().hash_previous_block;
    }
    
    ++extra_nonce;
    
    std::uint32_t height = index_previous->height() + 1;
    
    blk->transactions()[0].transactions_in()[
        0].set_script_signature((script() << height <<
        big_number(extra_nonce)) + globals::instance().coinbase_flags()
    );
    
    assert(
        blk->transactions()[0].transactions_in()[
        0].script_signature().size() <= 100
    );

    blk->header().hash_merkle_root = blk->build_merkle_tree();
}
