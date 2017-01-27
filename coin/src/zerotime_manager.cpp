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

#include <coin/address.hpp>
#include <coin/address_manager.hpp>
#include <coin/database_stack.hpp>
#include <coin/globals.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/message.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/utility.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_manager.hpp>
#include <coin/zerotime_vote.hpp>

using namespace coin;

zerotime_manager::zerotime_manager(
    boost::asio::io_service & ios, boost::asio::strand & s, stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
    , timer_probe_(ios)
{
    // ...
}

void zerotime_manager::start()
{
    if (globals::instance().is_zerotime_enabled())
    {
        log_info("ZeroTime manager is starting.");
        
        /**
         * Start the timer.
         */
        do_tick(60);
    }
}

void zerotime_manager::stop()
{
    log_info("ZeroTime manager is stopping.");
    
    timer_.cancel();
    timer_probe_.cancel();
}

void zerotime_manager::vote(
    const sha256 & hash_tx, const std::vector<transaction_in> & transactions_in
    )
{
    /**
     * Client nodes do not vote.
     */
    if (
        globals::instance().is_zerotime_enabled() &&
        globals::instance().is_client_spv() == false &&
        globals::instance().operation_mode() == protocol::operation_mode_peer
        )
    {
        assert(transactions_in.size());
        
        if (transactions_in.size() > 0)
        {
            /**
             * Get the best block index.
             */
            auto index = utility::find_block_index_by_height(
                globals::instance().best_block_height()
            );
        
            if (index)
            {
                /**
                 * Allocate the data_buffer.
                 */
                data_buffer buffer;
                
                /**
                 * Allocate the zerotime_vote.
                 */
                zerotime_vote ztvote(
                    index->height(), index->get_block_hash(), hash_tx,
                    transactions_in,
                    zerotime::instance().get_key().get_public_key()
                );
                
                /**
                 * Encode the zerotime_vote.
                 */
                ztvote.encode(buffer);

                /**
                 * Calulate our vote score.
                 */
                const auto & vote_score = ztvote.score();
                
                log_info(
                    "ZeroTime manager forming vote, calculated score = " <<
                    vote_score << " for " <<
                    ztvote.hash_nonce().to_string().substr(0, 8) << "."
                );
                
                /**
                 * If our vote score is at least zero we can vote otherwise
                 * peers will reject it.
                 */
                if (
                    vote_score > -1 &&
                    vote_score <= (constants::test_net == true ?
                    std::numeric_limits<std::int16_t>::max() :
                    std::numeric_limits<std::int16_t>::max() / 16)
                    )
                {
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_ztvote, ztvote.hash_nonce()
                    );
                    
                    /**
                     * Insert the zerotime_vote.
                     */
                    zerotime::instance().votes()[ztvote.hash_nonce()] = ztvote;

                    /**
                     * Get the TCP connections
                     */
                    auto tcp_connections =
                        stack_impl_.get_tcp_connection_manager(
                        )->tcp_connections()
                    ;
                    
                    for (auto & i : tcp_connections)
                    {
                        if (auto t = i.second.lock())
                        {
                            t->send_relayed_inv_message(inv, buffer);
                        }
                    }

                    /**
                     * Allocate the message.
                     */
                    message msg(inv.command(), buffer);

                    /**
                     * Encode the message.
                     */
                    msg.encode();

                    /**
                     * Allocate the UDP packet.
                     */
                    std::vector<std::uint8_t> udp_packet(msg.size());
                    
                    /**
                     * Copy the message to the UDP packet.
                     */
                    std::memcpy(&udp_packet[0], msg.data(), msg.size());
            
                    /**
                     * Broadcast the message over UDP.
                     */
                    stack_impl_.get_database_stack()->broadcast(udp_packet);
                }
            }
        }
    }
}

void zerotime_manager::probe_for_answers(
    const sha256 & hash_tx,
    const std::vector<transaction_in> & transactions_in
    )
{
    if (globals::instance().is_zerotime_enabled())
    {
        log_debug(
            "ZeroTime manager is probing for answers to " <<
            hash_tx.to_string().substr(0, 8) << "."
        );
        
        assert(transactions_in.size());
        
        std::lock_guard<std::mutex> l1(mutex_questions_);
        
        if (questions_.count(hash_tx) == 0)
        {
            /**
             * Insert the question.
             */
            questions_[hash_tx].first = std::time(0);
            questions_[hash_tx].second =
                std::make_shared<zerotime_question> (transactions_in)
            ;
            
            /**
             * Try to get some recent good endpoints.
             */
            auto recent_good_endpoints =
                stack_impl_.get_address_manager()->recent_good_endpoints()
            ;
            
            std::random_shuffle(
                recent_good_endpoints.begin(), recent_good_endpoints.end()
            );
            
            /**
             * Limit the number of queued tcp endpoints to
             * zerotime::answers_maximum.
             */
            recent_good_endpoints.resize(zerotime::answers_maximum);

            if (recent_good_endpoints.size() > 0)
            {
                std::lock_guard<std::mutex> l1(
                    mutex_question_queue_tcp_endpoints_
                );
                
                std::vector<boost::asio::ip::tcp::endpoint> eps;
                
                for (auto & i : recent_good_endpoints)
                {
                    eps.push_back(
                        boost::asio::ip::tcp::endpoint(
                        i.addr.ipv4_mapped_address(), i.addr.port)
                    );
                }
                
                question_queue_tcp_endpoints_[hash_tx].first = std::time(0);
                question_queue_tcp_endpoints_[hash_tx].second.insert(
                    question_queue_tcp_endpoints_[hash_tx].second.end(),
                    eps.begin(), eps.end()
                );
                
                /**
                 * Start the timer.
                 */
                do_tick_probe(interval_probe);
            }
            else
            {
                log_error(
                    "ZeroTime manager tried to probe for answers but no "
                    "recent endpoints were found"
                );
            }
        }
    }
}

void zerotime_manager::handle_answer(
    const boost::asio::ip::tcp::endpoint & ep, const zerotime_answer & ztanswer
    )
{
    if (globals::instance().is_zerotime_enabled())
    {
        std::lock_guard<std::mutex> l2(mutex_questions_);
        
        if (questions_.count(ztanswer.hash_tx()) > 0)
        {
            std::lock_guard<std::mutex> l2(mutex_zerotime_answers_tcp_);
            
            zerotime_answers_tcp_[ztanswer.hash_tx()].first = std::time(0);
            zerotime_answers_tcp_[ztanswer.hash_tx()].second[ep] = ztanswer;
            
            log_info(
                "ZeroTime manager got correct answer " <<
                ztanswer.hash_tx().to_string().substr(0, 8) << ", so far = " <<
                zerotime_answers_tcp_[ztanswer.hash_tx()].second.size() << "."
            );

            /**
             * Check the number of answers.
             */
            if (
                zerotime_answers_tcp_[ztanswer.hash_tx()].second.size() ==
                globals::instance().zerotime_answers_minimum()
                )
            {
                /**
                 * We now have a safe number of votes, locks conflicts are
                 * resolved and we have the required number of (TCP)
                 * answers therefore the transaction is now as safe as a
                 * single confirmation transaction.
                 */
                 
                /**
                 * Set the number of confirmations for this transaction.
                 */
                zerotime::instance().confirmations()[ztanswer.hash_tx()] =
                    globals::instance().zerotime_answers_minimum()
                ;
            
                /**
                 * Inform the wallet that the transacton was updated.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    if (
                        globals::instance().wallet_main()->transactions(
                        ).count(ztanswer.hash_tx()) > 0
                        )
                    {
                        const auto & wtx =
                            globals::instance().wallet_main()->transactions()[
                            ztanswer.hash_tx()]
                        ;
                        
                        wallet_manager::instance(
                            ).on_spv_transaction_updated(
                            wtx.spv_block_height(), ztanswer.hash_tx()
                        );
                    }
                }
                else
                {
                    wallet_manager::instance().on_transaction_updated(
                        ztanswer.hash_tx()
                    );
                }
            }
        }
        else
        {
            log_info(
                "ZeroTime manager got wrong answer " <<
                ztanswer.hash_tx().to_string().substr(0, 8) <<
                ", dropping."
            );
        }
    }
}

void zerotime_manager::handle_vote(
    const boost::asio::ip::tcp::endpoint & ep, const zerotime_vote & ztvote
    )
{
    if (globals::instance().is_zerotime_enabled())
    {
        const auto & hash_tx = ztvote.hash_tx();
        const auto & vote_score = ztvote.score();

        /**
         * The vote score must be at least zero.
         */
        if (
            vote_score <= (constants::test_net == true ?
            std::numeric_limits<std::int16_t>::max() :
            std::numeric_limits<std::int16_t>::max() / 16)
            )
        {
            log_debug(
                "ZeroTime manager got valid vote, calculated score = " <<
                vote_score << " for " <<
                ztvote.hash_nonce().to_string().substr(0, 8) << "."
            );
        
            /**
             * Get a copy of the votes.
             */
            auto votes = zerotime::instance().votes();
            
            /**
             * We require at least 15% of the K closest votes.
             */
            enum { safe_percentage = constants::test_net ? 8 : 15 };;

            std::vector<std::int16_t> vote_scores;

            auto it = votes.begin();
            
            while (it != votes.end())
            {
                if (
                    it->second.score() > -1 &&
                    it->second.score() <= (constants::test_net == true ?
                    std::numeric_limits<std::int16_t>::max() :
                    std::numeric_limits<std::int16_t>::max() / 16) &&
                    it->second.hash_tx() == hash_tx
                    )
                {
                    vote_scores.push_back(it->second.score());
                    
                    ++it;
                }
                else
                {
                    it = votes.erase(it);
                }
            }
            
            /**
             * Get our best block height.
             */
            auto block_height =
                globals::instance().is_client_spv() == true ?
                globals::instance().spv_best_block_height() :
                globals::instance().best_block_height()
            ;

            /**
             * Get the K closest scores to the block height.
             */
            auto kclosest = k_closest(vote_scores, block_height, zerotime::k);
            
            auto percentage =
                (static_cast<double> (kclosest.size()) /
                static_cast<double> (zerotime::k) * 100.0f)
            ;
            
            log_debug(
                "ZeroTime manager has " << percentage << "% (" <<
                vote_scores.size() << ") votes for " <<
                hash_tx.to_string().substr(0, 8) << "."
            );
            
            if (percentage >= safe_percentage && percentage <= 100)
            {
                log_debug(
                    "ZeroTime manager got enough votes for " <<
                    hash_tx.to_string().substr(0, 8) << "."
                );

                auto loop = true;
                
                /**
                 * Resolve conflicts on the inputs (this loop may not be
                 * required).
                 */
                for (auto & i1 : kclosest)
                {
                    for (auto & i2 : votes)
                    {
                        if (i1 == i2.second.score())
                        {
                            std::lock_guard<std::mutex> l1(
                                mutex_safe_percentages_
                            );
                            
                            /**
                             * Do not continue to process votes if we have a
                             * safe percentage.
                             */
                            if (safe_percentages_.count(hash_tx) == 0)
                            {
                                log_debug(
                                    "ZeroTime manager got vote nonce = " <<
                                    i2.second.hash_nonce(
                                    ).to_string().substr(0, 8) << "."
                                );
                                
                                /**
                                 * Set the this transaction has a safe
                                 * percentage.
                                 */
                                safe_percentages_[hash_tx] = std::time(0);

                                /**
                                 * If we have a lock conflict resolve it and wait
                                 * for block event inclusion of the transaction,
                                 * otherwise start probing for answers.
                                 */
                                if (
                                    zerotime::instance().has_lock_conflict(
                                    i2.second.transactions_in(),
                                    i2.second.hash_tx())
                                    )
                                {
                                    /**
                                     * Resolve conflicts and await block event.
                                     */
                                    zerotime::instance(
                                        ).resolve_conflicts(
                                        i2.second.transactions_in(),
                                        i2.second.hash_tx()
                                    );
                                }
                                else
                                {
                                    transaction_wallet wtx;
                                    
                                    /**
                                     * If the transaction is to/from us perform
                                     * interrogation if the configured depth is
                                     * greater than zero.
                                     */
                                    if (
                                        globals::instance(
                                        ).zerotime_depth() > 0 &&
                                        wallet_manager::instance(
                                        ).get_transaction(i2.second.hash_tx(),
                                        wtx) == true
                                        )
                                    {
                                        if (wtx.is_from_me() == false)
                                        {
                                            /**
                                             * Probe for answers.
                                             */
                                            probe_for_answers(
                                                i2.second.hash_tx(),
                                                i2.second.transactions_in()
                                            );
                                        }
                                        else
                                        {
                                            /**
                                             * We now have a safe number of
                                             * votes, locked conflicts are
                                             * resolved therefore the
                                             * transaction is now as safe as a
                                             * single confirmation transaction.
                                             */
                                             
                                            /**
                                             * Set the number of confirmations
                                             * for this transaction.
                                             */
                                            zerotime::instance().confirmations()[
                                                i2.second.hash_tx()] =
                                                globals::instance(
                                                ).zerotime_answers_minimum()
                                            ;
                                            
                                            if (
                                                globals::instance(
                                                ).is_client_spv() == true
                                                )
                                            {
                                                /**
                                                 * Inform the wallet that the
                                                 * transacton was updated.
                                                 */
                                                wallet_manager::instance(
                                                    ).on_spv_transaction_updated(
                                                    wtx.spv_block_height(),
                                                    i2.second.hash_tx()
                                                );
                                            }
                                            else
                                            {
                                                /**
                                                 * Inform the wallet that the
                                                 * transacton was updated.
                                                 */
                                                wallet_manager::instance(
                                                    ).on_transaction_updated(
                                                    i2.second.hash_tx()
                                                );
                                            }
                                        }
                                    }
                                    else
                                    {
                                        /**
                                         * We now have a safe number of votes,
                                         * locked conflicts are resolved
                                         * therefore the transaction is now as
                                         * safe as a single confirmation
                                         * transaction.
                                         */
                                         
                                        /**
                                         * Set the number of confirmations for
                                         * this transaction.
                                         */
                                        zerotime::instance().confirmations()[
                                            i2.second.hash_tx()] =
                                            globals::instance(
                                            ).zerotime_answers_minimum()
                                        ;
                                        
                                        if (
                                            globals::instance(
                                            ).is_client_spv() == true
                                            )
                                        {
                                            /**
                                             * Inform the wallet that the
                                             * transacton was updated.
                                             */
                                            wallet_manager::instance(
                                                ).on_spv_transaction_updated(
                                                wtx.spv_block_height(),
                                                i2.second.hash_tx()
                                            );
                                        }
                                        else
                                        {
                                            /**
                                             * Inform the wallet that the
                                             * transacton was updated.
                                             */
                                            wallet_manager::instance(
                                                ).on_transaction_updated(
                                                i2.second.hash_tx()
                                            );
                                        }
                                    }
                                }

                                loop = false;
                                
                                break;
                            }
                        }
                    }
                    
                    if (loop == false)
                    {
                        break;
                    }
                }
            }
        }
    }
}

void zerotime_manager::print()
{
    log_debug("questions_ = " << questions_.size());
    log_debug("zerotime_answers_tcp_ = " << zerotime_answers_tcp_.size());
    log_debug(
        "questioned_tcp_endpoints_ = " << questioned_tcp_endpoints_.size()
    );
    log_debug(
        "question_queue_tcp_endpoints_ = " <<
        question_queue_tcp_endpoints_.size()
    );
    log_debug("safe_percentages_ = " << safe_percentages_.size());
}

void zerotime_manager::do_tick(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(interval));
    timer_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (globals::instance().is_zerotime_enabled())
            {
                /**
                 * Clear expired input locks.
                 */
                zerotime::instance().clear_expired_input_locks();
                
                std::lock_guard<std::mutex> l1(mutex_zerotime_answers_tcp_);
                
                auto it1 = zerotime_answers_tcp_.begin();
                
                while (it1 != zerotime_answers_tcp_.end())
                {
                    if (std::time(0) - it1->second.first > interval_six_blocks)
                    {
                        it1 = zerotime_answers_tcp_.erase(it1);
                    }
                    else
                    {
                        ++it1;
                    }
                }
                
                std::lock_guard<std::mutex> l2(mutex_questions_);
                
                auto it2 = questions_.begin();
                
                while (it2 != questions_.end())
                {
                    if (std::time(0) - it2->second.first > interval_six_blocks)
                    {
                        it2 = questions_.erase(it2);
                    }
                    else
                    {
                        ++it2;
                    }
                }
                
                std::lock_guard<std::mutex> l3(
                    mutex_questioned_tcp_endpoints_
                );
                
                auto it3 = questioned_tcp_endpoints_.begin();
                
                while (it3 != questioned_tcp_endpoints_.end())
                {
                    if (std::time(0) - it3->second.first > interval_six_blocks)
                    {
                        it3 = questioned_tcp_endpoints_.erase(it3);
                    }
                    else
                    {
                        ++it3;
                    }
                }
                
                std::lock_guard<std::mutex> l4(mutex_safe_percentages_);
                
                auto it4 = safe_percentages_.begin();
                
                while (it4 != safe_percentages_.end())
                {
                    if (std::time(0) - it4->second > interval_six_blocks)
                    {
                        it4 = safe_percentages_.erase(it4);
                    }
                    else
                    {
                        ++it4;
                    }
                }
            }
            
            /**
             * Prints
             */
            print();
            
            /**
             * Print
             */
            zerotime::instance().print();

            /**
             * Start the timer.
             */
            do_tick(60);
        }
    }));
}

void zerotime_manager::do_tick_probe(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_probe_.expires_from_now(std::chrono::milliseconds(interval));
    timer_probe_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (globals::instance().is_zerotime_enabled())
            {
                std::lock_guard<std::mutex> l1(
                    mutex_question_queue_tcp_endpoints_
                );
                
                auto it1 = question_queue_tcp_endpoints_.begin();
                
                while (it1 != question_queue_tcp_endpoints_.end())
                {
                    /**
                     * If enough time has elapsed for a block to have been
                     * solved or there are no endpoints remaining erase the
                     * transaction hash and associated endpoints.
                     */
                    if (
                        std::time(0) - it1->second.first >
                        interval_six_blocks || it1->second.second.size() == 0
                        )
                    {
                        it1 = question_queue_tcp_endpoints_.erase(it1);
                    }
                    else
                    {
                        ++it1;
                    }
                }

                /**
                 * Probe each transaction hashes topmost endpoint and remove
                 * it adding to questioned TCP endpoints.
                 */
                
                std::lock_guard<std::mutex> l2(
                    mutex_questioned_tcp_endpoints_
                );
                
                for (auto & i : question_queue_tcp_endpoints_)
                {
                    if (i.second.second.size() > 0)
                    {
                        const auto & hash_tx = i.first;
                        
                        /**
                         * Get the endpoint at the front of the queue.
                         */
                        auto ep = *i.second.second.begin();
  
                        /**
                         * We are about to probe this endpoint with a question
                         * insert it into the questioned TCP endpoints.
                         */
                        questioned_tcp_endpoints_[hash_tx].first =
                            std::time(0)
                        ;
                        questioned_tcp_endpoints_[hash_tx].second.push_back(
                            ep
                        );
                        
                        /**
                         * Erase the front of the queue.
                         */
                        i.second.second.erase(i.second.second.begin());
                        
                        std::lock_guard<std::mutex> l3(mutex_questions_);
                        std::lock_guard<std::mutex> l4(
                            mutex_zerotime_answers_tcp_
                        );
                        
                        /**
                         * Make sure we have the question and have not yet
                         * received the required number of answers.
                         */
                        if (
                            questions_.count(hash_tx) > 0 &&
                            zerotime_answers_tcp_[hash_tx].second.size() <
                            globals::instance().zerotime_answers_minimum()
                            )
                        {
                            log_info(
                                "ZeroTime manager is questioning " << ep <<
                                " regarding transaction " <<
                                hash_tx.to_string().substr(0, 8) << "."
                            );
                            
                            /**
                             * Get the question.
                             */
                            const auto & ztquestion =
                                questions_[hash_tx].second
                            ;
                         
                            if (ztquestion)
                            {
                                assert(ztquestion->transactions_in().size());
                                
                                /**
                                 * Allocate tcp_transport.
                                 */
                                auto transport =
                                    std::make_shared<tcp_transport> (
                                    io_service_, strand_)
                                ;
                                
                                /**
                                 * Allocate the tcp_connection.
                                 */
                                auto connection =
                                    std::make_shared<tcp_connection> (
                                    io_service_, stack_impl_,
                                    tcp_connection::direction_outgoing,
                                    transport
                                );
                    
                                /**
                                 * Inform the address_manager.
                                 */
                                stack_impl_.get_address_manager(
                                    )->on_connection_attempt(
                                    protocol::network_address_t::from_endpoint(
                                    ep), std::time(0) - (20 * 60)
                                );
                                
                                /**
                                 * Set that this is a one-shot ztquestion
                                 * connection.
                                 */
                                connection->set_oneshot_ztquestion(ztquestion);
                                
                                /**
                                 * Start the tcp_connection.
                                 */
                                connection->start(ep);
                            }
                        }
                    }
                }
            }
            
            if (question_queue_tcp_endpoints_.size() > 0)
            {
                /**
                 * Start the timer.
                 */
                do_tick_probe(interval_probe);
            }
        }
    }));
}

std::vector<std::int16_t> zerotime_manager::k_closest(
    const std::vector<std::int16_t> & vote_scores,
    const std::uint32_t & block_height, const std::uint32_t & k
    )
{
    std::vector<std::int16_t> ret;
    
    std::map<std::uint32_t, std::int16_t> entries;
    
    /**
     * Sort all votes by distance.
     */
    for (auto & i : vote_scores)
    {
        auto distance = block_height ^ i;

        entries.insert(std::make_pair(distance, i));
    }
    
    /**
     * Limit the number of votes to K.
     */
    for (auto & i : entries)
    {
        ret.push_back(i.second);
        
        if (ret.size() >= k)
        {
            break;
        }
    }
    
    return ret;
}
