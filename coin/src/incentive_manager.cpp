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

#include <coin/address.hpp>
#include <coin/database_stack.hpp>
#include <coin/destination.hpp>
#include <coin/globals.hpp>
#include <coin/incentive.hpp>
#include <coin/incentive_collaterals.hpp>
#include <coin/incentive_manager.hpp>
#include <coin/key.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/script.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/types.hpp>
#include <coin/wallet.hpp>

using namespace coin;

incentive_manager::incentive_manager(
    boost::asio::io_service & ios, boost::asio::strand & s,
    stack_impl & owner
    )
    : m_collateral_is_valid(false)
    , m_collateral_balance(0.0f)
    , m_collateralized_nodes(0)
    , io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
    , timer_check_inputs_(ios)
    , last_block_height_(0)
{
    // ...
}

void incentive_manager::start()
{
    if (globals::instance().is_incentive_enabled())
    {
        log_info("Incentive manager is starting.");
        
        /**
         * Start the timer.
         */
        do_tick(8);
        
        /**
         * Start the check inputs timer.
         */
        do_tick_check_inputs(12);
    }
}

void incentive_manager::stop()
{
    log_info("Incentive manager is stopping.");
    
    timer_.cancel();
    timer_check_inputs_.cancel();
}

bool incentive_manager::handle_message(
    const boost::asio::ip::tcp::endpoint & ep, message & msg
    )
{
    if (globals::instance().is_incentive_enabled())
    {
        std::lock_guard<std::mutex> l1(mutex_handle_message_);
        
        if (msg.header().command == "ivote")
        {
            /**
             * Get the incentive_vote.
             */
            auto ivote = msg.protocol_ivote().ivote;
            
            auto is_vote_valid = true;
            
            /**
             * Get the best block_index.
             */
            auto index_previous = stack_impl::get_block_index_best();
            
            /**
             * Get the next block height
             */
            auto height = index_previous ? index_previous->height() + 1 : 0;
        
            /**
             * Check that the ivote is not negative.
             */
            if (ivote->score() < 0)
            {
                is_vote_valid = false;
            }

            /**
             * Check that the block height is close to ours (within two
             * blocks).
             * @note This (if) should never be reached since it is performed
             * by TCP and UDP however let's be safe since origins may change.
             */
            if (
                ivote->block_height() + 2 < height &&
                static_cast<std::int32_t> (height) - ivote->block_height() > 2
                )
            {
                is_vote_valid = false;
                
                log_debug(
                    "Incentive manager is dropping old vote " <<
                    ivote->block_height() + 2 <<
                    ", diff = " << static_cast<std::int32_t> (height) -
                    ivote->block_height() + 2 << "."
                );
            }
            
            /**
             * Check the collateral.
             * @note We perform this at the TCP and UDP level but just in
             * case a message origin is something else we do it here too.
             */
            if (validate_collateral(*ivote) == false)
            {
                is_vote_valid = false;
                
                log_info(
                    "Incentive manager is dropping vote, invalid collateral "
                    "for " << ivote->address().substr(0, 8) << "."
                );
            }
        
            if (is_vote_valid)
            {
                log_debug(
                    "Incentive manager got vote for " <<
                    ivote->block_height() + 2 << ":" <<
                    ivote->address().substr(0, 8) <<
                    ", score = " << ivote->score() << "."
                );
                
                std::lock_guard<std::mutex> l1(mutex_votes_);
                
                votes_[ivote->block_height() + 2][ivote->address()].push_back(
                    *ivote
                );

                auto incentive_votes = votes_[ivote->block_height() + 2];
                
                std::stringstream ss;
                
                ss << "votes:\n";
                
                /**
                 * The number of votes required to qualify.
                 */
                enum { minimum_votes = 8 };
                
                auto index = 0;
                
                std::size_t most_votes = 0;
                
                std::string winner;
                
                for (auto & i : incentive_votes)
                {
                    ++index;
                    
                    if (i.second.size() > most_votes)
                    {
                        most_votes = i.second.size();
                        
                        winner = i.first;
                    }
                    
                    /**
                     * We maintain a list of all runner's up.
                     */
                    if (i.second.size() >= minimum_votes)
                    {
                        /**
                         * Insert this winner as a runner up.
                         */
                        incentive::instance().runners_up()[
                            ivote->block_height() + 2
                        ].insert(i.first);
                    }
                    
                    ss <<
                        "\t" << index << ". " <<
                        i.first.substr(0, 8) << ":" <<
                        i.second.size() << "\n"
                    ;
                }

                if (
                    incentive::instance().runners_up().count(
                    ivote->block_height() + 2) > 0
                    )
                {
                    log_debug(
                        "Incentive manager got runner up " <<
                        ivote->block_height() + 2 <<
                        ":" << incentive::instance().runners_up()[
                        ivote->block_height() + 2].size() << "."
                    );
                }
                
                log_debug(ss.str());

                /**
                 * Check if they won.
                 */
                if (most_votes >= minimum_votes)
                {
                    log_debug(
                        "Incentive manager got winner " <<
                        winner.substr(0, 8) << " for block " <<
                        ivote->block_height() + 2 << "."
                    );
                
                    /**
                     * Set the winner so far, as votes are counted the winner
                     * could change.
                     */
                    incentive::instance().winners()[
                        ivote->block_height() + 2].first = std::time(0)
                    ;
                    incentive::instance().winners()[
                        ivote->block_height() + 2].second = winner
                    ;
                }

                ss.clear();
                
                ss << "all votes:\n";
                
                for (auto & i : votes_)
                {
                    for (auto & j : i.second)
                    {
                        std::string addr;
                        
                        auto votes = 0;
                    
                        addr = j.first.substr(0, 8);
                        votes += j.second.size();
                        
                        ss <<
                            "\t" << i.first << ". " << addr << ":" <<
                            votes << "\n"
                        ;
                    }
                }
                
                log_debug(ss.str());
            }
            else
            {
                log_none("Incentive manager is dropping invalid vote.");
            }
        }
        else if (msg.header().command == "icols")
        {
            /**
             * Get the incentive_collaterals.
             */
            auto icols = msg.protocol_icols().icols;
            
            if (icols)
            {
                std::lock_guard<std::mutex> l1(mutex_collaterals_);
                
                for (auto & i : icols->collaterals())
                {
                    /**
                     * Skip nodes older than ours.
                     */
                    if (i.protocol_version < protocol::version)
                    {
                        continue;
                    }
                    
                    /**
                     * @note We do not need to validate that the wallet address
                     * and public key belong to the tx_in because of the
                     * probing process.
                     */
                    
                    /**
                     * Check that the coins are not spent by
                     * forming a transaction to ourselves and
                     * checking it's validity.
                     */
                    address addr(
                        incentive::instance().get_key(
                        ).get_public_key().get_id()
                    );

                    script script_collateral;
                    
                    script_collateral.set_destination(
                        addr.get()
                    );

                    transaction tx;
                    
                    auto index_previous =
                        stack_impl::get_block_index_best()
                    ;
                    
                    /**
                     * Get the collateral.
                     */
                    auto collateral =
                        incentive::instance().get_collateral(
                        index_previous ?
                        index_previous->height() + 1 : 0)
                    ;

                    transaction_out vout = transaction_out(
                        collateral * constants::coin,
                        script_collateral
                    );
                    tx.transactions_in().push_back(i.tx_in);
                    tx.transactions_out().push_back(vout);

                    try
                    {
                        if (
                            transaction_pool::instance(
                            ).acceptable(tx).first == true
                            )
                        {
                            log_debug(
                                "Incentive manager validated isync "
                                "collateral " << i.wallet_address << "."
                            );
                            
                            /**
                             * Set the time in the random past so we probe this
                             * node soon.
                             */
                            collaterals_[
                                i.wallet_address].first =
                                std::time(0) - (std::rand() % (60 * 60))
                            ;
                            collaterals_[
                                i.wallet_address].second =
                                static_cast<std::uint32_t> (
                                collateral)
                            ;
                        }
                    }
                    catch (...)
                    {
                        // ...
                    }
                }
            }
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
    
    return true;
}

const double & incentive_manager::collateral_balance() const
{
    return m_collateral_balance;
}

const std::uint32_t & incentive_manager::collateralized_nodes() const
{
    return m_collateralized_nodes;
}

bool incentive_manager::validate_collateral(const incentive_vote & ivote)
{
    auto ret = true;
    
    /**
     * Get the best block_index.
     */
    auto index_previous = stack_impl::get_block_index_best();
    
    /**
     * Get the next block height
     */
    auto height = index_previous ? index_previous->height() + 1 : 0;
    
    /**
     * Get the collateral.
     */
    auto collateral = incentive::instance().get_collateral(height);
    
    if (collateral > 0)
    {
        std::lock_guard<std::mutex> l1(mutex_collaterals_);
        
        if (
            collaterals_.count(ivote.address()) > 0
            )
        {
            ret =
                collaterals_[ivote.address()].second >= collateral
            ;
        }
        else
        {
            ret = false;
        }
    }
    
    return ret;
}

std::shared_ptr<incentive_collaterals>
    incentive_manager::get_incentive_collaterals(
    const std::set<std::string> & filter,
    const std::size_t & maximum_collaterals
    )
{
    auto ret = std::make_shared<incentive_collaterals> ();
    
    /**
     * Get the recent good endpoints.
     */
    auto recent_good_endpoints =
        stack_impl_.get_address_manager()->recent_good_endpoints()
    ;
    
    for (auto & i : collaterals_)
    {
        /**
         * Iterate the recent good endpoints looking for a matching wallet
         * address that is not in the filter. If it is not found in the filter
         * and we are below the maximum_collaterals insert it into the
         * incentive_collaterals collaterals.
         */
        for (auto & j : recent_good_endpoints)
        {
            const auto & wallet_address = i.first;
            
            /**
             * If the filter contains the wallet address skip it.
             */
            if (
                wallet_address == j.wallet_address &&
                filter.count(wallet_address) == 0
                )
            {
                if (ret)
                {
                    ret->collaterals().insert(j);
                    
                    if (ret->collaterals().size() >= maximum_collaterals)
                    {
                        return ret;
                    }
                }
                
                break;
            }
        }
    }
    
    return ret;
}

void incentive_manager::do_tick(const std::uint32_t & interval)
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
            if (globals::instance().is_incentive_enabled())
            {
                if (incentive::instance().get_key().is_null())
                {
                    log_debug("Incentive manager key is null, trying wallet.");
                    
                    if (globals::instance().wallet_main()->is_locked())
                    {
                        log_debug(
                            "Incentive manager wallet is locked, will try "
                            "again."
                        );
                    }
                    else
                    {
                        types::id_key_t key_id;
                        
                        address addr(globals::instance().wallet_main(
                            )->key_public_default().get_id()
                        );
                        
                        if (addr.get_id_key(key_id))
                        {
                            key k;
                        
                            if (
                                globals::instance().wallet_main()->get_key(
                                key_id, k)
                                )
                            {
                                log_info(
                                    "Incentive manager is setting key to " <<
                                    addr.to_string() << "."
                                );
                                
                                incentive::instance().set_key(k);
                            }
                        }
                        else
                        {
                            log_error("Incentive manager failed to get key.");
                        }
                    }
                }
                
                /**
                 * Get our best block height.
                 */
                auto block_height =
                    globals::instance().best_block_height()
                ;
            
                /**
                 * Get the block height to vote for.
                 */
                auto vote_block_height = block_height + 2;
                
                /**
                 * Remove winners older than N mins.
                 */
                auto it1 = incentive::instance().winners().begin();
                
                while (it1 != incentive::instance().winners().end())
                {
                    if (std::time(0) - it1->second.first > 20 * 60)
                    {
                        it1 =
                            incentive::instance().winners().erase(it1)
                        ;
                    }
                    else
                    {
                        ++it1;
                    }
                }
                
                /**
                 * Remove votes older than 4 blocks.
                 */
                auto it2 = incentive::instance().votes().begin();
                
                while (it2 != incentive::instance().votes().end())
                {
                    if (
                        vote_block_height -
                        it2->second.block_height() > 4
                        )
                    {
                        it2 = incentive::instance().votes().erase(it2);
                    }
                    else
                    {
                        ++it2;
                    }
                }
                
                /**
                 * Remove runners up older than 4 blocks.
                 */
                auto it3 = incentive::instance().runners_up().begin();
                
                while (it3 != incentive::instance().runners_up().end())
                {
                    if (
                        vote_block_height - it3->first > 4
                        )
                    {
                        it3 =
                            incentive::instance().runners_up(
                            ).erase(it3)
                        ;
                    }
                    else
                    {
                        ++it3;
                    }
                }
                
                /**
                 * Remove candidates older than N mins.
                 */
                std::lock_guard<std::mutex> l1(mutex_candidates_);
            
                auto it4 = candidates_.begin();
                
                while (it4 != candidates_.end())
                {
                    if (std::time(0) - it4->second.first > 20 * 60)
                    {
                        it4 = candidates_.erase(it4);
                    }
                    else
                    {
                        ++it4;
                    }
                }
                
                /**
                 * Remove votes older than 4 blocks.
                 */
                std::lock_guard<std::mutex> l2(mutex_votes_);
                
                auto it5 = votes_.begin();
                
                while (it5 != votes_.end())
                {
                    if (vote_block_height - it5->first > 4)
                    {
                        it5 = votes_.erase(it5);
                    }
                    else
                    {
                        ++it5;
                    }
                }
                
                /**
                 * Remove collaterals older than 3 hours.
                 */
                std::lock_guard<std::mutex> l3(mutex_collaterals_);
                
                auto it6 = collaterals_.begin();
                
                while (it6 != collaterals_.end())
                {
                    if (
                        std::time(0) - it6->second.first > (3 * 60 * 60)
                        )
                    {
                        it6 = collaterals_.erase(it6);
                    }
                    else
                    {
                        ++it6;
                    }
                }
                
                if (incentive::instance().get_key().is_null() == false)
                {
                    /**
                     * Check if the block height has changed.
                     */
                    if (block_height > last_block_height_)
                    {
                        last_block_height_ = block_height;
                        
                        /**
                         * Get the recent good endpoints.
                         */
                        auto recent_good_endpoints =
                            stack_impl_.get_address_manager(
                            )->recent_good_endpoints()
                        ;
      
                        /**
                         * Get the K closest nodes to the vote block height.
                         */
                        auto kclosest = k_closest(
                            recent_good_endpoints, vote_block_height
                        );
                        
                        /**
                         * Erase all nodes with protocol versions less than
                         * ours so that they no longer receive incentive
                         * rewards to encourage an up-to-date network backbone.
                         */
                        auto it = kclosest.begin();
                        
                        while (it != kclosest.end())
                        {
                            const address_manager::recent_endpoint_t &
                                recent = *it
                            ;
                            
                            if (recent.protocol_version < protocol::version)
                            {
                                it = kclosest.erase(it);
                            }
                            else
                            {
                                ++it;
                            }
                        }

                        /**
                         * The winner.
                         */
                        address_manager::recent_endpoint_t winner;
                        
                        /**
                         * Using the rate limit is not a network consensus
                         * and used for testing purposes only.
                         */
                        auto use_time_rate_limit = false;
                        
                        auto index_previous =
                            stack_impl::get_block_index_best()
                        ;
                        
                        /**
                         * Get the collateral.
                         */
                        auto collateral =
                            incentive::instance().get_collateral(
                            index_previous ? index_previous->height() + 1 : 0)
                        ;
            
                        /**
                         * If collateral is required then check each of the
                         * K closest.
                         */
                        if (collateral > 0)
                        {
                            auto it = kclosest.begin();
                            
                            while (it != kclosest.end())
                            {
                                const address_manager::recent_endpoint_t &
                                    recent = *it
                                ;
                                
                                auto need_to_check_collateral = false;

                                if (
                                    collaterals_.count(
                                    recent.wallet_address) > 0
                                    )
                                {
                                    if (
                                        std::time(0) - collaterals_[
                                        recent.wallet_address].first > 60 * 60
                                        )
                                    {
                                        need_to_check_collateral = true;
                                    }
                                }
                                else
                                {
                                    if (recent.wallet_address.size() > 0)
                                    {
                                        need_to_check_collateral = true;
                                    }
                                }
                                
                                if (need_to_check_collateral)
                                {
                                    /**
                                     * Check that the coins are not spent by
                                     * forming a transaction to ourselves and
                                     * checking it's validity.
                                     */
                                    address addr(
                                        incentive::instance().get_key(
                                        ).get_public_key().get_id()
                                    );

                                    script script_collateral;
                                    
                                    script_collateral.set_destination(
                                        addr.get()
                                    );

                                    transaction tx;
                                    
                                    auto index_previous =
                                        stack_impl::get_block_index_best()
                                    ;
                                    
                                    /**
                                     * Get the collateral.
                                     */
                                    auto collateral =
                                        incentive::instance().get_collateral(
                                        index_previous ?
                                        index_previous->height() + 1 : 0)
                                    ;
            
                                    transaction_out vout = transaction_out(
                                        collateral * constants::coin,
                                        script_collateral
                                    );
                                    tx.transactions_in().push_back(
                                        recent.tx_in
                                    );
                                    tx.transactions_out().push_back(vout);

                                    try
                                    {
                                        if (
                                            transaction_pool::instance(
                                            ).acceptable(tx).first == false
                                            )
                                        {
                                            log_debug(
                                                "Incentive manager detected "
                                                "invalid collateral for " <<
                                                recent.wallet_address.substr(
                                                0, 8) << ", ignoring."
                                            );
                                            
                                            collaterals_[
                                                recent.wallet_address].first =
                                                std::time(0)
                                            ;
                                            collaterals_[
                                                recent.wallet_address
                                                ].second = 0
                                            ;
                                            
                                            it = kclosest.erase(it);
                                        }
                                        else
                                        {
                                            log_debug(
                                                "Incentive manager detected "
                                                "valid collateral for " <<
                                                recent.wallet_address.substr(
                                                0, 8) << ", making candidate."
                                            );
                                            
                                            collaterals_[
                                                recent.wallet_address].first =
                                                std::time(0)
                                            ;
                                            collaterals_[
                                                recent.wallet_address].second =
                                                static_cast<std::uint32_t> (
                                                collateral)
                                            ;
                                            
                                            ++it;
                                        }
                                    }
                                    catch (std::exception & e)
                                    {
                                        log_debug(
                                            "Incentive manager detected "
                                            "invalid collateral for " <<
                                            recent.wallet_address.substr(
                                            0, 8) << ", ignoring, what = " <<
                                            e.what() << "."
                                        );
                                        
                                        collaterals_[
                                            recent.wallet_address].first =
                                            std::time(0)
                                        ;
                                        collaterals_[
                                            recent.wallet_address].second = 0
                                        ;
                                        
                                        it = kclosest.erase(it);
                                    }
                                }
                                else
                                {
                                    if (
                                        collaterals_[
                                        recent.wallet_address].second <
                                        collateral
                                        )
                                    {
                                        it = kclosest.erase(it);
                                    }
                                    else
                                    {
                                        ++it;
                                    }
                                }
                            }
                            
                            m_collateralized_nodes = collaterals_.size();
                            
                            log_info(
                                "Incentive manager has " <<
                                collaterals_.size() << " collateralised nodes."
                            );
                        }
                        
                        if (kclosest.size() >= 2)
                        {
                            log_debug(
                                "kclosest0: " << vote_block_height <<
                                ":" << kclosest[0].addr.ipv4_mapped_address(
                                ).to_string().substr(0, 8) <<
                                ":" << kclosest[0].addr.port
                            );
                            log_debug(
                                "kclosest1: " << vote_block_height <<
                                ":" << kclosest[1].addr.ipv4_mapped_address(
                                ).to_string().substr(0, 8) <<
                                ":" << kclosest[1].addr.port
                            );
                            
                            if ((vote_block_height & 1) == 0)
                            {
                                log_debug(
                                    "candidate: " << vote_block_height << ":" <<
                                    kclosest[0].addr.ipv4_mapped_address(
                                    ).to_string().substr(0, 8) <<
                                    ":" << kclosest[0].addr.port
                                );
                                
                                if (
                                    use_time_rate_limit ? std::time(0) -
                                    candidates_[kclosest[0]].first >
                                    1 * 60 * 60 : true
                                    )
                                {
                                    winner = kclosest[0];
                                }
                                else
                                {
                                    log_debug(
                                        "Candidate " <<
                                        kclosest[0].addr.ipv4_mapped_address(
                                        ).to_string().substr(0, 8) <<
                                        ":" << kclosest[0].addr.port <<
                                        " too soon."
                                    );
                                    
                                    /**
                                     * Try the other candidate otherwise for
                                     * the next closest node that we know has
                                     * not been a recent candidate.
                                     */
                                    if (
                                        use_time_rate_limit ?
                                        std::time(0) -
                                        candidates_[kclosest[1]].first >
                                        1 * 60 * 60 : true
                                        )
                                    {
                                        winner = kclosest[1];
                                    }
                                    else
                                    {
                                        /**
                                         * The top two were aready candidates
                                         * in the past hour, use the next
                                         * closest node that has not recently
                                         * been a candidate.
                                         */
                                        for (auto & i : kclosest)
                                        {
                                            if (
                                                candidates_.count(i) > 0
                                                && (use_time_rate_limit ?
                                                std::time(0) -
                                                candidates_[i].first >
                                                1 * 60 * 60 : true)
                                                )
                                            {
                                                winner = i;
                                                
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                log_debug(
                                    "candidate: " << vote_block_height << ":" <<
                                    kclosest[1].addr.ipv4_mapped_address(
                                    ).to_string().substr(0, 8) <<
                                    ":" << kclosest[1].addr.port
                                );
                                
                                if (
                                    use_time_rate_limit ? std::time(0) -
                                    candidates_[kclosest[1]].first >
                                    1 * 60 * 60 : true
                                    )
                                {
                                    winner = kclosest[1];
                                }
                                else
                                {
                                    log_debug(
                                        "Candidate " <<
                                        kclosest[1
                                        ].addr.ipv4_mapped_address(
                                        ).to_string().substr(0, 8) << ":" <<
                                        kclosest[1].addr.port << " too soon."
                                    );
                                    
                                    /**
                                     * Try the other candidate otherwise for
                                     * the next closest node that we know has
                                     * not been a recent candidate.
                                     */
                                    if (
                                        use_time_rate_limit ?
                                        std::time(0) -
                                        candidates_[kclosest[0]].first >
                                        1 * 60 * 60 : true
                                        )
                                    {
                                        winner = kclosest[0];
                                    }
                                    else
                                    {
                                        /**
                                         * The top two were aready candidates
                                         * in the past hour, use the next
                                         * closest node that has not recently
                                         * been a candidate.
                                         */
                                        for (auto & i : kclosest)
                                        {
                                            if (
                                                candidates_.count(i) > 0
                                                && (use_time_rate_limit ?
                                                std::time(0) -
                                                candidates_[i].first >
                                                1 * 60 * 60 : true)
                                                )
                                            {
                                                winner = i;
                                                
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            
                            std::stringstream ss;
                            
                            ss << "candidate_stats:\n";
                            
                            auto index = 0;
                            auto sum = 0;
                            
                            for (auto & i : candidates_)
                            {
                                ss <<
                                    "\t" << ++index << ". " <<
                                    i.first.addr.ipv4_mapped_address(
                                    ).to_string().substr(0, 8) << ":" <<
                                    i.first.addr.port << ":" <<
                                    i.first.wallet_address.substr(0, 8
                                    ) << ":" << i.second.second << "\n"
                                ;
                                
                                sum += i.second.second;
                            }
                            
                            log_debug(ss.str());
                            log_debug("sum of all candidates = " << sum);

                            if (winner.wallet_address.size() > 0)
                            {
                                /**
                                 * Cast vote.
                                 */
                                vote(winner.wallet_address);

                                candidates_[winner].first =
                                    std::time(0)
                                ;
                                candidates_[winner].second++;
                            }
                        }
                    }
                }

                /**
                 * Start the timer.
                 */
                do_tick(4);
            }
        }
    }));
}

void incentive_manager::do_tick_check_inputs(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_check_inputs_.expires_from_now(std::chrono::seconds(interval));
    timer_check_inputs_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            auto index_previous = stack_impl::get_block_index_best();
            
            /**
             * Get the collateral.
             */
            auto collateral =
                incentive::instance().get_collateral(
                index_previous ?
                index_previous->height() + 1 : 0)
            ;
            
            if (collateral > 0)
            {
                if (incentive::instance().get_key().is_null() == false)
                {
                    /**
                     * Check that the collateral is valid.
                     */
                    try
                    {
                        address addr(
                            incentive::instance().get_key(
                            ).get_public_key().get_id()
                        );

                        script script_collateral;
                        
                        script_collateral.set_destination(addr.get());

                        transaction tx;
                        
                        transaction_out vout = transaction_out(
                            collateral * constants::coin,
                            script_collateral
                        );
                        tx.transactions_in().push_back(
                            incentive::instance().get_transaction_in()
                        );
                        tx.transactions_out().push_back(vout);

                        if (
                            transaction_pool::instance().acceptable(
                            tx).first == false
                            )
                        {
                            log_error(
                                "Incentive manager detected spent "
                                "collateral, will keep looking."
                            );
                            
                            m_collateral_balance = 0.0f;
                            
                            m_collateral_is_valid = false;
                        }
                        else
                        {
                            log_info(
                                "Incentive manager detected valid "
                                "collateral."
                            );
                            
                            m_collateral_is_valid = true;
                        }
                    }
                    catch (std::exception & e)
                    {
                        log_debug(
                            "Incentive manager detected invalid collateral, "
                            "what = " << e.what() << "."
                        );
                        
                        m_collateral_balance = 0.0f;
                        
                        m_collateral_is_valid = false;
                    }
                    
                    /**
                     * If the collateral is not valid let's try to find some.
                     */
                    if (m_collateral_is_valid == false)
                    {
                        /**
                         * Get candidate coins.
                         */
                        auto coins = select_coins();
                        
                        /**
                         * Allocate the transaction_in.
                         */
                        transaction_in tx_in;

                        /**
                         * Get the incentive public key.
                         */
                        auto public_key =
                            incentive::instance().get_key().get_public_key()
                        ;

                        /**
                         * Check the coins for valid collateral stopping at
                         * the first valid input.
                         */
                        for (auto & i : coins)
                        {
                            auto * output_ptr = &i;
                            
                            if (output_ptr)
                            {
                                if (
                                    tx_in_from_output(*output_ptr, tx_in,
                                    public_key, incentive::instance().get_key())
                                    )
                                {
                                    log_debug(
                                        "Incentive manager got tx_in = " <<
                                        tx_in.to_string() << "."
                                    );

                                    /**
                                     * Check if the collateral is spendable.
                                     */
                                    address addr(
                                        incentive::instance().get_key(
                                        ).get_public_key().get_id()
                                    );

                                    script script_collateral;
                                    
                                    script_collateral.set_destination(
                                        addr.get()
                                    );

                                    transaction tx;
                                    
                                    transaction_out tx_out = transaction_out(
                                        collateral * constants::coin,
                                        script_collateral
                                    );
                                    tx.transactions_in().push_back(tx_in);
                                    tx.transactions_out().push_back(tx_out);
                    
                                    if (
                                        transaction_pool::instance(
                                        ).acceptable(tx).first
                                        )
                                    {
                                        log_info(
                                            "Incentive manager found valid "
                                            "collateral input " <<
                                            tx_in.to_string() << "."
                                        );

                                        incentive::instance(
                                            ).set_transaction_in(tx_in
                                        );

                                        m_collateral_balance =
                                           static_cast<double> (
                                           i.get_transaction_wallet(
                                           ).transactions_out()[i.get_i()
                                           ].value()) / constants::coin
                                        ;
                                        
                                        log_info(
                                            "Incentive manager found "
                                            "collateral balance " <<
                                            m_collateral_balance << "."
                                        );
                                        
                                        m_collateral_is_valid = true;
                                        
                                        break;
                                    }
                                    else
                                    {
                                        log_info(
                                            "Incentive manager found invalid "
                                            "collateral input, checking more."
                                        );
                                        
                                        incentive::instance(
                                            ).set_transaction_in(
                                            transaction_in()
                                        );
                                        
                                        m_collateral_balance = 0.0f;
                                        
                                        m_collateral_is_valid = false;
                                    }
                                }
                                else
                                {
                                    log_error(
                                        "Incentive manager failed to "
                                        "tx_in_from_output."
                                    );
                                    
                                    incentive::instance().set_transaction_in(
                                        transaction_in()
                                    );
                                    
                                    m_collateral_balance = 0.0f;
                                    
                                    m_collateral_is_valid = false;
                                }
                            }
                        }
                    }
                }
                else
                {
                    log_error(
                        "Incentive manager failed to find collateral input, "
                        "wallet is locked."
                    );
                }
                
                /**
                 * Start the check inputs timer.
                 */
                do_tick_check_inputs(10 * 60);
            }
        }
    }));
}

bool incentive_manager::vote(const std::string & wallet_address)
{
    /**
     * Get the best block index.
     */
    auto index =
        utility::find_block_index_by_height(
        globals::instance().best_block_height()
    );

    if (index && incentive::instance().get_key().is_null() == false)
    {
        /**
         * Allocate the data_buffer.
         */
        data_buffer buffer;
        
        /**
         * Allocate the incentive_vote.
         */
        incentive_vote ivote(
            index->height(),
            index->get_block_hash(), wallet_address,
            incentive::instance().get_key(
            ).get_public_key()
        );
        
        /**
         * Encode the incentive_vote.
         */
        ivote.encode(buffer);

        /**
         * Calulate our vote score.
         */
        const auto & vote_score = ivote.score();
        
        log_info(
            "Incentve manager forming vote, "
            "calculated score = " << vote_score <<
            " for " <<
            ivote.address().substr(0, 8) << "."
        );
        
        /**
         * If our vote score is at least zero we
         * can vote otherwise peers will reject it.
         */
        if (
            vote_score > -1 &&
            vote_score <= std::numeric_limits<std::int16_t>::max() / 4
            )
        {
            if (utility::is_initial_block_download() == false)
            {
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_ivote, ivote.hash_nonce()
                );
                
                /**
                 * Insert the incentive_vote.
                 */
                incentive::instance().votes()[ivote.hash_nonce()] = ivote;

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
        else
        {
            return false;
        }
    }
    
    return true;
}

std::vector<address_manager::recent_endpoint_t> incentive_manager::k_closest(
    const std::vector<address_manager::recent_endpoint_t> & nodes,
    const std::uint32_t & block_height, const std::uint32_t & k
    )
{
    std::vector<address_manager::recent_endpoint_t> ret;
    
    std::map<std::uint32_t, address_manager::recent_endpoint_t> entries;
    
    /**
     * Sort all nodes by distance.
     */
    for (auto & i : nodes)
    {
        if (
            i.addr.ipv4_mapped_address().is_loopback() ||
            i.addr.ipv4_mapped_address().is_multicast() ||
            i.addr.ipv4_mapped_address().is_unspecified())
        {
            continue;
        }
        else
        {
            auto distance =
                block_height ^ incentive::instance().calculate_score(
                boost::asio::ip::tcp::endpoint(i.addr.ipv4_mapped_address(),
                i.addr.port)
            );

            entries.insert(std::make_pair(distance, i));
        }
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

std::vector<output> incentive_manager::select_coins()
{
    std::vector<output> ret;
    
    std::vector<output> coins;
    
    /**
     * Do not use ZeroTime (we are not creating a transaction).
     */
    auto use_zerotime = false;
    
    /**
     * Do not filter any coin denominations.
     */
    std::set<std::int64_t> filter;

    globals::instance().wallet_main()->available_coins(
        coins, true, filter, 0, use_zerotime
    );

    auto index_previous = stack_impl::get_block_index_best();
    
    /**
     * Get the collateral.
     */
    auto collateral =
        incentive::instance().get_collateral(
        index_previous ?
        index_previous->height() + 1 : 0)
    ;
    
    for (auto & i : coins)
    {
        if (
            i.get_transaction_wallet().transactions_out()[
            i.get_i()].value() >= collateral * constants::coin
            )
        {
            log_info(
                "Incentive manager found candidate " <<
                i.get_transaction_wallet().transactions_out()[
                i.get_i()].value() /  constants::coin << " for collateral."
            );
            
            ret.push_back(i);
        }
    }
    
    return ret;
}

bool incentive_manager::tx_in_from_output(
    const output & out, transaction_in & tx_in, key_public & public_key,
    key & k
    )
{
    tx_in =
        transaction_in(out.get_transaction_wallet().get_hash(), out.get_i())
    ;
    
    auto script_public_key =
        out.get_transaction_wallet().transactions_out()[
        out.get_i()].script_public_key()
    ;

    destination::tx_t dest_tx;

    if (script::extract_destination(script_public_key, dest_tx) == false)
    {
        log_error(
            "Incentive manager failed to get tx_in, unable to extract "
            "destination."
        );
        
        return false;
    }
    
    address addr(dest_tx);

    /**
     * The coins must be in the default wallet address.
     */
    if (
        address(incentive::instance().get_key().get_public_key(
        ).get_id()).to_string() != addr.to_string()
        )
    {
        log_error(
            "Incentive manager failed to get tx_in, address is not "
            "the default."
        );
        
        return false;
    }

    types::id_key_t key_id;
    
    if (addr.get_id_key(key_id) == false)
    {
        log_error(
            "Incentive manager failed to get tx_in, address does not "
            "match key."
        );
        
        return false;
    }

    if (globals::instance().wallet_main()->get_key(key_id, k) == false)
    {
        log_error(
            "Incentive manager failed to get tx_in, unknown private key."
        );
        
        return false;
    }

    public_key = k.get_public_key();

    return true;
}
