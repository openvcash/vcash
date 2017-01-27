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
#include <cassert>

#include <boost/algorithm/string.hpp>
#include <boost/timer.hpp>

#include <database/block.hpp>
#include <database/constants.hpp>
#include <database/logger.hpp>
#include <database/node_impl.hpp>
#include <database/query.hpp>
#include <database/routing_table.hpp>
#include <database/utility.hpp>

using namespace database;

routing_table::routing_table(
    boost::asio::io_service & ios, std::shared_ptr<node_impl> impl
    )
    : m_state(state_none)
    , io_service_(ios)
    , strand_(ios)
    , timer_(ios)
    , statistics_timer_(ios)
    , node_impl_(impl)
    , slot_index_(0)
    , block_index_(std::rand() % ((slot::length / 8 ) - 1))
    , ping_queue_timer_(ios)
    , pings_sent_(0)
    , random_find_timer_(ios)
    , random_find_index_(0)
    , random_find_iterations_(0)
{
    // ...
}

void routing_table::start()
{
    m_state = state_starting;
    
    /**
     * Allocate the blocks.
     */
    std::uint16_t block_index = 0;
    
    for (auto & i : m_blocks)
    {
        log_none("Routing table is allocating block " << block_index << ".");
        
        /**
         * Allocate the block.
         */
        i.reset(new block(io_service_, node_impl_.lock(), block_index));
        
        /**
         * Increment the index.
         */
        block_index++;
    }
    
    /**
     * Start the blocks.
     */
    for (auto & i : m_blocks)
    {
        i->start();
    }
    
    /**
     * Start the timer.
     */
    timer_.expires_from_now(std::chrono::seconds(8));
    timer_.async_wait(
        strand_.wrap(std::bind(&routing_table::tick, shared_from_this(),
        std::placeholders::_1))
    );
    
    /**
     * Start statistics timer.
     */
    statistics_timer_.expires_from_now(std::chrono::seconds(8));
    statistics_timer_.async_wait(
        strand_.wrap(std::bind(&routing_table::statistics_tick,
        shared_from_this(), std::placeholders::_1))
    );

    /**
     * Start the ping queue timer.
     */
    ping_queue_timer_.expires_from_now(std::chrono::milliseconds(5));
    ping_queue_timer_.async_wait(
        strand_.wrap(std::bind(&routing_table::ping_queue_tick,
        shared_from_this(), std::placeholders::_1))
    );

    /**
     * Calculate the random find index.
     */
    random_find_index_ = std::rand() % (slot::length - 1);
    
    /**
     * Start the random find timer.
     */
    random_find_timer_.expires_from_now(std::chrono::seconds(8));
    random_find_timer_.async_wait(
        strand_.wrap(std::bind(&routing_table::random_find_tick,
        shared_from_this(), std::placeholders::_1))
    );
    
    m_state = state_started;
}

void routing_table::stop()
{
    m_state = state_stopping;
    
    /**
     * Cancel the timer.
     */
    timer_.cancel();
    
    /**
     * Cancel the statistics timer.
     */
    statistics_timer_.cancel();
    
    /**
     * Cancel the ping queue timer.
     */
    ping_queue_timer_.cancel();
    
    /**
     * Cancel the random find timer.
     */
    random_find_timer_.cancel();
    
    /**
     * Stop the blocks.
     */
    for (auto & i : m_blocks)
    {
        i->stop();
    }
    
    m_state = state_stopped;
}

void routing_table::update(
    const boost::asio::ip::udp::endpoint & ep,
    const std::uint16_t & transaction_id
    )
{
    /**
     * Get the slot id for the endpoint.
     */
    std::int16_t slot_id = slot::id_from_endpoint(ep);

    /**
     * Determine which block the endpoint belongs to.
     */
    std::int16_t block_index = slot_id / 8;

    log_none("Routing table updating block " << block_index << ".");
    
    /**
     * Update the block.
     */
    m_blocks[block_index]->update(ep, transaction_id);
}

void routing_table::update_statistics(
    const boost::asio::ip::udp::endpoint & ep,
    const message::attribute_uint32 & attr
    )
{
    /**
     * Get the slot id for the endpoint.
     */
    std::int16_t slot_id = slot::id_from_endpoint(ep);

    /**
     * Determine which block the endpoint belongs to.
     */
    std::int16_t block_index = slot_id / 8;

    log_none("Routing table updating (statistics) block " << block_index << ".");
    
    /**
     * Update the block.
     */
    m_blocks[block_index]->update_statistics(ep, attr);
}

const std::array< std::shared_ptr<block>, slot::length / 8> &
    routing_table::blocks() const
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    return m_blocks;
}

std::set<storage_node> routing_table::storage_nodes()
{
    std::set<storage_node> ret;

    for (auto & i : m_blocks)
    {
        for (auto & j : i->slots())
        {
            for (auto & k : j->storage_nodes())
            {
                ret.insert(k);
            }
        }
    }
    
    return ret;
}

std::set<boost::asio::ip::udp::endpoint> routing_table::storage_nodes(
    const std::uint32_t & limit
    )
{
    std::set<boost::asio::ip::udp::endpoint> ret;
    
    if (limit == 0)
    {
        for (auto & i : m_blocks)
        {
            for (auto & j : i->slots())
            {
                for (auto & k : j->storage_nodes())
                {
                    ret.insert(k.endpoint);
                }
            }
        }
    }
    else
    {
        std::vector<boost::asio::ip::udp::endpoint> random;
        
        for (auto & i : m_blocks)
        {
            for (auto & j : i->slots())
            {
                for (auto & k : j->storage_nodes())
                {
                    random.push_back(k.endpoint);
                }
            }
        }
        
        std::random_shuffle(random.begin(), random.end());
        
        if (random.size() > limit)
        {
            random.resize(limit);
        }
        
        ret.insert(random.begin(), random.end());
    }
    
    return ret;
}

std::vector<storage_node> routing_table::random_storage_nodes(
    const std::uint32_t & limit
    )
{
    std::vector<storage_node> ret;
    
    for (auto & i : m_blocks)
    {
        for (auto & j : i->slots())
        {
            for (auto & k : j->storage_nodes())
            {
                ret.push_back(k);
            }
        }
    }
    
    std::random_shuffle(ret.begin(), ret.end());
    
    if (ret.size() > limit)
    {
        ret.resize(limit);
    }
    
    return ret;
}

std::set<boost::asio::ip::udp::endpoint> routing_table::storage_nodes_for_query(
    const std::string & query_string, const std::size_t & snodes_per_keyword
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    std::set<boost::asio::ip::udp::endpoint> ret;
    
    auto slot_ids = slot_ids_for_query(query_string);

    /**
     * Return a number of storage nodes.
     */
    auto snodes_count = snodes_per_keyword * slot_ids.size();

    for (auto & i : slot_ids)
    {
        /**
         * The current index of storage nodes inserted for the current slot id.
         */
        std::size_t snodes_index = 0;
        
        /**
         * Determine the slot id.
         */
        std::int16_t slot_id = i;
        
        /**
         * Determine the block the slot resides.
         */
        std::uint16_t block_index = slot_id / 8;
        
        if (slot_id < 0)
        {
            log_error("Routing table got invalid slot id " << slot_id << ".");
            
            continue;
        }
        else
        {
            log_none(
                "Routing table determined block index " << block_index <<
                " belongs to slot#" << slot_id << "."
            );

            auto slots = m_blocks[block_index]->slots();
            
            for (auto & j : slots)
            {
                auto k = j->storage_nodes();
                
                /**
                 * Allow empty slots (operations need the slot id's from them).
                 */
                if (j->id() == slot_id)
                {
                    for (auto & l : k)
                    {
                        ret.insert(l.endpoint);
                    }

                    snodes_index++;
                }
                
                if (
                    ret.size() >= snodes_count ||
                    snodes_index >= constants::snodes_per_keyword
                    )
                {
                    break;
                }
            }
        }
        
        if (ret.size() >= snodes_count)
        {
            break;
        }
    }

    /**
     * If we did not get enough storage nodes from the slot add some from the
     * responsible block.
     */
    if (ret.size() < snodes_count)
    {
        for (auto & i : slot_ids)
        {
            /**
             * The current index of storage nodes inserted for the current
             * slot id.
             */
            std::size_t snodes_index = 0;
            
            /**
             * Determine the block the slot resides.
             */
            std::uint16_t block_index = i / 8;
  
            if (i < 0)
            {
                log_error("Routing table got invalid slot id " << i << ".");
                
                continue;
            }
            else
            {
                auto slots = m_blocks[block_index]->slots();
                
                for (auto & j : slots)
                {
                    auto k = j->storage_nodes();
 
                    for (auto & l : k)
                    {
                        ret.insert(l.endpoint);
                    }

                    snodes_index++;
                    
                    if (
                        ret.size() >= snodes_count ||
                        snodes_index >= constants::snodes_per_keyword
                        )
                    {
                        break;
                    }
                }
            }
            
            if (ret.size() >= snodes_count)
            {
                break;
            }
        }
    }
    
    return ret;
}

std::set<boost::asio::ip::udp::endpoint>
    routing_table::random_storage_node_from_each_slot()
{
    std::set<boost::asio::ip::udp::endpoint> ret;
    
    for (auto & i : m_blocks)
    {
        for (auto & j : i->slots())
        {
            auto snodes = j->storage_nodes();
            
            if (snodes.size() > 0)
            {
                auto index = snodes.size() == 1 ? 0 :
                    std::rand() % (snodes.size() - 1)
                ;

                /**
                 * Take a random storage node from this slot.
                 */
                ret.insert(snodes[index].endpoint);
            }
        }
    }
    
    if (ret.size() > slot::length)
    {
        assert("invalid number of storage nodes");
    }
    
    return ret;
}

std::set<boost::asio::ip::udp::endpoint>
    routing_table::random_storage_node_from_each_block()
{
    std::set<boost::asio::ip::udp::endpoint> ret;
    
    for (auto & i : m_blocks)
    {
        for (auto & j : i->slots())
        {
            auto snodes = j->storage_nodes();
            
            if (snodes.size() > 0)
            {
                auto index = snodes.size() == 1 ? 0 :
                    std::rand() % (snodes.size() - 1)
                ;

                /**
                 * Take a random storage node from this slot.
                 */
                ret.insert(snodes[index].endpoint);
                
                break;
            }
        }
    }
    
    if (ret.size() > slot::length / 8)
    {
        assert("invalid number of storage nodes");
    }
    
    return ret;
}

std::set<std::uint16_t> routing_table::slot_ids_for_query(
    const std::string & query_string
    )
{
    std::set<std::uint16_t> ret;
    
    /**
     * Allocate the query (using the lowercase representation).
     */
    query q(boost::algorithm::to_lower_copy(query_string));

    for (auto & i : q.pairs())
    {
        if (i.first.size() == 0 || i.second.size() == 0)
        {
            continue;
        }
        
        /**
         * Do not return slot id's for common internet terms.
         */
        if (
            utility::string::starts_with(i.first, "http") ||
            utility::string::starts_with(i.first, "https") ||
            utility::string::starts_with(i.first, "ftp") ||
            utility::string::starts_with(i.first, "gopher") ||
            utility::string::starts_with(i.first, "magnet")
            )
        {
            continue;
        }

        /**
         * Skip "internal" terms.
         */
        if (utility::string::starts_with(i.first, "_"))
        {
            continue;
        }

        /**
         * Calculate the slot id and save it.
         */
        ret.insert(slot::id(i.second));
    }
    
    return ret;
}

std::shared_ptr<slot> routing_table::slot_for_id(const std::uint16_t & slot_id)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    std::shared_ptr<slot> ret;
    
    /**
     * Determine the block the slot resides.
     */
    std::uint16_t block_index = slot_id / 8;
    
    /**
     * Get all slots in the block.
     */
    auto slots = m_blocks[block_index]->slots();
    
    /**
     * Find the slot matching the slot id.
     */
    for (auto & i : slots)
    {
        if (i->id() == slot_id)
        {
            ret = i;
            
            break;
        }
    }
    
    return ret;
}

std::vector< std::shared_ptr<slot> > routing_table::slots_for_id(
    const std::uint16_t & slot_id
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    std::vector< std::shared_ptr<slot> > ret;
    
    /**
     * Return a number of storage nodes.
     */
    auto snodes_count = block::slot_length;
    
    /**
     * The number of storage nodes we've collected.
     */
    auto snodes_current = 0;
    
    /**
     * Determine the block the slot resides.
     */
    std::uint16_t block_index = slot_id / 8;
    
    if (slot_id < 0)
    {
        log_error("Routing table got invalid slot id " << slot_id << ".");
        
        return ret;
    }
    else
    {
        log_none(
            "Routing table determined block index " << block_index <<
            " belongs to slot#" << slot_id << "."
        );
        
        auto slots = m_blocks[block_index]->slots();
        
        for (auto & j : slots)
        {
            auto k = j->storage_nodes();
            
            if (j->id() == slot_id && k.size() > 0)
            {
                ret.push_back(j);
                
                snodes_current += k.size();
                
                if (snodes_current >= snodes_count)
                {
                    break;
                }
            }
        }
    }

    /**
     * We didn't find enough storage nodes in the slot, use some from the same
     * block.
     */
    if (ret.size() < snodes_count)
    {
        /**
         * Send back storage nodes from the same block.
         */
        auto slots = m_blocks[block_index]->slots();
        
        for (auto & j : slots)
        {
            auto k = j->storage_nodes();
            
            if (k.size() > 0)
            {
                ret.push_back(j);
                
                snodes_current += k.size();
                
                if (snodes_current >= snodes_count)
                {
                    break;
                }
            }
        }
    }

    return ret;
}

void routing_table::handle_rpc_response(
    const std::uint16_t & operation_id,
    const std::uint16_t & transaction_id,
    const boost::asio::ip::udp::endpoint & ep
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    if (m_state == state_started)
    {
        /**
         * Get the slot id for the endpoint.
         */
        std::int32_t slot_id = slot::id_from_endpoint(ep);

        /**
         * Determine which block the endpoint belongs to.
         */
        std::int16_t block_index = slot_id / 8;
    
        /**
         * Inform the block.
         */
        m_blocks[block_index]->handle_response(
            operation_id, transaction_id, ep
        );
    }
}

void routing_table::handle_rpc_timeout( const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    if (m_state == state_started)
    {
        /**
         * Get the slot id for the endpoint.
         */
        std::int32_t slot_id = slot::id_from_endpoint(ep);

        /**
         * Determine which block the endpoint belongs to.
         */
        std::int16_t block_index = slot_id / 8;
    
        /**
         * Inform the block.
         */
        m_blocks[block_index]->handle_timeout(ep);
    }
}

void routing_table::queue_ping(
    const boost::asio::ip::udp::endpoint & ep, const bool & force_queue
    )
{
    std::lock_guard<std::recursive_mutex> l(ping_queue_mutex_);

    bool should_queue = false;

    /**
     * To force queue simply erase the ping queue time for the endpoint.
     */
    if (force_queue)
    {
        ping_queue_times_.erase(ep);
    }
    
    auto it = ping_queue_times_.find(ep);
    
    if (it == ping_queue_times_.end())
    {
        should_queue = true;
    }
    else
    {
        if ((std::time(0) - it->second) >= (slot::update_interval * 8))
        {
            should_queue = true;
        }
    }
    
    if (should_queue)
    {
        bool was_empty = ping_queue_.empty();
        
        /**
         * Queue the ping.
         */
        ping_queue_.insert(ep);

        if (was_empty)
        {
            /**
             * This allows us to get "some" storage nodes into the routing table
             * quickly while allowing others to be inserted over time.
             */
            if (pings_sent_ < slot::length)
            {
                /**
                 * Generate a random timeout.
                 */
                auto timeout = std::min(5, (std::rand() % 25));
                
                /**
                 * Start the ping queue timer.
                 */
                ping_queue_timer_.expires_from_now(
                    std::chrono::milliseconds(timeout)
                );
                ping_queue_timer_.async_wait(
                    strand_.wrap(std::bind(&routing_table::ping_queue_tick,
                    shared_from_this(), std::placeholders::_1))
                );
            }
            else
            {
                /**
                 * Generate a random timeout.
                 */
                auto timeout = std::max(60, (std::rand() % 1000));
                
                /**
                 * Start the ping queue timer.
                 */
                ping_queue_timer_.expires_from_now(
                    std::chrono::milliseconds(timeout)
                );
                ping_queue_timer_.async_wait(
                    strand_.wrap(std::bind(&routing_table::ping_queue_tick,
                    shared_from_this(), std::placeholders::_1))
                );
            }
        }
    }
}

int routing_table::run_test()
{
    std::set<std::uint16_t> block_indexes;
    std::set<std::uint16_t> slot_ids;
    
    std::srand(std::time(0));
    
    std::uint16_t i = 0;
    
    for (; ; i++)
    {
        boost::asio::ip::udp::endpoint ep(
            boost::asio::ip::address::from_string("127.0.0.1"),
            std::rand() % std::numeric_limits<std::uint16_t>::max()
        );

        /**
         * Determine which block the endpoint belongs to.
         */
        std::int16_t slot_id = slot::id_from_endpoint(ep);
        
        block_indexes.insert(slot_id / 8);
        slot_ids.insert(slot_id);
        
        if (slot_ids.size() >= slot::length)
        {
            break;
        }
    }
    
    log_debug(
        "i = " << i << ", block_indexes = " << block_indexes.size() <<
        ", slot_ids = " << slot_ids.size()
    );
    
    return 0;
}

void routing_table::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        if (auto n = node_impl_.lock())
        {
            if (
                n->config().operation_mode() ==
                stack::configuration::operation_mode_interface
                )
            {
                /**
                 * We keep the timer ticking in case we switch to
                 * operation_mode_storage.
                 */
                timer_.expires_from_now(std::chrono::seconds(60));
                timer_.async_wait(
                    strand_.wrap(std::bind(&routing_table::tick,
                    shared_from_this(),std::placeholders::_1))
                );
            }
            else
            {
                /**
                 * Every one seconds ping a storage node piggy backing other
                 * storage nodes.
                 */
                
                if (++slot_index_ >= block::slot_length)
                {
                    slot_index_ = 0;
                    
                    if (++block_index_ >= (slot::length / 8) - 1)
                    {
                        log_debug("Routing table completed iteration.")
                        
                        block_index_ = 0;
                    }
                }
                
                /**
                 * Get all of the storage nodes from "higher up around" the
                 * block index.
                 */
                std::vector<storage_node> snodes;

                /**
                 * Generate a random number of storage nodes to piggy back.
                 */
                auto snodes_length = std::max(
                    (std::size_t)(std::rand() % block::slot_length),
                    (std::size_t)(std::rand() % block::slot_length)
                );
                
                auto block_index = block_index_;
                
                for (auto i = 0; i < (slot::length / 8); i++)
                {
                    if ((block_index + i) >= (slot::length / 8) - 1)
                    {
                        block_index = 0;
                    }
                    
                    for (auto & j : m_blocks[block_index + i]->slots())
                    {
                        for (auto & k : j->storage_nodes())
                        {
                            snodes.push_back(k);
                            
                            if (snodes.size() >= snodes_length)
                            {
                                break;
                            }
                        }
                    
                        if (snodes.size() >= snodes_length)
                        {
                            break;
                        }
                    }
                    
                    if (snodes.size() >= snodes_length)
                    {
                        break;
                    }
                }
                
                /**
                 * Clamp size.
                 */
                if (snodes.size() > snodes_length)
                {
                    snodes.resize(snodes_length);
                }

                if (
                    m_blocks[block_index_]->slots()[
                    slot_index_]->storage_nodes().size() > 0
                    )
                {                    
                    /**
                     * Ping the least seen storage nodes of the slot in the 
                     * current block.
                     */
                    if (
                        m_blocks[block_index_]->slots()[slot_index_
                        ]->ping_least_seen(snodes)
                        )
                    {
                        log_debug(
                            "Routing table is sending " << snodes.size() <<
                            " storage nodes to least seen (slot #" <<
                            slot_index_ << ", block #" << block_index_ << ")."
                        );
                    }
                }
                else
                {
                    // ...
                }
                
                /**
                 * @note This SHOULD tick based on routing table fullness and
                 * MAY need to tick at intervals less than one second.
                 */
                timer_.expires_from_now(std::chrono::seconds(1));
                timer_.async_wait(
                    strand_.wrap(std::bind(&routing_table::tick,
                    shared_from_this(),std::placeholders::_1))
                );
            }
        }
    }
}

void routing_table::statistics_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
#if (! defined NDEBUG)
        std::uint32_t storage_nodes = 0;
        
        std::stringstream ss;
        
        ss << std::endl;
        ss << "--- Routing Table ---" << std::endl;
        ss << "------- Begin -------" << std::endl;
        
        for (auto & i1 : m_blocks)
        {
            ss << "\tBlock #" << i1->index() << std::endl;

            for (auto & i2 : i1->slots())
            {
                storage_nodes += i2->storage_nodes().size();
                
                if (i2->storage_nodes().empty())
                {
                    continue;
                }
                
                ss << "\t\tSlot #" << i2->id() << std::endl;
                ss << "\t\tStorage Nodes:\n";
                
                for (auto & i3 : i2->storage_nodes())
                {
                    auto last_update = std::chrono::duration_cast<
                        std::chrono::seconds
                    >(std::chrono::steady_clock::now() -
                    i3.last_update).count();
            
                    ss << "\t\t endoint:" << i3.endpoint << " uptime:" <<
                        std::time(0) - i3.uptime << " last_update:" <<
                        last_update <<
                        " timeouts:" << (std::uint32_t)i3.timeouts() <<
                        " rtt:" << i3.rtt <<
                        " stats_udp_bps_inbound:" << i3.stats_udp_bps_inbound <<
                        " stats_udp_bps_outbound:" << i3.stats_udp_bps_outbound <<
                    std::endl;
                }
            }
        }
    
        ss << "\tStorage Nodes Total: " << storage_nodes << std::endl;
        ss << "--- Routing Table ---" << std::endl;
        ss << "-------- End --------" << std::endl;
        
        log_debug(ss.str());
#endif // NDEBUG

        statistics_timer_.expires_from_now(std::chrono::seconds(60));
        statistics_timer_.async_wait(
            strand_.wrap(std::bind(&routing_table::statistics_tick,
            shared_from_this(), std::placeholders::_1))
        );
    }
}

void routing_table::ping_queue_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(ping_queue_mutex_);

        if (ping_queue_.size() > 0)
        {
            auto it = ping_queue_times_.find(*ping_queue_.begin());
        
            if (it == ping_queue_times_.end())
            {
                ping_queue_times_.insert(
                    std::make_pair(*ping_queue_.begin(), std::time(0))
                );
                
                if (auto i = node_impl_.lock())
                {
                    /**
                     * Increment the number of pings sent.
                     */
                    pings_sent_++;
                    
                    /**
                     * Generate a random number of storage nodes to piggy back.
                     */
                    auto snodes_length =
                        std::rand() % 2 == 1 ?
                        std::rand() % block::slot_length : 0
                    ;
                
                    /**
                     * Get the random storage nodes.
                     */
                    auto snodes = random_storage_nodes(snodes_length);
                    
                    /**
                     * Ping the front of the queue.
                     */
                    i->ping(*ping_queue_.begin(), snodes);

                    /**
                     * Erase the front of the queue.
                     */
                    ping_queue_.erase(ping_queue_.begin());
                }
            }
            else
            {
                if ((std::time(0) - it->second) >= slot::update_interval * 8)
                {
                    if (auto i = node_impl_.lock())
                    {
                        /**
                         * Reset the time.
                         */
                        it->second = std::time(0);
                        
                        /**
                         * Generate a random number of storage nodes to piggy back.
                         */
                        auto snodes_length =
                            std::rand() % 2 == 1 ?
                            std::rand() % block::slot_length : 0
                        ;
                    
                        /**
                         * Get the random storage nodes.
                         */
                        auto snodes = random_storage_nodes(snodes_length);
                        
                        /**
                         * Ping the front of the queue.
                         */
                        i->ping(*ping_queue_.begin(), snodes);

                        /**
                         * Erase the front of the queue.
                         */
                        ping_queue_.erase(ping_queue_.begin());
                    }
                }
                else
                {
                    /**
                     * Erase the front of the queue.
                     */
                    ping_queue_.erase(ping_queue_.begin());
                }
            }

            it = ping_queue_times_.begin();
            
            for (; it != ping_queue_times_.end();)
            {
                if (
                    (std::time(0) - it->second) >=
                    (slot::update_interval * 8) * 8
                    )
                {
                    it = ping_queue_times_.erase(it);
                }
                else
                {
                    ++it;
                }
            }
        }

        if (!ping_queue_.empty())
        {
            if (auto n = node_impl_.lock())
            {
                /**
                 * Are we an interface node?
                 */
                bool is_interface_node =
                    n->config().operation_mode() ==
                    stack::configuration::operation_mode_interface
                ;

                /**
                 * Generate a random timeout.
                 */
                auto timeout = std::max(
                    (std::rand() % (is_interface_node ? 2000 : 60)),
                    (std::rand() % (is_interface_node ? 5250: 250))
                );
#if 0 // for testing timeouts
                static int count = 0;
                static int total = 0;
                
                count++;
                total += timeout;
                auto average = total / count;
                
                log_debug(
                    "size = " << ping_queue_.size() << ", timeout = " <<
                    timeout << ":" << average
                );
#endif
                /**
                 * Start the ping queue timer.
                 */
                ping_queue_timer_.expires_from_now(
                    std::chrono::milliseconds(timeout)
                );
                ping_queue_timer_.async_wait(
                    strand_.wrap(std::bind(&routing_table::ping_queue_tick,
                    shared_from_this(), std::placeholders::_1))
                );
            }
        }
    }
}

void routing_table::random_find_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        static const char * random_find_table[slot::length] =
        {
            "30286", "66774", "12901", "10469", "99990", "12121",
            "16630", "67478", "19783", "67989", "15192", "64197",
            "72556", "11161", "88302", "18728", "19649", "12120",
            "72136", "13884", "15477", "77732", "13547", "85499",
            "10326", "20192", "11404", "10266", "11101", "18240",
            "73075", "11931", "50260", "11751", "44187", "52021",
            "90915", "82060", "84931", "12382", "84395", "29402",
            "39701", "19270", "12721", "58880", "12988", "13870",
            "19511", "19507", "11619", "11954", "64265", "11949",
            "92572", "44290", "71250", "20668", "11384", "12142",
            "10030", "13431", "74689", "17303",
        };

        if (auto n = node_impl_.lock())
        {      
            std::string query;
            
            for (auto i = 0; i < block::slot_length; i++)
            {
                query.append(random_find_table[random_find_index_]);
                query.append("=", strlen("="));
                query.append(random_find_table[random_find_index_]);

                if (++random_find_index_ == slot::length)
                {
                    random_find_index_ = 0;
                }
                
                if (i < (block::slot_length - 1))
                {
                    query.append("&", strlen("&"));
                }
            }

            /**
             * If we are a store node store the query.
             */
            if (
                n->config().operation_mode() ==
                stack::configuration::operation_mode_storage
                )
            {
                log_debug(
                    "random_find_index_ = " << random_find_index_ <<
                    ", query = " << (query + "&_l=8")
                );
                
                /**
                 * Perform a store.
                 */
                n->store(query + "&_l=8");
            }
            else
            {
                log_debug(
                    "random_find_index_ = " << random_find_index_ <<
                    ", query = " << query
                );
            }

            /**
             * Perform a find.
             */
            n->find(query, constants::snodes_per_keyword);
        
            /**
             * Increment the number of iterations (used to accelerate
             * initial bootstrap, only resets if it wraps).
             */
            ++random_find_iterations_;

            auto timeout = 60;
        
            /**
             * Interface nodes do not need to perform random find operations
             * because they do not need to maintain a stable routing table however
             * they do need to keep the timer running in case they change roles
             * so we use a large timeout.
             */
            if (
                n->config().operation_mode() ==
                stack::configuration::operation_mode_interface
                )
            {
                timeout =
                    random_find_iterations_ <
                    (slot::length / block::slot_length) ? 60 : 600
                ;
            }
            else
            {
                timeout =
                    random_find_iterations_ <
                    (slot::length / block::slot_length) ? 8 : 200
                ;
            }
            
            /**
             * Start the random find timer.
             */
            random_find_timer_.expires_from_now(std::chrono::seconds(timeout));
            random_find_timer_.async_wait(
                strand_.wrap(std::bind(&routing_table::random_find_tick,
                shared_from_this(), std::placeholders::_1))
            );
        }
    }
}
