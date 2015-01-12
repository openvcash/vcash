/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

void routing_table::handle_rpc_timeout(
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
        m_blocks[block_index]->handle_timeout(ep);
    }
}

void routing_table::queue_ping(const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(ping_queue_mutex_);

    bool should_queue = false;
    
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
        std::uint32_t stats_tcp_inbound = 0;
        
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
                    stats_tcp_inbound += i3.stats_tcp_inbound;
                    
                    auto last_update = std::chrono::duration_cast<
                        std::chrono::seconds
                    >(std::chrono::steady_clock::now() -
                    i3.last_update).count();
            
                    ss << "\t\t endoint:" << i3.endpoint << " uptime:" <<
                        std::time(0) - i3.uptime << " last_update:" <<
                        last_update <<
                        " timeouts:" << (std::uint32_t)i3.timeouts() <<
                        " rtt:" << i3.rtt <<
                        " stats_tcp_inbound:" << i3.stats_tcp_inbound <<
                        " stats_udp_bps_inbound:" << i3.stats_udp_bps_inbound <<
                        " stats_udp_bps_outbound:" << i3.stats_udp_bps_outbound <<
                    std::endl;
                }
            }
        }
    
        ss << "\tStorage Nodes Total: " << storage_nodes << std::endl;
        ss << "\tTCP Inbound Total: " << stats_tcp_inbound << std::endl;
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
            "U4wq3", "S8eQa", "urq3Y", "brIry", "lxFY9", "mT3zb", "ztP5q",
            "UVWnC", "5mo2h", "OkmY6", "nxGCw", "16lev", "0JvNX", "dzvy0",
            "4bc7x", "qtHmq", "lYUWc", "APyRi", "R6ZaU", "gBoV8", "nToOQ",
            "lKuCK", "jysx0", "giwgO", "p0XgF", "HMOI9", "9i2Kt", "MrS2d",
            "1CYHt", "Wu44K", "FPR6P", "vj1Z8", "zg24g", "t0p8c", "PiXvf",
            "gtvI5", "z6tHG", "gTzZ0", "vZ9FN", "AyiEH", "d7lPQ", "dZydx",
            "WLVPM", "HIqvo", "qzhcl", "4M8Yp", "9w94z", "7LViu", "fWIQP",
            "SVWap", "zIBdS", "VLObH", "MlMAf", "JWR8w", "P2NjD", "par06",
            "EuRg6", "mWsqM", "CjjCA", "EY5Dq", "wxfDS", "TxHsN", "RF1Qm",
            "QIotE", "uAtW2", "k26GZ", "BoL7k", "oiek0", "sT5Xv", "SZyix",
            "HHlCP", "plAxz", "Tmbqr", "RAymM", "IUSi1", "hhXjf", "1aCm2",
            "LWR4Q", "LrlHD", "F38vk", "4yyxH", "NtWSD", "QiASB", "acpuE",
            "to5vq", "75iXL", "wrJOw", "3J1SJ", "Tyjyo", "8v69z", "Veu0Z",
            "8HgWA", "RrUnV", "8C3aD", "o82fW", "XYHsO", "Hc6uC", "7UT6o",
            "hM94N", "ZyMio", "phKIm", "9w7sJ", "bkkGX", "k1GVK", "wNh0O",
            "AqBGA", "G3Ip6", "KKcjl", "txldF", "TnhC0", "SBNCp", "EhhFv",
            "ijCQ7", "nSl7k", "CcsPO", "u0yrX", "SvEZh", "5dDyk", "NX2XB",
            "fWA41", "BmhYo", "UXh46", "kV1Qm", "ThOHs", "yDZ6Y", "tC5t7",
            "edVTm", "0fHUh", "DBYiR", "28SFO", "sOflm", "aMd2V", "dgGFo",
            "X3JvF", "sB8Jv", "G8CmB", "bYa0t", "7E9rH", "TZs4J", "HfhSc",
            "1Gess", "jPJ3I", "UJdFW", "G9dfN", "1mGoK", "4POGL", "H7C6Y",
            "10j6q", "mqlHE", "qU2HY", "m7MJq", "eTbUe", "C444u", "FwiEd",
            "k0dyP", "UTAwn", "ZvF8Z", "G4Hyl", "4zh9N", "Of1V5", "m4ixg",
            "HzH4t", "uapxn", "FfNIJ", "9DLCN", "lM276", "HV05c", "CE6rh",
            "MJYeT", "hrGzR", "uNlfW", "wFQ9J", "fLYGX", "6dEEX", "5J2RW",
            "FB7Ck", "MNc38", "mcw26", "kmBIH", "8loS8", "pTZqV", "mbc0y",
            "S32j1", "endc1", "frXkj", "VxF2O", "XgpVN", "nCJxE", "bnTNf",
            "b7CBA", "IP2Ir", "vtMSL", "MLwt2", "eTokZ", "NFRk0", "gbSBI",
            "5xAcy", "XXURg", "E1s2t", "e7QZS", "nX4y9", "8f9fc", "coYif",
            "Ryx3o", "BsbX9", "hLWkS", "Y65NI", "4KdHP", "C1jfJ", "QdzQW",
            "5YLGu", "xbxpo", "5QIi5", "gp3ln", "DYMXK", "LtGvu", "BKX2L",
            "hIiGX", "zL1Lo", "oH9Ix", "kHtk7", "grRZZ", "Q0WCI", "l4jQN",
            "yjNe1", "RPU2d", "pXsir", "XxDJh", "4aLCb", "TfyGE", "QMJ8W",
            "Q4axZ", "n1V3M", "e0Ory", "tIEj8", "o0ZRU", "N2QrF", "LUFJw",
            "Ytan9", "GjSVN", "pFw8r", "jEC4t", "Wh9tr", "gw4ib", "e8cvQ",
            "gKeQN", "dtXEw", "7f7yO", "YXYyv", "ixmO5", "rhpyl", "QdwyK",
            "LJFXZ", "ZZlQW", "nKssZ", "ALLvi", "yKTtM", "2gFwg", "EuWY7",
            "rw0zT", "gz2mK", "pwQF2", "fPKhY", "h6hVD", "jo6Ei", "a86cn",
            "aMkzm", "5JLOu", "Vy43g", "5H8Xs", "f5cfL", "yD2eb", "tf2pO",
            "Biejt", "bGJyd", "txeUh", "Npcia", "QFPaw", "BDMM0", "JlYDb",
            "4wLQA", "tcrkq", "Uc1VW", "KzviB", "lPxLd", "eySYl", "qonLW",
            "sXAuf", "r0Zup", "uJrnv", "M40iW", "1Hs9m", "4E2pZ", "d2RTK",
            "anmue", "F99aW", "Cc2JX", "nwnxV", "2VQMw", "M5ahV", "DDXuD",
            "GNPdZ", "28x7K", "519IX", "qNFNP", "46AlA", "Od4qk", "CT56U",
            "WYwqR", "4zXMt", "Yk7lZ", "YCVp4", "IkhDx", "k9z37", "MJ79z",
            "CazC7", "xBBTN", "xciY1", "oI76w", "4OLJu", "lQ1Fn", "Q8x9B",
            "PkMIF", "2DhvE", "NuZz6", "0JmY1", "4VIe6", "pWIic", "yViQI",
            "TcG60", "GZh1M", "W5d9X", "DqYFN", "7Sr0k", "Pfz3j", "sz5Dq",
            "RvDsp", "l3VK5", "Wmka6", "YtWws", "2dJfR", "Vfcqd", "YVOzg",
            "uWoo6", "3oPR1", "QS3A3", "pXUDn", "xqG0R", "116yO", "uiDI7",
            "GtO1o", "aeKCr", "fi0Br", "GdUMB", "vgcZq", "qN5SE", "W9eYV",
            "SlhNb", "u7FKN", "1ylHO", "piuDb", "eUVvU", "PCock", "iDxWA",
            "23gGm", "antMf", "tkz4o", "JX9HC", "cyxCy", "utL2t", "0nYAh",
            "ZdtUw", "cFZW6", "ySm7f", "6PZsL", "x5Sus", "DVCBo", "HU5wv",
            "8jav3", "WLqNf", "fXTIA", "nS7lp", "AFjnP", "GdGRS", "6fR0G",
            "uukbW", "3Sshb", "3q5u6", "ANg15", "YdpGn", "uiE7N", "qUJZa",
            "2UPNq", "4tQjk", "THyvo", "sNgrn", "GW8k6", "NZGWa", "smy86",
            "7oihD", "5Fq09", "EDKEM", "t2nz3", "zyumu", "7D7mQ", "iJFsl",
            "MiMsO", "JS35B", "1xmGZ", "gQlii", "KGImk", "y8YfY", "BkT0v",
            "R2AGl", "YiJur", "xK01Q", "N7kQO", "vrfhP", "VvVfW", "BO5Db",
            "p5GNl", "4Dau8", "rR1cd", "RTczR", "rvH1V", "SGydi", "oCprT",
            "AxEWM", "OuKbm", "wrGwz", "iUBR5", "Jm7zz", "xgjJ4", "UZxFQ",
            "IMBzB", "R4TNB", "Tl5oM", "PXJqv", "lzDU2", "RclMg", "Uv70c",
            "9SgmD", "ypKix", "e8cdm", "HLlXP", "zROSD", "T8xZN", "bPxSr",
            "iQrKV", "zSS4A", "qp6TE", "PWRTK", "vYEoy", "0hwGm", "YoBwY",
            "9CA7p", "nc8wZ", "41bk1", "ZVMqw", "WRQFr", "71jZy", "Zs3xb",
            "0Wwf1", "L9RNe", "OGYDU", "sYw5i", "lwIJV", "0xx4d", "WGccR",
            "RFdMX", "xO5cP", "6M4ls", "C2rM0", "uIISh", "HThBi", "fdxd2",
            "WaVR3", "OcRN0", "9diQI", "oZXil", "ui1YD", "K4Mfl", "izC2S",
            "XUdUI", "KPA4G", "9woD3", "8Nt5t", "ronTB", "dTcSM", "DxWqE",
            "ftX1f", "UUriK", "TtYCq", "0ZNM9", "5v06u", "pO5pF", "tDJa2",
            "5TmX1", "HMLxC", "8vta8", "uG0Ih", "yUbF1", "jUm52", "V0uOw",
            "wSaiv", "JFWIz", "OIu1p", "RfCI5", "C1sZ2", "QttYk", "xmbxD",
            "Tbga0", "KcywL", "AE6nP", "ypKwH", "JvXNi", "8j1rQ", "q4FyZ",
            "F43IF", "pnKxg", "ojGZp", "oO14O", "sYyl0", "jziJC", "76jRy",
            "NvKRB", "dEIDP", "JA5tv", "bv74k", "iHVx4", "9lHuE", "sooKh",
            "35Z6M", "2d18a", "Cp8aV", "GiG7P", "3z3ll", "uaABo", "IPRvD",
            "NR6hT", "bL0hQ", "DsPw8", "BTtsc", "nc0B4", "tp7VM", "quUCn",
            "vgtwX", "sa38i", "1T512", "OUW8J", "fHYVT", "uG9YL", "cqbDL",
            "jM9pm", "y6RcA", "ckCLy", "k3grv", "syg8w", "dUrYh", "1nyph",
            "Yvoss", "fUh2E", "zoyEr", "yeZBF", "xUUk3", "cj0AS", "8kJ5D",
            "T6nBu", "q5oWj", "Ee3yp", "ypcTJ", "Yk8fs", "AeO5r", "qvWtw",
            "G8TQ8", "uvmxd", "iaZ71", "3eUnC", "frw4V", "TksFE", "6rlLp",
            "bLZ8e", "ua0tO", "2zrBJ", "8d6Jj", "c8AB3", "P383V", "lD2r1",
            "GZoKe", "soNHZ", "ZPp20", "yJyaj", "9244G", "S1Wuf", "QnfR2",
            "LvX6R", "95ZWl", "laYtn", "WQ5Rm", "lTTgF", "9IIBw", "aX5Qr",
            "V6eYK", "QEzQ6", "sAncq", "ZfrJE", "7agyl", "Xq59a", "lyDVc",
            "3jfqg", "8EbAG", "Fww95", "pRrvo", "0RJZ0", "ac2Pj", "rfoi9",
            "0aqkd", "KMOJs", "0z73y", "Z4vXr", "nL5fV", "E9gNx", "7rwTp",
            "9gxzj", "WLGbR", "Q0dDT", "HmQfw", "4aZXV", "KBq1i", "rI2DW",
            "Vej3G", "29ZnV", "T6vq6", "G38Km", "MccZn", "T5XmN", "yAWjJ",
            "DzoZk", "NjfQa", "WGIuI", "wR2sB", "F7ddU", "Ja4Lr", "bRtL8",
            "8zoqY", "9VLDt", "bt8uT", "cojmp", "2xHgP", "ClH0W", "GeGeS",
            "fhndu", "qK3Xv", "f2VFe", "jwSVN", "JFA7n", "8MPml", "hugQp",
            "fbi4H", "1yPpH", "nCMIS", "s51op", "3tCxl", "miRvb", "rJEcn",
            "L8pvJ", "2O3r5", "9qHPx", "6aTVe", "9hU9I", "xZXmB", "1lEum",
            "Hyqtv", "HX9Sh", "rz6rA", "bVkK6", "nbwTE", "TfGjH", "IxKDi",
            "yGKAW", "b5zKU", "fzrn1", "n1NAX", "j5HuT", "TRWu1", "YbSvr",
            "3tkMp", "UAIZT", "kJCjk", "vb1zq", "bifA5", "dSOsF", "IAY2H",
            "Txhco", "LccGv", "6ARR6", "u0GfX", "jO3hH", "v9Cqy", "XP6Nr",
            "8nA1k", "3R25u", "bDdCJ", "eeXxi", "SWvEQ", "SbLB3", "8Oayn",
            "9Sdjq", "dwgPf", "73GQK", "7nHfr", "e0Cp1", "a2Wps", "pABEN",
            "jYfdb", "GWiIs", "UVzUw", "sq19z", "l0Q8k", "XUAyD", "cKA42",
            "U8sGC", "yhiD2", "uMTNi", "KVxFY", "fnRPy", "RnmyD", "Pkhgz",
            "Z8dub", "quzIi", "kOgHH", "p2QQ2", "7s1ge", "50PUC", "719DF",
            "MFbxg", "y2GrS", "Zn4Rs", "ysVNG", "VSGCU", "oJAKA", "qneKa",
            "nYPJ6", "cOIXU", "LMEM7", "3IyEI", "7Mvik", "C5w3o", "oZmHd",
            "Jcq5v", "TypoH", "bSZeY", "czopi", "3i8id", "LSUnV", "3KDrv",
            "PTvnt", "UFY6H", "GrOrr", "mv8Wc", "wl4Xa", "d7R1R", "Fs7DK",
            "WwxMx", "5O3LR", "ON09l", "6sTKd", "gBmqs", "5hAzS", "IkimA",
            "h5eyi", "sMfRx", "ejVuQ", "UJxMl", "o0ihK", "aUMMV", "44Rnx",
            "eOL19", "8xfZd", "UTL4v", "STrx2", "kI7EK", "EMBVz", "ZuYCh",
            "U8g07", "PTBJq", "2AbLp", "Kx1mA", "Fdmsn", "CpEKq", "7T67g",
            "KLm0P", "pGjqg", "p0FSL", "a2QCm", "mze1r", "LWbXa", "fFvgE",
            "KMjGK", "V3ZWY", "5V8yP", "kqBNN", "N3lQF", "7Eh24", "LNLcC",
            "YAPij", "hqllN", "cMSrn", "WZfrI", "j8B1A", "MQGfo", "inlMR",
            "6EwTN", "zTaZC", "DjAMW", "UWoZr", "tblgh", "20rYG", "3GLoX",
            "FTwK0", "wlrEv", "YbTc3", "vS7zh", "4Sx1X", "P2lVe", "vfa4w",
            "slYZa", "eaQoR", "yjTMa", "r03G7", "jXduQ", "WNO7J", "XBeBP",
            "8Rs13", "LqfIO", "SuJYl", "Vo69f", "ynOlP", "lRhTE", "bC7Dn",
            "mmt2f", "PKpb6", "GEQGZ", "YOhof", "tAffM", "Mnx4w", "9ze3o",
            "9xILs", "putbA", "dRXWX", "uwYYW", "fN7lQ", "AlDJ5", "Y6IOQ",
            "V4Ovn", "Zun6t", "S1a5f", "8fIDP", "jU2zg", "c9sn8", "oWHHo",
            "Llr24", "e4IjA", "6U2Pq", "1tZ6x", "sSdUP", "OVuYu", "CoY8w",
            "wVlCg", "BDflh", "ANH4p", "4nywP", "WIygJ", "KXZrm", "hAPPy",
            "rjzSB", "MbN4Y", "keWMd", "68Zrt", "m6d51", "RuD9O", "iWJ6U",
            "SkdOT", "sIb2v", "CCHfM", "kOAs8", "o3Jro", "ekNx4", "chgxI",
            "s97oA", "mThvg", "vs8K8", "8DtVw", "8nX6I", "kXRtl", "HuxOc",
            "uRTYS", "oKaCF", "V4r93", "AKde8", "bh5l3", "3h2F2", "LEubQ",
            "RAQGB", "jz7I0", "l2SBF", "nXf5A", "WQ7PF", "6dXij", "aJaXa",
            "H6zh1", "QK6KU", "tqzjc", "uhT8I", "C2Uud", "5FwkA", "SmIjC",
            "ncxoT", "tRS5j", "CyXhk", "biQ3f", "P40QM", "3AJHu", "raXxp",
            "Sd1xJ", "NsXNA", "xTv6O", "Lmdxp", "miWdq", "IkWL2", "FDXQ1",
            "onbfD", "W9ZiB", "qgH2o", "sw0DJ", "sSoKx", "VGoh1", "hryj7",
            "Ar2VY", "aIwFI", "T3IQp", "xEPhl", "hNb39", "oppnL", "oqMiz",
            "XbwlR", "sTyIs", "fZEuo", "I3xDY", "728or", "d09xC", "stQ8k",
            "hbb1T", "MkOc5", "IKKPo", "ac0SZ", "i5HGY", "M0DLg", "IYByv",
            "yZuog", "sIvyt", "JldK7", "0BSLJ", "ngiba", "eeJOT", "0kL9G",
            "IfF1Z", "vTJTy", "9nye4", "rZ9j0", "K7A5Z", "8roNq", "szQK0",
            "6mbFj", "0sZHS", "tDrC1", "zSR20", "DPeN3", "JVmFG", "XIodK",
            "p4J4h", "4uJJO", "r6pYN", "ebCAn", "CZhyx", "4LCvq", "BFbi9",
            "ey2oM", "RZg5Q", "oTEk6", "G1G0J", "H5s5F", "snVUk", "5PhI4",
            "bGIWn", "QbekT", "UiAih", "zdrxf", "r1W69", "aklGi", "wy1C5",
            "GGauk", "2WG1I", "GHXEH", "DDLSz", "rsfR5", "R1wsJ", "sSEAD",
            "tyvI4", "ygbgb", "HTCN7", "ymjoc", "GfKJl", "Hk15O", "jCnBR",
            "1Qt25", "UWYjJ", "9vPsC", "p1dwK", "4GNmT", "ZmwPM", "2a0OV",
            "31Pc8", "4U3ph", "kHYWM", "0Yko4", "6vBBi", "RMFSA", "plVU3",
            "AhCRd", "BEryH", "4ERcw", "2eSUr", "vqfBa", "L5yIC", "ml8XE",
            "Vmozj", "Nbf4L", "NsD80", "teffJ", "0rXga", "V1cD7", "sRwQB",
            "k5BUK", "bx539", "0VhYH", "lx5tg", "csVUr", "W6qFK", "xSK4N",
            "MsxgU", "WbkUi", "SHIBC", "vdXhV", "Sidl3", "zatBa", "66L9i",
            "lMXy3", "k9FAO", "MAo5F", "mJEBv", "6RflI", "0jCgx", "2A1wV",
            "X2hOh", "YcmV8", "iFTEo", "dMkNj", "KNoZy", "5Wj9v", "L8vjD",
            "HpPL8", "9zLlY", "kS2YZ", "8BuXH", "ZkuFz", "2qIWH", "P4mvF",
            "P7Gvi", "IDScV", "NraUG", "Ehvsc", "k84iD", "BGm7m", "4B831",
            "81CSG", "ZzUMd", "veaqA", "5LJIa", "GPVfk", "W6Q9P", "yF5aH",
            "g9ckU", "IDmzy", "eGAUG", "SVGrm", "E7FvP", "njXZy", "lnRzR",
            "6fRrf", "Cmrov", "yMk53", "0xDQ5", "CzWNb", "M82F1", "pgSfR",
            "X5Ynv", "3iCc1", "bfI86", "et3Gl", "CAjgA", "h69sO", "ePgz5",
            "JA1B5", "TPCCY", "omy0C", "XahDA", "iWMhQ", "k4ijQ", "6Tzhu",
            "fdQVz", "CpoC0", "5TfIh", "H3oju", "TobuP", "31OCN", "SdJty",
            "ZDRUd", "ZOwCP", "pPz4o", "TtcpG", "J9LsN", "r4Dt9", "QbXih",
            "509nH", "rhbxC", "MmL2y", "xuG4V", "Zuvf2", "hV2Mi", "VH1Cn",
            "a0MaG", "ShQyc", "rIiSR", "SyQov", "smhFl", "QQj6W", "nkS63",
            "3UOPf", "MZSSw", "WeGiH", "nJeiR", "ktZHK", "l9zLE", "mpCv8",
            "DqXzp", "90Mml", "oqLcD", "x9Lkf", "Jr9yi", "HjTus", "VJJVW",
            "JWojt", "gcaav", "wnXop", "gxyqS", "P3G20", "g243y", "yWcN7",
            "gsvUn", "aW6Ms", "cStRU", "Vunuc", "XAAqp", "KQaUg", "i0LAc",
            "OXtmr", "LIegb", "SwgOl", "Q55eP", "sxbYn", "hhY14", "3Ra34",
            "nvpZU", "8vSXK", "vbX6H", "sedrR", "Y0PH0", "86R4J", "7jIYX",
            "Abswc", "8W1tJ", "OkOIU", "ZVApJ", "3R2kX", "CwLkT", "85c23",
            "l7fpQ", "1M80U", "SGQIN", "nteZn", "8UQgh", "sDNvB", "lvGql",
            "fYJ2w", "1XN1i", "92yyv", "a7KVI", "bxcR8", "jKnWa", "5N2PT",
            "xj2z9", "2SJd2", "AfzdY", "kWgeM", "eA46w", "q37IU", "Lz6Xh",
            "wcQVS", "bpBSx", "UxFyj", "OnvYo", "kLeCT", "490UJ", "ixZSX",
            "zBatR", "pEsEF", "R5FMf", "UwIob", "aQuR8", "79e6m", "KyaH9",
            "ZYhXU", "oUYVe", "NwZoQ", "LFPMs", "m3D1O", "jOb2C", "JwPI2",
            "96Wry", "n5Glu", "d7sAN", "UtH45", "aXkG9", "ox7Pi", "fPVCF",
            "1omuO", "xurQW", "2QjMU", "wKaZy", "gmWAn", "PAG4e", "uH0hN",
            "tm3Sq", "aGnBZ", "DEoGl", "NSgoc", "OTCsK", "w5jf5", "TIm5Y",
            "w5qvS", "sqdFz", "nXmfr", "KPOh7", "dtYDH", "VbiOJ", "Tq4aK",
            "rDBKp", "Vby4a", "gaBEq", "wdd0w", "Q06ft", "kvuvF", "YxcFb",
            "hQaaU", "H1qtu", "tAYwU", "ij2yc", "Lq1nW", "yh56j", "pi6Cq",
            "NTrrj", "F9ImL", "OdUnC", "MceUk", "bKV6I", "7CM9i", "g6sZ4",
            "EcffH", "YPqod", "wgiNj", "qLBoX", "5rOjQ", "GCu1T", "YUvrn",
            "YkXT8", "5dS0H", "wSwt3", "lTWhz", "pdJhZ", "idXHw", "NOzmR",
            "9UorA", "RpUl9", "tHwOG", "brmi4", "UWJln", "IOWer", "Zz7GR",
            "TdFBL", "RAAak", "ucNwA", "sIv1x", "Gdfbz", "V4A7R", "27nH9",
            "YIgxr", "BKT2q", "5FkyZ", "r34LR", "SNoQC", "HCY4c", "y2yjk",
            "uejsT", "JMopK", "Mqorz", "yNFVU", "PVtsy", "r8hGA", "etnJh",
            "2RfXV", "JXC10", "rYZ9x", "GWA3H", "kOHlW", "LkM3k", "0c2kj",
            "YXq4l", "qSRIT", "1GJvY", "blL1k", "5tlQe", "RHqZC", "ExxUg",
            "YQLSd", "9iuB1", "91wRA", "8IAZ7", "zcBWT", "WpbUl", "nYrQQ",
            "Js7eP", "fCRze", "Dm6Hy", "mJDZf", "KUr97", "cf7Ov", "OFrqx",
            "Rrh8Q", "Z8cqD", "F7QNt", "kNEBj", "QS6gL", "XVSBS", "gYfbK",
            "Y6bJo", "l4aWN", "ALwv9", "N4Gz7", "oK4rZ", "Kxz9C", "SyL8u",
            "9VKTB", "1kLoW", "FMHqS", "2p0JI", "UGi5e", "y6DYg", "qiXKV",
            "u1iuR", "BwVhk", "Yz2e0", "XOnVk", "XiIWx", "6nsOb", "gYoCA",
            "jXXUv", "uLAjM", "1Kr31", "YcCjm", "sKsKy", "vZH2B", "Z4e9w",
            "xBboU", "OLstO", "fYVzQ", "okPoW", "vfN9e", "CP2Sk", "pYPra",
            "YIX1z", "nWWsU", "BKsrK", "Tii0m", "XWjXG", "q2XU0", "TXrHV",
            "g4K76", "ovHx7", "Uh8b9", "gY5Mh", "IclRd", "jLd2U", "FXfAG",
            "vWoSd", "A4KXS", "oCBoB", "riyh6", "wB79r", "3i6Lk", "ZZt7d",
            "5Yswq", "HLJCT", "tnquf", "nLX3Z", "I1tT1", "VfAXi", "BHubh",
            "zNi3B", "7qgP5", "sD75q", "TcRhj", "duLeE", "Desp0", "0heh7",
            "ldIY5", "uh7No", "kQpxu", "VXqU7", "gnPqX", "ymw8x", "cR1Qn",
            "kVfAu", "NDgnC", "REAR0", "DIXJO", "cF99m", "A1tET", "Os4SA",
            "JcHg2", "0tgwa", "Esks8", "BA2Zg", "Xp2LV", "tRTUO", "9g1cZ",
            "SQxga", "Fx8tZ", "izUcA", "72Iq5", "mzgGn", "qG61e", "Mrfb9",
            "xsMU7", "Jh7Go", "dIB21", "RoL2l", "1Kovb", "U7x8B", "xy2JK",
            "JntNp", "ic9Hp", "HdNT1", "Ll7mM", "96XtT", "nlVFk", "fX5C3",
            "wgRli", "NJI0E", "e1J7n", "mfhJg", "e8NYy", "oxrVz", "k7FVW",
            "wu1cR", "TMM34", "r8z8q", "VwQB1", "gMB4j", "gnebf", "mPbTf",
            "9BAXN", "76qxP", "lIDvc", "rGNdn", "FszBb", "ihEJ8", "IXX9Z",
            "ATlaI", "6psLc", "GqYnI", "jwcQv", "GDhY3", "3wyZ8", "Yv252",
            "Rjc5a", "6Q12T", "QI0bk", "Xlhc4", "LtAO2", "jDJSV", "8NN9M",
            "Z6e6s", "Y8Z8o", "r8ubP", "6m2vn", "hHg1M", "FVypR", "tYXQc",
            "MalVz", "lQ4Ol", "r6Hgp", "dCuK5", "QkX2K", "rTePE", "MtvS5",
            "nPS6p", "hE70n", "r5Jhd", "Kj7Bo", "IC4jD", "UNlDD", "J50Yg",
            "U0VMU", "6l9Ws", "wgK78", "FBjt9", "M5cnS", "Fg1tv", "C3Q8r",
            "OFKsH", "NTSoN", "Geu7M", "F0rBu", "wLegJ", "KzwLq", "5t2r0",
            "q4kRm", "GjdSk", "zbEeP", "b2qeR", "u2D5S", "pfBRc", "jCSZg",
            "qcCd2", "kDS1a", "Xiion", "N2ozI", "RUz2K", "ckR4p", "ZOoG2",
            "IZKsS", "Ib4lF", "a8Nao", "ezakC", "suCvL", "WakQG", "9HNg8",
            "voHvW", "lV1Pb", "me8Rn", "112gs", "k6QiQ", "Segst", "M8ylH",
            "R9whP", "pUmqz", "RikP6", "Lao9p", "bFioA", "bXs8Y", "tsDgz",
            "SV3dU", "JCTs6", "ZZMlc", "TP3fL", "6LYgB", "lW908", "qJGw7",
            "m4GG7", "xhiQQ", "Uck9S", "5ZgIs", "Ob4OP", "3FQ69", "WmKDm",
            "b43Hr", "3vHa6", "vKXlM", "Skmcn", "ofWBV", "SHVAM", "JO0zG",
            "2uN6b", "xQzvt", "OUppy", "fusWY", "pfoH3", "euXXB", "V3FtB",
            "zniPX", "jyhoK", "mgeVw", "4SN7d", "M3Dpi", "JbxlE", "Y65dI",
            "oF1O9", "F4Jf2", "OD89Q", "mG7Un", "DwZYG", "fLrnK", "I9p7D",
            "A9DKx", "OdKMm", "LBpCB", "TUnLL", "fvETQ", "yfMKw", "gqyTx",
            "8CPYA", "HwSNq", "mAvuY", "318wT", "LHEpR", "61hWB", "7mwv7",
            "o4lnS", "vpRF7", "vt38o", "qlybi", "tZe3I", "TJxq0", "tPlEW",
            "i2SYj", "f7NgN", "UdaMD", "54NEn", "gDKA6", "s3tNI", "bnqBI",
            "kIUho", "KdjiU", "grUu7", "giawK", "m8GNB", "ihJ5P", "wjsFa",
            "Kb0ux", "YHYo4", "9vA5u", "bbstr", "n1bbd", "cO2r5", "VkKsP",
            "Hqv43", "Zx6gh", "P4jkw", "a3k8x", "1zDLG", "iuiOt", "4IFYd",
            "lhNfr", "msJkf", "PHhl6", "uUQ43", "mSICB", "k7yO9", "64dzX",
            "gcRIS", "MgQLO", "VEo25", "pTk5w", "gMho2", "PP67n", "q8IVy",
            "JmQDj", "0mHYq", "FN0gf", "5xdT1", "Oua2B", "PKDwp", "YVdl9",
            "BOrzL", "L6TVw", "lQPPW", "Pi8BC", "6wKiR", "92LHP", "dnUw9",
            "6mf7V", "wdaHv", "FgfkF", "fYFko", "YdFaR", "j1pNP", "OanpV",
            "Hhfbp", "GvZ1R", "VxO9l", "jlUgE", "9thIB", "b0DxW", "UpEnp",
            "iVq08", "zPo51", "IPlpA", "APuNt", "lbMey", "Ojh94", "ck8fM",
            "v475C", "GHtt7", "KGDkX", "5Axsh", "PgV1k", "Nef95", "fHQNx",
            "sMLyY", "EQPH7", "xq9rt", "ukMHc", "zLmqO", "CUHPH", "auVwG",
            "8jugt", "m4iRX", "3BPAg", "LJjZT", "T9X5k", "cfzzZ", "dDHmF",
            "vPxkC", "kdHgO", "rVMb3", "dTMSK", "BzVxQ", "VSb7w", "5R1IK",
            "dy5ng", "GZCiz", "EPyr3", "QDRP4", "Bugu8", "bRvzx", "JLNGu",
            "aACDb", "4kPp6", "amRl3", "HBg6H", "SoiMs", "G9Y86", "9HXJR",
            "wY8KZ", "cfKtI", "K9pQO", "dpV6m", "FFoFd", "nGxXr", "ppgXX",
            "KBihq", "sWCJA", "VCEK2", "4Pqae", "1SzLd", "HvxIr", "4UCls",
            "r90lq", "4OUIh", "SC0Z6", "FjEa2", "82X0r", "4F8T2", "DtLGm",
            "KpfGM", "hBo3J", "fuhiY", "pMNpO", "3mnR7", "2baOh", "m3zDu",
            "73LT5", "U9iCT", "HXUNK", "aRDr3", "Y9OJY", "3IpPL", "MliVA",
            "ZEMzH", "JoCkk", "ZUw4z", "yyy3b", "O989f", "zORxN", "BU0JB",
            "CsZFS", "6wXAO", "Ch6NX", "mELhv", "OOZaf", "AxhK2", "eQExd",
            "a9jMd", "JkZN1", "2YJ9g", "yLwMC", "KAkcn", "woRb9", "9IQ1r",
            "VWMDU", "9816b", "8ibXX", "0zMYL", "TuZLz", "L5AxF", "jMPno",
            "nDpE9", "sl2PB", "PVdge", "He0FE", "x3dZI", "N0CNr", "tIi66",
            "Tqnsf", "4KtFb", "W1mO9", "ZKa7y", "TEQfL", "bBGOO", "JwxwL",
            "mBlaZ", "uRUZs", "sDwMi", "Is11Q", "fm422", "hudSB", "dJdPa",
            "sQTAX", "sTgGR", "5s5qb", "ZIICE", "5pJDM", "982Y3", "4KgSm",
            "m7Vcf", "WdjhT", "JGfPg", "xKo8S", "8q54B", "Xqytn", "1vpOr",
            "z0c2R", "rX672", "Ge6q1", "MDkYy", "Y1BvT", "uTBTu", "Pc2Hl",
            "6SQ9j", "IU7Rp", "L4bVs", "75aHo", "jRX4s", "YGgfC", "f0xRl",
            "8OwYh", "REM1i", "w8Si3", "pHmSO", "7rR2V", "Ib6TT", "W537c",
            "H7rao", "nH1hG", "MslkW", "A66ag", "Tt98G", "IEFNC", "ptnw2",
            "fADo9", "cvZJx", "ZEvbw", "tQmYb", "3IFwX", "RDK8F", "c0dD8",
            "IRFJt", "26xA1", "0jrbe", "dlyTS", "ycO11", "jN0x3", "qwL6G",
            "9bL9W", "BCN3F", "UsNk1", "JlYns", "IshF5", "uw3tH", "ZbHff",
            "bAOW0", "tpYYk", "nxn1H", "CYQfe", "IrVui", "SgFBL", "vwB9I",
            "IzdbD", "dMz4z", "upsuK", "tarOu", "asHpm", "aS3Nr", "WRWO5",
            "VrCJ8", "kvUcY", "gYKwB", "P3oAH", "xWxd9", "i9FO6", "21lin",
            "Ncezg", "rZ3be", "RRkPG", "wV6Dw", "6QhK0", "FrCnC", "wLocA",
            "whbHX", "qDZ3y", "5S7F0", "2BrCg", "Hx3VP", "h3EkJ", "Vlcl8",
            "d6QCZ", "knV3H", "SrXuO", "C0etP", "Va2fl", "YXro6", "1Il4U",
            "OOYTL", "GxVfC", "PaTzf", "fUWYk", "cZZH6", "dTnEh", "XfKJh",
            "4QaVV", "OiY9V", "EIv9I", "xe6oe", "Q8MNZ", "Loa1W", "obXtp",
            "vnoUQ", "0JKXI", "luXhZ", "1fR3Z", "k7GE1", "tt9bD", "WGidn",
            "ptONK", "tFlTE", "FXoTj", "xBbNU", "hCdYT", "S3WY3", "SKTp5",
            "nXCBN", "1DszL", "YyXGt", "gy7LH", "Gkgra", "yfW4W", "Ok0GS",
            "yDD0T", "SVf40", "T0HuQ", "dmZmY", "lej68", "zYzOC", "iNyUQ",
            "0FN2j", "Q2oZK", "q3VV6", "X8Vhx", "vxBLt", "pSvXO", "P9gIh",
            "zZCcB", "wOJaV", "cthii", "E6WSE", "jOM1g", "l6cjf", "pfkij",
            "QyTO9", "FZS2f", "vdzVU", "8QrbD", "5YYrd", "BsLNx", "Olu0S",
            "DMpUY", "jUzas", "s8QIO", "3Q9wp", "vM96I", "ezYA8", "pxgrU",
            "q5dhj", "xUiVg", "QuHEa", "EHrxD", "hSy70", "wf5Et", "dVCRM",
            "HjRsx", "T2Ohz", "8f7Cz", "09ESo", "ithFO", "gBUhG", "Ba4kp",
            "ESeEi", "cZrEq", "OXBzu", "10eoN", "lPTv6", "AcyzU", "einwX",
            "4rbNt", "jT8tf", "IY0JT", "4MlJT"
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
            
            log_none(
                "random_find_index_ = " << random_find_index_ <<
                ", query = " << query
            );

            n->find(query, constants::snodes_per_keyword);
        
            /**
             * Increment the numbner of iterations.
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
                    (slot::length / block::slot_length) ? 60 : 300
                ;
            }
            else
            {
                timeout =
                    random_find_iterations_ <
                    (slot::length / block::slot_length) ? 8 : 60
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
