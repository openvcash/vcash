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
#include <chrono>
#include <iostream>

#include <database/block.hpp>
#include <database/logger.hpp>
#include <database/node_impl.hpp>
#include <database/routing_table.hpp>
#include <database/slot.hpp>
#include <database/utility.hpp>

using namespace database;

slot::slot(
    boost::asio::io_service & ios, std::shared_ptr<node_impl> impl,
    const std::string & val
    )
    : m_value(val)
    , m_id(associated_id(val))
    , timer_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , ping_queue_timer_(ios)
{
    // ...
}

slot::slot(
    boost::asio::io_service & ios, std::shared_ptr<node_impl> impl,
    const std::uint32_t & id
    )
    : m_value("")
    , m_id(id)
    , timer_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , ping_queue_timer_(ios)
{
    // ...
}

void slot::start()
{
    timer_.expires_from_now(std::chrono::seconds(std::rand() % 60));
    timer_.async_wait(
        std::bind(&slot::handle_tick, this, std::placeholders::_1)
    );
    
    /**
     * Start the ping queue timer.
     */
    ping_queue_timer_.expires_from_now(std::chrono::milliseconds(500));
    ping_queue_timer_.async_wait(
        strand_.wrap(std::bind(&slot::ping_queue_tick,
        shared_from_this(), std::placeholders::_1))
    );
}

void slot::stop()
{
    timer_.cancel();
    ping_queue_timer_.cancel();
}

const std::string & slot::value() const
{
    return m_value;
}

const std::int32_t & slot::id() const
{
    return m_id;
}

void slot::insert(const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    /**
     * Only allow one unique IP address per slot.
     */
    auto is_duplicate = false;
    
    for (auto & i : m_storage_nodes)
    {
        if (i.first.address() == ep.address())
        {
            is_duplicate = true;
            
            break;
        }
    }
    
    if (is_duplicate == false)
    {
        /**
         * Allocate the storage node.
         */
        storage_node snode;
        
        /**
         * Set the endpoint.
         */
        snode.endpoint = ep;
        
        auto it = m_storage_nodes.insert(std::make_pair(snode.endpoint, snode));
        
        if (it.second == true)
        {
            log_none(
                "Slot #" << m_id << " inserted storage node = " << ep << "."
            );
            
            log_none(
                "Slot #" << m_id << " is pinging new storage node " <<
                snode.endpoint << "."
            );
            
            /**
             * Queue the ping.
             */
            queue_ping(it.first->second.endpoint);
        }
    }
}

bool slot::update(
    const boost::asio::ip::udp::endpoint & ep,
    const std::uint16_t & transaction_id
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    auto found_it = m_storage_nodes.find(ep);
    
    if (found_it != m_storage_nodes.end())
    {
        storage_node & snode = found_it->second;
        
        snode.last_update = std::chrono::steady_clock::now();
        snode.set_timeouts(0);
        
        log_none(
            "Slot " << m_id << " updated storage node = " << ep <<
            " tid = " << transaction_id << ", rtt = " << snode.rtt << "."
        );
        
        return true;
    }

    return false;
}

bool slot::update_statistics(
    const boost::asio::ip::udp::endpoint & ep,
    const message::attribute_uint32 & attr
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    auto found_it = m_storage_nodes.find(ep);
    
    if (found_it != m_storage_nodes.end())
    {
        storage_node & snode = found_it->second;
        
        if (attr.type == message::attribute_type_stats_udp_bps_inbound)
        {
            snode.stats_udp_bps_inbound = attr.value;
        }
        else if (attr.type == message::attribute_type_stats_udp_bps_outbound)
        {
            snode.stats_udp_bps_outbound = attr.value;
        }
        
        log_none(
            "Slot " << m_id << " updated statistics for storage node = " <<
            ep << " tid = " << transaction_id << ", rtt = " << snode.rtt << "."
        );
        
        return true;
    }

    return false;
}

bool compare_storage_node_last_update(
    const std::pair<boost::asio::ip::udp::endpoint, storage_node> & lhs,
    const std::pair<boost::asio::ip::udp::endpoint, storage_node> & rhs
    )
{
    return (
        std::chrono::steady_clock::now() - lhs.second.last_update) <
        (std::chrono::steady_clock::now() - rhs.second.last_update
    );
}

bool slot::ping_least_seen(
    const std::vector<storage_node> & snodes, const bool & force
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    bool ret = false;
    
    auto it = std::max_element(
        m_storage_nodes.begin(), m_storage_nodes.end(),
        &compare_storage_node_last_update
    );
    
    if (it != m_storage_nodes.end())
    {
        if (auto i = node_impl_.lock())
        {
            auto elapsed = std::chrono::duration_cast<
                std::chrono::seconds
            >(std::chrono::steady_clock::now() -
            it->second.last_update).count();
            
            /**
             * We ping the least seen storage node if either the last update
             * is greater than the update interval or the storage node has
             * a timeout.
             */
            if (elapsed > (update_interval * 8) || it->second.timeouts() > 0)
            {
                log_debug(
                    "Slot #" << m_id << " is pinging least seen storage node " <<
                    it->second.endpoint << ", last update = " << elapsed << "."
                );

                /**
                 * Ping the endpoint and retain the transaction id and time
                 * sent for this ping for the storage node.
                 */
                it->second.transaction_ids[
                    i->ping(it->second.endpoint, snodes)] =
                    std::chrono::steady_clock::now()
                ;
                
                ret = true;
            }
        }
    }
    
    return ret;
}

bool compare_storage_node_last_update_sort(
    const storage_node & lhs, const storage_node & rhs
    )
{
    return (
        std::chrono::steady_clock::now() - lhs.last_update) <
        (std::chrono::steady_clock::now() - rhs.last_update
    );
}

std::vector<storage_node> slot::storage_nodes()
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    std::vector<storage_node> ret;
    
    for (auto & i : m_storage_nodes)
    {
        ret.push_back(i.second);
    }
    
    return ret;
}


std::set<boost::asio::ip::udp::endpoint> slot::storage_node_endpoints(
    const std::uint32_t & limit
    )
{
    std::set<boost::asio::ip::udp::endpoint> ret;
    
    auto index = 0;
    
    for (auto & i : m_storage_nodes)
    {
        ret.insert(i.second.endpoint);
        
        if (limit > 0)
        {
            if (++index >= limit)
            {
                break;
            }
        }
    }
    
    return ret;
}

bool slot::handle_response(
    const std::uint16_t & operation_id,
    const std::uint16_t & transaction_id,
    const boost::asio::ip::udp::endpoint & ep
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);

    bool found = false;

    for (auto & i : m_storage_nodes)
    {
        if (i.second.endpoint == ep)
        {
            auto time_sent_it = i.second.transaction_ids.find(operation_id);

            if (time_sent_it != i.second.transaction_ids.end())
            {
                auto elapsed = std::chrono::duration_cast<
                    std::chrono::milliseconds
                >(std::chrono::steady_clock::now() - time_sent_it->second).count();
                
                i.second.rtt = elapsed;
                
                i.second.transaction_ids.erase(time_sent_it);
            }

            /**
             * Reset the time last updated.
             */
            i.second.last_update = std::chrono::steady_clock::now();
            
            i.second.set_timeouts(0);
            
            found = true;
            
            break;
        }
    }
    
    return found;
}

bool slot::handle_timeout(const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);

    bool found = false;

    auto it = m_storage_nodes.begin();
    
    for (; it != m_storage_nodes.end(); ++it)
    {  
        if (it->second.endpoint == ep)
        {
            /**
             * Increment the timeouts.
             */
            it->second.set_timeouts(it->second.timeouts() + 1);

            log_debug(
                "Slot " << m_id << ", storage node " << ep <<
                " has timed out " <<
                static_cast<std::uint16_t> (it->second.timeouts()) << " times."
            );
            
            auto elapsed = std::chrono::duration_cast<
                std::chrono::seconds
            >(std::chrono::steady_clock::now() -
            it->second.last_update).count();
            
            /**
             * A node is considered to have failed if at least 2 timeouts have
             * occured and 200 seconds has elapsed since the node has last been
             * seen.
             */
            if (it->second.timeouts() > 1 && elapsed > 200)
            {
                log_debug(
                    "Slot " << m_id << " storage node " <<
                    it->second.endpoint << " has failed after " <<
                    elapsed << ", evicting."
                );
                
                /**
                 * Erase the storage node.
                 */
                m_storage_nodes.erase(it);
            }

            found = true;
            
            break;
        }
    }
    
    return found;
}

std::int32_t slot::id(const std::string & val)
{
    return associated_id(val);
}

std::int32_t slot::id_from_endpoint(const boost::asio::ip::udp::endpoint & ep)
{
    return id_from_endpoint2(ep);
}

std::int32_t slot::id_from_endpoint2(const boost::asio::ip::udp::endpoint & ep)
{
    std::int16_t ret = -1;

    if (ep.address().is_v4())
    {
        auto ip = htonl(ep.address().to_v4().to_ulong());

        ip ^= htons(ep.port());
        
        ret = associated_id(std::string((char *)&ip, 4));
    }
    else
    {
        boost::asio::ip::address_v6::bytes_type bytes =
            ep.address().to_v6().to_bytes()
        ;
		
        std::uint32_t * ip = reinterpret_cast<std::uint32_t *>(&bytes[0]);

        for (auto i = 0; i < bytes.size() / sizeof(std::uint32_t); i++)
        {
            ip[i] ^= htons(ep.port());
        } 

        ret = associated_id(std::string((char *)ip, 4));
    }

    return ret;
}

bool slot::needs_update()
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    auto it = std::max_element(
        m_storage_nodes.begin(), m_storage_nodes.end(),
        &compare_storage_node_last_update
    );
    
    if (it != m_storage_nodes.end())
    {
        auto elapsed = std::chrono::duration_cast<
            std::chrono::seconds
        >(std::chrono::steady_clock::now() - it->second.last_update).count();
        

        if (elapsed > (update_interval * 8) || it->second.timeouts() > 0)
        {
            log_debug(
                "Slot #" << m_id << " needs update, last update = " << elapsed
            );
            return true;
        }
    }
    
    return false;
}

void slot::handle_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        // ...
        
        auto timeout = std::chrono::seconds(update_interval);
        
        timer_.expires_from_now(timeout);
        timer_.async_wait(
            std::bind(&slot::handle_tick, this, std::placeholders::_1)
        );
    }
}


void slot::queue_ping(const boost::asio::ip::udp::endpoint & ep)
{
    std::lock_guard<std::recursive_mutex> l(ping_queue_mutex_);
    
    bool was_empty = ping_queue_.empty();
    
    /**
     * Queue the ping.
     */
    ping_queue_.insert(ep);

    if (was_empty)
    {
        ping_queue_tick(boost::system::error_code());
    }
}

void slot::ping_queue_tick(const boost::system::error_code & ec)
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
            if (auto i = node_impl_.lock())
            {
                /**
                 * Get the slot id for the endpoint.
                 */
                std::int16_t slot_id = slot::id_from_endpoint(
                    *ping_queue_.begin()
                );
                
                /**
                 * Get a random number of storage nodes starting with current
                 * slot id.
                 */
                std::vector<storage_node> snodes;
                
                /**
                 * Generate a random number of storage nodes to piggy back.
                 */
                auto snodes_length = std::min(
                    (std::size_t)std::rand() % block::slot_length,
                    (std::size_t)std::rand() % block::slot_length
                );
                
                if (snodes_length > 0)
                {
                    /**
                     * Get the slots for the slot id.
                     */
                    auto slots = i->routing_table_->slots_for_id(slot_id);
                
                    for (auto & j : slots)
                    {
                        for (auto & k : j->storage_nodes())
                        {
                            if (snodes.size() >= snodes_length)
                            {
                                break;
                            }
                            
                            snodes.push_back(k);
                        }
                    }
                }

                for (auto & j : m_storage_nodes)
                {
                    if (*ping_queue_.begin() == j.second.endpoint)
                    {
                        auto elapsed = std::chrono::duration_cast<
                            std::chrono::seconds
                        >(std::chrono::steady_clock::now() -
                        j.second.last_update).count();

                        if (
                            elapsed > (update_interval * 8) ||
                            j.second.timeouts() > 0
                            )
                        {
                            std::uint16_t operation_id = i->ping(
                                *ping_queue_.begin(), snodes
                            );
                            
                            /**
                             * Ping the front of the queue and retain the
                             * transaction id and time sent for this ping for
                             * the storage node.
                             */
                            j.second.transaction_ids[operation_id] =
                                std::chrono::steady_clock::now()
                            ;
                        }
                
                        break;
                    }
                }

                /**
                 * Erase the front of the queue.
                 */
                ping_queue_.erase(ping_queue_.begin());
            }
        }
        
        if (!ping_queue_.empty())
        {
            /**
             * Generate a random timeout.
             */
            auto timeout = std::max(
                1000, (std::rand() % (block::slot_length * 1000))
            );
            
            /**
             * Start the ping queue timer.
             */
            ping_queue_timer_.expires_from_now(
                std::chrono::milliseconds(timeout)
            );
            ping_queue_timer_.async_wait(
                strand_.wrap(std::bind(&slot::ping_queue_tick,
                shared_from_this(), std::placeholders::_1))
            );
        }
    }
}

void slot_test_gen_random_str(char * s, const int len)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    unsigned i = len;
    
    while (i-- > 0)
    {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len - 1] = 0;
}

int rand_int(int upper_bound)
{
    std::srand(std::clock());

    return std::rand() % upper_bound;
}

int slot::run_test()
{
    boost::asio::io_service ios2;
    
    std::shared_ptr<node_impl> impl2;

    std::set<std::int16_t> slot_id_nonces;
    
    auto index = 0;
    
    for (;;)
    {
        std::uint16_t random_port = rand_int(65535 - 49152 + 1) + 49152;
        
        std::int16_t slot_id = id_from_endpoint2(
            boost::asio::ip::udp::endpoint(
            boost::asio::ip::address::from_string("192.168.245.5"), random_port)
        );
        
        printf(
            "index = %d, port = %d, slot_id = %d, total = %zu\n", index,
            random_port, slot_id, slot_id_nonces.size()
        );

        if (slot_id_nonces.find(slot_id) == slot_id_nonces.end())
        {
            slot_id_nonces.insert(slot_id);
        }

        if (slot_id_nonces.size() >= length)
        {
            printf("Slot distribution took %d rounds.\n", index);
            
            break;
        }
        
        index++;
    }

    slot_id_nonces.clear();
    
    index = 0;
    
    std::stringstream ss;
    
    for (;;)
    {
        std::string random_str = utility::to_string(std::rand()).substr(0, 5);
        
        std::int16_t slot_id = id(random_str);

        printf(
            "index = %d, random_str = %s, slot_id = %d, total = %zu\n", index,
            random_str.c_str(), slot_id, slot_id_nonces.size()
        );

        if (slot_id_nonces.find(slot_id) == slot_id_nonces.end())
        {
            ss << "\"" << random_str << "\""  << ", ";
        
            slot_id_nonces.insert(slot_id);
        }

        if (slot_id_nonces.size() >= length)
        {
            printf("Slot distribution took %d rounds.\n", index);
            
            break;
        }
        
        index++;
    }
    
    std::cout << ss.str() << std::endl;
    
    /**
     * The index should always be much less than 20,000.
     */
    assert(index < 20000);

    boost::asio::io_service ios;
    
    std::shared_ptr<node_impl> impl;
    
    std::uint32_t slot_id;
    
    /**
     * Check partial match.
     */
    slot_id = slot(ios, impl, "johnathan").id();
    
    assert(slot_id == 53);
    assert(slot_id == slot(ios, impl, "johna").id());

    std::cerr << "Test (slot) Completed." << std::endl;
    
    return 0;
}

char crc32_table[] =
    "\x00\x00\x00\x00\x96\x30\x07\x77\x2C\x61\x0E\xEE\xBA\x51\x09\x99"
    "\x19\xC4\x6D\x07\x8F\xF4\x6A\x70\x35\xA5\x63\xE9\xA3\x95\x64\x9E"
    "\x32\x88\xDB\x0E\xA4\xB8\xDC\x79\x1E\xE9\xD5\xE0\x88\xD9\xD2\x97"
    "\x2B\x4C\xB6\x09\xBD\x7C\xB1\x7E\x07\x2D\xB8\xE7\x91\x1D\xBF\x90"
    "\x64\x10\xB7\x1D\xF2\x20\xB0\x6A\x48\x71\xB9\xF3\xDE\x41\xBE\x84"
    "\x7D\xD4\xDA\x1A\xEB\xE4\xDD\x6D\x51\xB5\xD4\xF4\xC7\x85\xD3\x83"
    "\x56\x98\x6C\x13\xC0\xA8\x6B\x64\x7A\xF9\x62\xFD\xEC\xC9\x65\x8A"
    "\x4F\x5C\x01\x14\xD9\x6C\x06\x63\x63\x3D\x0F\xFA\xF5\x0D\x08\x8D"
    "\xC8\x20\x6E\x3B\x5E\x10\x69\x4C\xE4\x41\x60\xD5\x72\x71\x67\xA2"
    "\xD1\xE4\x03\x3C\x47\xD4\x04\x4B\xFD\x85\x0D\xD2\x6B\xB5\x0A\xA5"
    "\xFA\xA8\xB5\x35\x6C\x98\xB2\x42\xD6\xC9\xBB\xDB\x40\xF9\xBC\xAC"
    "\xE3\x6C\xD8\x32\x75\x5C\xDF\x45\xCF\x0D\xD6\xDC\x59\x3D\xD1\xAB"
    "\xAC\x30\xD9\x26\x3A\x00\xDE\x51\x80\x51\xD7\xC8\x16\x61\xD0\xBF"
    "\xB5\xF4\xB4\x21\x23\xC4\xB3\x56\x99\x95\xBA\xCF\x0F\xA5\xBD\xB8"
    "\x9E\xB8\x02\x28\x08\x88\x05\x5F\xB2\xD9\x0C\xC6\x24\xE9\x0B\xB1"
    "\x87\x7C\x6F\x2F\x11\x4C\x68\x58\xAB\x1D\x61\xC1\x3D\x2D\x66\xB6"
    "\x90\x41\xDC\x76\x06\x71\xDB\x01\xBC\x20\xD2\x98\x2A\x10\xD5\xEF"
    "\x89\x85\xB1\x71\x1F\xB5\xB6\x06\xA5\xE4\xBF\x9F\x33\xD4\xB8\xE8"
    "\xA2\xC9\x07\x78\x34\xF9\x00\x0F\x8E\xA8\x09\x96\x18\x98\x0E\xE1"
    "\xBB\x0D\x6A\x7F\x2D\x3D\x6D\x08\x97\x6C\x64\x91\x01\x5C\x63\xE6"
    "\xF4\x51\x6B\x6B\x62\x61\x6C\x1C\xD8\x30\x65\x85\x4E\x00\x62\xF2"
    "\xED\x95\x06\x6C\x7B\xA5\x01\x1B\xC1\xF4\x08\x82\x57\xC4\x0F\xF5"
    "\xC6\xD9\xB0\x65\x50\xE9\xB7\x12\xEA\xB8\xBE\x8B\x7C\x88\xB9\xFC"
    "\xDF\x1D\xDD\x62\x49\x2D\xDA\x15\xF3\x7C\xD3\x8C\x65\x4C\xD4\xFB"
    "\x58\x61\xB2\x4D\xCE\x51\xB5\x3A\x74\x00\xBC\xA3\xE2\x30\xBB\xD4"
    "\x41\xA5\xDF\x4A\xD7\x95\xD8\x3D\x6D\xC4\xD1\xA4\xFB\xF4\xD6\xD3"
    "\x6A\xE9\x69\x43\xFC\xD9\x6E\x34\x46\x88\x67\xAD\xD0\xB8\x60\xDA"
    "\x73\x2D\x04\x44\xE5\x1D\x03\x33\x5F\x4C\x0A\xAA\xC9\x7C\x0D\xDD"
    "\x3C\x71\x05\x50\xAA\x41\x02\x27\x10\x10\x0B\xBE\x86\x20\x0C\xC9"
    "\x25\xB5\x68\x57\xB3\x85\x6F\x20\x09\xD4\x66\xB9\x9F\xE4\x61\xCE"
    "\x0E\xF9\xDE\x5E\x98\xC9\xD9\x29\x22\x98\xD0\xB0\xB4\xA8\xD7\xC7"
    "\x17\x3D\xB3\x59\x81\x0D\xB4\x2E\x3B\x5C\xBD\xB7\xAD\x6C\xBA\xC0"
    "\x20\x83\xB8\xED\xB6\xB3\xBF\x9A\x0C\xE2\xB6\x03\x9A\xD2\xB1\x74"
    "\x39\x47\xD5\xEA\xAF\x77\xD2\x9D\x15\x26\xDB\x04\x83\x16\xDC\x73"
    "\x12\x0B\x63\xE3\x84\x3B\x64\x94\x3E\x6A\x6D\x0D\xA8\x5A\x6A\x7A"
    "\x0B\xCF\x0E\xE4\x9D\xFF\x09\x93\x27\xAE\x00\x0A\xB1\x9E\x07\x7D"
    "\x44\x93\x0F\xF0\xD2\xA3\x08\x87\x68\xF2\x01\x1E\xFE\xC2\x06\x69"
    "\x5D\x57\x62\xF7\xCB\x67\x65\x80\x71\x36\x6C\x19\xE7\x06\x6B\x6E"
    "\x76\x1B\xD4\xFE\xE0\x2B\xD3\x89\x5A\x7A\xDA\x10\xCC\x4A\xDD\x67"
    "\x6F\xDF\xB9\xF9\xF9\xEF\xBE\x8E\x43\xBE\xB7\x17\xD5\x8E\xB0\x60"
    "\xE8\xA3\xD6\xD6\x7E\x93\xD1\xA1\xC4\xC2\xD8\x38\x52\xF2\xDF\x4F"
    "\xF1\x67\xBB\xD1\x67\x57\xBC\xA6\xDD\x06\xB5\x3F\x4B\x36\xB2\x48"
    "\xDA\x2B\x0D\xD8\x4C\x1B\x0A\xAF\xF6\x4A\x03\x36\x60\x7A\x04\x41"
    "\xC3\xEF\x60\xDF\x55\xDF\x67\xA8\xEF\x8E\x6E\x31\x79\xBE\x69\x46"
    "\x8C\xB3\x61\xCB\x1A\x83\x66\xBC\xA0\xD2\x6F\x25\x36\xE2\x68\x52"
    "\x95\x77\x0C\xCC\x03\x47\x0B\xBB\xB9\x16\x02\x22\x2F\x26\x05\x55"
    "\xBE\x3B\xBA\xC5\x28\x0B\xBD\xB2\x92\x5A\xB4\x2B\x04\x6A\xB3\x5C"
    "\xA7\xFF\xD7\xC2\x31\xCF\xD0\xB5\x8B\x9E\xD9\x2C\x1D\xAE\xDE\x5B"
    "\xB0\xC2\x64\x9B\x26\xF2\x63\xEC\x9C\xA3\x6A\x75\x0A\x93\x6D\x02"
    "\xA9\x06\x09\x9C\x3F\x36\x0E\xEB\x85\x67\x07\x72\x13\x57\x00\x05"
    "\x82\x4A\xBF\x95\x14\x7A\xB8\xE2\xAE\x2B\xB1\x7B\x38\x1B\xB6\x0C"
    "\x9B\x8E\xD2\x92\x0D\xBE\xD5\xE5\xB7\xEF\xDC\x7C\x21\xDF\xDB\x0B"
    "\xD4\xD2\xD3\x86\x42\xE2\xD4\xF1\xF8\xB3\xDD\x68\x6E\x83\xDA\x1F"
    "\xCD\x16\xBE\x81\x5B\x26\xB9\xF6\xE1\x77\xB0\x6F\x77\x47\xB7\x18"
    "\xE6\x5A\x08\x88\x70\x6A\x0F\xFF\xCA\x3B\x06\x66\x5C\x0B\x01\x11"
    "\xFF\x9E\x65\x8F\x69\xAE\x62\xF8\xD3\xFF\x6B\x61\x45\xCF\x6C\x16"
    "\x78\xE2\x0A\xA0\xEE\xD2\x0D\xD7\x54\x83\x04\x4E\xC2\xB3\x03\x39"
    "\x61\x26\x67\xA7\xF7\x16\x60\xD0\x4D\x47\x69\x49\xDB\x77\x6E\x3E"
    "\x4A\x6A\xD1\xAE\xDC\x5A\xD6\xD9\x66\x0B\xDF\x40\xF0\x3B\xD8\x37"
    "\x53\xAE\xBC\xA9\xC5\x9E\xBB\xDE\x7F\xCF\xB2\x47\xE9\xFF\xB5\x30"
    "\x1C\xF2\xBD\xBD\x8A\xC2\xBA\xCA\x30\x93\xB3\x53\xA6\xA3\xB4\x24"
    "\x05\x36\xD0\xBA\x93\x06\xD7\xCD\x29\x57\xDE\x54\xBF\x67\xD9\x23"
    "\x2E\x7A\x66\xB3\xB8\x4A\x61\xC4\x02\x1B\x68\x5D\x94\x2B\x6F\x2A"
    "\x37\xBE\x0B\xB4\xA1\x8E\x0C\xC3\x1B\xDF\x05\x5A\x8D\xEF\x02\x2D"
    "\x00\x00\x21\x10\x42\x20\x63\x30\x84\x40\xA5\x50\xC6\x60\xE7\x70"
;

std::uint32_t slot::crc32(const std::uint32_t & crc, const std::uint32_t & word)
{
    std::uint32_t result;
    std::uint32_t v3;
    std::uint32_t v4;
    std::uint32_t v5;
    std::uint32_t v6;
    std::uint32_t data;
    std::uint32_t index;

    v3 = word >> 8;

    data = 0;
    index = (std::uint8_t)word ^ *(std::uint32_t *)&crc & 0xFF;
    std::memcpy((char *)&data, (char *)crc32_table + index * 4, 4);
    v4 = (*(std::uint32_t *)&crc >> 8) ^ data;

    data = 0;
    index = (std::uint8_t)v3 ^ (std::uint8_t)v4;
    std::memcpy((char *)&data,(char *)crc32_table + index * 4, 4);
    v5 = ((std::uint32_t)v4 >> 8) ^ data;
    v3 >>= 8;

    data = 0;
    index = (std::uint8_t)v3 ^ (std::uint8_t)v5;
    std::memcpy((char *)&data, (char *)crc32_table + index * 4, 4);
    v6 = ((std::uint32_t)v5 >> 8) ^ data;

    data = 0;
    index = (std::uint8_t)v6 ^ (std::uint16_t)((std::uint32_t)v3 >> 8);
    std::memcpy((char *)&data, (char *)crc32_table + index * 4, 4);
    result = ((std::uint32_t)v6 >> 8) ^ data;

    return result;
}

std::int32_t slot::associated_id(const std::string & val)
{
    std::uint32_t ret = 0xFFFFFFFF;

    if (!val.empty())
    { 
        for (std::size_t i = 0; i < std::min((std::size_t)5, val.size()); i++)
        {
            ret = crc32(ret, val[i]);
        }

        return ret & (length - 1);
    }

    return -1;
}
