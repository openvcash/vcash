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

#include <database/crypto.hpp>
#include <database/firewall.hpp>
#include <database/firewall_manager.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/routing_table.hpp>
#if (!defined __arm__ && !defined __thumb__ && \
    !defined _M_ARM && !defined _M_ARMT)
#include <database/nat_pmp_client.hpp>
#endif // __arm__
#include <database/network.hpp>
#if (!defined __arm__ && !defined __thumb__ && \
    !defined _M_ARM && !defined _M_ARMT)
#include <database/upnp_client.hpp>
#endif // __arm__

/**
 * Get local ip address.
 * Add firewall rules.
 * Start nat-pmp and upnp (map ports).
 * Perform firewall checks.
 */

using namespace database;

firewall_manager::firewall_manager(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl
    )
    : io_service_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , timer_(ios)
    , firewall_check_timer_(ios)
    , firewall_check_queue_timer_(ios)
    , m_checks_sent(0)
    , m_tcp_checks_success(0)
    , m_udp_checks_success(0)
    , m_tcp_score(0.0f)
    , m_udp_score(0.0f)
{
    // ...
}

void firewall_manager::start()
{    
    /**
     * Get the local ip address.
     */
    local_address_ = network::local_address();
    
    log_info("Firewall manager discovered local ip " << local_address_ << ".");
    
    /**
     * Allocate the firewall.
     */
    firewall_.reset(new firewall());
    
    /**
     * Start the firewall.
     */
    firewall_->start();
    
    if (network::address_is_private(local_address_))
    {
        log_info("Firewall manager has determined local ip is private.");
#if (!defined __arm__ && !defined __thumb__ && \
        !defined _M_ARM && !defined _M_ARMT)
        /**
         * Allocate the nat_pmp_client.
         */
        nat_pmp_client_.reset(new nat_pmp_client(io_service_));

        /**
         * Allocate the upnp_client.
         */
        upnp_client_.reset(new upnp_client(io_service_));

        /**
         * Start the nat_pmp_client.
         */
        nat_pmp_client_->start();
        
        /**
         * Start the upnp_client.
         */
        upnp_client_->start();
#endif // __arm__
    }
    else if (network::address_is_any(local_address_))
    {
        // ...
    }
    else if (network::address_is_loopback(local_address_))
    {
        // ...
    }
    else if (network::address_is_multicast(local_address_))
    {
        // ...
    }
    else
    {
        log_info("Firewall manager has determined local ip is public.");
    }

    /**
     * Start the timer.
     */
    auto timeout = std::chrono::seconds(1);
    
    timer_.expires_from_now(timeout);
    timer_.async_wait(
        strand_.wrap(std::bind(&firewall_manager::tick, shared_from_this(),
        std::placeholders::_1))
    );
    
    /**
     * Start the timer.
     */
    timeout = std::chrono::seconds(8);
    
    firewall_check_timer_.expires_from_now(timeout);
    firewall_check_timer_.async_wait(
        strand_.wrap(std::bind(&firewall_manager::firewall_check_tick,
        shared_from_this(), std::placeholders::_1))
    );
}

void firewall_manager::stop()
{
    stop_firewall_checks();
    
    timer_.cancel();
    
    if (firewall_)
    {
        firewall_->stop();
    }
#if (!defined __arm__ && !defined __thumb__ && \
    !defined _M_ARM && !defined _M_ARMT)
    if (nat_pmp_client_)
    {
        nat_pmp_client_->stop();
    }
    
    if (upnp_client_)
    {
        upnp_client_->stop();
    }
#endif // __arm__
}

const float & firewall_manager::tcp_score() const
{
    return m_tcp_score;
}

const float & firewall_manager::udp_score() const
{
    return m_udp_score;
}

bool firewall_manager::handle_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_code() == protocol::message_code_ack)
    {
        std::lock_guard<std::recursive_mutex> l(
            inflight_udp_firewall_checks_mutex_
        );
        
        auto it = inflight_udp_firewall_checks_.find(msg.header_transaction_id());
        
        if (it != inflight_udp_firewall_checks_.end())
        {
            log_debug(
                "Firewall (udp) check " << it->first << " success."
            );

            m_udp_checks_success++;
            
            inflight_udp_firewall_checks_.erase(it);
            
            return true;
        } 
    }
    
    return false;
}

bool firewall_manager::handle_message(
    const boost::asio::ip::tcp::endpoint & ep, message & msg
    )
{
    if (msg.header_code() == protocol::message_code_ack)
    {
        std::lock_guard<std::recursive_mutex> l(
            inflight_tcp_firewall_checks_mutex_
        );
        
        auto it = inflight_tcp_firewall_checks_.find(
            msg.header_transaction_id()
        );
        
        if (it != inflight_tcp_firewall_checks_.end())
        {
            log_debug(
                "Firewall (tcp) check " << it->first << " success."
            );

            m_tcp_checks_success++;
            
            inflight_tcp_firewall_checks_.erase(it);
            
            return true;
        } 
    }

    return false;
}

void firewall_manager::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
#if (!defined __arm__ && !defined __thumb__ && \
    !defined _M_ARM && !defined _M_ARMT)        
        // :TODO: fix
        static bool did_map_shit = false;
        
        if (!did_map_shit)
        {
            did_map_shit = true;

            if (auto n = node_impl_.lock())
            {
                if (nat_pmp_client_)
                {
                    /**
                     * Add a nat-pmp mapping.
                     */
                    nat_pmp_client_->add_mapping(
                        nat_pmp::protocol_tcp, n->config().port()
                    );
                    
                    /**
                     * Add a nat-pmp mapping.
                     */
                    nat_pmp_client_->add_mapping(
                        nat_pmp::protocol_udp, n->config().port()
                    );
                }

                if (upnp_client_)
                {
                    /**
                     * Add a upnp mapping.
                     */
                    upnp_client_->add_mapping(
                        upnp_client::protocol_tcp, n->config().port()
                    );
                    
                    /**
                     * Add a upnp mapping.
                     */
                    upnp_client_->add_mapping(
                        upnp_client::protocol_udp, n->config().port()
                    );
                }
            }
        }
#endif // __arm__

        std::lock_guard<std::recursive_mutex> l1(
            inflight_tcp_firewall_checks_mutex_
        );
        
        auto it = inflight_tcp_firewall_checks_.begin();
        
        while (it != inflight_tcp_firewall_checks_.end())
        {
            auto t = std::time(0) - it->second;
            
            if (t > 8)
            {
                log_debug(
                    "Firewall manager (tcp) check " << it->first <<
                    " timed out."
                );
                
                it = inflight_tcp_firewall_checks_.erase(it);
            }
            else
            {
                log_debug(
                    "Firewall manager (tcp) check " << it->first <<
                    " is pending response, sent " << t << " seconds ago."
                );
                
                ++it;
            }
        }
        
        if (inflight_tcp_firewall_checks_.empty())
        {
            if (m_checks_sent > 0)
            {
                /**
                 * Calculate the score.
                 */
                m_tcp_score = (
                    (float)m_tcp_checks_success /
                    (float)m_checks_sent) * 100.0f
                ;
                
                log_debug(
                    "Firewall manager (tcp) score = " << m_tcp_score << "."
                );
            }
        }
        
        std::lock_guard<std::recursive_mutex> l2(
            inflight_udp_firewall_checks_mutex_
        );
        
        it = inflight_udp_firewall_checks_.begin();
        
        while (it != inflight_udp_firewall_checks_.end())
        {
            auto t = std::time(0) - it->second;
            
            if (t > 8)
            {
                log_debug(
                    "Firewall manager (udp) check " << it->first <<
                    " timed out."
                );
                
                it = inflight_udp_firewall_checks_.erase(it);
            }
            else
            {
                log_debug(
                    "Firewall manager (udp) check " << it->first <<
                    " is pending response, sent " << t << " seconds ago."
                );
                
                ++it;
            }
        }
        
        if (inflight_udp_firewall_checks_.empty())
        {
            if (m_checks_sent > 0)
            {
                /**
                 * Calculate the score.
                 */
                m_udp_score = (
                    (float)m_udp_checks_success /
                    (float)m_checks_sent) * 100.0f
                ;
                
                log_debug(
                    "Firewall manager (udp) score = " << m_udp_score << "."
                );
            }
        }
        
        /**
         * Start the timer.
         */
        auto timeout = std::chrono::seconds(8);
        
        timer_.expires_from_now(timeout);
        timer_.async_wait(
            strand_.wrap(std::bind(&firewall_manager::tick, shared_from_this(),
            std::placeholders::_1))
        );
    }
}

void firewall_manager::firewall_check_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * Start the firewall checks.
         */
        start_firewall_checks();
        
        firewall_check_timer_.expires_from_now(std::chrono::seconds(3600));
        firewall_check_timer_.async_wait(
            strand_.wrap(std::bind(&firewall_manager::firewall_check_tick,
            shared_from_this(), std::placeholders::_1))
        );
    }
}

void firewall_manager::start_firewall_checks()
{
    m_tcp_checks_success = 0;
    m_udp_checks_success = 0;
    m_checks_sent = 0;
    
    if (auto n = node_impl_.lock())
    {
        /**
         * Get all of the storage nodes.
         */
        const auto & snodes = n->routing_table_->storage_nodes();

        /**
         * Randomize the storage nodes.
         */
        std::vector<boost::asio::ip::udp::endpoint> randomized(
            snodes.begin(), snodes.end()
        );
        std::random_shuffle(randomized.begin(), randomized.end());
        
        /**
         * Prune the storage nodes.
         */
        if (randomized.size() > 8)
        {
            randomized.resize(8);
        }
        
        std::lock_guard<std::recursive_mutex> l(firewall_check_queue_mutex_);
        
        /**
         * Insert the endpoints into the cehck queue.
         */
        firewall_check_queue_.insert(
            firewall_check_queue_.begin(), randomized.begin(), randomized.end()
        );

        auto timeout = std::chrono::seconds(1);
    
        /**
         * Start processing the firewall check queue.
         */
        firewall_check_queue_timer_.expires_from_now(timeout);
        firewall_check_queue_timer_.async_wait(
            strand_.wrap(
            std::bind(&firewall_manager::process_firewall_check_queue_tick,
            shared_from_this(), std::placeholders::_1))
        );
    }
}

void firewall_manager::stop_firewall_checks()
{
    firewall_check_timer_.cancel();
    firewall_check_queue_timer_.cancel();
}

void firewall_manager::process_firewall_check_queue_tick(
    const boost::system::error_code & ec
    )
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(firewall_check_queue_mutex_);
        
        if (!firewall_check_queue_.empty())
        {
            /**
             * The boost::asio::ip::udp::socket.
             */
            std::unique_ptr<boost::asio::ip::udp::socket> udp_socket;
            
            /**
             * Allocate the socket.
             */
            udp_socket.reset(new boost::asio::ip::udp::socket(io_service_));
            
            boost::system::error_code ec;
            
            /**
             * Open the socket.
             */
            udp_socket->open(
                local_address_.is_v4() ?
                boost::asio::ip::udp::v4() : boost::asio::ip::udp::v6(), ec
            );
            
            if (ec)
            {
                log_error(
                    "Firewall manager open socket failed message = " <<
                    ec.message() << "."
                );
            }
            else
            {
                if (auto n = node_impl_.lock())
                {
                    /**
                     * Allocate the messsage.
                     */
                    std::shared_ptr<message> msg(
                        new message(protocol::message_code_firewall)
                    );
                    
                    if (protocol::udp_obfuscation_enabled)
                    {
                        msg->set_header_flags(
                            static_cast<protocol::message_flag_t> (
                            msg->header_flags() | protocol::message_flag_obfuscated)
                        );
                    }
            
                    /**
                     * Set the message header flag DONTROUTE so that other nodes do
                     * not add this endpoint to their routing table.
                     */
                    msg->set_header_flags(
                        static_cast<protocol::message_flag_t> (
                        msg->header_flags() | protocol::message_flag_dontroute)
                    );
                    
                    /**
                     * Allocate the endpoint attribute with our local endpoint.
                     */
                    message::attribute_endpoint attr;
                    attr.type = message::attribute_type_endpoint;
                    attr.length = 0;
                    attr.value = boost::asio::ip::udp::endpoint(
                        local_address_, n->config().port()
                    );
                    msg->endpoint_attributes().push_back(attr);
                    
                    /**
                     * Retain the tid and time.
                     */
                    inflight_tcp_firewall_checks_.insert(
                        std::make_pair(msg->header_transaction_id(),
                        std::time(0))
                    );
                    
                    /**
                     * Retain the tid and time.
                     */
                    inflight_udp_firewall_checks_.insert(
                        std::make_pair(msg->header_transaction_id(),
                        std::time(0))
                    );
                    
                    /**
                     * Encode the message.
                     */
                    if (msg->encode())
                    {
                        if (protocol::udp_obfuscation_enabled)
                        {
                            if (auto n = node_impl_.lock())
                            {
                                auto key = crypto::generate_obfuscation_key(
                                    n->public_endpoint().address().to_string()
                                );
 
                                if (msg->obfuscate(key))
                                {
                                    // ...
                                }
                                else
                                {
                                    log_debug(
                                        "Firewall manager, message Obfuscation "
                                        "failed."
                                    );
                                }
                            }
                        }
                        
                        log_debug(
                            "Firewall manager sending message to " <<
                            firewall_check_queue_.front() << "."
                        );
                        
                        m_checks_sent++;
                        
                        try
                        {
                            /**
                             * Send the message.
                             */
                            udp_socket->send_to(
                                boost::asio::buffer(msg->data(), msg->size()),
                                firewall_check_queue_.front()
                            );
                        }
                        catch (std::exception & e)
                        {
                            log_error(
                                "Firewall manaer send_to failed, what = " <<
                                e.what() << "."
                            );
                        }
                        
                        /**
                         * Close the socket.
                         */
                        udp_socket->close();
                    }
                    else
                    {
                        log_error("Firewall manager message encoding failed.");
                    }
                    
                    firewall_check_queue_.pop_front();
                    
                    if (!firewall_check_queue_.empty())
                    {
                        auto timeout = std::chrono::seconds(8);
                    
                        /**
                         * Start processing the firewall check queue.
                         */
                        firewall_check_queue_timer_.expires_from_now(timeout);
                        firewall_check_queue_timer_.async_wait(
                            strand_.wrap(
                            std::bind(&firewall_manager::process_firewall_check_queue_tick,
                            shared_from_this(), std::placeholders::_1))
                        );
                    }
                    else
                    {
                        // ...
                    }
                }
            }
        }
    }
}
