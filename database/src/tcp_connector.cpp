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
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/routing_table.hpp>
#include <database/tcp_connector.hpp>
#include <database/tcp_transport.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

tcp_connector::tcp_connector(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl,
    const std::function<void (const boost::asio::ip::tcp::endpoint &)> & f1,
    const std::function<void (const boost::asio::ip::tcp::endpoint &)> & f2,
    const std::function<void (const boost::asio::ip::tcp::endpoint &, message & msg)> & f3
    )
    : io_service_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , m_state(state_disconnected)
    , m_on_connected(f1)
    , m_on_disconnected(f2)
    , m_on_message(f3)
    , timer_(ios)
    , inflight_udp_probes_timer_(ios)
    , step4_timer_(ios)
    , tcp_attempts_(0)
    , handshake_timeout_timer_(ios)
    , handshake_transaction_id_(0)
    , ping_timer_(ios)
{
    // ...
}

void tcp_connector::start()
{
    if (auto n = node_impl_.lock())
    {
        auto self(shared_from_this());
    
        if (n->bootstrap_contacts().size() > 0)
        {
#if 0
            m_endpoints.push_back(boost::asio::ip::udp::endpoint(
                boost::asio::ip::address::from_string("192.168.4.2"), 1999)
            );
#else
            /** 
             * Put the bootstrap nodes into the endpoints queue.
             */
            m_endpoints.insert(
                m_endpoints.begin(), n->bootstrap_contacts().begin(),
                n->bootstrap_contacts().end()
            );
#endif
            /**
             * Get some of the storage nodes.
             */
            auto snodes = n->routing_table_->storage_nodes(200);
            
            /** 
             * Put the storage nodes into the endpoints queue.
             */
            m_endpoints.insert(
                m_endpoints.begin(), snodes.begin(), snodes.end()
            );
            
            m_endpoints.sort();
            m_endpoints.unique();
    
            /**
             * Randomize the bootstrap nodes.
             */
            std::vector<boost::asio::ip::udp::endpoint> randomized;
            randomized.insert(randomized.begin(), m_endpoints.begin(), m_endpoints.end());
            std::random_shuffle(randomized.begin(), randomized.end());
            m_endpoints.clear();
            m_endpoints.insert(m_endpoints.begin(), randomized.begin(), randomized.end());
            
            udp_probe_queue_.insert(
                udp_probe_queue_.begin(), m_endpoints.begin(), m_endpoints.end()
            );
            
            log_debug(
                "TCP connector has " << m_endpoints.size() <<
                " bootstrap nodes."
            );
            
            if (m_current_endpoint == boost::asio::ip::tcp::endpoint())
            {
                m_current_endpoint = boost::asio::ip::tcp::endpoint(
                    m_endpoints.front().address(), m_endpoints.front().port()
                );
            }
            
            m_endpoints.pop_front();
            
            do_tick(1);
            
            /**
             * Perform step 2.
             */
            do_step2();
        }
        else
        {
            log_debug("TCP connector has no bootstrap nodes, trying again.");

            timer_.expires_from_now(std::chrono::seconds(1));
            timer_.async_wait(strand_.wrap(
                [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    // :TODO: Only try 8 times.
                    
                    start();
                }
            }));
        }
    }   
}

void tcp_connector::stop()
{
    m_state = state_disconnected;
    
    if (auto t = tcp_transport_.lock())
    {
        t->stop();
    }
    
    timer_.cancel();
    inflight_udp_probes_timer_.cancel();
    step4_timer_.cancel();
    handshake_timeout_timer_.cancel();
    ping_timer_.cancel();
}

bool tcp_connector::send(const char * buf, const std::size_t & len)
{
    if (auto t = tcp_transport_.lock())
    {
        /**
         * Send the buffer.
         */
        t->write(buf, len);
        
        return true;
    }
    
    return false;
}

void tcp_connector::handle_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    switch (msg.header_code())
    {
        case protocol::message_code_ack:
        {
            auto it = sent_udp_probes_.find(msg.header_transaction_id());
            
            if (it != sent_udp_probes_.end())
            {
                bool has_client_connection = false;
                
                for (auto & i : msg.uint32_attributes())
                {
                    if (i.type == message::attribute_type_client_connection)
                    {
                        has_client_connection = true;
                        
                        break;
                    }
                }
                
                if (has_client_connection)
                {
                    log_debug(
                        "TCP connector got ack " <<
                        msg.header_transaction_id() <<
                        ", has_client_connection = " <<
                        has_client_connection << "."
                    );
                    
                    /**
                     * Because the node responded put it at the front of the
                     * queue.
                     */
                    m_endpoints.push_front(ep);
                    udp_probe_queue_.push_front(ep);
                }
                else
                {
                    // ...
                }
            
                sent_udp_probes_.erase(it);
            }
        }
        break;
        case protocol::message_code_nack:
        {
            auto it = sent_udp_probes_.find(msg.header_transaction_id());
            
            if (it != sent_udp_probes_.end())
            {
                log_debug(
                    "TCP connector got nack " << msg.header_transaction_id() <<
                    ", endpoints = " << msg.endpoint_attributes().size() << "."
                );
                
                for (auto & i : msg.endpoint_attributes())
                {
                    m_endpoints.push_back(i.value);
                    udp_probe_queue_.push_back(i.value);
                }
                
                m_endpoints.sort();
                m_endpoints.unique();
            }
        }
        break;
        default:
        break;
    }
}

void tcp_connector::do_step2()
{
    auto t = std::make_shared<tcp_transport>(io_service_);
    
    if (t)
    {
        t->set_on_read(
            [this](std::shared_ptr<tcp_transport> t,
            const char * buf, const std::size_t & len)
        {
            /**
             * Allocate the message.
             */
            message msg(buf, len);
            
            if (msg.decode())
            {
                if (m_on_message)
                {
                    m_on_message(m_current_endpoint, msg);
                }
                
                switch (msg.header_code())
                {
                    case protocol::message_code_ack:
                    {
                        log_debug("TCP connector got (tcp) ack.");
                        
                        bool has_client_connection = false;
                        
                        for (auto & i : msg.uint32_attributes())
                        {
                            if (
                                i.type ==
                                message::attribute_type_client_connection
                                )
                            {
                                has_client_connection = true;
                                
                                break;
                            }
                        }
                        
                        if (
                            handshake_transaction_id_ ==
                            msg.header_transaction_id()
                            )
                        {
                            log_debug("Got ack for handshake, sending probe.");
                            
                            handshake_timeout_timer_.cancel();

                            /**
                             * Allocate the probe message.
                             */
                            std::shared_ptr<message> msg(
                                new message(protocol::message_code_probe)
                            );
                        
                            message::attribute_uint32 attr;
                            
                            attr.type =
                                message::attribute_type_client_connection
                            ;
                            attr.length = sizeof(attr.value);
                            attr.value = 0;
                        
                            msg->uint32_attributes().push_back(attr);
                            
                            /**
                             * Encode the message.
                             */
                            msg->encode();
                            
                            /**
                             * Send the probe message.
                             */
                            t->write(msg->data(), msg->size());
                        }
                        else if (has_client_connection)
                        {
                            log_debug("Got ack for probe, finished.");
                            
                            do_finish();
                        }
                    }
                    break;
                    case protocol::message_code_nack:
                    {
                        log_debug("TCP connector got (tcp) nack.");
                    }
                    break;
                    case protocol::message_code_ping:
                    {
                        /**
                         * Allocate the ack message.
                         */
                        message response(
                            protocol::message_code_ack,
                            msg.header_transaction_id()
                        );
                    
                        /**
                         * Encode the message.
                         */
                        response.encode();
                    
                        /**
                         * Send the ack message.
                         */
                        t->write(response.data(), response.size());
                    }
                    break;
                    case protocol::message_code_handshake:
                    {
                        // ...
                    }
                    break;
                    case protocol::message_code_error:
                    {
                        log_debug(
                            "TCP connector got error message = " <<
                            (msg.string_attributes().empty() ?
                            std::string("null") :
                            msg.string_attributes().front().value) << "."
                        );
                        
                        do_step3();
                    }
                    break;
                    default:
                    {
                        do_step3();
                    }
                    break;
                }
            }
            else
            {
                log_debug("TCP connector message decode failed, do_step3.");
                
                do_step3();
            }
        });

        log_debug(
            "TCP connector tcp_transport connecting to " <<
            m_current_endpoint << "."
        );

        m_state = state_connecting;
        
        t->start(
            m_current_endpoint.address().to_string(), m_current_endpoint.port(),
            [this](boost::system::error_code ec, std::shared_ptr<tcp_transport> t)
        {
            if (ec)
            {
                log_debug(
                    "tcp_transport connect failed, message = " <<
                    ec.message() << "."
                );
                
                tcp_attempts_++;
                
                log_debug("tcp_attempts_ = " << tcp_attempts_);

                if (tcp_attempts_ >= 16)
                {
                    log_error(
                        "TCP connector failed (step 2) after " <<
                        tcp_attempts_ << " tcp attempts."
                    );
                    
                    auto self(shared_from_this());
                    
                    step4_timer_.expires_from_now(std::chrono::seconds(60));
                    step4_timer_.async_wait(strand_.wrap(
                        [this, self](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            /**
                             * Restart
                             */
                            stop();
                            tcp_attempts_ = 0;
                            start();
                        }
                    }));
                }
                else
                {
                    do_step3();
                }
            }
            else
            {
                log_debug("tcp_transport connect success.");

                auto self(shared_from_this());
                
                handshake_timeout_timer_.expires_from_now(
                    std::chrono::seconds(2)
                );
                handshake_timeout_timer_.async_wait(strand_.wrap(
                    [this, self, t](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_debug("TCP connector handshake timed out.");
                        
                        t->stop();
                        
                        do_step3();
                    }
                }));
                
                /**
                 * Allocate the handshake message.
                 */
                std::shared_ptr<message> msg(
                    new message(protocol::message_code_handshake)
                );

                /**
                 * Set the handshake transaction id.
                 */
                handshake_transaction_id_ =
                    msg->header_transaction_id()
                ;
                
                /**
                 * Encode the message.
                 */
                msg->encode();
            
                /**
                 * Send the handshake message.
                 */
                t->write(msg->data(), msg->size());
            }
        });
    }
    
    tcp_transport_ = t;
}

void tcp_connector::do_step3()
{
    if (udp_probe_queue_.size() > 0)
    {
        if (auto n = node_impl_.lock())
        {
            auto self(shared_from_this());
            
            inflight_udp_probes_timer_.expires_from_now(std::chrono::seconds(2));
            inflight_udp_probes_timer_.async_wait(strand_.wrap(
                [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    do_step4();
                }
            }));
            
            for (auto i = 0; i < 1; i++)
            {
                log_debug(
                    "TCP connector sending udp probe to " <<
                    udp_probe_queue_.front() << "."
                );
                
                /**
                 * Allocate the probe message.
                 */
                std::shared_ptr<message> msg(
                    new message(protocol::message_code_probe)
                );
                
                if (protocol::udp_obfuscation_enabled)
                {
                    msg->set_header_flags(
                        static_cast<protocol::message_flag_t> (
                        msg->header_flags() | protocol::message_flag_obfuscated)
                    );
                }
            
                message::attribute_uint32 attr;
                
                attr.type = message::attribute_type_client_connection;
                attr.length = sizeof(attr.value);
                attr.value = 0;
            
                msg->uint32_attributes().push_back(attr);
                
                /**
                 * Retain the transaction id.
                 */
                sent_udp_probes_[msg->header_transaction_id()] = std::time(0);

                /**
                 * Send the message.
                 */
                n->send_message(udp_probe_queue_.front(), msg);

                udp_probe_queue_.pop_front();
                
                if (udp_probe_queue_.empty())
                {
                    break;
                }
            }
        }
    }
    else
    {
        log_none("TCP connector step 3 failed, udp probe queue is empty.");
    }
}

void tcp_connector::do_step4()
{
    if (m_endpoints.size() > 0)
    {
        m_current_endpoint = boost::asio::ip::tcp::endpoint(
            m_endpoints.front().address(), m_endpoints.front().port()
        );
        
        m_endpoints.pop_front();

        log_debug(
            "TCP connector step 4 Connecting to = " << m_current_endpoint << "."
        );
        
        auto t = std::make_shared<tcp_transport>(io_service_);
        
        if (t)
        {
            t->set_on_read(
                [this](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                /**
                 * Allocate the message.
                 */
                message msg(buf, len);
                
                if (msg.decode())
                {
                    if (m_on_message)
                    {
                        m_on_message(m_current_endpoint, msg);
                    }
                
                    switch (msg.header_code())
                    {
                        case protocol::message_code_ack:
                        {
                            log_debug("TCP connector got (tcp) ack.");
                            
                            bool has_client_connection = false;
                            
                            for (auto & i : msg.uint32_attributes())
                            {
                                if (i.type == message::attribute_type_client_connection)
                                {
                                    has_client_connection = true;
                                    
                                    break;
                                }
                            }
                            
                            if (
                                handshake_transaction_id_ ==
                                msg.header_transaction_id()
                                )
                            {
                                
                                log_debug(
                                    "Got ack for handshake, sending probe."
                                );
                                
                                handshake_timeout_timer_.cancel();
 
                                /**
                                 * Allocate the probe message.
                                 */
                                std::shared_ptr<message> msg(
                                    new message(protocol::message_code_probe)
                                );
                            
                                message::attribute_uint32 attr;
                                
                                attr.type =
                                    message::attribute_type_client_connection
                                ;
                                attr.length = sizeof(attr.value);
                                attr.value = 0;
                            
                                msg->uint32_attributes().push_back(attr);
                                
                                /**
                                 * Encode the message.
                                 */
                                msg->encode();
                                
                                /**
                                 * Send the probe message.
                                 */
                                t->write(msg->data(), msg->size());
                            }
                            else if (has_client_connection)
                            {
                                log_debug("Got ack for probe, finished.");
                                
                                do_finish();
                            }
                        }
                        break;
                        case protocol::message_code_nack:
                        {
                            log_debug("TCP connector got (tcp) nack.");
                        }
                        break;
                        case protocol::message_code_ping:
                        {
                            /**
                             * Allocate the ack message.
                             */
                            message response(
                                protocol::message_code_ack,
                                msg.header_transaction_id()
                            );
                        
                            /**
                             * Encode the message.
                             */
                            response.encode();
                        
                            /**
                             * Send the ack message.
                             */
                            t->write(response.data(), response.size());
                        }
                        break;
                        case protocol::message_code_handshake:
                        {
                            // ...
                        }
                        break;
                        case protocol::message_code_error:
                        {
                            log_debug(
                                "TCP connector got error message = " <<
                                (msg.string_attributes().empty() ?
                                std::string("null") :
                                msg.string_attributes().front().value) << "."
                            );

                            t->stop();
                        }
                        break;
                        default:
                        {
                            t->stop();
                        }
                        break;
                    }
                }
                else
                {
                    t->stop();
                }
            });

            log_debug(
                "TCP connector tcp_transport connecting to " <<
                m_current_endpoint << "."
            );

            m_state = state_connecting;
            
            t->start(
                m_current_endpoint.address().to_string(), m_current_endpoint.port(),
                [this](boost::system::error_code ec, std::shared_ptr<tcp_transport> t)
            {
                if (ec)
                {
                    log_debug(
                        "tcp_transport connect failed, message = " <<
                        ec.message() << "."
                    );
                    
                    tcp_attempts_++;
                }
                else
                {
                    log_debug("tcp_transport connect success.");

                    auto self(shared_from_this());
                    
                    handshake_timeout_timer_.expires_from_now(
                        std::chrono::seconds(2)
                    );
                    handshake_timeout_timer_.async_wait(strand_.wrap(
                        [this, self, t](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            log_debug("TCP connector handshake timed out.");
                            
                            t->stop();
                            
                            do_step3();
                        }
                    }));
                
                    /**
                     * Allocate the handshake message.
                     */
                    std::shared_ptr<message> msg(
                        new message(protocol::message_code_handshake)
                    );
                
                    /**
                     * Set the handshake transaction id.
                     */
                    handshake_transaction_id_ =
                        msg->header_transaction_id()
                    ;

                    /**
                     * Encode the message.
                     */
                    msg->encode();
                    
                    /**
                     * Send the handshake message.
                     */
                    t->write(msg->data(), msg->size());
                }
            });
        }
        
        tcp_transport_ = t;

        if (tcp_attempts_ == 16)
        {
            log_error(
                "TCP connector failed after " << tcp_attempts_ <<
                " tcp attempts."
            );
            
            auto self(shared_from_this());
            
            step4_timer_.expires_from_now(std::chrono::seconds(60));
            step4_timer_.async_wait(strand_.wrap(
                [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    /**
                     * Restart
                     */
                    stop();
                    tcp_attempts_ = 0;
                    start();
                }
            }));
        }
        else
        {
            // wait N seconds and do_step3();
            
            auto self(shared_from_this());
            
            step4_timer_.expires_from_now(std::chrono::seconds(2));
            step4_timer_.async_wait(strand_.wrap(
                [this, self](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    do_step3();
                }
            }));
        } 
    }
    else
    {
        log_error("TCP connector step 4 failed, restarting.");
        
        /**
         * Restart
         */
        stop();
        start();
    }
}

void tcp_connector::do_finish()
{
    if (auto t = tcp_transport_.lock())
    {
        try
        {
            m_current_endpoint =
                t->socket().remote_endpoint()
            ;
            
        }
        catch (std::exception & e)
        {
            // ...
        }
        
        if (t->state() == tcp_transport::state_connected)
        {
            m_state = state_connected;
        }
        else
        {
            m_state = state_disconnected;
        }
    }
    
    if (m_state == state_connected)
    {
        log_debug(
            "TCP connector finish success, connected to " <<
            m_current_endpoint << "."
        );
        
        inflight_udp_probes_timer_.cancel();
        step4_timer_.cancel();
        handshake_timeout_timer_.cancel();
        
        /**
         * Start the ping timer.
         */
        do_ping(95);
        
        log_info(
            "TCP connector connection to " << m_current_endpoint <<
            " established."
        );
        
        if (m_on_connected)
        {
            m_on_connected(m_current_endpoint);
        }
    }
    else
    {
        log_debug("TCP connector finish failed.");
    }
}

void tcp_connector::do_tick(const std::uint32_t & seconds)
{
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(seconds));
    timer_.async_wait(strand_.wrap(
        [this, self](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {

            /**
             * Check if we are already connected.
             */
            auto connected = false;
            
            if (auto t = tcp_transport_.lock())
            {
                try
                {
                    m_current_endpoint =
                        t->socket().remote_endpoint()
                    ;
                    
                }
                catch (std::exception & e)
                {
                    // ...
                }
                
                connected = t->state() == tcp_transport::state_connected;
            }
            
            if (connected)
            {
                log_none(
                    "TCP connector is connected to " << m_current_endpoint <<
                    "."
                );
            }
            else
            {
                if (m_state == state_connecting)
                {
                    // ...
                }
                else if (m_state == state_connected)
                {
                    log_debug("TCP connector is not connected, step 2.");
                    
                    m_state = state_disconnected;
                    
                    log_info(
                        "TCP connector connection to " << m_current_endpoint <<
                        " closed."
                    );

                    if (m_on_disconnected)
                    {
                        m_on_disconnected(m_current_endpoint);
                    }
                    
                    do_step2();
                }
                else
                {
                    do_step2();
                }
            }
            
            auto it = sent_udp_probes_.begin();
            
            while (it != sent_udp_probes_.end())
            {
                if (std::time(0) - it->second > 5)
                {
                    log_debug(
                        "TCP connector udp probe " << it->first << " timed out."
                    );
                    
                    it = sent_udp_probes_.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            do_tick(1);
        }
    }));
}

void tcp_connector::do_ping(const std::uint32_t & seconds)
{
    auto self(shared_from_this());
    
    ping_timer_.expires_from_now(std::chrono::seconds(seconds));
    ping_timer_.async_wait(strand_.wrap(
        [this, self](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (auto t = tcp_transport_.lock())
            {
                log_debug(
                    "TCP connector sending ping to " << m_current_endpoint <<
                    "."
                );
                
                /**
                 * Allocate the ping message.
                 */
                std::shared_ptr<message> msg(
                    new message(protocol::message_code_ping)
                );
            
                /**
                 * Encode the message.
                 */
                msg->encode();
            
                /**
                 * Send the ping message.
                 */
                t->write(msg->data(), msg->size());
            }
            
            do_ping(95);
        }
    }));
}
