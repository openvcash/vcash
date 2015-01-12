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

#include <sstream>

#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <database/http_transport.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/protocol.hpp>
#include <database/random.hpp>
#include <database/storage.hpp>
#include <database/tcp_acceptor.hpp>
#include <database/tcp_transport.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

tcp_acceptor::tcp_acceptor(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl
    )
    : io_service_(ios)
    , strand_(ios)
    , node_impl_(impl)
    , acceptor_ipv4_(ios)
    , acceptor_ipv6_(ios)
    , transports_timer_(ios)
{
    // ...
}

void tcp_acceptor::open(const std::uint16_t & port)
{
    assert(!acceptor_ipv4_.is_open());
    assert(!acceptor_ipv6_.is_open());
    
    boost::system::error_code ec;
    
    /**
     * Allocate the ipv4 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv4_endpoint(
        boost::asio::ip::address_v4::any(), port
    );
    
    /**
     * Open the ipv4 socket.
     */
    acceptor_ipv4_.open(boost::asio::ip::tcp::v4(), ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
    /**
     * Set option SO_REUSEADDR.
     */
    acceptor_ipv4_.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true)
    );
    
    /**
     * Bind the socket.
     */
    acceptor_ipv4_.bind(ipv4_endpoint, ec);
   
    if (ec)
    {
        throw std::runtime_error(
            "ipv4 bind failed, what = " + ec.message()
        );
    }
    
    /**
     * Listen
     */
    acceptor_ipv4_.listen();
    
    /**
     * Accept
     */
    do_ipv4_accept();
    
    /**
     * Allocate the ipv6 endpoint.
     */
    boost::asio::ip::tcp::endpoint ipv6_endpoint(
        boost::asio::ip::address_v6::any(),
        acceptor_ipv4_.local_endpoint().port()
    );
    
    /**
     * Open the ipv6 socket.
     */
    acceptor_ipv6_.open(boost::asio::ip::tcp::v6(), ec);
    
    if (ec)
    {
        throw std::runtime_error(ec.message());
    }
    
#if defined(__linux__) || defined(__APPLE__)
    acceptor_ipv6_.set_option(boost::asio::ip::v6_only(true));
#endif

    /**
     * Set option SO_REUSEADDR.
     */
    acceptor_ipv6_.set_option(
        boost::asio::ip::tcp::acceptor::reuse_address(true)
    );
    
    /**
     * Bind the socket.
     */
    acceptor_ipv6_.bind(ipv6_endpoint, ec);
   
    if (ec)
    {
        throw std::runtime_error(
            "ipv6 bind failed, what = " + ec.message()
        );
    }
    
    /**
     * Listen
     */
    acceptor_ipv6_.listen();
    
    /**
     * Accept
     */
    do_ipv6_accept();
    
    /**
     * Start the tick timer.
     */
    do_tick(1);
}

void tcp_acceptor::close()
{
    auto self(shared_from_this());
    
    io_service_.post(strand_.wrap(
        [this, self]()
    {
        acceptor_ipv4_.close();
        acceptor_ipv6_.close();
        transports_timer_.cancel();
    }));
}

const boost::asio::ip::tcp::endpoint tcp_acceptor::local_endpoint() const
{
    return acceptor_ipv4_.is_open() ?
        acceptor_ipv4_.local_endpoint() :
        acceptor_ipv6_.local_endpoint()
    ;
}

const std::vector< std::weak_ptr<tcp_transport> > &
    tcp_acceptor::tcp_transports() const
{
    std::lock_guard<std::recursive_mutex> l(tcp_transports_mutex_);
    
    return m_tcp_transports;
}

void tcp_acceptor::do_ipv4_accept()
{
    auto self(shared_from_this());
    
    auto t = std::make_shared<tcp_transport>(io_service_);
    
    std::lock_guard<std::recursive_mutex> l(tcp_transports_mutex_);
    
    m_tcp_transports.push_back(t);
    
    acceptor_ipv4_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            try
            {
                boost::asio::ip::tcp::endpoint remote_endpoint =
                    t->socket().remote_endpoint()
                ;
                
                log_debug("Accepting tcp connection from " << remote_endpoint);
                
                t->set_on_read(
                    [this, remote_endpoint](std::shared_ptr<tcp_transport> t,
                    const char * buf, const std::size_t & len)
                {
                    if (auto n = node_impl_.lock())
                    {
                        if (
                            std::string(buf).find("HTTP/") != std::string::npos
                            )
                        {
                            handle_http_message(t, buf, len);
                        }
                        else
                        {
                            n->handle_message(remote_endpoint, buf, len);

                            this->handle_message(t, buf, len);
                        }
                    }
                });
                
                t->start();
            }
            catch (std::exception & e)
            {
                log_none("TCP acceptor remote_endpoint, what = " << e.what());
            }
        }

        do_ipv4_accept();
    }));
}

void tcp_acceptor::do_ipv6_accept()
{
    auto self(shared_from_this());
    
    auto t = std::make_shared<tcp_transport>(io_service_);
    
    std::lock_guard<std::recursive_mutex> l(tcp_transports_mutex_);
    
    m_tcp_transports.push_back(t);
    
    acceptor_ipv6_.async_accept(t->socket(), strand_.wrap(
        [this, self, t](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            try
            {
                boost::asio::ip::tcp::endpoint remote_endpoint =
                    t->socket().remote_endpoint()
                ;
                
                log_debug("Accepting tcp connection from " << remote_endpoint);
            
                t->set_on_read(
                    [this, remote_endpoint](std::shared_ptr<tcp_transport> t,
                    const char * buf, const std::size_t & len)
                {
                    if (auto n = node_impl_.lock())
                    {
                        if (
                            std::string(buf).find("/ HTTP/") != std::string::npos
                            )
                        {
                            handle_http_message(t, buf, len);
                        }
                        else
                        {
                            n->handle_message(remote_endpoint, buf, len);

                            this->handle_message(t, buf, len);
                        }
                    }
                });
                
                t->start();
            
            }
            catch (std::exception & e)
            {
                log_none("TCP acceptor remote_endpoint, what = " << e.what());
            }
        }

        do_ipv6_accept();
    }));
}

void tcp_acceptor::do_tick(const std::uint32_t & seconds)
{
    transports_timer_.expires_from_now(std::chrono::seconds(seconds));
    transports_timer_.async_wait(strand_.wrap(
        [this, seconds](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            std::lock_guard<std::recursive_mutex> l(tcp_transports_mutex_);
            
            auto it = m_tcp_transports.begin();
            
            while (it != m_tcp_transports.end())
            {
                if (auto t = it->lock())
                {
                     ++it;
                }
                else
                {
                   it = m_tcp_transports.erase(it);
                }
            }
            
            do_tick(seconds);
        }
    }));
}

void tcp_acceptor::handle_message(
    const std::shared_ptr<tcp_transport> & t, const char * buf,
    const std::size_t & len
    )
{
    try
    {
        /**
         * Allocate the message.
         */
        message msg(buf, len);

        /**
         * Decode the message.
         */
        if (msg.decode())
        {
            switch (msg.header_code())
            {
                case protocol::message_code_ack:
                {
                    // ...
                }
                break;
                case protocol::message_code_nack:
                {
                    // ...
                }
                break;
                case protocol::message_code_ping:
                {
                    /**
                     * Send an ack message.
                     */
                    std::shared_ptr<message> ack(new message(
                        protocol::message_code_ack,
                        msg.header_transaction_id())
                    );
                    
                    if (ack->encode())
                    {
                        t->write(ack->data(), ack->size());
                    }
                }
                break;
                case protocol::message_code_store:
                case protocol::message_code_find:
                {
                    t->set_close_after_writes(true);
                    
                    std::shared_ptr<message> response(
                        new message(
                        protocol::message_code_error,
                        msg.header_transaction_id())
                    );
                    
                    if (response->encode())
                    {
                        t->write(response->data(), response->size());
                    }
                }
                break;
                case protocol::message_code_firewall:
                {
                    // ...
                }
                break;
                case protocol::message_code_probe:
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
                        std::lock_guard<std::recursive_mutex> l(
                            tcp_transports_mutex_
                        );
                        
                        if (m_tcp_transports.size() < max_tcp_connections)
                        {
                            t->set_read_timeout(1200);
                            
                            /**
                             * Send an ack message.
                             */
                            std::shared_ptr<message> ack(new message(
                                protocol::message_code_ack,
                                msg.header_transaction_id())
                            );
                            
                            message::attribute_uint32 attr;
                            
                            attr.type =
                                message::attribute_type_client_connection
                            ;
                            attr.length = sizeof(attr.value);
                            attr.value = 0;
                        
                            ack->uint32_attributes().push_back(attr);
            
                            if (ack->encode())
                            {
                                t->write(ack->data(), ack->size());
                            }
                        }
                        else
                        {
                            t->set_close_after_writes(true);
                            
                            std::shared_ptr<message> response(
                                new message(protocol::message_code_error,
                                msg.header_transaction_id())
                            );
                            
                            std::string error = "429 Too Many Requests";
                            
                            message::attribute_string attr;
                            
                            attr.type = message::attribute_type_error;
                            attr.length = error.size();
                            attr.value = error;
                            
                            response->string_attributes().push_back(attr);
                            
                            if (response->encode())
                            {
                                t->write(response->data(), response->size());
                            }
                        }
                    }
                    else
                    {
                        /**
                         * Send an ack message.
                         */
                        std::shared_ptr<message> ack(new message(
                            protocol::message_code_ack,
                            msg.header_transaction_id())
                        );
        
                        if (ack->encode())
                        {
                            t->write(ack->data(), ack->size());
                        }
                    }
                }
                break;
                case protocol::message_code_handshake:
                {
                    /**
                     * Send an ack message.
                     */
                    std::shared_ptr<message> ack(new message(
                        protocol::message_code_ack,
                        msg.header_transaction_id())
                    );
                    
                    if (ack->encode())
                    {
                        t->write(ack->data(), ack->size());
                    }
                }
                break;
                case protocol::message_code_proxy:
                {
                    if (
                        msg.endpoint_attributes().size() > 0 &&
                        msg.string_attributes().size() > 0
                        )
                    {
                        auto ep = msg.endpoint_attributes().front().value;
                        
                        std::string proxy_payload;
                        
                        for (auto & i : msg.string_attributes())
                        {
                            if (i.type == message::attribute_type_proxy_payload)
                            {
                                proxy_payload = i.value;
                                
                                break;
                            }
                        }
                    
                        if (proxy_payload.size() > 0)
                        {
                            std::string proxy_url;
                            
                            if (ep.port() == 443)
                            {
                                proxy_url =
                                    "https://" + ep.address().to_string() + "/"
                                ;
                            }
                            else
                            {
                                proxy_url =
                                    "http://" + ep.address().to_string() + "/"
                                ;
                            }
                            
                            std::shared_ptr<http_transport> t2 =
                                std::make_shared<http_transport>(
                                io_service_, proxy_url)
                            ;
                            
                            /**
                             * Set the http request messasge to the contents of
                             * the proxy blob.
                             */
                            t2->set_request(proxy_payload);
                            
                            t2->start(
                                [this, t, msg](
                                boost::system::error_code ec,
                                std::shared_ptr<http_transport> t2)
                            {
                                if (ec)
                                {
                                    /**
                                     * Allocate the nack message.
                                     */
                                    std::shared_ptr<message> response(
                                        new message(
                                        protocol::message_code_nack,
                                        msg.header_transaction_id())
                                    );
                                    
                                    /**
                                     * Return an
                                     * empty attribute_type_proxy_payload.
                                     */
                                    message::attribute_string attr2;
                                    
                                    attr2.type =
                                        message::attribute_type_proxy_payload
                                    ;
                                    attr2.length = 0;
                                    attr2.value = "";
                                    
                                    response->string_attributes().push_back(
                                        attr2
                                    );
                                
                                    if (response->encode())
                                    {
                                        t->write(
                                            response->data(),
                                            response->size()
                                        );
                                    }
                                }
                                else
                                {
                                    /**
                                     * Allocate the ack message.
                                     */
                                    std::shared_ptr<message> response(
                                        new message(protocol::message_code_ack,
                                        msg.header_transaction_id())
                                    );
                                    
                                    message::attribute_string attr2;
                                    
                                    attr2.type =
                                        message::attribute_type_proxy_payload
                                    ;
                                    attr2.length = t2->response_body().size();
                                    attr2.value = std::string(
                                        t2->response_body().data(),
                                        t2->response_body().size()
                                    );
                                    
                                    response->string_attributes().push_back(
                                        attr2
                                    );
                                    
                                    if (response->encode())
                                    {
                                        t->write(
                                            response->data(), response->size()
                                        );
                                    }
                                }
                            });
                        }
                    }
                }
                break;
                case protocol::message_code_error:
                {
                    log_debug("TCP (acceptor) transport got error message.");
                }
                break;
                default:
                {
                    t->set_close_after_writes(true);
                    
                    std::shared_ptr<message> response(
                        new message(
                        protocol::message_code_error,
                        msg.header_transaction_id())
                    );
                    
                    if (response->encode())
                    {
                        t->write(response->data(), response->size());
                    }
                }
                break;
            }
        }
    }
    catch (std::exception & e)
    {
        log_debug(
            "TCP acceptor handle_message failed, what = " << e.what() << "."
        );
    }
}

void tcp_acceptor::handle_http_message(
    const std::shared_ptr<tcp_transport> & t, const char * buf,
    const std::size_t & len
    )
{
    if (std::string(buf).find("/stats HTTP/") != std::string::npos)
    {
        std::stringstream body;
        
        try
        {
            /**
             * Allocate empty property tree object.
             */
            boost::property_tree::ptree pt;
            
            std::lock_guard<std::recursive_mutex> l(tcp_transports_mutex_);
            
            /**
             * Put stats_tcp_inbound into property tree.
             */
            pt.put("stats_tcp_inbound", std::to_string(m_tcp_transports.size()));
            
            if (auto n = node_impl_.lock())
            {
                pt.put(
                    "stats_udp_bps_inbound",
                    std::to_string(n->udp_multiplexor_->bps_received())
                );
                pt.put(
                    "stats_udp_bps_outbound",
                    std::to_string(n->udp_multiplexor_->bps_sent())
                );
                pt.put(
                    "stats_storage_entries",
                    std::to_string(n->storage_->entries().size())
                );
            }
            
            /**
             * Write property tree to json file.
             */
            write_json(body, pt);
        }
        catch (std::exception & e)
        {
            log_error(
                "TCP acceptor, what = " << e.what() << "."
            ); 
        }
        
        std::string response;
     
        response += "HTTP/1.1 200 OK\r\n";
        response += "Connection: close\r\n";
        response += "Content-Type: text/plain; charset=utf-8\r\n";
        response += "Content-Length: " +
            std::to_string(body.str().size()) + "\r\n"
        ;
        response += "\r\n";
        response += body.str();
        
        t->set_close_after_writes(true);
        
        t->write(response.data(), response.size());
    }
    else
    {
        std::string response;

        response += "HTTP/1.1 404 Not Found\r\n";
        response += "Connection: close\r\n";
        response += "Content-Type: text/plain; charset=utf-8\r\n";
        response += "Content-Length: " +
            std::to_string(strlen("These aren't the droids you're looking for.")
            ) + "\r\n"
        ;
        response += "\r\n";
        response += "These aren't the droids you're looking for.";
        
        t->set_close_after_writes(true);
        
        t->write(response.data(), response.size());
    }
}

int tcp_acceptor::run_test()
{
    boost::asio::io_service ios;
    
    auto acceptor = std::make_shared<tcp_acceptor>(
        ios, std::shared_ptr<node_impl> ()
    );
    
    try
    {
        acceptor->open(33033);
    }
    catch (std::exception & e)
    {
        std::cerr << "what = " << e.what() << std::endl;
    }
    
    ios.run();

    return 0;
}
