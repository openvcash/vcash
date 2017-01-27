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

#include <iterator>

#include <database/crypto.hpp>
#include <database/ecdhe.hpp>
#include <database/key_pool.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/protocol.hpp>
#include <database/stack.hpp>
#include <database/udp_handler.hpp>
#include <database/udp_multiplexor.hpp>
#include <database/whirlpool.hpp>

using namespace database;

udp_handler::udp_handler(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl,
    std::shared_ptr<udp_multiplexor> & multiplexor   
    )
    : handler(ios, impl, multiplexor)
{
    // ...
}

void udp_handler::stop()
{
    // ...
}

void udp_handler::send_to(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    udp_multiplexor_.lock()->send_to(ep, buf, len);
}

bool udp_handler::on_async_receive_from(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    if (auto n = node_impl_.lock())
    {
        if (static_cast<std::uint8_t> (buf[0]) & protocol::message_flag_0x40)
        {
            if (
                static_cast<std::uint8_t> (buf[0]) &
                protocol::message_flag_encrypted
                )
            {
                /**
                 * Allocate the message.
                 */
                message msg(buf, len);
                
                /**
                 * Get the shared secret.
                 */
                auto shared_secret = n->get_key_pool()->find(ep);

                if (shared_secret.size() > 0 && msg.decrypt(shared_secret))
                {
                    on_data(ep, msg.data(), msg.size());
                }
                else
                {
                    protocol::header_t hdr;
                    
                    std::memcpy(&hdr, buf, sizeof(hdr));
       
                    hdr.transaction_id = ntohs(hdr.transaction_id);
                
                    log_debug(
                        "UDP handler, message " << hdr.transaction_id  <<
                        " decryption failed."
                    );
                    
                    /**
                     * Allocate the protocol::message_code_public_key_ping.
                     */
                    std::shared_ptr<message> request(
                        new message(protocol::message_code_public_key_ping)
                    );
                    
                    /**
                     * Add their public endpoint as a
                     * message::attribute_type_endpoint.
                     */
                    message::attribute_endpoint attr1;
                    
                    attr1.type = message::attribute_type_endpoint;
                    attr1.length = 0;
                    attr1.value = ep;
                    
                    request->endpoint_attributes().push_back(attr1);
                    
                    /**
                     * Add our public key as a message::attribute_string of
                     * type message::attribute_type_public_key.
                     */
                    message::attribute_string attr2;
                    
                    attr2.type = message::attribute_type_public_key;
                    attr2.length = n->get_ecdhe()->public_key().size();
                    attr2.value = n->get_ecdhe()->public_key();
                    
                    request->string_attributes().push_back(attr2);
                    
                    /**
                     * Send the request.
                     */
                    send_message(ep, request);

                    return false;
                }
            }
            else
            {
                on_data(ep, buf, len);
            }
        }
        else
        {
            n->on_app_udp_receive(
                ep.address().to_string().c_str(), ep.port(), buf, len
            );
        }
    }
    else
    {
        return false;
    }
    
    return true;
}

void udp_handler::send_message(
    const boost::asio::ip::udp::endpoint & ep, std::shared_ptr<message> msg
    )
{    
    if (auto m = udp_multiplexor_.lock())
    {
        try
        {
            if (auto n = node_impl_.lock())
            {
                /**
                 * If we are operating in interface mode we must set the message
                 * header flag DONTROUTE so that other nodes do not add us to
                 * their routing table.
                 */
                if (
                    n->config().operation_mode() ==
                    stack::configuration::operation_mode_interface
                    )
                {
                    msg->set_header_flags(
                        static_cast<protocol::message_flag_t> (
                        msg->header_flags() | protocol::message_flag_dontroute)
                    );
                }
            }

            /**
             * Compress the attributes if needed.
             */
            if (
                msg->string_attributes().size() > 0 ||
                msg->endpoint_attributes().size() > 1 ||
                msg->uint32_attributes().size() > 1
                )
            {
                /**
                 * Set the compressed flag.
                 */
                msg->set_header_flags(
                    static_cast<protocol::message_flag_t> (
                    msg->header_flags() | protocol::message_flag_compressed)
                );
            }

            /**
             * If encryption is enabled public key messages are left as
             * plain text.
             */
            auto encrypt =
                protocol::udp_ecdhe_enabled &&
                msg->header_code() != protocol::message_code_public_key_ping &&
                msg->header_code() != protocol::message_code_public_key_pong
            ;
            
            if (encrypt)
            {
                msg->set_header_flags(
                    static_cast<protocol::message_flag_t> (
                    msg->header_flags() | protocol::message_flag_encrypted)
                );
            }
            
            if (msg->encode())
            {
                if (encrypt)
                {
                    if (auto n = node_impl_.lock())
                    {
                        /**
                         * Get the shared secret.
                         */
                        auto shared_secret = n->get_key_pool()->find(ep);
                        
                        /**
                         * If we do not have a shared secret then send a
                         * protocol::message_code_public_key_ping message, the
                         * remote node will respond with a
                         * protocol::message_code_public_key_pong in which we
                         * will respond with a protocol::message_code_ping.
                         */
                        if (
                            shared_secret.size() > 0 &&
                            msg->encrypt(shared_secret)
                            )
                        {
#if 1 // Test to see what size certain packets are.
                            if (
                                msg->header_code() == protocol::message_code_ack
                                )
                            {
                                log_debug(
                                    "UDP ACK: " << ep << ", BYTES: " <<
                                    msg->size()
                                );
                            }
                            else if (
                                msg->header_code() == protocol::message_code_ping
                                )
                            {
                                log_debug(
                                    "UDP PING:" << ep << ", BYTES: " <<
                                    msg->size()
                                );
                            }
#endif
                            /**
                             * Send the message.
                             */
                            send_to(ep, msg->data(), msg->size());
                        }
                        else
                        {
                            /**
                             * Send the ECDHE.
                             */
                            if (n->get_ecdhe())
                            {
                                /**
                                 * Allocate the
                                 * protocol::message_code_public_key_ping.
                                 */
                                std::shared_ptr<message> request(
                                    new message(
                                    protocol::message_code_public_key_ping)
                                );
                                
                                /**
                                 * If we are operating in interface mode we
                                 * must set the message header flag DONTROUTE
                                 * so that other nodes do not add us to their
                                 * routing table.
                                 */
                                if (
                                    n->config().operation_mode() ==
                                    stack::configuration::operation_mode_interface
                                    )
                                {
                                    request->set_header_flags(
                                        static_cast<protocol::message_flag_t> (
                                        request->header_flags() |
                                        protocol::message_flag_dontroute)
                                    );
                                }
                            
                                /**
                                 * Add their public endpoint as a
                                 * message::attribute_type_endpoint.
                                 */
                                message::attribute_endpoint attr1;
                                
                                attr1.type = message::attribute_type_endpoint;
                                attr1.length = 0;
                                attr1.value = ep;
                                
                                request->endpoint_attributes().push_back(attr1);
                
                                /**
                                 * Add our public key as a
                                 * message::attribute_string of type
                                 * message::attribute_type_public_key.
                                 */
                                message::attribute_string attr2;
                                
                                attr2.type =
                                    message::attribute_type_public_key
                                ;
                                attr2.length =
                                    n->get_ecdhe()->public_key().size()
                                ;
                                attr2.value = n->get_ecdhe()->public_key();
                                
                                request->string_attributes().push_back(attr2);
                                
                                /**
                                 * Compress the attributes if needed.
                                 */
                                if (
                                    request->string_attributes().size() > 0 ||
                                    request->endpoint_attributes().size() > 1 ||
                                    request->uint32_attributes().size() > 1
                                    )
                                {
                                    /**
                                     * Set the compressed flag.
                                     */
                                    request->set_header_flags(
                                        static_cast<protocol::message_flag_t> (
                                        request->header_flags() |
                                        protocol::message_flag_compressed)
                                    );
                                }
                
                                /**
                                 * Encode the request.
                                 */
                                if (request->encode())
                                {
                                    /**
                                     * Send the request.
                                     */
                                    send_to(
                                        ep, request->data(), request->size()
                                    );
                                }
                                else
                                {
                                    log_error(
                                        "UDP handler failed to encode message "
                                        "(protocol::"
                                        "message_code_public_key_ping)."
                                    );
                                }
                            }
                        }
                    }
                }
                else
                {
                    /**
                     * Send the message.
                     */
                    send_to(ep, msg->data(), msg->size());
                }
            }
            else
            {
                log_error("UDP handler, message encoding failed, dropping.");
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "UDP handler message encoding failed, what = " <<
                e.what() << "."
            );
        }
    }
}

const std::set<std::uint16_t> & udp_handler::sent_transaction_ids()
{
    std::lock_guard<std::recursive_mutex> lock(sent_transaction_ids_mutex_);
    
    return m_sent_transaction_ids;
}

void udp_handler::on_data(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    if (std::shared_ptr<node_impl> n = node_impl_.lock())
    {
        n->handle_message(ep, buf, len);
    }
}
