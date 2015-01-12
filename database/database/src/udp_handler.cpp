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

#include <iterator>

#include <boost/uuid/sha1.hpp>

#include <database/crypto.hpp>
#include <database/crypto_handler.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/node_impl.hpp>
#include <database/protocol.hpp>
#include <database/stack.hpp>
#include <database/udp_handler.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

udp_handler::udp_handler(
    boost::asio::io_service & ios, const std::shared_ptr<node_impl> & impl,
    std::shared_ptr<udp_multiplexor> & multiplexor   
    )
    : handler(ios, impl, multiplexor)
    , crypto_handler_(new crypto_handler(ios, impl, multiplexor))
{
    /**
     * Set the crypto_handler data handler.
     */
    crypto_handler_->set_on_data(
        std::bind(&udp_handler::on_data, this,
        std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
    );
    
    /**
     * Start the crypto_handler.
     */
    crypto_handler_->start();
}

void udp_handler::stop()
{
    /**
     * Stop the crypto_handler.
     */
    crypto_handler_->stop();
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
    if (crypto_handler_->on_async_receive_from(ep, buf, len))
    {
        // ...
    }
    else if (static_cast<std::uint8_t> (buf[0]) & protocol::message_flag_0x40)
    {
        if (
            static_cast<std::uint8_t> (buf[0]) &
            protocol::message_flag_obfuscated
            )
        {
            message msg(buf, len);
            
            auto key = crypto::generate_obfuscation_key(
                ep.address().to_string()
            );

            if (msg.unobfuscate(key))
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
                    " Unobfuscation failed."
                );
                
                std::shared_ptr<message> response(
                    new message(protocol::message_code_error,
                    hdr.transaction_id)
                );
                
                std::string error = "418 I'm a teapot";
                
                message::attribute_string attr1;
                
                attr1.type = message::attribute_type_error;
                attr1.length = error.size();
                attr1.value = error;
                
                response->string_attributes().push_back(attr1);
                
                message::attribute_endpoint attr2;
                
                attr2.type = message::attribute_type_endpoint;
                attr2.length = 0;
                attr2.value = ep;
                
                response->endpoint_attributes().push_back(attr2);
                
                send_message(ep, response);
                
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
        if (std::shared_ptr<node_impl> n = node_impl_.lock())
        {
            n->on_app_udp_receive(
                ep.address().to_string().c_str(), ep.port(), buf, len
            );
        }
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

            if (protocol::udp_obfuscation_enabled)
            {
                msg->set_header_flags(
                    static_cast<protocol::message_flag_t> (
                    msg->header_flags() | protocol::message_flag_obfuscated)
                );
            }
            
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
                            log_error(
                                "UDP handler, message Obfuscation failed."
                            );
                        }
                    }
                }

                send_to(ep, msg->data(), msg->size());
            }
            else
            {
                log_error("UDP handler, message encoding failed, dropping.");
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "UDP handler message encoding failed, what = " << e.what() << "."
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
