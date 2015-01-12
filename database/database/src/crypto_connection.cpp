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

#include <chrono>
#include <cmath>
#include <random>
#include <set>

#include <database/crypto.hpp>
#include <database/crypto_connection.hpp>
#include <database/crypto_handler.hpp>
#include <database/logger.hpp>
#include <database/protocol.hpp>
#include <database/udp_multiplexor.hpp>

using namespace database;

crypto_connection::crypto_connection(
    boost::asio::io_service & ios, const std::shared_ptr<crypto_handler> & h,
    const std::shared_ptr<udp_multiplexor> & multiplexor,
    const boost::asio::ip::udp::endpoint & ep, const direction_t & d
    )
    : m_state(state_open)
    , m_direction(d)
    , m_endpoint(ep)
    , io_service_(ios)
    , strand_(ios)
    , crypto_handler_(h)
    , udp_multiplexor_(multiplexor)
    , retransmit_timer_(ios)
    , timeout_timer_(ios)
    , sending_(false)
    , sent_(0)
    , timeout_(rto)
    , next_transaction_id_(0)
{
    hc256_.reset(
        new hc256("x9HehRBG7C6V7V1294cJYzryPgobo28r",
        "x9HehRBG7C6V7V1294cJYzryPgobo28r",
        "u97WiCR6J4i3O0zF5roD2i23UQn5pFZJ")
    );
}

crypto_connection::~crypto_connection()
{
    // ...
}

void crypto_connection::open()
{
    if (m_direction == direction_outbound)
    {
        // ...
    }
}

void crypto_connection::send(const char * buf, const std::size_t & len)
{
    if (m_state == state_open)
    {
        std::lock_guard<std::recursive_mutex> l(send_mutex_);
        
        /**
         * Allocate the message.
         */
        std::shared_ptr<crypto_message> msg(new crypto_message());
        
        /**
         * Set the code.
         */
        msg->header().code = crypto_message::code_data;
        
        /**
         * Set the transaction id.
         */
        msg->header().transaction_id = ++next_transaction_id_;
        
        /**
         * Set the body.
         */
        msg->set_body(buf, len);
        
        /**
         * Encode the message.
         */
        msg->encode();
        
        /**
         * Insert the message into the send queue.
         */
        send_queue_.push(msg);
        
        /**
         * Process the send queue.
         */
        process_send_queue();
    }
    else
    {
        log_debug("Crypto connection, send failed, state is closed.");
    }
}

void crypto_connection::on_receive(const char * buf, const std::size_t & len)
{
    if (m_state == state_open)
    {
        /**
         * Start the timeout timer.
         */
        timeout_timer_.expires_from_now(std::chrono::seconds(5));
        timeout_timer_.async_wait(
            strand_.wrap(std::bind(&crypto_connection::timeout_tick,
            shared_from_this(), std::placeholders::_1))
        );
        
        auto decrypted = hc256_->decrypt(
            std::string(buf + (crypto::dtls_header_length + 1),
            len - (crypto::dtls_header_length + 1))
        );
        
        decrypted.insert(
            decrypted.begin(), buf,
            buf + (crypto::dtls_header_length + 1)
        );
        
        /**
         * Allocate the message.
         */
        std::shared_ptr<crypto_message> msg(
            new crypto_message(decrypted.data(), decrypted.size())
        );
        
        try
        {
            /**
             * Decode the message.
             */
            msg->decode();
        }
        catch (std::exception & e)
        {
            log_error(
                "Crypto connection to " << m_endpoint <<
                ", receive failed, what = " << e.what() << "."
            );
            
            return;
        }
        
        /**
         * Handle the message.
         */
        handle_message(msg);
    }
    else
    {
        log_debug("Crypto connection, receive failed, state is closed.");
    }
}

const crypto_connection::state_t & crypto_connection::state() const
{
    return m_state;
}

void crypto_connection::set_endpoint(const boost::asio::ip::udp::endpoint & val)
{
    m_endpoint = val;
}

const boost::asio::ip::udp::endpoint & crypto_connection::endpoint() const
{
    return m_endpoint;
}

void crypto_connection::process_send_queue()
{
    std::lock_guard<std::recursive_mutex> l(send_mutex_);;

    if (!sending_ && !send_queue_.empty())
    {
        sending_ = true;
        
        /**
         * Get the message.
         */
        std::shared_ptr<crypto_message> msg = send_queue_.front();
        
        if (msg)
        {
            /**
             * Increment sent.
             */
            sent_++;
            
            /**
             * Start the retransmit timer.
             */
            retransmit_timer_.expires_from_now(
                std::chrono::milliseconds(timeout_)
            );
            retransmit_timer_.async_wait(
                strand_.wrap(std::bind(&crypto_connection::retransmit_tick,
                shared_from_this(), std::placeholders::_1))
            );
   
            auto encrypted = hc256_->encrypt(
                std::string(msg->data() + (crypto::dtls_header_length + 1),
                msg->size() - (crypto::dtls_header_length + 1))
            );
            
            encrypted.insert(
                encrypted.begin(), msg->data(),
                msg->data() + (crypto::dtls_header_length + 1)
            );

            /**
             * Send the message.
             */
            udp_multiplexor_.lock()->send_to(
                m_endpoint, encrypted.data(), encrypted.size()
            );
        }
    }
}

void crypto_connection::handle_message(std::shared_ptr<crypto_message> msg)
{
    std::lock_guard<std::recursive_mutex> l(receive_mutex_);
    
    switch (msg->header().code)
    {
        case crypto_message::code_ack:
        {
            std::lock_guard<std::recursive_mutex> l(send_mutex_);;

            if (
                !send_queue_.empty() &&
                send_queue_.front()->header().transaction_id ==
                msg->header().transaction_id
                )
            {
                /**
                 * Cancel the retransmit timer.
                 */
                retransmit_timer_.cancel();
            
                /**
                 * Remove the message.
                 */
                send_queue_.pop();
                
                /**
                 * Reset sent.
                 */
                sent_ = 0;
                
                /**
                 * Reset timeout.
                 */
                timeout_ = rto;
                
                /**
                 * Reset sending.
                 */
                sending_ = false;
            }
            
            /**
             * Process the send queue.
             */
            process_send_queue();
        }
        break;
        case crypto_message::code_nack:
        {
            // ...
        }
        break;
        case crypto_message::code_data:
        {
            if (auto h = crypto_handler_.lock())
            {
                if (h && h->on_data())
                {
                    if (msg->body().size() > 0)
                    {
                        h->on_data()(
                            m_endpoint, msg->body().data(),
                            msg->body().size()
                        );
                    }
                    else
                    {
                        log_debug(
                            "Crypto connection attempted to process 0 byte "
                            "message."
                        );
                    }
                }
            }
            
            /**
             * Allocate the response.
             */
            crypto_message response;
            
            /**
             * Set the code.
             */
            response.header().code = crypto_message::code_ack;
            
            /**
             * Copy the transaction id.
             */
            response.header().transaction_id = msg->header().transaction_id;
            
            /**
             * Encode the response.
             */
            response.encode();
            
            auto encrypted = hc256_->encrypt(
                std::string(response.data() +
                (crypto::dtls_header_length + 1), response.size() -
                (crypto::dtls_header_length + 1))
            );
            
            encrypted.insert(
                encrypted.begin(), response.data(),
                response.data() + (crypto::dtls_header_length + 1)
            );
            
            /**
             * Send the response.
             */
            udp_multiplexor_.lock()->send_to(
                m_endpoint, encrypted.data(), encrypted.size()
            );
        }
        break;
        case crypto_message::code_handshake:
        {
            // ...
        }
        break;
        default:
        break;
    }
}

void crypto_connection::retransmit_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(send_mutex_);
        
        if (m_state == state_open)
        {
            if (sent_ == Rc)
            {
                log_debug(
                    "Crypto connection has timed out, sent = " <<
                    sent_ << ", timeout = " << timeout_ << "."
                );
                
                /**
                 * Set the state to closed.
                 */
                m_state = state_closed;
            }
            else
            {
                /**
                 * Calculate the timeout.
                 */
                if (sent_ == Rc - 1)
                {
                    timeout_ = rto * Rm;
                } 
                else
                {
                    timeout_ = (timeout_ * 2);
                }

                if (send_queue_.size() > 0)
                {
                    /**
                     * Get the message.
                     */
                    std::shared_ptr<crypto_message> msg = send_queue_.front();
                    
                    if (msg)
                    {
                        log_none(
                            "Crypto connection sending, sent_ = " << sent_ <<
                            ", timeout_ = " << timeout_ << ", msg = " << msg.get()
                        );
                        
                        /**
                         * Increment sent.
                         */
                        sent_++;
                    
                        /**
                         * Start the retransmit timer.
                         */
                        retransmit_timer_.expires_from_now(
                            std::chrono::milliseconds(timeout_)
                        );
                        retransmit_timer_.async_wait(
                            strand_.wrap(std::bind(&crypto_connection::retransmit_tick,
                            shared_from_this(), std::placeholders::_1))
                        );
                        
                        /**
                         * Retransmit the message.
                         */
                        udp_multiplexor_.lock()->send_to(
                            m_endpoint, msg->data(), msg->size()
                        );
                    }
                }
            }
        }
    }
}

void crypto_connection::timeout_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        m_state = state_closed;
    }
}

void crypto_connection::send_dtls()
{
    crypto::dtls_header_t dtls_header;
    
    std::memset(&dtls_header, 0, crypto::dtls_header_length);
    
    dtls_header.content_type = crypto::content_type_handshake;
    dtls_header.version_major = crypto::version_major;
    dtls_header.version_minor = crypto::version_minor;

    dtls_header.epoch = std::rand() % std::numeric_limits<std::uint16_t>::max();
    
    dtls_header.sequence_number[0] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[1] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[2] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[3] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[4] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[5] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    
    dtls_header.length = 0;

    byte_buffer buffer;
    
    buffer.write_uint8(dtls_header.content_type);
    buffer.write_uint8(dtls_header.version_major);
    buffer.write_uint8(dtls_header.version_minor);
    buffer.write_uint16(dtls_header.epoch);
    buffer.write_uint8(dtls_header.sequence_number[0]);
    buffer.write_uint8(dtls_header.sequence_number[1]);
    buffer.write_uint8(dtls_header.sequence_number[2]);
    buffer.write_uint8(dtls_header.sequence_number[3]);
    buffer.write_uint8(dtls_header.sequence_number[4]);
    buffer.write_uint8(dtls_header.sequence_number[5]);
    buffer.write_uint16(dtls_header.length);
    
    buffer.write_uint8(crypto::msg_type_client_hello);
    
    udp_multiplexor_.lock()->send_to(m_endpoint, buffer.data(), buffer.size());
}
