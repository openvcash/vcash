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

#include <coin/address_manager.hpp>
#include <coin/alert.hpp>
#include <coin/alert_manager.hpp>
#include <coin/block_merkle.hpp>
#include <coin/block_locator.hpp>
#include <coin/chainblender.hpp>
#include <coin/chainblender_broadcast.hpp>
#include <coin/chainblender_join.hpp>
#include <coin/chainblender_leave.hpp>
#include <coin/chainblender_status.hpp>
#include <coin/checkpoints.hpp>
#include <coin/checkpoint_sync.hpp>
#include <coin/db_tx.hpp>
#include <coin/globals.hpp>
#include <coin/incentive.hpp>
#include <coin/incentive_answer.hpp>
#include <coin/incentive_collaterals.hpp>
#include <coin/incentive_manager.hpp>
#include <coin/incentive_sync.hpp>
#include <coin/incentive_question.hpp>
#include <coin/incentive_vote.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/network.hpp>
#include <coin/random.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/stack_impl.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/zerotime.hpp>
#include <coin/zerotime_answer.hpp>
#include <coin/zerotime_lock.hpp>
#include <coin/zerotime_manager.hpp>
#include <coin/zerotime_question.hpp>

using namespace coin;

tcp_connection::tcp_connection(
    boost::asio::io_service & ios, stack_impl & owner,
    const direction_t & direction, std::shared_ptr<tcp_transport> transport
    )
    : m_tcp_transport(transport)
    , m_identifier(random::uint32())
    , m_direction(direction)
    , m_protocol_version(0)
    , m_protocol_version_services(0)
    , m_protocol_version_timestamp(0)
    , m_protocol_version_start_height(-1)
    , m_protocol_version_relay(true)
    , m_sent_getaddr(false)
    , m_dos_score(0)
    , m_spv_dos_score(0.0)
    , m_probe_only(false)
    , m_state(state_none)
    , io_service_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
    , timer_ping_(io_service_)
    , timer_ping_timeout_(io_service_)
    , did_send_getblocks_(false)
    , last_getblocks_index_begin_(0)
    , time_last_block_received_(std::time(0))
    , timer_delayed_stop_(io_service_)
    , timer_version_timeout_(io_service_)
    , timer_getblocks_(io_service_)
    , timer_getheaders_(io_service_)
    , timer_addr_rebroadcast_(io_service_)
    , time_last_getblocks_sent_(std::time(0) - 60)
    , time_last_headers_received_(0)
    , timer_cbstatus_(io_service_)
    , did_send_cbstatus_cbready_code_(false)
    , timer_spv_getheader_timeout_(io_service_)
    , timer_spv_getblocks_timeout_(io_service_)
    , timer_isync_(io_service_)
    , did_send_isync_(false)
{
    // ...
}

tcp_connection::~tcp_connection()
{
    // ...
}

void tcp_connection::start()
{
    /**
     * Hold onto the tcp_transport until the post operation completes.
     */
    if (auto transport = m_tcp_transport.lock())
    {
        auto self(shared_from_this());
        
        /**
         * Post the operation onto the boost::asio::io_service.
         */
        io_service_.post(strand_.wrap([this, self, transport]()
        {
            do_start();
        }));
    }
}

void tcp_connection::start(const boost::asio::ip::tcp::endpoint ep)
{
    /**
     * Hold onto the tcp_transport until the post operation completes.
     */
    if (auto transport = m_tcp_transport.lock())
    {
        auto self(shared_from_this());
        
        /**
         * Post the operation onto the boost::asio::io_service.
         */
        io_service_.post(strand_.wrap([this, self, ep, transport]()
        {
            do_start(ep);
        }));
    }
}

void tcp_connection::stop()
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self]()
    {
        do_stop();
    }));
}

void tcp_connection::stop_after(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    /**
     * Starts the delayed stop timer.
     */
    timer_delayed_stop_.expires_from_now(std::chrono::seconds(interval));
    timer_delayed_stop_.async_wait(strand_.wrap(
        [this, self, interval](boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            log_debug(
                "TCP connection is stopping after " << interval << " seconds."
            );
            
            /**
             * Stop
             */
            do_stop();
        }
    }));
}

void tcp_connection::send(const char * buf, const std::size_t & len)
{
    if (auto transport = m_tcp_transport.lock())
    {
        transport->write(buf, len);
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_addr_message(const bool & local_address_only)
{
    log_debug("TCP connection is sending addr message.");
    
    if (auto t = m_tcp_transport.lock())
    {
        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        /**
         * Allocate the message.
         */
        message msg("addr");

        if (local_address_only == false)
        {
            auto addr_list = stack_impl_.get_address_manager()->get_addr();
            
            for (auto & i : addr_list)
            {
                if (m_seen_network_addresses.count(i) == 0)
                {
                    msg.protocol_addr().addr_list.push_back(i);
                }
            }
        }
        
        if (globals::instance().is_client_spv() == false)
        {
            /**
             * Get our network port.
             */
            auto port =
                stack_impl_.get_tcp_acceptor()->local_endpoint().port()
            ;
            
            protocol::network_address_t addr =
                protocol::network_address_t::from_endpoint(
                boost::asio::ip::tcp::endpoint(m_address_public, port)
            );
            
            msg.protocol_addr().addr_list.push_back(addr);
        }
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getblocks_message(
    const sha256 & hash_stop, const block_locator & locator
    )
{
    /**
     * Only send a getblocks message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer) == 1
        )
    {
        if (globals::instance().is_client_spv() == true)
        {
            auto should_send_spv_getblocks =
                globals::instance().spv_use_getblocks() == true
            ;
            
            if (should_send_spv_getblocks == true)
            {
                if (auto t = m_tcp_transport.lock())
                {
                    /**
                     * Set the last time we sent a getblocks.
                     */
                    time_last_getblocks_sent_ = std::time(0);
        
                    /**
                     * Allocate the message.
                     */
                    message msg("getblocks");
                    
                    /**
                     * Set the hashes.
                     */
                    msg.protocol_getblocks().hashes = locator.have();
                    
                    /**
                     * Set the stop hash.
                     */
                    msg.protocol_getblocks().hash_stop = hash_stop;
                    
                    log_none("TCP connection is sending (SPV) getblocks.");
                    
                    /**
                     * Encode the message.
                     */
                    msg.encode();
                    
                    if (utility::is_spv_initial_block_download() == true)
                    {
                        auto self(shared_from_this());
                        
                        /**
                         * Starts the (SPV) getblocks timeout timer.
                         */
                        timer_spv_getblocks_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_spv_getblocks_timeout_.async_wait(
                            strand_.wrap(
                            [this, self](boost::system::error_code ec)
                        {
                            if (ec)
                            {
                                // ...
                            }
                            else
                            {
                                log_info(
                                    "TCP connection " << m_identifier <<
                                    " (SPV) getblocks timed out, stopping."
                                );
                                
                                /**
                                 * Stop
                                 */
                                do_stop();
                            }
                        }));
                    }
                    
                    /**
                     * Write the message.
                     */
                    t->write(msg.data(), msg.size());
                }
                else
                {
                    stop();
                }
            }
        }
        else
        {
            log_error(
                "TCP connection tried to send (SPV) getblocks message when "
                "not in SPV client mode."
            );
        }
    }
}

void tcp_connection::send_getblocks_message(
    const block_index * index_begin, const sha256 & hash_end
    )
{
    /**
     * Only send a getblocks message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer) == 1
        )
    {
        /**
         * Do not send duplicate requests.
         */
        if (
            index_begin == last_getblocks_index_begin_ &&
            hash_end == last_getblocks_hash_end_
            )
        {
            return;
        }

        /**
         * Set the last time we sent a getblocks.
         */
        time_last_getblocks_sent_ = std::time(0);
        
        last_getblocks_index_begin_ =
            const_cast<block_index *> (index_begin)
        ;
        last_getblocks_hash_end_ = hash_end;
        
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("getblocks");
            
            /**
             * Set the hashes.
             */
            msg.protocol_getblocks().hashes =
                block_locator(index_begin).have()
            ;
            
            /**
             * Set the stop hash.
             */
            msg.protocol_getblocks().hash_stop = hash_end;
            
            log_none("TCP connection is sending getblocks.");
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_inv_message(
    const inventory_vector::type_t type, const sha256 hash_block
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, type, hash_block]()
    {
        do_send_inv_message(type, hash_block);
    }));
}

void tcp_connection::send_inv_message(
    const inventory_vector::type_t type,
    const std::vector<sha256> block_hashes
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, type, block_hashes]()
    {
        do_send_inv_message(type, block_hashes);
    }));
}

void tcp_connection::send_relayed_inv_message(
    const inventory_vector inv, const data_buffer buffer
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, inv, buffer]()
    {
        do_send_relayed_inv_message(inv, buffer);
    }));
}

void tcp_connection::send_getdata_message(
    const std::vector<inventory_vector> & getdata
    )
{
    /**
     * Only send a getdata message if the remote node is a peer.
     */
    if (
        (m_protocol_version_services & protocol::operation_mode_peer) == 1
        )
    {
        /**
         * Append the entries to the end.
         */
        getdata_.insert(getdata_.end(), getdata.begin(), getdata.end());

        /**
         * Send the getdata message.
         */
        send_getdata_message();
    }
}

void tcp_connection::send_checkpoint_message(checkpoint_sync & checkpoint)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Do not relay the same checkpoint we just relayed.
         */
        if (m_hash_checkpoint_known != checkpoint.hash_checkpoint())
        {
            /**
             * Set the hash of the last known checkpoint.
             */
            m_hash_checkpoint_known = checkpoint.hash_checkpoint();
        
            /**
             * Allocate the message.
             */
            message msg("checkpoint");

            /**
             * Set the message.
             */
            msg.protocol_checkpoint().message = checkpoint.message();
            
            /**
             * Set the message.
             */
            msg.protocol_checkpoint().signature = checkpoint.signature();
            
            log_debug("TCP connection is sending checkpoint.");
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_block_message(const block blk)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, blk]()
    {
        do_send_block_message(blk);
    }));
}

void tcp_connection::send_filterload_message(
    const transaction_bloom_filter & filter
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filterload");

            /**
             * Set the filterload.
             */
            msg.protocol_filterload().filterload =
                std::make_shared<transaction_bloom_filter> (filter)
            ;
            
            log_info("TCP connection is sending filterload.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_filteradd_message(
    const std::vector<std::uint8_t> & data
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filteradd");

            /**
             * Set the data.
             */
            msg.protocol_filteradd().filteradd = data;
            
            log_info("TCP connection is sending filteradd.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_filterclear_message()
{
    if (globals::instance().is_client_spv() == true)
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("filterclear");

            log_info("TCP connection is sending filterclear.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_cbbroadcast_message(
    const std::shared_ptr<chainblender_broadcast> & cbbroadcast
    )
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, cbbroadcast]()
    {
        do_send_cbbroadcast_message(cbbroadcast);
    }));
}

void tcp_connection::send_cbleave_message()
{
    if (globals::instance().is_chainblender_enabled())
    {
        if (auto t = m_tcp_transport.lock())
        {
            if (m_direction == direction_outgoing)
            {
                if (m_hash_chainblender_session_id.is_empty() == false)
                {
                    /**
                     * Allocate the message.
                     */
                    message msg("cbleave");

                    /**
                     * Set the cbleave.
                     */
                    msg.protocol_cbleave().cbleave =
                        std::make_shared<chainblender_leave> ()
                    ;
                    
                    /**
                     * Set the session id.
                     */
                    msg.protocol_cbleave().cbleave->set_session_id(
                        m_hash_chainblender_session_id
                    );
                    
                    log_debug("TCP connection is sending cbleave.");

                    /**
                     * Encode the message.
                     */
                    msg.encode();
                    
                    /**
                     * Write the message.
                     */
                    t->write(msg.data(), msg.size());
                }
            }
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_tx_message(const transaction tx)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, tx]()
    {
        do_send_tx_message(tx);
    }));
}

void tcp_connection::set_hash_checkpoint_known(const sha256 & val)
{
    m_hash_checkpoint_known = val;
}

const sha256 & tcp_connection::hash_checkpoint_known() const
{
    return m_hash_checkpoint_known;
}

void tcp_connection::clear_seen_network_addresses()
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self]()
    {
        m_seen_network_addresses.clear();
    }));
}

void tcp_connection::set_dos_score(const std::uint8_t & val)
{
    m_dos_score = val;
    
    /**
     * If the Denial-of-Service score is at least 100 the address is banned
     * and the connection is dropped.
     */
    if (m_dos_score >= 100)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto addr =
                transport->socket().remote_endpoint().address().to_string()
            ;
        
            /**
             * Ban the address for 24 hours.
             */
            network::instance().ban_address(addr);
            
            /**
             * Stop.
             */
            stop();
        }
    }
}

const std::uint8_t & tcp_connection::dos_score() const
{
    return m_dos_score;
}

void tcp_connection::set_spv_dos_score(const double & val)
{
    assert(globals::instance().is_client_spv() == true);
    
    m_spv_dos_score = val;
    
    /**
     * If the Denial-of-Service score is at least 100% the address is banned
     * and the connection is dropped.
     */
    if (m_spv_dos_score >= 100.0)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto addr =
                transport->socket().remote_endpoint().address().to_string()
            ;
        
            /**
             * Ban the address for one hour.
             */
            network::instance().ban_address(addr, 1 * 60 * 60);
            
            /**
             * Stop.
             */
            stop();
        }
    }
}

const double & tcp_connection::spv_dos_score() const
{
    return m_spv_dos_score;
}

void tcp_connection::set_probe_only(const bool & val)
{
    m_probe_only = val;
}

void tcp_connection::set_oneshot_ztquestion(
    const std::shared_ptr<zerotime_question> & val
    )
{
    m_oneshot_ztquestion = val;
}

void tcp_connection::set_cbjoin(const std::shared_ptr<chainblender_join> & val)
{
    m_chainblender_join = val;
}

const sha256 & tcp_connection::hash_chainblender_session_id() const
{
    return m_hash_chainblender_session_id;
}

const std::uint32_t & tcp_connection::identifier() const
{
    return m_identifier;
}

bool tcp_connection::is_transport_valid()
{
    if (auto transport = m_tcp_transport.lock())
    {
        return true;
    }
    
    return false;
}

void tcp_connection::on_read(const char * buf, const std::size_t & len)
{
    if (globals::instance().state() == globals::state_started)
    {
        auto buffer = std::string(buf, len);
        
        /**
         * Check if it is an HTTP message.
         */
        if (buffer.find("HTTP/1.") == std::string::npos)
        {
            /**
             * Append to the read queue.
             */
            read_queue_.insert(read_queue_.end(), buf, buf + len);

            while (
                globals::instance().state() == globals::state_started &&
                read_queue_.size() >= message::header_length
                )
            {
                /**
                 * Allocate a packet from the entire read queue.
                 */
                std::string packet(read_queue_.begin(), read_queue_.end());
                
                /**
                 * Allocate the message.
                 * @note Packets can be combined, after decoding the message
                 * it's buffer will be resized to the actual length.
                 */
                message msg(packet.data(), packet.size());
            
                try
                {
                    /**
                     * Decode the message.
                     */
                    msg.decode();
                }
                catch (std::exception & e)
                {
                    log_none(
                        "TCP connection failed to decode message, "
                        "what = " << e.what() << "."
                    );

                    break;
                }
                
                /**
                 * Erase the full/partial packet.
                 */
                read_queue_.erase(
                    read_queue_.begin(), read_queue_.begin() +
                    message::header_length + msg.header().length
                );
                
                try
                {
                    /**
                     * Handle the message.
                     */
                    handle_message(msg);
                }
                catch (std::exception & e)
                {
                    log_debug(
                        "TCP connection failed to handle message, "
                        "what = " << e.what() << "."
                    );
                    
                    /**
                     * If we failed to parse a message with a read queue
                     * twice the size of block::get_maximum_size_median220
                     * then the stream must be corrupted, clear the read queue
                     * and stop the connection.
                     */
                    if (
                        read_queue_.size() >
                        block::get_maximum_size_median220() * 2
                        )
                    {
                        log_error(
                            "TCP connection read queue too large (" <<
                            read_queue_.size() << "), calling stop."
                        );
                        
                        /**
                         * Clear the read queue.
                         */
                        read_queue_.clear();
                        
                        /**
                         * Call stop
                         */
                        do_stop();
                        
                        return;
                    }
                }
            }
        }
        else
        {
            log_debug("TCP connection got HTTP message.");
            
            if (auto transport = m_tcp_transport.lock())
            {
                /**
                 * Allocate the user agent comments.
                 */
                std::vector<std::string> comments;
                
                if (
                    globals::instance().operation_mode() ==
                    protocol::operation_mode_peer
                    )
                {
                    comments.push_back("Peer");
                }
                else
                {
                    comments.push_back("Unknown");
                }
#if (defined _MSC_VER)
                comments.push_back("Windows");
#elif (defined __ANDROID__)
                comments.push_back("Android");
#elif (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
                comments.push_back("iOS");
#elif (defined __APPLE__)
                comments.push_back("macOS");
#elif (defined __linux__)
                comments.push_back("Linux");
#endif
                /**
                 * Create the user agent string.
                 */
                auto user_agent = utility::format_sub_version(
                    constants::client_name, constants::version_client,
                    comments
                );
                
                /**
                 * Allocate the response.
                 */
                std::string response;
             
                /**
                 * Allocate the body.
                 */
                std::string body =
                    "{\"version\":\"" +
                    constants::version_string + "\"""," +
                    "\"protocol\":\"" +
                    std::to_string(protocol::version) + "\"""," +
                    "\"useragent\":\"" +
                    user_agent + "\"""," +
                    "\"height\":\"" +
                    std::to_string(
                    stack_impl::get_block_index_best()->height()) + "\"""}"
                ;
                
                /**
                 * Formulate the response.
                 */
                response += "HTTP/1.1 200 OK\r\n";
                response += "Connection: close\r\n";
                response += "Content-Type: text/plain; charset=utf-8\r\n";
                response += "Content-Length: " +
                    std::to_string(body.size()) + "\r\n"
                ;
                response += "\r\n";
                response += body;
            
                /**
                 * Set the transport to close after it sends the response.
                 */
                transport->set_close_after_writes(true);
                
                /**
                 * Write the response.
                 */
                transport->write(response.data(), response.size());
            }
        }
    }
}

void tcp_connection::do_start()
{
    m_state = state_starting;
    
    if (m_direction == direction_incoming)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto self(shared_from_this());
            
            /**
             * Set the transport on read handler.
             */
            transport->set_on_read(
                [this, self](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                on_read(buf, len);
            });

            /**
             * Start the transport accepting the connection.
             */
            transport->start();
            
            /**
             * Start the ping timer.
             */
            timer_ping_.expires_from_now(
                std::chrono::seconds(interval_ping / 4)
            );
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(1));
            timer_getblocks_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_send_getblocks, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the addr rebroadcast timer.
             */
            do_rebroadcast_addr_messages(900);
        }
    }
    else if (m_direction == direction_outgoing)
    {
        assert(0);
    }
    
    m_state = state_started;
}

void tcp_connection::do_start(const boost::asio::ip::tcp::endpoint ep)
{
    m_state = state_starting;

    if (m_direction == direction_incoming)
    {
        assert(0);
    }
    else if (m_direction == direction_outgoing)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            auto self(shared_from_this());
            
            /**
             * Set the transport on read handler.
             */
            transport->set_on_read(
                [this, self](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                on_read(buf, len);
            });

            /**
             * Start the transport connecting to the endpoint.
             */
            transport->start(
                ep.address().to_string(), ep.port(), [this, self, ep](
                boost::system::error_code ec,
                std::shared_ptr<tcp_transport> transport)
                {
                    if (ec)
                    {
                        log_none(
                            "TCP connection to " << ep << " failed, "
                            "message = " << ec.message() << "."
                        );
                        
                        stop();
                    }
                    else
                    {
                        log_debug(
                            "TCP connection to " << ep << " success, sending "
                            "version message."
                        );
        
                        /**
                         * Start the version timeout timer.
                         */
                        timer_version_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_version_timeout_.async_wait(
                            strand_.wrap(
                                [this, self](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        log_error(
                                            "TCP connection (version) timed "
                                            "out, calling stop."
                                        );
                                    
                                        /**
                                         * The connection has timed out, call
                                         * stop.
                                         */
                                        do_stop();
                                    }
                                }
                            )
                        );
                        
                        /**
                         * Send a version message.
                         */
                        send_version_message();
                    }
                }
            );
            
            /**
             * Start the ping timer.
             */
            timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(1));
            timer_getblocks_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_send_getblocks, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the addr rebroadcast timer.
             */
            do_rebroadcast_addr_messages(300);
        }
        else
        {
            assert(0);
        }
    }
    
    m_state = state_started;
}

void tcp_connection::do_stop()
{
    m_state = state_stopping;
    
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * If we are a part of a chainblender session we need to reduce the
     * participants count.
     */
    if (m_hash_chainblender_session_id.is_empty() == false)
    {
        /**
         * Get the sessions.
         */
        auto & sessions = chainblender::instance().sessions();
        
        if (
            sessions.count(m_hash_chainblender_session_id) > 0
            )
        {
            if (
                sessions[m_hash_chainblender_session_id].participants > 0
                )
            {
                sessions[
                    m_hash_chainblender_session_id
                ].participants -= 1;
            }
            else
            {
                sessions.erase(m_hash_chainblender_session_id);
            }
        }
    }
    
    /**
     * If we are an (SPV) client set the active identifier to that of another
     * tcp_connection object.
     */
    if (globals::instance().is_client_spv() == true)
    {
        if (stack_impl_.get_tcp_connection_manager())
        {
            const auto & tcp_connections =
                stack_impl_.get_tcp_connection_manager()->tcp_connections()
            ;
            
            for (auto & i : tcp_connections)
            {
                if (auto connection = i.second.lock())
                {
                    if (
                        connection->is_transport_valid() &&
                        connection->identifier() != m_identifier
                        )
                    {
                        globals::instance(
                            ).set_spv_active_tcp_connection_identifier(
                            connection->identifier()
                        );
                        
                        break;
                    }
                }
            }
        }
    }
    
    /**
     * Stop the transport.
     */
    if (auto t = m_tcp_transport.lock())
    {
        t->stop();
    }
    
    /**
     * Remove references to shared pointers.
     */
    m_oneshot_ztquestion = nullptr,
        m_on_probe = nullptr, m_on_ianswer = nullptr, m_on_cbstatus = nullptr,
        m_on_cbbroadcast = nullptr, m_chainblender_join = nullptr;
    ;
    
    read_queue_.clear();
    timer_ping_.cancel();
    timer_version_timeout_.cancel();
    timer_ping_timeout_.cancel();
    timer_getblocks_.cancel();
    timer_getheaders_.cancel();
    timer_addr_rebroadcast_.cancel();
    timer_cbstatus_.cancel();
    timer_delayed_stop_.cancel();
    timer_spv_getheader_timeout_.cancel();
    timer_spv_getblocks_timeout_.cancel();
    timer_isync_.cancel();
    
    m_state = state_stopped;
}

void tcp_connection::send_verack_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("verack");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_version_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        /**
         * Allocate the message.
         */
        message msg("version");

        /**
         * Get our network port.
         */
        auto port =
            globals::instance().is_client_spv() == true ? 0 :
            stack_impl_.get_tcp_acceptor()->local_endpoint().port()
        ;
        
        /**
         * Set the version addr_src address.
         */
        msg.protocol_version().addr_src.port = port;
    
        /**
         * Set the version nonce.
         */
        msg.protocol_version().nonce = globals::instance().version_nonce();
        
        /**
         * Copy the peers' ip address into the addr_dst address.
         */
        if (t->socket().remote_endpoint().address().is_v4())
        {
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0],
                &protocol::v4_mapped_prefix[0],
                protocol::v4_mapped_prefix.size()
            );
            
            auto ip = htonl(
                t->socket().remote_endpoint().address().to_v4().to_ulong()
            );
            
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0] +
                protocol::v4_mapped_prefix.size(), &ip, sizeof(ip)
            );
        }
        else
        {
            std::memcpy(
                &msg.protocol_version().addr_dst.address[0],
                &t->socket().remote_endpoint().address().to_v6().to_bytes()[0],
                msg.protocol_version().addr_dst.address.size()
            );
        }
    
        /**
         * Encode the message.
         */
        msg.encode();

        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_addr_message(const protocol::network_address_t & addr)
{
    auto self(shared_from_this());
    
    /**
     * Post the operation onto the boost::asio::io_service.
     */
    io_service_.post(strand_.wrap([this, self, addr]()
    {
        do_send_addr_message(addr);
    }));
}

void tcp_connection::do_send_addr_message(
    const protocol::network_address_t & addr
    )
{
    if (m_seen_network_addresses.count(addr) == 0)
    {
        /**
         * Insert the seen address.
         */
        m_seen_network_addresses.insert(addr);
    
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("addr");
            
            msg.protocol_addr().addr_list.push_back(addr);
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::do_send_cbbroadcast_message(
    const std::shared_ptr<chainblender_broadcast> & cbbroadcast
    )
{
    if (globals::instance().is_chainblender_enabled())
    {
        if (auto t = m_tcp_transport.lock())
        {
            if (m_hash_chainblender_session_id.is_empty() == false)
            {
                /**
                 * Allocate the message.
                 */
                message msg("cbbroadcast");

                /**
                 * Set the cbbroadcast.
                 */
                msg.protocol_cbbroadcast().cbbroadcast = cbbroadcast;

                /**
                 * Set the session id.
                 */
                msg.protocol_cbbroadcast().cbbroadcast->set_session_id(
                    m_hash_chainblender_session_id
                );

                log_info("TCP connection is sending cbbroadcast.");

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::do_send_tx_message(const transaction & tx)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("tx");

        /**
         * Set the tx.
         */
        msg.protocol_tx().tx = std::make_shared<transaction> (tx);
        
        log_debug(
            "TCP connection is sending tx " <<
            msg.protocol_tx().tx->get_hash().to_string().substr(0, 20) <<
            "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getaddr_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("getaddr");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ping_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("ping");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        log_debug(
            "TCP connection is sending ping, nonce = " <<
            msg.protocol_ping().nonce << "."
        );
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_pong_message(const std::uint64_t & nonce)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("pong");
        
        /**
         * Set the nonce.
         */
        msg.protocol_pong().nonce = nonce;
        
        log_debug(
            "TCP connection is sending pong, nonce = " <<
            msg.protocol_pong().nonce << "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getdata_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Only send a getdata message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer) == 1
            )
        {
            if (getdata_.size() > 0)
            {
                /**
                 * Allocate the message.
                 */
                message msg("getdata");
                
                /**
                 * Set the getdata.
                 */
                msg.protocol_getdata().inventory = getdata_;
                
                /**
                 * Clear the getdata.
                 */
                getdata_.clear();
                
                if (msg.protocol_getdata().inventory.size() == 1)
                {
                    log_info(
                        "TCP connection " << m_identifier << " is sending "
                        "getdata, count = 1, type = " <<
                        msg.protocol_getdata().inventory[0].type()
                    );
                }
                else
                {
                    log_info(
                        "TCP connection " << m_identifier << " is sending "
                        "getdata, count = " <<
                        msg.protocol_getdata().inventory.size() << "."
                    );
                }
                
                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
        }
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_headers_message(const std::vector<block> & headers)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("headers");

        /**
         * Set the headers.
         */
        msg.protocol_headers().headers = headers;
        
        log_debug(
            "TCP connection is sending headers " <<
            msg.protocol_headers().headers.size() << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_getheaders_message(
    const sha256 & hash_stop, const block_locator & locator
    )
{
    if (globals::instance().is_client_spv() == true)
    {
        if (
            m_identifier == globals::instance(
            ).spv_active_tcp_connection_identifier()
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("getheaders");
                
                /**
                 * Set the getheaders.
                 */
                msg.protocol_getheaders().hash_stop = hash_stop;
                msg.protocol_getheaders().locator =
                    std::make_shared<block_locator> (locator)
                ;
                
                log_debug(
                    "TCP connection is sending getheaders, hash_stop = " <<
                    msg.protocol_getheaders().hash_stop.to_string().substr(
                    0, 8) << "."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                auto self(shared_from_this());
                
                /**
                 * Starts the (SPV) getheaders timeout timer.
                 */
                timer_spv_getheader_timeout_.expires_from_now(
                    std::chrono::seconds(8)
                );
                timer_spv_getheader_timeout_.async_wait(strand_.wrap(
                    [this, self](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_debug(
                            "TCP connection " << m_identifier << " (SPV) "
                            "getheaders timed out, stopping."
                        );
                        
                        /**
                         * Stop
                         */
                        do_stop();
                    }
                }));
    
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_merkleblock_message(const block_merkle & merkleblock)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("merkleblock");

        /**
         * Set the merkleblock.
         */
        msg.protocol_merkleblock().merkleblock =
            std::make_shared<block_merkle> (merkleblock)
        ;
        
        log_debug(
            "TCP connection is sending merkleblock, tx's = " <<
            msg.protocol_merkleblock(
            ).merkleblock->transactions_matched().size() << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ztlock_message(const zerotime_lock & ztlock)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("ztlock");

        /**
         * Set the ztlock.
         */
        msg.protocol_ztlock().ztlock = std::make_shared<zerotime_lock> (ztlock);
        
        log_debug(
            "TCP connection is sending ztlock " <<
            msg.protocol_ztlock().ztlock->hash_tx().to_string().substr(0, 20) <<
            "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ztquestion_message(
    const zerotime_question & ztquestion
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("ztquestion");

        /**
         * Set the ztquestion.
         */
        msg.protocol_ztquestion().ztquestion =
            std::make_shared<zerotime_question> (ztquestion)
        ;
        
        log_debug(
            "TCP connection is sending ztquestion " <<
            msg.protocol_ztquestion(
            ).ztquestion->transactions_in().size() << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ztanswer_message(const zerotime_answer & ztanswer)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("ztanswer");

        /**
         * Set the ztanswer.
         */
        msg.protocol_ztanswer().ztanswer =
            std::make_shared<zerotime_answer> (ztanswer)
        ;
        
        log_debug(
            "TCP connection is sending ztanswer " <<
            msg.protocol_ztanswer().ztanswer->hash_tx(
            ).to_string().substr(0, 20) << "."
        );

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_ianswer_message()
{
    if (globals::instance().is_incentive_enabled())
    {
        if (auto t = m_tcp_transport.lock())
        {
            if (incentive::instance().get_key().is_null() == false)
            {
                /**
                 * Allocate the message.
                 */
                message msg("ianswer");

                /**
                 * Set the ianswer.
                 */
                msg.protocol_ianswer().ianswer =
                    std::make_shared<incentive_answer> (
                    incentive::instance().get_key().get_public_key(),
                    incentive::instance().get_transaction_in()
                );
                
                log_debug("TCP connection is sending ianswer.");

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_iquestion_message()
{
    if (globals::instance().is_incentive_enabled())
    {
        if (auto t = m_tcp_transport.lock())
        {
            /**
             * Allocate the message.
             */
            message msg("iquestion");

            /**
             * Set the iquestion.
             */
            msg.protocol_iquestion().iquestion =
                std::make_shared<incentive_question> ()
            ;
            
            log_debug("TCP connection is sending iquestion.");

            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Write the message.
             */
            t->write(msg.data(), msg.size());
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_ivote_message(const incentive_vote & ivote)
{
    if (globals::instance().is_incentive_enabled())
    {
        /**
         * Only send a ivote message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer) == 1
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("ivote");

                /**
                 * Set the ivote.
                 */
                msg.protocol_ivote().ivote =
                    std::make_shared<incentive_vote> (ivote)
                ;
                
                log_debug(
                    "TCP connection is sending ivote " <<
                    msg.protocol_ivote().ivote->address().substr(0, 8) <<
                    "."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_isync_message()
{
    if (globals::instance().is_incentive_enabled() == true)
    {
        /**
         * Only send an isync message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer) == 1
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("isync");

                /**
                 * Get the recent good endpoints.
                 */
                auto recent_good_endpoints =
                    stack_impl_.get_address_manager(
                    )->recent_good_endpoints()
                ;

                std::set<std::string> filter;
                
                /**
                 * Iterate the recent good endpoints looking for wallet
                 * addresses we already have collateral for.
                 */
                for (auto & i : recent_good_endpoints)
                {
                    filter.insert(i.wallet_address);
                }
                
                /**
                 * Set the isync.
                 */
                msg.protocol_isync().isync =
                    std::make_shared<incentive_sync> (filter)
                ;
                
                log_info(
                    "TCP connection is sending isync, filter size = " <<
                    msg.protocol_isync().isync->filter().size() << "."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_icols_message(
    const incentive_collaterals & icols
    )
{
    if (globals::instance().is_incentive_enabled())
    {
        /**
         * Only send an icols message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer) == 1
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("icols");

                /**
                 * Set the icols.
                 */
                msg.protocol_icols().icols =
                    std::make_shared<incentive_collaterals> (icols)
                ;
                
                log_info(
                    "TCP connection is sending " <<
                    msg.protocol_icols().icols->collaterals().size() <<
                    " icols ."
                );

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_cbjoin_message(const chainblender_join & cbjoin)
{
    if (globals::instance().is_chainblender_enabled())
    {
        /**
         * Only send a cbjoin message if the remote node is a peer.
         */
        if (
            (m_protocol_version_services & protocol::operation_mode_peer) == 1
            )
        {
            if (auto t = m_tcp_transport.lock())
            {
                /**
                 * Allocate the message.
                 */
                message msg("cbjoin");

                /**
                 * Set the cbjoin.
                 */
                msg.protocol_cbjoin().cbjoin =
                    std::make_shared<chainblender_join> (cbjoin)
                ;
                
                log_debug("TCP connection is sending cbjoin.");

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
            else
            {
                stop();
            }
        }
    }
}

void tcp_connection::send_cbstatus_message(
    const chainblender_status & cbstatus
    )
{
    if (globals::instance().is_chainblender_enabled())
    {
        if (auto t = m_tcp_transport.lock())
        {
            if (m_direction == direction_incoming)
            {
                /**
                 * Allocate the message.
                 */
                message msg("cbstatus");

                /**
                 * Set the cbstatus.
                 */
                msg.protocol_cbstatus().cbstatus =
                    std::make_shared<chainblender_status> (cbstatus)
                ;
                
                log_debug("TCP connection is sending cbstatus.");

                /**
                 * Encode the message.
                 */
                msg.encode();
                
                /**
                 * Write the message.
                 */
                t->write(msg.data(), msg.size());
            }
        }
        else
        {
            stop();
        }
    }
}

void tcp_connection::send_mempool_message()
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("mempool");
        
        log_debug("TCP connection is sending mempool " << ".");

        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

std::weak_ptr<tcp_transport> & tcp_connection::get_tcp_transport()
{
    return m_tcp_transport;
}

const tcp_connection::direction_t & tcp_connection::direction() const
{
    return m_direction;
}

const std::uint32_t & tcp_connection::protocol_version() const
{
    return m_protocol_version;
}

const std::uint64_t & tcp_connection::protocol_version_services() const
{
    return m_protocol_version_services;
}

const std::uint64_t & tcp_connection::protocol_version_timestamp() const
{
    return m_protocol_version_timestamp;
}

const std::string & tcp_connection::protocol_version_user_agent() const
{
    return m_protocol_version_user_agent;
}

const std::int32_t & tcp_connection::protocol_version_start_height() const
{
    return m_protocol_version_start_height;
}

const protocol::network_address_t &
    tcp_connection::protocol_version_addr_src() const
{
    return m_protocol_version_addr_src;
}

const bool & tcp_connection::protocol_version_relay() const
{
    return m_protocol_version_relay;
}

void tcp_connection::set_on_probe(
    const std::function<void (const std::uint32_t &, const std::string &,
    const std::uint64_t &, const std::int32_t &)> & f
    )
{
    m_on_probe = f;
}

void tcp_connection::set_on_ianswer(
    const std::function< void (const incentive_answer &) > & f
    )
{
    m_on_ianswer = f;
}

void tcp_connection::set_on_cbbroadcast(
    const std::function< void (
    const chainblender_broadcast &) > & f
    )
{
    m_on_cbbroadcast = f;
}

void tcp_connection::set_on_cbstatus(
    const std::function< void (const chainblender_status &) > & f
    )
{
    m_on_cbstatus = f;
}

void tcp_connection::relay_checkpoint(const checkpoint_sync & checkpoint)
{
    /**
     * Do not relay the same checkpoint we just relayed.
     */
    if (m_hash_checkpoint_known != checkpoint.hash_checkpoint())
    {
        /**
         * Set the hash of the last known checkpoint.
         */
        m_hash_checkpoint_known = checkpoint.hash_checkpoint();
    
        /**
         * Allocate the message.
         */
        message msg_checkpoint("checkpoint");

        /**
         * Set the message.
         */
        msg_checkpoint.protocol_checkpoint().message =
            checkpoint.message()
        ;
        
        /**
         * Set the message.
         */
        msg_checkpoint.protocol_checkpoint().signature =
            checkpoint.signature()
        ;
        
        log_debug("TCP connection is relaying checkpoint message.");
        
        /**
         * Encode the message.
         */
        msg_checkpoint.encode();

        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        /**
         * Broadcast (Relay) the message to "all" connected peers.
         */
        stack_impl_.get_tcp_connection_manager()->broadcast(
            msg_checkpoint.data(), msg_checkpoint.size()
        );
    }
}

void tcp_connection::relay_alert(const alert & msg)
{
    if (msg.is_in_effect())
    {
        if (m_seen_alerts.insert(msg.get_hash()).second)
        {
            if (msg.applies_to_me())
            {
                /**
                 * Allocate the message.
                 */
                message msg_alert("alert");

                /**
                 * Set the alert.
                 */
                msg_alert.protocol_alert().a = std::make_shared<alert> (msg);
                
                log_debug("TCP connection is relaying alert message.");
                
                /**
                 * Encode the message.
                 */
                msg_alert.encode();
                
                std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
                
                /**
                 * Broadcast (Relay) the message to "all" connected peers.
                 */
                stack_impl_.get_tcp_connection_manager()->broadcast(
                    msg_alert.data(), msg_alert.size()
                );
            }
        }
    }
}

void tcp_connection::relay_inv(
    const inventory_vector & inv, const data_buffer & buffer
    )
{
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * Expire old relay messages.
     */
    while (
        globals::instance().relay_inv_expirations().size() > 0 &&
        globals::instance().relay_inv_expirations().front().first < std::time(0)
        )
    {
        globals::instance().relay_invs().erase(
            globals::instance().relay_inv_expirations().front().second
        );
        
        globals::instance().relay_inv_expirations().pop_front();
    }

    /**
     * Save original serialized message so newer versions are preserved.
     */
    globals::instance().relay_invs().insert(std::make_pair(inv, buffer));
    
    globals::instance().relay_inv_expirations().push_back(
        std::make_pair(std::time(0) + 15 * 60, inv)
    );
    
    log_debug(
        "TCP connection is relaying inv message, command = " <<
        inv.command() << "."
    );
    
    /**
     * Allocate the message.
     */
    message msg(inv.command(), buffer);

    /**
     * Encode the message.
     */
    msg.encode();

    /**
     * Check if this is related to a transaction.
     */
    auto is_tx_related =
        inv.command() == "tx" || inv.command() == "ztlock"
    ;
    
    if (m_protocol_version_relay == false && is_tx_related)
    {
        /**
         * Broadcast the message via bip0037 rules.
         */
         stack_impl_.get_tcp_connection_manager()->broadcast_bip0037(
            msg.data(), msg.size()
         );
    }
    else
    {
        /**
         * Broadcast the message to "all" connected peers.
         */
        stack_impl_.get_tcp_connection_manager()->broadcast(
            msg.data(), msg.size()
        );
    }
}

bool tcp_connection::handle_message(message & msg)
{
    if (m_state == state_stopped)
    {
        log_debug(
            "TCP connection got message while stopped, returning."
        );
        
        return false;
    }
    
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());

    if (msg.header().command == "verack")
    {
        timer_version_timeout_.cancel();
    }
    else if (msg.header().command == "version")
    {
        /**
         * Check that we didn't connection to ourselves.
         */
        if (msg.protocol_version().nonce == globals::instance().version_nonce())
        {
            log_debug(
                "TCP connection got message from ourselves, closing connection."
            );
            
            /**
             * Stop
             */
            do_stop();
            
            return false;
        }
        else
        {
            /**
             * If the protocol version is zero we need to send a verack and a
             * version message.
             */
            if (m_protocol_version == 0)
            {
                /**
                 * Send a verack message.
                 */
                send_verack_message();
            
                /**
                 * Set the protocol version.
                 */
                m_protocol_version = std::min(
                    msg.protocol_version().version,
                    static_cast<std::uint32_t> (protocol::version)
                );
                
                /**
                 * Check for the minimum protocol version.
                 */
                if (m_protocol_version < protocol::minimum_version)
                {
                    log_info(
                        "TCP connection got old protocol version = " <<
                        m_protocol_version << ", calling stop."
                    );
                    
                    /**
                     * Stop
                     */
                    do_stop();
                    
                    return false;
                }

                /**
                 * Set the protocol version services.
                 */
                m_protocol_version_services = msg.protocol_version().services;
                
                /**
                 * Set the protocol version timestamp.
                 */
                m_protocol_version_timestamp =
                    msg.protocol_version().timestamp
                ;
                
                /**
                 * Set the protocol version user agent.
                 */
                m_protocol_version_user_agent =
                    msg.protocol_version().user_agent
                ;
                
                /**
                 * Set the protocol version start height.
                 */
                m_protocol_version_start_height =
                    msg.protocol_version().start_height
                ;
                
                log_debug(
                    "TCP connection " << m_identifier <<
                    " got version = " << m_protocol_version << "."
                );

                /**
                 * Set the protocol version source address.
                 */
                m_protocol_version_addr_src = msg.protocol_version().addr_src;
                
                /**
                 * Set the protocol version relay.
                 */
                m_protocol_version_relay = msg.protocol_version().relay == 1;

                /**
                 * Add the timestamp from the peer.
                 */
                time::instance().add(
                    msg.protocol_version().addr_src,
                    msg.protocol_version().timestamp
                );

                /**
                 * If this is an incoming connection we must send a version
                 * message. If this is an outgoing connection we send both an
                 * getaddr and addr message.
                 */
                if (m_direction == direction_incoming)
                {
                    if (auto transport = m_tcp_transport.lock())
                    {
                        /**
                         * If the remote node is a peer add it to the address
                         * manager.
                         */
                        if (
                            (m_protocol_version_services &
                            protocol::operation_mode_peer) == 1
                            )
                        {
                            /**
                             * If the source address in the version message
                             * matches the address as seen by us inform the
                             * address_manager.
                             */
                            if (
                                protocol::network_address_t::from_endpoint(
                                transport->socket().remote_endpoint()) ==
                                msg.protocol_version().addr_src
                                )
                            {
                                /**
                                 * Add to the address_manager.
                                 */
                                stack_impl_.get_address_manager()->add(
                                    msg.protocol_version().addr_src,
                                    msg.protocol_version().addr_src
                                );

                                /**
                                 * Mark as good.
                                 */
                                stack_impl_.get_address_manager()->mark_good(
                                    msg.protocol_version().addr_src
                                );
                            }
                        }
                        
                        auto self(shared_from_this());
                        
                        /**
                         * Start the version timeout timer.
                         */
                        timer_version_timeout_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_version_timeout_.async_wait(
                            strand_.wrap(
                                [this, self](boost::system::error_code ec)
                                {
                                    if (ec)
                                    {
                                        // ...
                                    }
                                    else
                                    {
                                        log_error(
                                            "TCP connection (version) timed "
                                            "out, calling stop."
                                        );
                                    
                                        /**
                                         * The connection has timed out, call
                                         * stop.
                                         */
                                        do_stop();
                                    }
                                }
                            )
                        );
                        
                        /**
                         * Send a version message.
                         */
                        send_version_message();
                    }
                }
                else if (m_direction == direction_outgoing)
                {
                    if (auto transport = m_tcp_transport.lock())
                    {
                        /**
                         * Inform the address_manager.
                         */
                        stack_impl_.get_address_manager()->mark_good(
                            protocol::network_address_t::from_endpoint(
                            transport->socket().remote_endpoint())
                        );
                    }
                    
                    /**
                     * If we have a one-shot ztquestion send it.
                     */
                    if (m_oneshot_ztquestion)
                    {
                        /**
                         * Stop the connection after N seconds, in case we
                         * get a ztanswer it will be closed immediately.
                         */
                        stop_after(4);
                        
                        /**
                         * Send the ztquestion.
                         */
                        send_ztquestion_message(*m_oneshot_ztquestion);
                    }
                    else if (m_chainblender_join)
                    {
                        /**
                         * Send the cbjoin.
                         */
                        send_cbjoin_message(*m_chainblender_join);
                    }
                    else if (m_probe_only == true)
                    {
                        /**
                         * Callback
                         */
                        if (m_on_probe)
                        {
                            m_on_probe(
                                m_protocol_version,
                                m_protocol_version_user_agent,
                                m_protocol_version_services,
                                m_protocol_version_start_height
                            );
                        }
                        
                        if (globals::instance().is_incentive_enabled())
                        {
                            /**
                             * Stop the connection after N seconds, in case we
                             * get an ianswer it will be closed immediately.
                             */
                            stop_after(4);

                            /**
                             * Send the iquestion.
                             */
                            send_iquestion_message();
                        }
                        else
                        {
                            /**
                             * We have confirmed the peer is valid, stop the
                             * connection.
                             */
                            stop();
                        }

                        return true;
                    }
                    else
                    {
                        /**
                         * Set our public ip address for this connection as
                         * reported in the version message.
                         */
                        m_address_public =
                            msg.protocol_version().addr_dst.ipv4_mapped_address()
                        ;
                        
                        /**
                         * Set our public ip address for this connection as
                         * reported in the version message into the global
                         * variables.
                         */
                        globals::instance().set_address_public(
                            m_address_public
                        );

                        log_debug(
                            "TCP connection learned our public ip address (" <<
                            m_address_public.to_string() << ") from "
                            "version message."
                        );
                        
                        if (utility::is_initial_block_download() == false)
                        {
                            /**
                             * If we are a peer advertise our address.
                             */
                            if (
                                globals::instance().operation_mode() ==
                                protocol::operation_mode_peer
                                )
                            {
                                /**
                                 * Send an addr message to advertise our
                                 * address only.
                                 */
                                send_addr_message(true);
                            }
                        }
                        
                        /**
                         * Only send a getaddr message if we have less than
                         * 1000 peers.
                         */
                        if (stack_impl_.get_address_manager()->size() < 1000)
                        {
                            /**
                             * Send a getaddr message to get more addresses.
                             */
                            send_getaddr_message();
                            
                            /**
                             * Set that we just sent a getaddr message.
                             */
                            m_sent_getaddr = true;
                        }
                    }
                }
            }

            if (m_oneshot_ztquestion)
            {
                /**
                 * This is a one-shot connection, no need to proceed.
                 */
            }
            else if (m_chainblender_join)
            {
                /**
                 * This is a chainblender session, no need to proceed.
                 */
            }
            else
            {
                /**
                 * If we are an (SPV) client set this connection as the active
                 * tcp_connection.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    globals::instance(
                        ).set_spv_active_tcp_connection_identifier(m_identifier
                    );
                }
                
                /**
                 * Send BIP-0035 mempool message.
                 */
                if (
                    m_direction == direction_outgoing &&
                    utility::is_initial_block_download() == false
                    )
                {
                    send_mempool_message();
                }

                /**
                 * Send isync message.
                 */
                if (m_direction == direction_outgoing)
                {
                    do_send_isync(8);
                }
                
                /**
                 * If we are an (SPV) client send a filterfload message before
                 * sending a getheaders or getblocks message.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    /**
                     * Send the filter load message.
                     */
                    send_filterload_message(
                        *globals::instance().spv_transaction_bloom_filter()
                    );
                }
                
                /**
                 * If we are an (SPV) client send a getheaders message otherwise
                 * if we have never sent a getblocks message or if our best
                 * block is the genesis block send getblocks.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    if (globals::instance().spv_use_getblocks() == false)
                    {
                        /**
                         * Get the block_locator hashes.
                         */
                        const auto & block_locator_hashes =
                            globals::instance().spv_block_locator_hashes()
                        ;
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(block_locator_hashes);
                        
                        /**
                         * Send the getheaders message.
                         */
                        send_getheaders_message(sha256(), locator);
                        
                        auto self(shared_from_this());
                        
                        /**
                         * Start the getheaders timer.
                         */
                        timer_getheaders_.expires_from_now(
                            std::chrono::seconds(8)
                        );
                        timer_getheaders_.async_wait(
                            strand_.wrap(
                            std::bind(&tcp_connection::do_send_getheaders, self,
                            std::placeholders::_1))
                        );
                    }
                    else
                    {
                        /**
                         * Get the block_locator hashes.
                         */
                        const auto & block_locator_hashes =
                            globals::instance().spv_block_locator_hashes()
                        ;
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(block_locator_hashes);
                        
                        /**
                         * Send the getblocks message.
                         */
                        send_getblocks_message(sha256(), locator);
                    }
                }
                else if (
                    did_send_getblocks_ == false ||
                    (constants::test_net == true &&
                    stack_impl::get_block_index_best()->get_block_hash() ==
                    block::get_hash_genesis_test_net()) ||
                    (constants::test_net == false &&
                    stack_impl::get_block_index_best()->get_block_hash() ==
                    block::get_hash_genesis())
                    )
                {
                    did_send_getblocks_ = true;
                    
                    log_debug(
                        "Connection is sending getblocks, best block = " <<
                        stack_impl::get_block_index_best()->get_block_hash(
                        ).to_string().substr(0, 20) << "."
                    );
                    
                    send_getblocks_message(
                        stack_impl::get_block_index_best(), sha256()
                    );
                }

                /**
                 * If we are a peer relay alerts and checkpoints.
                 */
                if (
                    globals::instance().operation_mode() ==
                    protocol::operation_mode_peer
                    )
                {
                    /**
                     * Relay alerts.
                     */
                    for (auto & i : stack_impl_.get_alert_manager()->alerts())
                    {
                        relay_alert(i.second);
                    }

                    /**
                     * Relay the sync-checkpoint (ppcoin).
                     */
                    relay_checkpoint(
                        checkpoints::instance().get_checkpoint_message()
                    );
                }
            
                log_debug(
                    "Connection received version message, version = " <<
                    msg.protocol_version().version << ", start height = " <<
                    msg.protocol_version().start_height << ", dest = " <<
                    msg.protocol_version().addr_dst.ipv4_mapped_address(
                    ).to_string() << ", src = " << msg.protocol_version(
                    ).addr_src.ipv4_mapped_address().to_string() << "."
                );

                /**
                 * Update the peer block counts.
                 */
                globals::instance().peer_block_counts().input(
                    m_protocol_version_start_height
                );

                /**
                 * Ask for pending sync-checkpoint if any (ppcoin).
                 */
                if (utility::is_initial_block_download() == false)
                {
                    checkpoints::instance().ask_for_pending_sync_checkpoint(
                        shared_from_this()
                    );
                }
            }
        }
    }
    else if (msg.header().command == "addr")
    {
        if (msg.protocol_addr().count > 1000)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 20);
        }
        else
        {
            log_debug(
                "TCP transport got " << msg.protocol_addr().count <<
                " addresses."
            );

            /**
             * Use the peer adjusted time.
             */
            auto now = time::instance().get_adjusted();
            
            auto since = now - 10 * 60;
        
            auto addr_list = msg.protocol_addr().addr_list;
            
            for (auto & i : addr_list)
            {
                if (i.timestamp <= 100000000 || i.timestamp > now + 10 * 60)
                {
                    i.timestamp = static_cast<std::uint32_t> (
                        now - 5 * 24 * 60 * 60
                    );
                }
                
                /**
                 * Insert the seen address.
                 */
                m_seen_network_addresses.insert(i);

                log_debug(
                    "TCP connection got addr.address = " <<
                    i.ipv4_mapped_address().to_string() <<
                    ", addr.port = " << i.port <<
                    ", is_local = " << i.is_local() <<
                    ", timestamp = " <<
                    ((std::time(0) - i.timestamp) / 60) << " mins."
                );
                
                if (i.is_local() == false)
                {
                    if (
                        i.timestamp > since && m_sent_getaddr == false &&
                        addr_list.size() <= 10
                        )
                    {
                        static sha256 hash_salt;
                        
                        if (hash_salt == 0)
                        {
                            hash_salt = hash::sha256_random();
                        }
                        
                        std::uint64_t hash_addr = i.get_hash();
                        
                        sha256 hash_random =
                            hash_salt ^ (hash_addr << 32) ^
                            ((std::time(0) + hash_addr) / (24 * 60 * 60))
                        ;
                        
                        hash_random = sha256::from_digest(&hash::sha256d(
                            hash_random.digest(), sha256::digest_length)[0]
                        );
                        
                        std::multimap<
                            sha256, std::shared_ptr<tcp_connection>
                        > mixes;
                        
                        auto tcp_connections =
                            stack_impl_.get_tcp_connection_manager(
                            )->tcp_connections()
                        ;
                        
                        for (auto & i2 : tcp_connections)
                        {
                            if (auto t = i2.second.lock())
                            {
                                std::uint32_t ptr_uint32;
                                
                                auto ptr_transport = t.get();
                                
                                std::memcpy(
                                    &ptr_uint32, &ptr_transport,
                                    sizeof(ptr_uint32)
                                );
                                
                                sha256 hash_key = hash_random ^ ptr_uint32;
                                
                                hash_key = sha256::from_digest(&hash::sha256d(
                                    hash_key.digest(), sha256::digest_length)[0]
                                );
                            
                                mixes.insert(std::make_pair(hash_key, t));
                            }
                        }
                        
                        int relay_nodes = 8;
                        
                        for (
                            auto it = mixes.begin();
                            it != mixes.end() && relay_nodes-- > 0; ++it
                            )
                        {
                            if (it->second)
                            {
                                it->second->send_addr_message(i);
                            }
                        }
                    }
                    
                    /**
                     * Set to false to disable learning of new peers.
                     */
                    if (true)
                    {
                        /**
                         * Add the address to the address_manager.
                         */
                        stack_impl_.get_address_manager()->add(
                            i, msg.protocol_version().addr_src, 60
                        );
                    }
                }
            }
            
            if (stack_impl_.get_address_manager()->get_addr().size() < 1000)
            {
                /**
                 * Set that we have not sent a getaddr message.
                 */
                m_sent_getaddr = false;
            }
        }
    }
    else if (msg.header().command == "getaddr")
    {
        /**
         * Send an addr message.
         */
        send_addr_message();
    }
    else if (msg.header().command == "ping")
    {
        log_debug(
            "TCP connection got ping, nonce = " <<
            msg.protocol_ping().nonce << ", sending pong."
        );
        
        /**
         * Send a pong message with the nonce.
         */
        send_pong_message(msg.protocol_ping().nonce);
    }
    else if (msg.header().command == "pong")
    {
        log_debug(
            "TCP connection got pong, nonce = " <<
            msg.protocol_pong().nonce << "."
        );
        
        /**
         * Cancel the ping timeout timer.
         */
        timer_ping_timeout_.cancel();
    }
    else if (msg.header().command == "inv")
    {
        /**
         * If true we must send an SPV getblocks message AFTER sending
         * a getdata message on the current block.
         */
        auto should_send_spv_getblocks = false;
        
        if (msg.protocol_inv().inventory.size() > protocol::max_inv_size)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 20);
        }
        else
        {
            if (globals::instance().is_client_spv() == false)
            {
                /**
                 * Find the last block in the inventory vector.
                 */
                auto last_block = static_cast<std::uint32_t> (-1);
                
                for (auto i = 0; i < msg.protocol_inv().inventory.size(); i++)
                {
                    if (
                        msg.protocol_inv().inventory[
                        msg.protocol_inv().inventory.size() - 1 - i].type() ==
                        inventory_vector::type_msg_block
                        )
                    {
                        last_block = static_cast<std::uint32_t> (
                            msg.protocol_inv().inventory.size() - 1 - i
                        );
                        
                        break;
                    }
                }
                
                /**
                 * Open the transaction database for reading.
                 */
                db_tx tx_db("r");
                
                auto index = 0;
                
                auto inventory = msg.protocol_inv().inventory;

                for (auto & i : inventory)
                {
                    insert_inventory_vector_seen(i);
                
                    auto already_have = inventory_vector::already_have(
                        tx_db, i
                    );
                    
                    if (globals::instance().debug() && false)
                    {
                        log_debug(
                            "Connection got inv = " << i.to_string() <<
                            (already_have ? " have" : " new") << "."
                        );
                    }
                    
                    if (already_have == false)
                    {
                        /**
                         * Ask for the data.
                         */
                        getdata_.push_back(i);
                    }
                    else if (
                        i.type() == inventory_vector::type_msg_block &&
                        globals::instance().orphan_blocks().count(i.hash())
                        )
                    {
                        send_getblocks_message(
                            stack_impl::get_block_index_best(),
                            utility::get_orphan_root(
                            globals::instance().orphan_blocks()[i.hash()])
                        );
                    }
                    else if (index == last_block)
                    {
                        /**
                         * In case we are on a very long side-chain, it is possible
                         * that we already have the last block in an inv bundle
                         * sent in response to getblocks. Try to detect this
                         * situation and push another getblocks to continue.
                         */
                        send_getblocks_message(
                            globals::instance().block_indexes()[i.hash()],
                            sha256()
                        );
                        
                        if (globals::instance().debug() && false)
                        {
                            log_debug(
                                "Connection is forcing getblocks request " <<
                                i.to_string() << "."
                            );
                        }
                    }
                    
                    /**
                     * Inform the wallet manager.
                     */
                    wallet_manager::instance().on_inventory(i.hash());
                    
                    index++;
                }
            }
            else
            {
                /**
                 * Find the last block in the inventory vector.
                 */
                auto last_block = static_cast<std::uint32_t> (-1);

                /**
                 * If the type is of inventory_vector::type_msg_block
                 * set it to
                 * inventory_vector::type_msg_filtered_block_nonstandard
                 * so the remote node does not send blocks in response
                 * to our getdata requests but instead merkleblocks.
                 */
                for (auto & i : msg.protocol_inv().inventory)
                {
                    if (i.type() == inventory_vector::type_msg_block)
                    {
                        i.set_type(
                            inventory_vector::
                            type_msg_filtered_block_nonstandard
                        );
                    }
                }
                
                for (auto i = 0; i < msg.protocol_inv().inventory.size(); i++)
                {
                    if (
                        msg.protocol_inv().inventory[
                        msg.protocol_inv().inventory.size() - 1 - i].type() ==
                        inventory_vector::type_msg_filtered_block_nonstandard
                        )
                    {
                        last_block = static_cast<std::uint32_t> (
                            msg.protocol_inv().inventory.size() - 1 - i
                        );
                        
                        break;
                    }
                }
                
                auto index = 0;
                
                auto inventory = msg.protocol_inv().inventory;
                
                for (auto & i : inventory)
                {
                    log_none("SPV inv already_have = " << already_have);
                    
                    if (inventory_vector::spv_already_have(i) == false)
                    {
                        /**
                         * :TODO: Filter out INV's that (SPV) clients do not
                         * need to know about.
                         */
                        if (globals::instance().spv_use_getblocks() == true)
                        {
                            /**
                             * Ask for the data.
                             */
                            getdata_.push_back(i);
                         }
                    }
                    else if (index == last_block)
                    {
                        // ...
                    }
                    
                    /**
                     * Inform the wallet manager.
                     */
                    wallet_manager::instance().on_inventory(i.hash());
                    
                    index++;
                }
            }
        }

        /**
         * Set the first and last hash.
         */
        std::vector<sha256> hashes;
        
        if (globals::instance().is_client_spv() == true)
        {
            /**
             * If we got > 1 block hashes request the next 500 block hashes.
             */
            if (getdata_.size() > 1)
            {
                should_send_spv_getblocks = true;
                
                /**
                 * Get the first block header.
                 */
                auto hash_first = getdata_.front().hash();
                
                /**
                 * Get the last block header.
                 */
                auto hash_last = getdata_.back().hash();
                
                hashes.push_back(hash_last);
                hashes.push_back(hash_first);
            }
        }

        /**
         * If we are an (SPV) client add any matched transaction hashes
         * from the merkle block to the next getdata message.
         */
        if (globals::instance().is_client_spv() == true)
        {
            for (auto & i : spv_transactions_matched_)
            {
                inventory_vector inv(inventory_vector::type_msg_tx, i);
                
                /**
                 * Ask for the data.
                 */
                getdata_.push_back(inv);
            }
            
            spv_transactions_matched_.clear();
        }
        
        /**
         * If we have some getdata send it now.
         */
        send_getdata_message();
        
        /**
         * If we should send SPV getblocks do so now.
         */
        if (
            globals::instance().is_client_spv() == true &&
            should_send_spv_getblocks == true
            )
        {

            /**
             * Allocate the block_locator with the last and
             * first hash.
             */
            block_locator locator(hashes);

            /**
             * Send the getblocks message.
             */
            send_getblocks_message(sha256(), locator);
        }
    }
    else if (msg.header().command == "getdata")
    {
        /**
         * If we are a peer handle the getdata message.
         */
        if (
            globals::instance().operation_mode() ==
            protocol::operation_mode_peer
            )
        {
            if (msg.protocol_getdata().count > protocol::max_inv_size)
            {
                log_debug(
                    "TCP connection received getdata, size = " <<
                    msg.protocol_getdata().count << "."
                );
                
                /**
                 * Set the Denial-of-Service score for the connection.
                 */
                set_dos_score(m_dos_score + 20);
            }
            else
            {
                if (msg.protocol_getdata().count != 1)
                {
                    log_debug(
                        "TCP connection received getdata, size = " <<
                        msg.protocol_getdata().count << "."
                    );
                }
                
                auto inventory = msg.protocol_getdata().inventory;
                
                for (auto & i : inventory)
                {
                    if (msg.protocol_getdata().count == 1)
                    {
                        log_debug(
                            "TCP connection received getdata for " <<
                            i.to_string() << "."
                        );
                    }
                    
                    if (
                        i.type() == inventory_vector::type_msg_block ||
                        i.type() ==
                        inventory_vector::type_msg_filtered_block_nonstandard
                        )
                    {
                        /**
                         * Find the block.
                         */
                        auto it = globals::instance().block_indexes().find(
                            i.hash()
                        );
                        
                        if (it != globals::instance().block_indexes().end())
                        {
                            /**
                             * Allocate the block.
                             */
                            block blk;
                            
                            /**
                             * Read the block from disk.
                             */
                            blk.read_from_disk(it->second);
                            
                            if (i.type() == inventory_vector::type_msg_block)
                            {
                                /**
                                 * Send the block message.
                                 */
                                do_send_block_message(blk);
                            }
                            else
                            {
                                /**
                                 * Check if we have a BIP-0037 bloom filter.
                                 */
                                if (transaction_bloom_filter_)
                                {
                                    /**
                                     * Create the block_merkle.
                                     */
                                    block_merkle merkle_block(
                                        blk, *transaction_bloom_filter_
                                    );
                                    
                                    /**
                                     * Send the merkleblock message.
                                     */
                                    send_merkleblock_message(merkle_block);
                                    
                                    for (
                                        auto & i :
                                        merkle_block.transactions_matched()
                                        )
                                    {
                                        for (auto & j : blk.transactions())
                                        {
                                            if (i.second == j.get_hash())
                                            {
                                                /**
                                                 * Send the tx message.
                                                 */
                                                send_tx_message(j);
                                            }
                                        }
                                    }
                                }
                            }

                            /**
                             * Trigger them to send a getblocks request for the
                             * next batch of inventory.
                             */
                            if (i.hash() == m_hash_continue)
                            {
                                /**
                                 * Send latest proof-of-work block to allow the
                                 * download node to accept as orphan
                                 * (proof-of-stake block might be rejected by
                                 * stake connection check) (ppcoin).
                                 */
                                std::vector<sha256> block_hashes;
                                
                                /**
                                 * Insert the (previous) best block index's
                                 * hash.
                                 */
                                block_hashes.push_back(
                                    utility::get_last_block_index(
                                    stack_impl::get_block_index_best(), false
                                    )->get_block_hash()
                                );
               
                                /**
                                 * Send an inv message.
                                 */
                                do_send_inv_message(
                                    inventory_vector::type_msg_block,
                                    block_hashes
                                );
                                
                                /**
                                 * Set the hash continue to null.
                                 */
                                m_hash_continue = 0;
                            }
                        }
                    }
                    else if (i.is_know_type())
                    {
                        /**
                         * Send stream from relay memory.
                         */
                        bool did_send = false;
                        
                        auto it = globals::instance().relay_invs().find(i);
                        
                        if (it != globals::instance().relay_invs().end())
                        {
                            /**
                             * Send the relayed inv message.
                             */
                            do_send_relayed_inv_message(
                                i, data_buffer(it->second.data(),
                                it->second.size())
                            );
                            
                            did_send = true;
                        }
                        
                        if (did_send == false)
                        {
                            if (i.type() == inventory_vector::type_msg_tx)
                            {
                                if (
                                    transaction_pool::instance().exists(
                                    i.hash())
                                    )
                                {
                                    auto tx = transaction_pool::instance(
                                        ).lookup(i.hash()
                                    );

                                    /**
                                     * Send the tx message.
                                     */
                                    send_tx_message(tx);
                                }
                            }
                            else if (
                                i.type() == inventory_vector::type_msg_ztlock
                                )
                            {
                                if (
                                    zerotime::instance().locks().count(
                                    i.hash()) > 0
                                    )
                                {
                                    auto ztlock =
                                        zerotime::instance().locks()[i.hash()]
                                    ;

                                    /**
                                     * Send the ztlock message.
                                     */
                                    send_ztlock_message(ztlock);
                                }
                            }
                           else if (
                                i.type() == inventory_vector::type_msg_ivote
                                )
                            {
                                if (
                                    incentive::instance().votes().count(
                                    i.hash()) > 0
                                    )
                                {
                                    auto ivote =
                                        incentive::instance().votes()[i.hash()]
                                    ;

                                    /**
                                     * Send the ivote message.
                                     */
                                    send_ivote_message(ivote);
                                }
                            }
                        }
                    }
                    
                    /**
                     * Inform the wallet manager.
                     */
                    wallet_manager::instance().on_inventory(i.hash());
                }
            }
        }
        else
        {
            log_info(
                "TCP connection (operation mode client) is dropping "
                "getdata message."
            );
        }
    }
    else if (msg.header().command == "getblocks")
    {
        /**
         * If we are a peer with an up-to-date blockchain handle the
         * getblocks message.
         */
        if (
            utility::is_initial_block_download() == false &&
            globals::instance().operation_mode() ==
            protocol::operation_mode_peer
            )
        {
            /**
             * Find the last block the sender has in the main chain.
             */
            auto index = block_locator(
                msg.protocol_getblocks().hashes
            ).get_block_index();
            
            /**
             * Send the rest of the chain.
             */
            if (index)
            {
                index = index->block_index_next();
            }
            
            /**
             * We send 500 block hashes.
             */
            enum { default_blocks = 500 };
            
            /**
             * The limit on the number of blocks to send.
             */
            std::int16_t limit = default_blocks;

            log_debug(
                "TCP connection getblocks " <<
                (index ? index->height() : -1) << " to " <<
                msg.protocol_getblocks().hash_stop.to_string(
                ).substr(0, 20) << " limit " << limit << "."
            );
            
            /**
             * The block hashes to send.
             */
            std::vector<sha256> block_hashes;
            
            for (; index; index = index->block_index_next())
            {
                if (
                    index->get_block_hash() ==
                    msg.protocol_getblocks().hash_stop
                    )
                {
                    log_debug(
                        "TCP connection getblocks stopping at " <<
                        index->height() << " " <<
                        index->get_block_hash().to_string().substr(0, 20)
                        << "."
                    );
                    
                    /**
                     * Tell the downloading node about the latest block if
                     * it's without risk of being rejected due to stake
                     * connection check (ppcoin).
                     */
                    if (
                        msg.protocol_getblocks().hash_stop !=
                        globals::instance().hash_best_chain() &&
                        index->time() + constants::min_stake_age >
                        stack_impl::get_block_index_best()->time()
                        )
                    {
                        /**
                         * Insert the block hash.
                         */
                        block_hashes.push_back(
                            globals::instance().hash_best_chain()
                        );
                    }
                    
                    break;
                }
                
                /**
                 * Insert the block hash.
                 */
                block_hashes.push_back(index->get_block_hash());
                
                if (--limit <= 0)
                {
                    /**
                     * When this block is requested, we'll send an inv
                     * that'll make them getblocks the next batch of
                     * inventory.
                     */
                    log_debug(
                        "TCP connection getblocks stopping at limit " <<
                        index->height() << " " <<
                        index->get_block_hash().to_string().substr(
                        0, 20) << "."
                    );

                    /**
                     * Set the hash continue.
                     */
                    m_hash_continue = index->get_block_hash();
                    
                    break;
                }
            }

            if (block_hashes.size() > 0)
            {
                /**
                 * Send an inv message with the block hashes.
                 */
                do_send_inv_message(
                    inventory_vector::type_msg_block, block_hashes
                );
            }
        }
        else
        {
            log_debug(
                "TCP connection (operation mode client or initial download)"
                " is dropping getblocks message."
            );
        }
    }
    else if (msg.header().command == "checkpoint")
    {
        log_debug("TCP connection got checkpoint.");

        /**
         * Allocate the checpoint.
         */
        checkpoint_sync checkpoint;
        
        /**
         * Set the message.
         */
        checkpoint.set_message(msg.protocol_checkpoint().message);
        
        /**
         * Set the signature.
         */
        checkpoint.set_signature(msg.protocol_checkpoint().signature);
        
        /**
         * Copy the message into the buffer.
         */
        data_buffer buffer(reinterpret_cast<const char *>(
            &msg.protocol_checkpoint().message[0]),
            msg.protocol_checkpoint().message.size()
        );
        
        /**
         * Decode the message.
         */
        ((checkpoint_sync_unsigned)checkpoint).decode(buffer);
        
        /**
         * Process the sync checkpoint.
         */
        if (checkpoint.process_sync_checkpoint(shared_from_this()))
        {
            /**
             * Relay the checkpoint.
             */
            relay_checkpoint(checkpoint);
        }
    }
    else if (msg.header().command == "getheaders")
    {
        log_debug("Got getheaders");
        
        const auto & locator = msg.protocol_getheaders().locator;
        
        block_index * index = 0;
        
        if (locator && locator->is_null())
        {
            auto it = globals::instance().block_indexes().find(
                msg.protocol_getheaders().hash_stop
            );
            
            if (it == globals::instance().block_indexes().end())
            {
                return true;
            }
            
            index = it->second;
        }
        else
        {
            index = locator->get_block_index();
            
            if (index)
            {
                index = index->block_index_next();
            }
        }

        std::vector<block> headers;
        
        std::int16_t limit = 2000;
        
        log_debug(
            "TCP connection getheaders " << (index ? index->height() : -1) <<
            " to " <<
            msg.protocol_getheaders().hash_stop.to_string().substr(0, 8) << "."
        );

        for (; index; index = index->block_index_next())
        {
            headers.push_back(index->get_block_header());
            
            if (
                --limit <= 0 ||
                index->get_block_hash() == msg.protocol_getheaders().hash_stop
                )
            {
                break;
            }
        }
        
        /**
         * Send headers message.
         */
        send_headers_message(headers);
    }
    else if (msg.header().command == "headers")
    {
        log_none("Got headers = " << msg.protocol_headers().headers.size());
        
        /**
         * Set the last time we got a headers.
         */
        time_last_headers_received_ = std::time(0);
        
        if (
            globals::instance().operation_mode() ==
            protocol::operation_mode_client &&
            globals::instance().is_client_spv() == true
            )
        {
            /**
             * Make sure we have some headers.
             */
            if (msg.protocol_headers().headers.size() > 0)
            {
                /**
                 * Cancel the (SPV) getheaders timeout timer.
                 */
                timer_spv_getheader_timeout_.cancel();
            
                /**
                 * Get the time of the last block header.
                 */
                auto time_last_header = static_cast<std::time_t> (
                    msg.protocol_headers().headers.back().header().timestamp)
                ;
                
                log_none(
                    "TCP connection got " <<
                    msg.protocol_headers().headers.size() <<
                    " headers, last time ago = " <<
                    std::time(0) - time_last_header
                );
                
                if (
                    msg.protocol_headers().headers.size() >= 2000 ||
                    time_last_header >=
                    globals::instance().spv_time_wallet_created()
                    )
                {
                    /**
                     * Get the first block header.
                     */
                    auto hash_first =
                        msg.protocol_headers().headers.front().get_hash()
                    ;
                    
                    /**
                     * Get the last block header.
                     */
                    auto hash_last =
                        msg.protocol_headers().headers.back().get_hash()
                    ;

                    /**
                     * After N time since wallet creation switch from
                     * downloading headers to BIP-0037 merkleblock's for
                     * the rest of the chain.
                     */
                    if (
                        time_last_header >=
                        globals::instance().spv_time_wallet_created() &&
                        globals::instance().spv_use_getblocks() == false
                        )
                    {
                        globals::instance().set_spv_use_getblocks(true);
                        
                        log_info(
                            "TCP connection is switching to (SPV) getblocks."
                        );
                        
                        log_info(
                            time_last_header << ":" <<
                            globals::instance().spv_time_wallet_created()
                        );
                    }

                    if (globals::instance().spv_use_getblocks() == true)
                    {
                        /**
                         * Set the first and last hash.
                         */
                        std::vector<sha256> hashes;
                        
                        hashes.push_back(hash_last);
                        hashes.push_back(hash_first);
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(hashes);
                        
                        /**
                         * Send the next getblocks message.
                         */
                        send_getblocks_message(sha256(), locator);
                    }
                    else
                    {
                        /**
                         * Set the first and last hash.
                         */
                        std::vector<sha256> hashes;
                        
                        hashes.push_back(hash_last);
                        hashes.push_back(hash_first);
                        
                        /**
                         * Allocate the block_locator with the last and
                         * first hash.
                         */
                        block_locator locator(hashes);
                        
                        /**
                         * Send the next getheaders message.
                         */
                        send_getheaders_message(sha256(), locator);
                    }
                }
                else
                {
                    /**
                     * We expect at least 2000 headers, any less and we ignore
                     * the message.
                     */
                }
            }
            else
            {
                /**
                 * We expect at least 1 header, any less and we switch to
                 * getblocks.
                 */
                globals::instance().set_spv_use_getblocks(true);
                
                log_info(
                    "TCP connection is switching to (SPV) getblocks because we "
                    "got 0 headers."
                );
            
                /**
                 * Send a getblocks message.
                 */
                if (globals::instance().spv_use_getblocks() == true)
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getblocks message.
                     */
                    send_getblocks_message(sha256(), locator);
                }
            }
            
            auto self(shared_from_this());
            
            for (auto & i : msg.protocol_headers().headers)
            {
                block_merkle merkle_block(i);
                
                if (merkle_block.is_valid_spv() == true)
                {
                    log_none(
                        "TCP connection " << this << " got valid merkle_block, "
                        "matches = " <<
                        merkle_block.transactions_matched().size() << "."
                    );
                    
                    /**
                     * Only block_merkle's required matching received
                     * transactions.
                     */
                    std::vector<transaction> transactions_received;

                    auto self(shared_from_this());
                    
                    /**
                     * Post the operation onto the boost::asio::io_service.
                     */
                    globals::instance().strand().dispatch(
                        [this, self, merkle_block, transactions_received]()
                    {
                        /**
                         * Callback
                         */
                        stack_impl_.on_spv_merkle_block(
                            self, *const_cast<block_merkle *> (&merkle_block),
                            transactions_received
                        );
                    });
                }
                else
                {
                    log_error(
                        "TCP connection " << this << " got bad merkle "
                        "block, dropping."
                    );
                }
            }
        }
        else
        {
            /**
             * Make sure we have some headers.
             */
            if (msg.protocol_headers().headers.size() > 0)
            {
                /**
                 * Get the first block header.
                 */
                auto hash_first =
                    msg.protocol_headers().headers.front().get_hash()
                ;
                
                /**
                 * Get the last block header.
                 */
                auto hash_last =
                    msg.protocol_headers().headers.back().get_hash()
                ;
                
                /**
                 * Set the first and last hash.
                 */
                std::vector<sha256> hashes;
                
                hashes.push_back(hash_last);
                hashes.push_back(hash_first);
                
                /**
                 * Allocate the block_locator with the last and
                 * first hash.
                 */
                block_locator locator(hashes);
                
                /**
                 * Send the next getheaders message.
                 */
                send_getheaders_message(sha256(), locator);
            }
            else
            {
                /**
                 * We expect at least 2000 headers, any less and we ignore the
                 * message.
                 */
            }
        }
    }
    else if (msg.header().command == "tx")
    {
        log_debug("Got tx");

        const auto & tx = msg.protocol_tx().tx;
        
        if (tx)
        {
            /**
             * If we are an (SPV) client we handle transactions differently.
             */
            if (globals::instance().is_client_spv() == true)
            {
                wallet_manager::instance().sync_with_wallets(
                    *tx, 0, true
                );

                auto self(shared_from_this());
                
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                io_service_.post(strand_.wrap(
                    [this, tx]()
                {
                    /**
                     * :TODO: We are using the best block height (which is
                     * most likely correct), instead we need to find the
                     * block_merkle with the transaction and use that
                     * height.
                     */
                    if (utility::is_spv_initial_block_download() == true)
                    {
                        wallet_manager::instance().on_spv_transaction_updated(
                            globals::instance().spv_best_block_height(),
                            tx->get_hash()
                        );
                    }
                }));
                
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_tx, tx->get_hash()
                );

                insert_inventory_vector_seen(inv);
            }
            else
            {
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_tx, tx->get_hash()
                );

                /**
                 * Allocate the data_buffer.
                 */
                data_buffer buffer;
                
                /**
                 * Encode the transaction.
                 */
                tx->encode(buffer);
                
                std::vector<sha256> queue_work;
                std::vector<sha256> queue_erase;
                
                db_tx txdb("r");
            
                auto missing_inputs = false;
                
                if (
                    tx->accept_to_transaction_pool(txdb, &missing_inputs).first
                    )
                {
                    /**
                     * Inform the wallet_manager.
                     */
                    wallet_manager::instance().sync_with_wallets(*tx, 0, true);
            
                    if (m_protocol_version_relay == false)
                    {
                        log_info(
                            "TCP connection is not relaying transaction."
                        );
                    }
                    else
                    {
                        /**
                         * Relay the inv.
                         */
                        relay_inv(inv, buffer);
                    }
                    
                    queue_work.push_back(inv.hash());
                    queue_erase.push_back(inv.hash());

                    /**
                     * Recursively process any orphan transactions that
                     * depended on this one.
                     */
                    for (auto i = 0; i < queue_work.size(); i++)
                    {
                        auto hash_previous = queue_work[i];

                        auto it = globals::instance(
                            ).orphan_transactions_by_previous()[
                            hash_previous].begin()
                        ;
                        
                        for (
                            ;
                            it != globals::instance(
                            ).orphan_transactions_by_previous()[
                            hash_previous].end();
                            ++it
                            )
                        {
                            data_buffer buffer2(
                                it->second->data(), it->second->size()
                            );
                            
                            transaction tx2;
                            
                            tx2.decode(buffer2);
                            
                            inventory_vector inv2(
                                inventory_vector::type_msg_tx, tx2.get_hash()
                            );
                            
                            bool missing_inputs2 = false;

                            if (
                                tx2.accept_to_transaction_pool(txdb,
                                &missing_inputs2).first
                                )
                            {
                                log_debug(
                                    "TCP connection accepted orphan "
                                    "transaction " << inv2.hash().to_string(
                                    ).substr(0, 10) << "."
                                )
                                /**
                                 * Inform the wallet_manager.
                                 */
                                wallet_manager::instance().sync_with_wallets(
                                    tx2, 0, true
                                );

                                if (m_protocol_version_relay == false)
                                {
                                    log_info(
                                        "TCP connection is not relaying "
                                        "transaction to BIP-0037 node."
                                    );
                                }
                                else
                                {
                                    relay_inv(inv2, buffer2);
                                }
                                
                                queue_work.push_back(inv2.hash());
                                queue_erase.push_back(inv2.hash());
                            }
                            else if (missing_inputs2 == false)
                            {
                                /**
                                 * Invalid orphan.
                                 */
                                queue_erase.push_back(inv2.hash());
                                
                                log_debug(
                                    "TCP connection removed invalid orphan "
                                    "transaction " <<
                                    inv2.hash().to_string().substr(0, 10) << "."
                                );
                            }
                        }
                    }

                    for (auto & i : queue_erase)
                    {
                        utility::erase_orphan_tx(i);
                    }
                }
                else if (missing_inputs)
                {
                    utility::add_orphan_tx(buffer);

                    /**
                     * Limit the size of the orphan transactions.
                     */
                    auto evicted = utility::limit_orphan_tx_size(
                        block::get_maximum_size_median220() / 100
                    );
                    
                    if (evicted > 0)
                    {
                        log_debug(
                            "TCP connection orphans overflow, evicted = " <<
                            evicted << "."
                        );
                    }
                }
            }
        }
    }
    else if (msg.header().command == "block")
    {
        if (msg.protocol_block().blk)
        {
            log_debug(
                "Connection received block " <<
                msg.protocol_block().blk->get_hash().to_string(
                ).substr(0, 20)
                << "."
            );
#if 0
            msg.protocol_block().blk->print();
#endif
            /**
             * Set the time we received a block.
             */
            time_last_block_received_ = std::time(0);
            
            if (globals::instance().is_client_spv() == false)
            {
                /**
                 * Allocate an inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_block,
                    msg.protocol_block().blk->get_hash()
                );
                
                insert_inventory_vector_seen(inv);
                
                /**
                 * Get a shared pointer to the block so the post operation
                 * will hold onto it.
                 */
                auto ptr_block = msg.protocol_block().blk;
                
                auto self(shared_from_this());
                
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                globals::instance().strand().dispatch(
                    [this, self, ptr_block]()
                {
                    /**
                     * Process the block.
                     */
                    if (
                        stack_impl_.process_block(self, ptr_block)
                        )
                    {
                        // ...
                    }
                });
            }
            else
            {
                block_merkle merkle_block(*msg.protocol_block().blk);
                
                std::vector<transaction> transactions_received;
                
                auto self(shared_from_this());
                
                /**
                 * Post the operation onto the boost::asio::io_service.
                 */
                globals::instance().strand().dispatch(
                    [this, self, merkle_block, transactions_received]()
                {
                    /**
                     * Callback
                     */
                    stack_impl_.on_spv_merkle_block(
                        self, *const_cast<block_merkle *> (&merkle_block),
                        transactions_received
                    );
                });
            }
        }
    }
    else if (msg.header().command == "merkleblock")
    {
        assert(msg.protocol_merkleblock().merkleblock);
        
        if (msg.protocol_merkleblock().merkleblock)
        {
            log_none(
                "Connection received merkleblock " <<
                msg.protocol_merkleblock().merkleblock->get_hash().to_string(
                ).substr(0, 20)
                << "."
            );
            
            /**
             * Allocate an inventory_vector.
             */
            inventory_vector inv(
                inventory_vector::type_msg_filtered_block_nonstandard,
                msg.protocol_merkleblock().merkleblock->get_hash()
            );
            
            insert_inventory_vector_seen(inv);
            
            /**
             * Cancel the (SPV) getblocks timeout timer.
             */
            timer_spv_getblocks_timeout_.cancel();
            
            /**
             * Set the time we received a block.
             */
            time_last_block_received_ = std::time(0);

            block_merkle merkle_block(
                *msg.protocol_merkleblock().merkleblock
            );
            
            /**
             * This block_merkle has no matching received transactions.
             */
            std::vector<transaction> transactions_received;
            
            auto self(shared_from_this());
            
            /**
             * Post the operation onto the boost::asio::io_service.
             */
            globals::instance().strand().dispatch(
                [this, self, merkle_block, transactions_received]()
            {
                /**
                 * Callback
                 */
                stack_impl_.on_spv_merkle_block(
                    self, *const_cast<block_merkle *> (&merkle_block),
                    transactions_received
                );
            });
            
            if (
                msg.protocol_merkleblock().merkleblock->is_valid_spv() == true
                )
            {
                /**
                 * Copy the hashes of the matched transactions from the
                 * merkle block.
                 */
                for (
                    auto & i : msg.protocol_merkleblock(
                    ).merkleblock->transactions_matched()
                    )
                {
                    spv_transactions_matched_.insert(i.second);
                }
            }
            else
            {
                log_error("TCP connection got invalid merkleblock message.");
            }
        }
    }
    else if (msg.header().command == "filterload")
    {
        assert(msg.protocol_filterload().filterload);
        
        /**
         * First check the size constrainsts of the filter.
         */
        if (
            msg.protocol_filterload(
            ).filterload->is_within_size_constraints() == false
            )
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 100);
        }
        else
        {
            transaction_bloom_filter_.reset(
                new transaction_bloom_filter(
                *msg.protocol_filterload().filterload)
            );
            
            transaction_bloom_filter_->update_empty_full();
        }
        
        m_protocol_version_relay = true;
    }
    else if (msg.header().command == "filteradd")
    {
        /**
         * First check the size.
         */
        if (
            msg.protocol_filteradd().filteradd.size() >
            script::max_element_size
            )
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 100);
        }
        else
        {
            if (transaction_bloom_filter_ == 0)
            {
                /**
                 * Set the Denial-of-Service score for the connection.
                 */
                set_dos_score(m_dos_score + 100);
            }
            else
            {
                transaction_bloom_filter_->insert(
                    msg.protocol_filteradd().filteradd
                );
            }
        }
    }
    else if (msg.header().command == "filterclear")
    {
        transaction_bloom_filter_.reset(
            new transaction_bloom_filter()
        );
        
        m_protocol_version_relay = true;
    }
    else if (msg.header().command == "ztlock")
    {
        log_debug("Got ztlock");

        assert(msg.protocol_ztlock().ztlock);
        
        if (globals::instance().is_zerotime_enabled())
        {
            const auto & ztlock = msg.protocol_ztlock().ztlock;

            if (ztlock)
            {
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_ztlock, ztlock->hash_tx()
                );

                /**
                 * Check that the zerotime lock is not expired.
                 */
                if (time::instance().get_adjusted() < ztlock->expiration())
                {
                    /**
                     * Check that the transaction hash exists in the
                     * transaction pool before accepting a zerotime_lock.
                     */
                    auto hash_not_found = true;
                    
                    /**
                     * If we are an (SPV) client we do not use the
                     * transaction_pool.
                     */
                    if (globals::instance().is_client_spv() == true)
                    {
                        hash_not_found =
                            globals::instance().wallet_main()->transactions(
                            ).count(ztlock->hash_tx()) == 0
                        ;
                    }
                    else
                    {
                        hash_not_found =
                            transaction_pool::instance().transactions().count(
                            ztlock->hash_tx()) == 0
                        ;
                    }

                    if (hash_not_found)
                    {
                        log_info(
                            "TCP connection got ZeroTime lock (hash not found)"
                            ", dropping " <<
                            ztlock->hash_tx().to_string().substr(0, 8) << "."
                        );
                    }
                    else if (
                        globals::instance().is_client_spv() == true &&
                        globals::instance().wallet_main()->transactions()[
                        ztlock->hash_tx()].time() >
                        time::instance().get_adjusted()
                        )
                    {
                        log_info(
                            "TCP connection (SPV) got ZeroTime lock (arrived "
                            "in a flying delorean), dropping " <<
                            ztlock->hash_tx().to_string().substr(0, 8) << "."
                        );
                    }
                    else if (
                        globals::instance().is_client_spv() == false &&
                        transaction_pool::instance().transactions()[
                        ztlock->hash_tx()].time() >
                        time::instance().get_adjusted()
                        )
                    {
                        log_info(
                            "TCP connection got ZeroTime lock (arrived in "
                            "a flying delorean), dropping " <<
                            ztlock->hash_tx().to_string().substr(0, 8) << "."
                        );
                    }
                    else if (
                        zerotime::instance().locks().count(
                        ztlock->hash_tx()) > 0
                        )
                    {
                        // ...
                    }
                    else
                    {
                        /**
                         * Prevent a peer from sending a conflicting lock.
                         */
                        if (
                            zerotime::instance().has_lock_conflict(
                            ztlock->transactions_in(), ztlock->hash_tx())
                            )
                        {
                            log_info(
                                "TCP connection got ZeroTime (lock conflict)"
                                ", dropping " <<
                                ztlock->hash_tx().to_string().substr(0, 8) <<
                                "."
                            );
                        }
                        else
                        {
                            /**
                             * (SPV) clients do not relay ZeroTime locks.
                             */
                            if (globals::instance().is_client_spv() == false)
                            {
                                /**
                                 * Allocate the buffer for relaying.
                                 */
                                data_buffer buffer;
                            
                                /**
                                 * Encode the zerotime_lock.
                                 */
                                ztlock->encode(buffer);
                                
                                /**
                                 * Relay the inv.
                                 */
                                relay_inv(inv, buffer);
                            }

                            log_info(
                                "TCP connection is adding ZeroTime lock " <<
                                ztlock->hash_tx().to_string().substr(0, 8) <<
                                "."
                            );
                            
                            /**
                             * Insert the zerotime_lock.
                             */
                            zerotime::instance().locks().insert(
                                std::make_pair(ztlock->hash_tx(), *ztlock)
                            );
                            
                            /**
                             * Lock the inputs.
                             */
                            for (auto & i : ztlock->transactions_in())
                            {
                                zerotime::instance().locked_inputs()[
                                    i.previous_out()] = ztlock->hash_tx()
                                ;
                            }

                            /**
                             * (SPV) clients do not vote on ZeroTime locks.
                             */
                            if (globals::instance().is_client_spv() == false)
                            {
                                /**
                                 * Vote for the ztlock.
                                 */
                                stack_impl_.get_zerotime_manager()->vote(
                                    ztlock->hash_tx(), ztlock->transactions_in()
                                );
                            }
                        }
                    }
                }
                else
                {
                    log_info(
                        "TCP connection got expired ZeroTime lock, dropping."
                    );
                }
            }
        }
    }
    else if (msg.header().command == "ztquestion")
    {
        log_debug("Got ztquestion");

        if (globals::instance().is_zerotime_enabled())
        {
            const auto & ztquestion = msg.protocol_ztquestion().ztquestion;

            if (ztquestion)
            {
                const auto & tx_ins = ztquestion->transactions_in();
                
                sha256 hash_tx;
                
                auto should_send_answer = false;
                
                for (auto & i : tx_ins)
                {
                    if (
                        zerotime::instance().locked_inputs().count(
                        i.previous_out()) > 0
                        )
                    {
                        /**
                         * Get the transaction's hash.
                         */
                        hash_tx =
                            zerotime::instance().locked_inputs()[
                            i.previous_out()
                        ];
                        
                        /**
                         * The transaction hash must remain the same as the
                         * first for all transaction_in's in the question.
                         */
                        if (
                            hash_tx == zerotime::instance().locked_inputs()[
                            tx_ins.front().previous_out()]
                            )
                        {
                            should_send_answer = true;
                        }
                        else
                        {
                            should_send_answer = false;
                            
                            break;
                        }
                    }
                }
                
                if (should_send_answer)
                {
                    /**
                     * Allocate the answer.
                     */
                    zerotime_answer ztanswer(hash_tx);
                
                    /**
                     * Send the message.
                     */
                    send_ztanswer_message(ztanswer);
                }
            }
        }
    }
    else if (msg.header().command == "ztanswer")
    {
        log_debug("Got ztanswer");

        if (globals::instance().is_zerotime_enabled())
        {
            const auto & ztanswer = msg.protocol_ztanswer().ztanswer;

            if (ztanswer)
            {
                if (auto transport = m_tcp_transport.lock())
                {
                    /**
                     * Inform the zerotime_manager.
                     */
                    stack_impl_.get_zerotime_manager()->handle_answer(
                        transport->socket().remote_endpoint(), *ztanswer
                    );
                }
            }
            
            /**
             * If we have a one-shot ztquestion call stop.
             */
            if (m_oneshot_ztquestion)
            {
                /**
                 * Stop
                 */
                stop();
            }
        }
    }
    else if (msg.header().command == "ztvote")
    {
        log_debug("Got ztvote");
        
        assert(msg.protocol_ztvote().ztvote);

        if (globals::instance().is_zerotime_enabled())
        {
            const auto & ztvote = msg.protocol_ztvote().ztvote;

            /**
             * Check that the vote has a valid score before proceeding.
             */
            if (
                ztvote && ztvote->score() > -1 &&
                ztvote->score() <= (constants::test_net == true ?
                std::numeric_limits<std::int16_t>::max() :
                std::numeric_limits<std::int16_t>::max() / 16)
                )
            {
                /**
                 * Allocate the inventory_vector.
                 */
                inventory_vector inv(
                    inventory_vector::type_msg_ztvote,
                    ztvote->hash_nonce()
                );

                if (
                    zerotime::instance().votes().count(
                    ztvote->hash_nonce()) > 0
                    )
                {
                    // ...
                }
                else
                {
                    /**
                     * Insert the zerotime_vote.
                     */
                    zerotime::instance().votes()[
                        ztvote->hash_nonce()] = *ztvote
                    ;
                    
                    /**
                     * Inform the zerotime_manager.
                     */
                    if (auto transport = m_tcp_transport.lock())
                    {
                        stack_impl_.get_zerotime_manager()->handle_vote(
                            transport->socket().remote_endpoint(), *ztvote
                        );
                    }

                    /**
                     * (SPV) clients do not relay ztvote's.
                     */
                    if (globals::instance().is_client_spv() == false)
                    {
                        /**
                         * Allocate the data_buffer.
                         */
                        data_buffer buffer;
                        
                        /**
                         * Encode the transaction (reuse the signature).
                         */
                        ztvote->encode(buffer, true);
                
                        /**
                         * Relay the ztvote.
                         */
                        relay_inv(inv, buffer);
                    }
                }
            }
        }
    }
    else if (msg.header().command == "ianswer")
    {
        if (globals::instance().is_incentive_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & ianswer = msg.protocol_ianswer().ianswer;
                
                if (ianswer && m_on_ianswer)
                {
                    m_on_ianswer(*ianswer);
                }
            }
        }
    }
    else if (msg.header().command == "iquestion")
    {
        if (globals::instance().is_incentive_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & iquestion = msg.protocol_iquestion().iquestion;
                
                if (iquestion)
                {
                    send_ianswer_message();
                }
            }
        }
    }
    else if (msg.header().command == "ivote")
    {
        if (globals::instance().is_incentive_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & ivote = msg.protocol_ivote().ivote;
                
                /**
                 * Check that the vote has a valid score before proceeding.
                 */
                if (
                    ivote && ivote->score() > -1 &&
                    ivote->score() <=
                    std::numeric_limits<std::int16_t>::max() / 4
                    )
                {
                    /**
                     * Allocate the inventory_vector.
                     */
                    inventory_vector inv(
                        inventory_vector::type_msg_ivote, ivote->hash_nonce()
                    );

                    if (
                        incentive::instance().votes().count(
                        ivote->hash_nonce()) > 0
                        )
                    {
                        // ...
                    }
                    else
                    {
                        /**
                         * Get the best block_index.
                         */
                        auto index_previous =
                            stack_impl::get_block_index_best()
                        ;
                        
                        /**
                         * Get the next block height
                         */
                        auto height =
                            index_previous ?
                            index_previous->height() + 1 : 0
                        ;

                        /**
                         * Check that the block height is close to
                         * ours (within one blocks).
                         */
                        if (
                            ivote->block_height() + 2 < height &&
                            static_cast<std::int32_t> (height) -
                            (ivote->block_height() + 2) > 0
                            )
                        {
                            log_debug(
                                "TCP connection is dropping old vote " <<
                                ivote->block_height() + 2 <<
                                ", diff = " << static_cast<std::int32_t> (
                                height) - (ivote->block_height() + 2) << "."
                            );
                        }
                        else
                        {
                            if (ivote->score() < 0)
                            {
                                log_debug(
                                    "TCP connection is dropping invalid ivote, "
                                    "score = " << ivote->score() << "."
                                );
                            }
                            else if (
                                stack_impl_.get_incentive_manager(
                                )->validate_collateral(*ivote) == false
                                )
                            {
                                log_debug(
                                    "TCP connection is dropping ivote invalid "
                                    "collateral."
                                );
                            }
                            else
                            {
                                /**
                                 * Insert the incentive_vote.
                                 */
                                incentive::instance().votes()[
                                    ivote->hash_nonce()] = *ivote
                                ;
                                
                                /**
                                 * Inform the incentive_manager.
                                 */
                                if (auto transport = m_tcp_transport.lock())
                                {
                                    stack_impl_.get_incentive_manager(
                                        )->handle_message(transport->socket(
                                        ).remote_endpoint(), msg
                                    );
                                }

                                /**
                                 * Allocate the data_buffer.
                                 */
                                data_buffer buffer;
                                
                                /**
                                 * Encode the transaction (reuse the signature).
                                 */
                                ivote->encode(buffer, true);
                        
                                /**
                                 * Relay the ztvote.
                                 */
                                relay_inv(inv, buffer);
                            }
                        }
                    }
                }
            }
        }
    }
    else if (msg.header().command == "isync")
    {
        log_info("TCP connection got isync.");
        
        if (
            globals::instance().is_incentive_enabled() == true &&
            incentive::instance().get_key().is_null() == false
            )
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & isync = msg.protocol_isync().isync;
                
                if (isync)
                {
                    /**
                     * Get some icols.
                     */
                    auto icols =
                        stack_impl_.get_incentive_manager(
                        )->get_incentive_collaterals(isync->filter())
                    ;
                    
                    /**
                     * Send the icols message.
                     */
                    send_icols_message(*icols);
                }
            }
        }
    }
    else if (msg.header().command == "icols")
    {
        log_info("TCP connection got icols.");

        /**
         * If we did not send an isync message consider it unsolicited SPAM and
         * drop them.
         */
        if (did_send_isync_ == true)
        {
            /**
             * Ignore icols if they did not originate from a peer.
             */
            if (
                (m_protocol_version_services &
                protocol::operation_mode_peer) == 1
                )
            {
                if (
                    globals::instance().is_incentive_enabled() == true &&
                    incentive::instance().get_key().is_null() == false
                    )
                {
                    if (utility::is_initial_block_download() == false)
                    {
                        const auto & icols = msg.protocol_icols().icols;
                        
                        if (icols)
                        {
                            log_info(
                                "TCP connection got " <<
                                icols->collaterals().size() << " icols."
                            );
                            
                            if (auto transport = m_tcp_transport.lock())
                            {
                                /**
                                 * Inform the incentive_manager.
                                 */
                                stack_impl_.get_incentive_manager(
                                    )->handle_message(transport->socket(
                                    ).remote_endpoint(), msg
                                );

                                /**
                                 * Inform the address_manager.
                                 */
                                stack_impl_.get_address_manager(
                                    )->handle_message(transport->socket(
                                    ).remote_endpoint(), msg
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    else if (msg.header().command == "cbbroadcast")
    {
        log_info("TCP connection got cbbroadcast.");
        
        if (globals::instance().is_chainblender_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & cbbroadcast =
                    msg.protocol_cbbroadcast().cbbroadcast
                ;
                
                if (cbbroadcast)
                {
                    if (m_direction == direction_incoming)
                    {
                        if (
                            m_hash_chainblender_session_id ==
                            cbbroadcast->hash_session_id()
                            )
                        {
                            auto self(shared_from_this());
        
                            /**
                             * Get all of the tcp_connection's.
                             */
                            auto connections =
                                stack_impl_.get_tcp_connection_manager(
                                )->tcp_connections()
                            ;
                            
                            log_info(
                                "TCP connection is relaying cbbroadcast."
                            );
                            
                            /**
                             * Relay the message to all connections except this
                             * one.
                             */
                            for (auto & i : connections)
                            {
                                if (auto j = i.second.lock())
                                {
                                    if (j == self)
                                    {
                                        continue;
                                    }
                                    else if (
                                        j->hash_chainblender_session_id() ==
                                        cbbroadcast->hash_session_id()
                                        )
                                    {
                                        /**
                                         * Send the cbbroadcast message.
                                         */
                                        j->send_cbbroadcast_message(
                                            cbbroadcast
                                        );
                                        
                                        log_info(
                                            "TCP connection relayed "
                                            "cbbroadcast."
                                        );
                                    }
                                }
                            }
                        }
                        else
                        {
                            log_error(
                                "TCP connection cbbroadcast session id "
                                "mismatch."
                            );
                            
                            /**
                             * Call stop.
                             */
                            stop();
                        }
                    }
                    else if (m_direction == direction_outgoing)
                    {
                        /**
                         * Callback
                         */
                        if (m_on_cbbroadcast)
                        {
                            m_on_cbbroadcast(*cbbroadcast);
                        }
                    }
                }
            }
        }
    }
    else if (msg.header().command == "cbjoin")
    {
        if (globals::instance().is_chainblender_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & cbjoin = msg.protocol_cbjoin().cbjoin;
                
                if (cbjoin)
                {
                    if (m_direction == direction_incoming)
                    {
                        /**
                         * :TODO: Check that the denomination is one of the
                         * possible combinations given the sum of the input
                         * denominations.
                         */
                        
                        /**
                         * First try to find an inactive session with a
                         * matching denomination otherwise create a new session
                         * if we have room in our fixed size queue.
                         */
                        chainblender::session_t s;

                        auto found = false;
                        
                        /**
                         * Get the sessions.
                         */
                        auto & sessions = chainblender::instance().sessions();
                        
                        /**
                         * If set to true all outputs for each session must
                         * be of identical denominations.
                         */
                        auto
                            enforce_common_output_denominations =
                            cbjoin->denomination() > 0
                        ;
                        
                        /**
                         * We limit two participants per session.
                         */
                        for (auto & i : sessions)
                        {
                            if (enforce_common_output_denominations)
                            {
                                /**
                                 * An inactive session that is at least 56
                                 * seconds old is considered stalled.
                                 */
                                auto is_session_stalled =
                                    i.second.is_active == false &&
                                    std::time(0) - i.second.time >= 56
                                ;
                                
                                if (
                                    i.second.denomination ==
                                    cbjoin->denomination() &&
                                    i.second.participants <= 1 &&
                                    is_session_stalled == false
                                    )
                                {
                                    s = i.second;
                                    
                                    found = true;
                                    
                                    break;
                                }
                            }
                            else
                            {
                                if (
                                    i.second.participants <= 1 &&
                                    i.second.is_active == false
                                    )
                                {
                                    s = i.second;
                                    
                                    found = true;
                                    
                                    break;
                                }
                            }
                        }
                        
                        /**
                         * If true we accepted the session.
                         */
                        auto accepted = false;
                        
                        if (found)
                        {
                            /**
                             * Set the we have accepted the session.
                             */
                            accepted = true;
                            
                            /**
                             * Increment the participants.
                             */
                            s.participants += 1;
                            
                            /**
                             * Replace the session information.
                             */
                            sessions[s.hash_id] = s;
                        }
                        else if (sessions.size() < 12)
                        {
                            /**
                             * Set the we have accepted the session.
                             */
                            accepted = true;
                            
                            /**
                             * Create a new session.
                             */
                            s.hash_id = hash::sha256_random();
                            s.denomination = cbjoin->denomination();
                            s.time = std::time(0);
                            s.participants = 1;
                            s.is_active = false;
                            
                            /**
                             * Add the new session.
                             */
                            sessions[s.hash_id] = s;
                        }
                        else
                        {
                            log_info(
                                "TCP connection is rejecting cbjoin, session "
                                "queue is full."
                            );
                            
                            /**
                             * Create the chainblender_status message.
                             */
                            auto cbstatus =
                                std::make_shared<chainblender_status> ()
                            ;
                            
                            /**
                             * Set the code to
                             * (chainblender_status::code_declined).
                             */
                            cbstatus->set_code(
                                chainblender_status::code_declined
                            );
            
                            /**
                             * Send the cbstatus message.
                             */
                            send_cbstatus_message(*cbstatus);
                            
                            /**
                             * Stop the connection after N seconds.
                             */
                            stop_after(4);
                        }
                        
                        if (accepted == true)
                        {
                            /**
                             * Set the session id.
                             */
                            m_hash_chainblender_session_id = s.hash_id;
                            
                            /**
                             * Create the chainblender_status message.
                             */
                            auto cbstatus =
                                std::make_shared<chainblender_status> ()
                            ;
                            
                            /**
                             * Set the code to
                             * (chainblender_status::code_accepted).
                             */
                            cbstatus->set_code(
                                chainblender_status::code_accepted
                            );
                            
                            /**
                             * Set the session id.
                             */
                            cbstatus->set_hash_session_id(s.hash_id);
                            
                            /**
                             * Set the number of participants.
                             */
                            cbstatus->set_participants(s.participants);
                            
                            /**
                             * Send the cbstatus message.
                             */
                            send_cbstatus_message(*cbstatus);
                            
                            /**
                             * Start sending cbstatus messages.
                             */
                            do_send_cbstatus(2);
                        }
                    }
                }
            }
        }
    }
    else if (msg.header().command == "cbleave")
    {
        if (globals::instance().is_chainblender_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & cbleave = msg.protocol_cbleave().cbleave;
                
                if (cbleave)
                {
                    if (m_direction == direction_incoming)
                    {
                        /**
                         * Get the sessions.
                         */
                        auto & sessions = chainblender::instance().sessions();
                        
                        if (sessions.count(cbleave->hash_session_id()) > 0)
                        {
                            if (
                                sessions[cbleave->hash_session_id()
                                ].participants > 0
                                )
                            {
                                sessions[
                                    cbleave->hash_session_id()
                                ].participants -= 1;
                            }
                            else
                            {
                                sessions.erase(cbleave->hash_session_id());
                            }
                        }
                        
                        /**
                         * Call stop.
                         */
                        stop();
                    }
                }
            }
        }
    }
    else if (msg.header().command == "cbstatus")
    {
        if (globals::instance().is_chainblender_enabled())
        {
            if (utility::is_initial_block_download() == false)
            {
                const auto & cbstatus = msg.protocol_cbstatus().cbstatus;
                
                if (cbstatus)
                {
                    if (m_direction == direction_outgoing)
                    {
                        switch (cbstatus->code())
                        {
                            case chainblender_status::code_accepted:
                            {
                                if (m_hash_chainblender_session_id.is_empty())
                                {
                                    /**
                                     * The session was accepted, set the id.
                                     */
                                    m_hash_chainblender_session_id =
                                        cbstatus->hash_session_id()
                                    ;
                                }
                            }
                            break;
                            default:
                            {
                                // ...
                            }
                            break;
                        }
                        
                        if (
                            m_hash_chainblender_session_id.is_empty(
                            ) == false && m_hash_chainblender_session_id ==
                            cbstatus->hash_session_id()
                            )
                        {
                            if (m_on_cbstatus)
                            {
                                m_on_cbstatus(*cbstatus);
                            }
                        }
                        else
                        {
                            stop();
                        }
                    }
                }
            }
        }
    }
    else if (msg.header().command == "mempool")
    {
        log_debug("Got mempool");
        
        std::vector<sha256> block_hashes;
        
        transaction_pool::instance().query_hashes(block_hashes);
        
        if (transaction_bloom_filter_)
        {
            std::vector<sha256> block_hashes_filtered;
            
            for (auto & i : block_hashes)
            {
                if (transaction_pool::instance().exists(i) == true)
                {
                    auto tx = transaction_pool::instance().lookup(i);
                    
                    if (
                        transaction_bloom_filter_->is_relevant_and_update(
                        tx) == true
                        )
                    {
                        block_hashes_filtered.push_back(i);
                    }
                }
            }
            
            if (block_hashes_filtered.size() > protocol::max_inv_size)
            {
                block_hashes_filtered.resize(protocol::max_inv_size);
            }
        
            if (block_hashes_filtered.size() > 0)
            {
                do_send_inv_message(
                    inventory_vector::type_msg_tx, block_hashes_filtered
                );
            }
        }
        else
        {
            if (block_hashes.size() > protocol::max_inv_size)
            {
                block_hashes.resize(protocol::max_inv_size);
            }
        
            if (block_hashes.size() > 0)
            {
                do_send_inv_message(
                    inventory_vector::type_msg_tx, block_hashes
                );
            }
        }
    }
    else if (msg.header().command == "alert")
    {
        if (msg.protocol_alert().a)
        {
            log_debug(
                "Got alert, status = " << msg.protocol_alert().a->status()
            );
            
            if (m_seen_alerts.count(msg.protocol_alert().a->get_hash()) == 0)
            {
                /**
                 * Process the alert.
                 */
                if (
                    stack_impl_.get_alert_manager()->process(
                    *msg.protocol_alert().a)
                    )
                {
                    /**
                     * Relay the alert to all connected peers.
                     */
                    relay_alert(*msg.protocol_alert().a);
                }
                else
                {
                    /**
                     * Set the Denial-of-Service score for the connection.
                     */
                    set_dos_score(m_dos_score + 10);
                }
            }
        }
    }
    else
    {
        log_error(
            "Connection got unknown command " << msg.header().command << "."
        );
    }
    
    if (
        msg.header().command == "version" || msg.header().command == "addr" ||
        msg.header().command == "inv" || msg.header().command == "getdata" ||
        msg.header().command == "ping"
        )
    {
        /**
         * Inform the address_manager.
         */
        stack_impl_.get_address_manager()->on_connected(
            msg.protocol_version().addr_src
        );
    }
    
    return true;
}

void tcp_connection::do_ping(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        /**
         * Start the ping timeout timer.
         */
        timer_ping_timeout_.expires_from_now(
            std::chrono::seconds(60)
        );
        timer_ping_timeout_.async_wait(
            strand_.wrap(
                [this, self](boost::system::error_code ec)
                {
                    if (ec)
                    {
                        // ...
                    }
                    else
                    {
                        log_error(
                            "TCP connection (ping) timed out, calling stop."
                        );
                    
                        /**
                         * The connection has timed out, call stop.
                         */
                        do_stop();
                    }
                }
            )
        );
        
        if (m_state == state_started)
        {
            /**
             * Send a ping message every interval_ping seconds.
             */
            send_ping_message();
            
            timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
            timer_ping_.async_wait(strand_.wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
        }
    }
}

void tcp_connection::do_send_getblocks(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * The block spacing must be more than 63 seconds.
         */
        assert(constants::work_and_stake_target_spacing > 63);
        
        /**
         * If we have not received a block in a long time drop the connection
         * but do not ban it.
         */
        if (
            m_direction == direction_outgoing &&
            std::time(0) - time_last_block_received_ >
            constants::work_and_stake_target_spacing * 12
            )
        {
            if (auto transport = m_tcp_transport.lock())
            {
                auto ep = transport->socket().remote_endpoint();
                
                log_info(
                    "TCP connection has not received a block since too "
                    "long, dropping connection to " << ep << "."
                );
            }
            
            /**
             * Call stop.
             */
            do_stop();
            
            return;
        }
        else
        {
            if (globals::instance().is_client_spv() == true)
            {
                auto should_send_spv_getblocks =
                    globals::instance().spv_use_getblocks() == true
                ;
                
                if (should_send_spv_getblocks == true)
                {
                    if (
                        globals::instance().spv_best_block_height() <
                        stack_impl_.peer_block_count() &&
                        std::time(0) - time_last_block_received_ >= 60
                        )
                    {
                        log_info(
                            "TCP connection " << m_identifier <<
                            " (SPV) getblocks stalled, calling stop."
                        );
                        
                        /**
                         * We've stalled.
                         */
                        do_stop();
                        
                        return;
                    }
                }
            }
            else
            {
                if (
                    utility::is_initial_block_download() == true &&
                    (std::time(0) - time_last_block_received_ >=
                    constants::work_and_stake_target_spacing * 3)
                    )
                {
                    log_info(
                        "TCP connection " << m_identifier <<
                        " chain sync stalled, calling stop."
                    );
                    
                    /**
                     * We've stalled.
                     */
                    do_stop();
                    
                    return;
                }
                else if (
                    (std::time(0) - time_last_block_received_ >=
                    (constants::work_and_stake_target_spacing * 3)) ||
                    (utility::is_initial_block_download() == true &&
                    std::time(0) - time_last_block_received_ >=
                    constants::work_and_stake_target_spacing * 3)
                    )
                {
                    if (
                        std::time(0) - time_last_getblocks_sent_ >=
                        constants::work_and_stake_target_spacing * 3
                        )
                    {
                        log_info(
                            "TCP connection " << m_identifier << " is sending "
                            "getblocks."
                        );

                        /**
                         * Send a getblocks message with our best index.
                         */
                        send_getblocks_message(
                            stack_impl::get_block_index_best(), sha256()
                        );
                    }
                }
            }
            
            if (m_state == state_started)
            {
                auto self(shared_from_this());
                
                /**
                 * Start the getblocks timer.
                 */
                if (globals::instance().is_client_spv() == true)
                {
                    timer_getblocks_.expires_from_now(std::chrono::seconds(8));
                }
                else
                {
                    timer_getblocks_.expires_from_now(std::chrono::seconds(8));
                }
                
                timer_getblocks_.async_wait(strand_.wrap(
                    std::bind(&tcp_connection::do_send_getblocks, self,
                    std::placeholders::_1))
                );
            }
        }
    }
}

void tcp_connection::do_send_inv_message(
    const inventory_vector::type_t & type, const sha256 & hash_block
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        inventory_vector inv(type, hash_block);
        
        /**
         * Prevent sending duplicate INV's.
         */
        if (inventory_vectors_seen_set_.count(inv) > 0)
        {
            log_debug(
                "Already sent INV " << hash_block.to_string().substr(0, 16)
            );
            
            return;
        }
        
        /**
         * Allocate the message.
         */
        message msg("inv");
        
        /**
         * Set the inventory_vector.
         */
        msg.protocol_inv().inventory.push_back(inv);
        
        /**
         * Set the count.
         */
        msg.protocol_inv().count = msg.protocol_inv().inventory.size();
        
        log_none("TCP connection is sending inv.");
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_inv_message(
    const inventory_vector::type_t & type,
    const std::vector<sha256> & block_hashes
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("inv");
        
        for (auto & i : block_hashes)
        {
            inventory_vector inv(type, i);

            if (inventory_vectors_seen_set_.count(inv) > 0)
            {
                log_debug(
                    "Already sent INV " << i.to_string().substr(0, 16) <<
                    ", continuing."
                );
                
                continue;
            }
            /**
             * Append the inventory_vector.
             */
            msg.protocol_inv().inventory.push_back(inv);
        }
        
        /**
         * Set the count.
         */
        msg.protocol_inv().count = msg.protocol_inv().inventory.size();
        
        log_none(
            "TCP connection is sending inv, count = " <<
            msg.protocol_inv().count << "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_relayed_inv_message(
    const inventory_vector & inv, const data_buffer & buffer
    )
{
    std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
    
    /**
     * Expire old relay messages.
     */
    while (
        globals::instance().relay_inv_expirations().size() > 0 &&
        globals::instance().relay_inv_expirations().front().first < std::time(0)
        )
    {
        globals::instance().relay_invs().erase(
            globals::instance().relay_inv_expirations().front().second
        );
        
        globals::instance().relay_inv_expirations().pop_front();
    }

    /**
     * Save original serialized message so newer versions are preserved.
     */
    globals::instance().relay_invs().insert(std::make_pair(inv, buffer));
    
    globals::instance().relay_inv_expirations().push_back(
        std::make_pair(std::time(0) + 15 * 60, inv)
    );
    
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg(inv.command(), buffer);

        /**
         * Encode the message.
         */
        msg.encode();

        log_debug(
            "TCP connection is sending (relayed) inv message, command = " <<
            inv.command() << ", buffer size = " << buffer.size() << "."
        );
    
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_block_message(const block & blk)
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("block");
        
        /**
         * Set the block.
         */
        msg.protocol_block().blk = std::make_shared<block> (blk);
        
        log_none(
            "TCP connection is sending block " <<
            msg.protocol_block().blk->get_hash().to_string().substr(0, 20) <<
            "."
        );
        
        /**
         * Encode the message.
         */
        msg.encode();
        
        /**
         * Write the message.
         */
        t->write(msg.data(), msg.size());
    }
    else
    {
        stop();
    }
}

void tcp_connection::do_send_getheaders(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * The block spacing must be more than 63 seconds.
         */
        assert(constants::work_and_stake_target_spacing > 63);

        std::lock_guard<std::recursive_mutex> l1(stack_impl::mutex());
        
        if (
            globals::instance().is_client_spv() == true &&
            globals::instance().spv_use_getblocks() == false
            )
        {
            if (
                m_identifier == globals::instance(
                ).spv_active_tcp_connection_identifier()
                )
            {
                if (
                    std::time(0) - time_last_headers_received_ >=
                    (constants::work_and_stake_target_spacing * 2) ||
                    (utility::is_spv_initial_block_download() &&
                    std::time(0) - time_last_headers_received_ > 3)
                    )
                {
                    /**
                     * Get the block_locator hashes.
                     */
                    const auto & block_locator_hashes =
                        globals::instance().spv_block_locator_hashes()
                    ;
                    
                    /**
                     * Allocate the block_locator with the last and
                     * first hash.
                     */
                    block_locator locator(block_locator_hashes);
                    
                    /**
                     * Send the getheaders message.
                     */
                    send_getheaders_message(sha256(), locator);
                }
            }
            
            /**
             * After initial download of the headers SPV clients use getblocks
             * to continue synchronisation.
             */
            if (utility::is_spv_initial_block_download() == true)
            {
                if (m_state == state_started)
                {
                    auto self(shared_from_this());
                    
                    /**
                     * Start the getheaders timer.
                     */
                    timer_getheaders_.expires_from_now(std::chrono::seconds(8));
                    timer_getheaders_.async_wait(strand_.wrap(
                        std::bind(&tcp_connection::do_send_getheaders, self,
                        std::placeholders::_1))
                    );
                }
            }
        }
    }
}

void tcp_connection::do_rebroadcast_addr_messages(
    const std::uint32_t & interval
    )
{
    auto self(shared_from_this());
    
    /**
     * Start the addr rebroadcast timer.
     */
    timer_addr_rebroadcast_.expires_from_now(std::chrono::seconds(interval));
    timer_addr_rebroadcast_.async_wait(strand_.wrap(
        [this, self] (const boost::system::error_code & ec)
        {
            if (ec)
            {
                // ...
            }
            else
            {
                static std::int64_t g_last_addr_rebroadcast;
                
                if (
                    utility::is_initial_block_download() == false &&
                    (std::time(0) - g_last_addr_rebroadcast > 8 * 60 * 60)
                    )
                {
                    std::lock_guard<std::recursive_mutex> l1(
                        stack_impl::mutex()
                    );
                    
                    auto tcp_connections =
                        stack_impl_.get_tcp_connection_manager(
                        )->tcp_connections()
                    ;
                    
                    for (auto & i : tcp_connections)
                    {
                        if (g_last_addr_rebroadcast > 0)
                        {
                            if (auto t = i.second.lock())
                            {
                                /**
                                 * Periodically clear the seen network
                                 * addresses to allow for new rebroadcasts.
                                 */
                                t->clear_seen_network_addresses();

                                /**
                                 * Get our network port.
                                 */
                                auto port =
                                    globals::instance().is_client_spv(
                                    ) == true ? 0 :stack_impl_.get_tcp_acceptor(
                                    )->local_endpoint().port()
                                ;

                                protocol::network_address_t addr =
                                    protocol::network_address_t::from_endpoint(
                                    boost::asio::ip::tcp::endpoint(
                                    m_address_public, port)
                                );
    
                                t->send_addr_message(addr);
                            }
                        }
                    }
                    
                    g_last_addr_rebroadcast = std::time(0);
                    
                    do_rebroadcast_addr_messages(8 * 60 * 60);
                }
                else
                {
                    do_rebroadcast_addr_messages(60 * 60);
                }
            }
        })
    );
}

void tcp_connection::do_send_cbstatus(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    /**
     * Start the cbstatus timer.
     */
    timer_cbstatus_.expires_from_now(std::chrono::seconds(interval));
    timer_cbstatus_.async_wait(strand_.wrap(
        [this, self] (const boost::system::error_code & ec)
        {
            if (ec)
            {
                // ...
            }
            else
            {
                if (
                    chainblender::instance().sessions().count(
                    m_hash_chainblender_session_id) > 0
                    )
                {
                    auto & s = chainblender::instance().sessions()[
                        m_hash_chainblender_session_id]
                    ;
                    
                    auto should_send_ready_code = false;
                    
                    if (s.is_active == true)
                    {
                        if (did_send_cbstatus_cbready_code_ == false)
                        {
                            did_send_cbstatus_cbready_code_ = true;
                            
                            should_send_ready_code = true;
                        }
                        else
                        {
                            should_send_ready_code = false;
                        }
                    }
                    else
                    {
                        /**
                         * We only set the session active after 8 seconds to
                         * allow more time for participants to join.
                         */
                        if (
                            s.participants >= 2 &&
                            did_send_cbstatus_cbready_code_ == false &&
                            std::time(0) - s.time >= 8
                            )
                        {
                            s.is_active = true;
                            
                            did_send_cbstatus_cbready_code_ = true;
                            
                            should_send_ready_code = true;
                        }
                        else
                        {
                            should_send_ready_code = false;
                        }
                    }

                    if (should_send_ready_code == true)
                    {
                        /**
                         * Create the chainblender_status message.
                         */
                        auto cbstatus =
                            std::make_shared<chainblender_status> ()
                        ;
                        
                        /**
                         * Set the code to
                         * (chainblender_status::code_ready).
                         */
                        cbstatus->set_code(
                            chainblender_status::code_ready
                        );
                        
                        /**
                         * Set the session id.
                         */
                        cbstatus->set_hash_session_id(s.hash_id);
                        
                        /**
                         * Set the number of participants.
                         */
                        cbstatus->set_participants(s.participants);
                        
                        /**
                         * Send the cbstatus message.
                         */
                        send_cbstatus_message(*cbstatus);
                    }
                    else
                    {
                        /**
                         * Create the chainblender_status message.
                         */
                        auto cbstatus =
                            std::make_shared<chainblender_status> ()
                        ;
                        
                        /**
                         * Set the code to
                         * (chainblender_status::code_update).
                         */
                        cbstatus->set_code(
                            chainblender_status::code_update
                        );
                        
                        /**
                         * Set the session id.
                         */
                        cbstatus->set_hash_session_id(s.hash_id);
                        
                        /**
                         * Set the number of participants.
                         */
                        cbstatus->set_participants(s.participants);
                        
                        /**
                         * Send the cbstatus message.
                         */
                        send_cbstatus_message(*cbstatus);
                    }
                }
            }
            
            do_send_cbstatus(2);
        })
    );
}

void tcp_connection::do_send_isync(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    /**
     * Start the isync timer.
     */
    timer_isync_.expires_from_now(std::chrono::seconds(interval));
    timer_isync_.async_wait(strand_.wrap(
        [this, self] (const boost::system::error_code & ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (
                utility::is_initial_block_download() == false &&
                globals::instance().is_incentive_enabled() == true
                )
            {
                static auto g_isync_sent = 0;
                static auto g_isync_time_last_sent = std::time(0);
                
                auto should_send_isync = false;
                
                /**
                 * Only send an isync message 8 times every 3 hours or
                 * on initial connection up to 8 times.
                 */
                if (std::time(0) - g_isync_time_last_sent >= 3 * 60 * 60)
                {
                    did_send_isync_ = false;
                    
                    g_isync_sent = 0;
                    
                    should_send_isync = true;
                }
                else if (g_isync_sent < 8 && did_send_isync_ == false)
                {
                    should_send_isync = true;
                }
                
                if (should_send_isync == true)
                {
                    did_send_isync_ = true;
                    
                    g_isync_sent++;

                    log_info(
                        "TCP connection " << m_identifier << " is sending "
                        "isync message, globally sent = " << g_isync_sent << "."
                    );
                    
                    g_isync_time_last_sent = std::time(0);
                    
                    send_isync_message();
                }
                
                /**
                 * Double the interval each time.
                 */
                do_send_isync(g_isync_sent * 2);
            }
            else
            {
                do_send_isync(8);
            }
        }
    }));
}

bool tcp_connection::insert_inventory_vector_seen(const inventory_vector & inv)
{
    auto ret = inventory_vectors_seen_set_.insert(inv);
    
    enum { inv_queue_max_len = 1024 };
    
    if (ret.second == true)
    {
        if (inventory_vectors_seen_queue_.size() == inv_queue_max_len)
        {
            inventory_vectors_seen_set_.erase(
                inventory_vectors_seen_queue_.front()
            );
            
            inventory_vectors_seen_queue_.pop_front();
        }
        
        inventory_vectors_seen_queue_.push_back(inv);
    }
    
    return ret.second;
}
