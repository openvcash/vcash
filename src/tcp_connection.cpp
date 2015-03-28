/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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
#include <coin/block_locator.hpp>
#include <coin/checkpoints.hpp>
#include <coin/checkpoint_sync.hpp>
#include <coin/db_tx.hpp>
#include <coin/globals.hpp>
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

using namespace coin;

tcp_connection::tcp_connection(
    boost::asio::io_service & ios, stack_impl & owner,
    const direction_t & direction, std::shared_ptr<tcp_transport> transport
    )
    : m_tcp_transport(transport)
    , m_direction(direction)
    , m_protocol_version(0)
    , m_protocol_version_services(0)
    , m_protocol_version_timestamp(0)
    , m_protocol_version_start_height(-1)
    , m_sent_getaddr(false)
    , m_dos_score(0)
    , io_service_(ios)
    , strand_(ios)
    , stack_impl_(owner)
    , timer_ping_(ios)
    , did_send_getblocks_(false)
    , time_last_block_received_(std::time(0))
    , timer_delayed_stop_(ios)
    , timer_getblocks_(ios)
    , timer_addr_rebroadcast_(ios)
    , time_last_getblocks_received_(0)
    , time_last_getblocks_sent_(0)
    , need_to_send_getblocks_(false)
{
    // ...
}

tcp_connection::~tcp_connection()
{
    // ...
}

void tcp_connection::start()
{
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
            timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
            timer_ping_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(8));
            timer_getblocks_.async_wait(globals::instance().strand().wrap(
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
}

void tcp_connection::start(const boost::asio::ip::tcp::endpoint & ep)
{
    auto self(shared_from_this());

    if (m_direction == direction_incoming)
    {
        assert(0);
    }
    else if (m_direction == direction_outgoing)
    {
        if (auto transport = m_tcp_transport.lock())
        {
            /**
             * Set the transport on read handler.
             */
            transport->set_on_read(
                [this](std::shared_ptr<tcp_transport> t,
                const char * buf, const std::size_t & len)
            {
                on_read(buf, len);
            });

            /**
             * Start the transport connecting to the endpoint.
             */
            transport->start(
                ep.address().to_string(), ep.port(), [self, ep](
                boost::system::error_code ec,
                std::shared_ptr<tcp_transport> transport)
                {
                    if (ec)
                    {
                        log_none(
                            "TCP connection to " << ep << " failed, "
                            "message = " << ec.message() << "."
                        );
                        
                        self->stop();
                    }
                    else
                    {
                        log_debug(
                            "TCP connection to " << ep << " success, sending "
                            "version message."
                        );
                        
                        /**
                         * Send a version message.
                         */
                        self->send_version_message();
                    }
                }
            );
            
            /**
             * Start the ping timer.
             */
            timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
            timer_ping_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection::do_ping, self,
                std::placeholders::_1))
            );
            
            /**
             * Start the getblocks timer.
             */
            timer_getblocks_.expires_from_now(std::chrono::seconds(8));
            timer_getblocks_.async_wait(globals::instance().strand().wrap(
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
}

void tcp_connection::stop()
{
    if (auto t = m_tcp_transport.lock())
    {
        t->stop();
    }
    
    read_queue_.clear();
    timer_ping_.cancel();
    timer_getblocks_.cancel();
    timer_addr_rebroadcast_.cancel();
    timer_delayed_stop_.cancel();
}

void tcp_connection::stop_after(const std::uint32_t & interval)
{
    /**
     * Starts the delayed stop timer.
     */
    timer_delayed_stop_.expires_from_now(std::chrono::seconds(interval));
    timer_delayed_stop_.async_wait(strand_.wrap(
        [this, interval](boost::system::error_code ec)
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
            stop();
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
        
        /**
         * Get our network port.
         */
        auto port = stack_impl_.get_tcp_acceptor()->local_endpoint().port();
        
        protocol::network_address_t addr =
            protocol::network_address_t::from_endpoint(
            boost::asio::ip::tcp::endpoint(m_address_public, port)
        );
        
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

void tcp_connection::send_getblocks_message(
    const std::shared_ptr<block_index> & index_begin, const sha256 & hash_end
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
         * Only allow one getblocks message every 8 seconds per connection.
         */
        if (std::time(0) - time_last_getblocks_sent_ >= 8)
        {
            /**
             * Set the last time we sent a getblocks.
             */
            time_last_getblocks_sent_ = std::time(0);

            /**
             * Set that we need to send getblocks.
             */
            need_to_send_getblocks_ = true;
            
            last_getblocks_index_begin_ = index_begin;
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
        else
        {
            log_debug(
                "TCP connection tried to send getblocks message too soon."
            );
        }
    }
}

void tcp_connection::send_inv_message(
    const inventory_vector::type_t & type, const sha256 & hash_block
    )
{
    if (auto t = m_tcp_transport.lock())
    {
        /**
         * Allocate the message.
         */
        message msg("inv");
        
        /**
         * Set the inventory_vector.
         */
        msg.protocol_inv().inventory.push_back(
            inventory_vector(type, hash_block)
        );
        
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

void tcp_connection::send_inv_message(
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
            /**
             * Append the inventory_vector.
             */
            msg.protocol_inv().inventory.push_back(
                inventory_vector(type, i)
            );
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

void tcp_connection::send_relayed_inv_message(
    const inventory_vector & inv, const data_buffer & buffer
    )
{
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
            inv.command() << "."
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

void tcp_connection::send_getdata_message(
    const std::vector<inventory_vector> & getdata
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_getdata_);
    
    /**
     * Append the entries to the end.
     */
    getdata_.insert(getdata_.end(), getdata.begin(), getdata.end());
    
    /**
     * Send the getdata message.
     */
    send_getdata_message();
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

void tcp_connection::set_hash_checkpoint_known(const sha256 & val)
{
    m_hash_checkpoint_known = val;
}

const sha256 & tcp_connection::hash_checkpoint_known() const
{
    return m_hash_checkpoint_known;
}

std::set<protocol::network_address_t> &
    tcp_connection::seen_network_addresses()
{
    return m_seen_network_addresses;
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
             * Ban the address.
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
    auto buffer = std::string(buf, len);
    
    /**
     * Check if it is an HTTP message.
     */
    if (buffer.find("HTTP/1.") == std::string::npos)
    {
        std::lock_guard<std::mutex> l1(mutex_read_queue_);
        
        /**
         * Append to the read queue.
         */
        read_queue_.insert(read_queue_.end(), buf, buf + len);
        
        while (read_queue_.size() >= message::header_length)
        {
            /**
             * Allocate a packet.
             */
            std::string packet(read_queue_.begin(), read_queue_.end());
            
            /**
             * Allocate the message.
             */
            message msg(packet.data(), packet.size());
        
            try
            {
                /**
                 * Decode the message.
                 */
                msg.decode();
                
                log_none("TCP connection got " << msg.header().command << ".");
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
                log_error(
                    "TCP connection failed to handle message, "
                    "what = " << e.what() << "."
                );
            }
        }
    }
    else
    {
        log_debug("TCP connection got HTTP message.");
        
        if (auto transport = m_tcp_transport.lock())
        {
            /**
             * Allocate the response.
             */
            std::string response;
         
            /**
             * Allocate the body.
             */
            std::string body = "{\"statistics\": {}}";
            
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
        /**
         * Allocate the message.
         */
        message msg("version");

        /**
         * Get our network port.
         */
        auto port = stack_impl_.get_tcp_acceptor()->local_endpoint().port();
        
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
        std::lock_guard<std::recursive_mutex> l1(mutex_getdata_);
        
        if (getdata_.size() > 0)
        {
            /**
             * :FIXME: Keep track of sent inv's and retry after N if necessary?
             */
            
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
            
            log_none(
                "TCP connection is sending getdata, count = " <<
                msg.protocol_getdata().inventory.size() << "."
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
    }
    else
    {
        stop();
    }
}

void tcp_connection::send_block_message(const block & blk)
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

void tcp_connection::send_tx_message(const transaction & tx)
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
     * Broadcast the message to "all" connected peers.
     */
    stack_impl_.get_tcp_connection_manager()->broadcast(
        msg.data(), msg.size()
    );
}

bool tcp_connection::handle_message(message & msg)
{
    if (msg.header().command == "verack")
    {
        // ...
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
            stop();
            
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
                    stop();
                    
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
                
                log_none(
                    "TCP connection got version = " << m_protocol_version << "."
                );

                /**
                 * Set the protocol version source address.
                 */
                m_protocol_version_addr_src = msg.protocol_version().addr_src;

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
                        
                        /**
                         * Send a version message.
                         */
                        send_version_message();
                    }
                }
                else if (m_direction == direction_outgoing)
                {
                    /**
                     * Inform the address_manager.
                     */
                    stack_impl_.get_address_manager()->mark_good(
                        msg.protocol_version().addr_src
                    );
                    
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
                    globals::instance().set_address_public(m_address_public);

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
                             * Send an addr message to advertise our address
                             * only.
                             */
                            send_addr_message(true);
                        }
                    }
                    
                    /**
                     * Only send a getaddr message if we have less than 1000
                     * peers.
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

            /**
             * Send bip-0035 mempool message.
             */
            if (
                m_direction == direction_outgoing &&
                utility::is_initial_block_download() == false &&
                m_protocol_version >= constants::mempool_getdata_version
                )
            {
                send_mempool_message();
            }
            
            /**
             * If we have never sent a getblocks message or if our best
             * block is the genesis block send getblocks.
             */
            if (
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
    else if (msg.header().command == "addr")
    {
        if (
            msg.protocol_addr().count > 1000 ||
            m_protocol_version < constants::min_addr_version
            )
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
                        
                        for (
                            auto & i2 :
                            stack_impl_.get_tcp_connection_manager(
                            )->tcp_connections()
                            )
                        {
                            if (auto t = i2.second.lock())
                            {
                                if (
                                    t->protocol_version() <
                                    constants::min_addr_version
                                    )
                                {
                                    continue;
                                }
                            
                                std::uint32_t ptr_uint32;
                                
                                auto ptr_transport = t.get();
                                
                                std::memcpy(
                                    &ptr_uint32, &ptr_transport,
                                    sizeof(ptr_uint32)
                                );
                                
                                sha256 hashKey = hash_random ^ ptr_uint32;
                                
                                hashKey = sha256::from_digest(&hash::sha256d(
                                    hashKey.digest(), sha256::digest_length)[0]
                                );
                            
                                mixes.insert(std::make_pair(hashKey, t));
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
    }
    else if (msg.header().command == "inv")
    {
        if (msg.protocol_inv().inventory.size() > protocol::max_inv_size)
        {
            /**
             * Set the Denial-of-Service score for the connection.
             */
            set_dos_score(m_dos_score + 20);
        }
        else
        {
            /**
             * Find the last block in the inventory vector.
             */
            std::uint32_t last_block = static_cast<std::uint32_t> (-1);
            
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
            
            std::lock_guard<std::recursive_mutex> l1(mutex_getdata_);
            std::lock_guard<std::mutex> l2(mutex_inventory_cache_);
            
            /**
             * Open the transaction database for reading.
             */
            db_tx tx_db("r");
            
            auto index = 0;
            
            auto inventory = msg.protocol_inv().inventory;
            
            for (auto & i : inventory)
            {
                /**
                 * Add to the inventory_cache.
                 */
                inventory_cache_.insert(i);

                auto already_have = inventory_vector::already_have(tx_db, i);
                
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
        
        /**
         * If we have some getdata send it now.
         */
        if (getdata_.size() > 0)
        {
            send_getdata_message();
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
                    
                    if (i.type() == inventory_vector::type_msg_block)
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
                            
                            /**
                             * Send the block message.
                             */
                            send_block_message(blk);

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
                                send_inv_message(
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
                            send_relayed_inv_message(
                                i, data_buffer(it->second.data(),
                                it->second.size())
                            );
                            
                            did_send = true;
                        }
                        
                        if (
                            did_send == false &&
                            i.type() == inventory_vector::type_msg_tx
                            )
                        {
                            if (transaction_pool::instance().exists(i.hash()))
                            {
                                auto tx = transaction_pool::instance().lookup(
                                    i.hash()
                                );

                                /**
                                 * Send the tx message.
                                 */
                                send_tx_message(tx);
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
        if (std::time(0) - time_last_getblocks_received_ < 8)
        {
            log_debug(
                "TCP connection remote peer is sending getblocks too fast (" <<
                (std::time(0) - time_last_getblocks_received_) <<
                "), rate limiting."
            );
            
            /**
             * Set the last time we got a getblocks.
             */
            time_last_getblocks_received_ = std::time(0);
        }
        else
        {
            /**
             * Set the last time we got a getblocks.
             */
            time_last_getblocks_received_ = std::time(0);
            
            /**
             * If we are a peer handle the getblocks message.
             */
            if (
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
                 * We send a random number of blocks between 500 and 1500.
                 */
                auto limit = static_cast<std::int16_t> (
                    random::uint16_random_range(500, 1500)
                );
                
                log_debug(
                    "TCP connection getblocks " <<
                    (index ? index->height() : -1) << " to " <<
                    msg.protocol_getblocks().hash_stop.to_string(
                    ).substr(0, 20) << " limit " << limit << "."
                );
                
                /**
                 * The block hashes to send (we do not trickle like the reference
                 * implementation).
                 */
                std::vector<sha256> block_hashes;
                
                for (; index; index = index->block_index_next())
                {
                    if (
                        index->get_block_hash() == msg.protocol_getblocks().hash_stop
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
                    send_inv_message(
                        inventory_vector::type_msg_block, block_hashes
                    );
                }
            }
            else
            {
                log_info(
                    "TCP connection (operation mode client) is dropping "
                    "getblocks message."
                );
            }
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
        log_debug("got getheaders");
        
        /**
         * :JC: If there is high enough demand I will implement this.
         */
    }
    else if (msg.header().command == "tx")
    {
        log_debug("Got tx");

        const auto & tx = msg.protocol_tx().tx;
        
        std::vector<sha256> queue_work;
        std::vector<sha256> queue_erase;
        
        db_tx txdb("r");

        /**
         * Allocate the inventory_vector.
         */
        inventory_vector inv(inventory_vector::type_msg_tx, tx->get_hash());
        
        /**
         * Add to the inventory_cache.
         */
        inventory_cache_.insert(inv);
        
        bool missing_inputs = false;
        
        data_buffer buffer;
        
        tx->encode(buffer);
        
        if (tx->accept_to_transaction_pool(txdb, &missing_inputs).first)
        {
            /**
             * Inform the wallet_manager.
             */
            wallet_manager::instance().sync_with_wallets(*tx, 0, true);
            
            /**
             * Relay the inv.
             */
            relay_inv(inv, buffer);

            queue_work.push_back(inv.hash());
            queue_erase.push_back(inv.hash());

            /**
             * Recursively process any orphan transactions that depended on
             * this one.
             */
            for (auto i = 0; i < queue_work.size(); i++)
            {
                auto hash_previous = queue_work[i];

                auto it = globals::instance().orphan_transactions_by_previous()[
                    hash_previous].begin()
                ;
                
                for (
                    ;
                    it != globals::instance().orphan_transactions_by_previous()[
                    hash_previous].end();
                    ++it
                    )
                {
                    data_buffer buffer2(it->second->data(), it->second->size());
                    
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
                            "TCP connection accepted orphan transaction " <<
                            inv2.hash().to_string().substr(0, 10) << "."
                        )
                        /**
                         * Inform the wallet_manager.
                         */
                        wallet_manager::instance().sync_with_wallets(
                            tx2, 0, true
                        );

                        relay_inv(inv2, buffer2);
                        
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
                constants::max_orphan_transactions
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
    else if (msg.header().command == "block")
    {
        if (msg.protocol_block().blk)
        {
            log_none(
                "Connection received block " <<
                msg.protocol_block().blk->get_hash().to_string().substr(0, 20)
                << "."
            );
#if 0
            msg.protocol_block().blk->print();
#endif
            /**
             * Set the time we received this block.
             */
            time_last_block_received_ = std::time(0);
            
            /**
             * Allocate an inventory_vector.
             */
            inventory_vector inv(
                inventory_vector::type_msg_block,
                msg.protocol_block().blk->get_hash()
            );
            
            std::lock_guard<std::mutex> l2(mutex_inventory_cache_);
            
            /**
             * Cache the inventory_vector.
             */
            inventory_cache_.insert(inv);
            
            /**
             * Process the block.
             */
            if (
                stack_impl_.process_block(
                shared_from_this(), msg.protocol_block().blk)
                )
            {
                /**
                 * The inv as been fulfilled.
                 */
            }
        }
    }
    else if (msg.header().command == "mempool")
    {
        log_debug("Got mempool");
        
        std::vector<sha256> block_hashes;
        
        transaction_pool::instance().query_hashes(block_hashes);
        
        if (block_hashes.size() > protocol::max_inv_size)
        {
            block_hashes.resize(protocol::max_inv_size);
        }
        
        if (block_hashes.size() > 0)
        {
            send_inv_message(inventory_vector::type_msg_tx, block_hashes);
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
        /**
         * Send a ping message every 30 minutes.
         */
        send_ping_message();
        
        auto self(shared_from_this());
        
        timer_ping_.expires_from_now(std::chrono::seconds(interval_ping));
        timer_ping_.async_wait(globals::instance().strand().wrap(
            std::bind(&tcp_connection::do_ping, self,
            std::placeholders::_1))
        );
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
         * The block spacing must be more than 60 seconds.
         */
        assert(constants::work_and_stake_target_spacing > 60);
        
        /**
         * If we have not received a block in a while or we know we need to
         * then send a getblocks message.
         */
        if (
            std::time(0) - time_last_block_received_ >=
            (constants::work_and_stake_target_spacing * 2) ||
            need_to_send_getblocks_ == true
            )
        {
            /**
             * Send a getblocks message with our best index.
             */
            send_getblocks_message(
                stack_impl::get_block_index_best(), sha256()
            );
        }
        
        auto self(shared_from_this());
        
        /**
         * Start the getblocks timer.
         */
        timer_getblocks_.expires_from_now(std::chrono::seconds(8));
        timer_getblocks_.async_wait(globals::instance().strand().wrap(
            std::bind(&tcp_connection::do_send_getblocks, self,
            std::placeholders::_1))
        );
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
    timer_addr_rebroadcast_.async_wait(globals::instance().strand().wrap(
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
                    for (
                        auto & i : stack_impl_.get_tcp_connection_manager(
                        )->tcp_connections()
                        )
                    {
                        if (g_last_addr_rebroadcast > 0)
                        {
                            if (auto t = i.second.lock())
                            {
                                /**
                                 * Periodically clear the seen network
                                 * addresses to allow for new rebroadcasts.
                                 */
                                t->seen_network_addresses().clear();

                                /**
                                 * Get our network port.
                                 */
                                auto port =
                                    stack_impl_.get_tcp_acceptor(
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
                    do_rebroadcast_addr_messages(8 * 60 * 60);
                }
            }
        })
    );
}
