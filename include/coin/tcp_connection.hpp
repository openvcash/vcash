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

#ifndef COIN_TCP_CONNECTION_HPP
#define COIN_TCP_CONNECTION_HPP

#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <coin/inventory_cache.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    class alert;
    class block;
    class block_index;
    class checkpoint_sync;
    class message;
    class stack_impl;
    class tcp_transport;
    class transaction;
    
    /**
     * Implement a tcp connection.
     */
    class tcp_connection : public std::enable_shared_from_this<tcp_connection>
    {
        public:
        
            /**
             * The direction.
             */
            typedef enum
            {
                direction_incoming,
                direction_outgoing,
            } direction_t;
        
            /**
             * Constructor
             * ios The boost::asio::io_service.
             * @param owner The stack_impl.
             * @param direction The direction_t
             * @param transport The tcp_transport.
             */
            explicit tcp_connection(
                boost::asio::io_service & ios, stack_impl & owner,
                const direction_t & direction,
                std::shared_ptr<tcp_transport> transport
            );
        
            /**
             * Destructor
             */
            ~tcp_connection();
        
            /**
             * Starts direction_incoming.
             */
            void start();
        
            /**
             * Starts direction_outgoing.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            void start(const boost::asio::ip::tcp::endpoint & ep);
        
            /**
             * Stops
             */
            void stop();
        
            /** 
             * Stops after the specified interval.
             * @param interval The interval in seconds.
             */
            void stop_after(const std::uint32_t & interval);
        
            /**
             * Sends a raw buffer.
             * @param buf The buffer.
             * @param len The length.
             */
            void send(const char * buf, const std::size_t & len);
        
            /**
             * Sends an addr message.
             * @param local_address_only If true only the local address will
             * be sent.
             */
            void send_addr_message(const bool & local_address_only = false);
            
            /**
             * Sends a getblocks message.
             * @param index_begin The start block index.
             * @param hash_end The end hash.
             */
            void send_getblocks_message(
                const std::shared_ptr<block_index> & index_begin,
                const sha256 & hash_end
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param hash_block The hash of the block.
             */
            void send_inv_message(
                const inventory_vector::type_t & type, const sha256 & hash_block
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param block_hashes The hashes of the blocks.
             */
            void send_inv_message(
                const inventory_vector::type_t & type,
                const std::vector<sha256> & block_hashes
            );
        
            /**
             * Sends a (relayed) encoded inv given command.
             * @param command The command.
             * @param
             */
            void send_relayed_inv_message(
                const inventory_vector & inv, const data_buffer & buffer
            );
        
            /**
             * Sends a getdata message by appending the inventory_vector to
             * the queue.
             * getdata The inventory_vector's.
             */
            void send_getdata_message(
                const std::vector<inventory_vector> & getdata
            );
        
            /**
             * Sends a checkpoint message.
             * @param checkpoint The checkpoint_sync.
             */
            void send_checkpoint_message(checkpoint_sync & checkpoint);
        
            /**
             * The tcp_transport.
             */
            std::weak_ptr<tcp_transport> & get_tcp_transport();
        
            /**
             * The direction.
             */
            const direction_t & direction() const;
        
            /**
             * The (remote) protocol version.
             */
            const std::uint32_t & protocol_version() const;
        
            /**
             * The (remote) protocol version services.
             */
            const std::uint64_t & protocol_version_services() const;
        
            /**
             * The (remote) protocol version timestamp.
             */
            const std::uint64_t & protocol_version_timestamp() const;
        
            /**
             * The (remote) protocol version start height.
             */
            const std::int32_t & protocol_version_start_height() const;
        
            /**
             * The (remote) protocol version user agent.
             */
            const std::string & protocol_version_user_agent() const;
        
            /**
             * The (remote) protocol version source address.
             */
            const protocol::network_address_t &
                protocol_version_addr_src() const
            ;
        
            /**
             * Sets the hash of the known checkpoint.
             * @param val The sha256.
             */
            void set_hash_checkpoint_known(const sha256 & val);
        
            /**
             * The hash of the known checkpoint.
             */
            const sha256 & hash_checkpoint_known() const;
        
            /**
             * The "seen" protocol::network_address_t objects.
             */
            std::set<protocol::network_address_t> & seen_network_addresses();
        
            /**
             * Sets the Denial-of-Service score.
             * @param val The value.
             */
            void set_dos_score(const std::uint8_t & val);
        
            /**
             * The Denial-of-Service score.
             */
            const std::uint8_t & dos_score() const;
        
            /**
             * If true the transport is valid (usable).
             */
            bool is_transport_valid();
        
            /**
             * The on read handler.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_read(const char * buf, const std::size_t & len);
        
        private:
        
            /**
             * Sends a verack message.
             */
            void send_verack_message();
        
            /**
             * Sends a version message.
             */
            void send_version_message();
        
            /**
             * Sends an address message.
             * @param addr The address.
             */
            void send_addr_message(const protocol::network_address_t & addr);
        
            /**
             * Sends a getaddr message.
             */
            void send_getaddr_message();
        
            /**
             * Sends a ping message.
             */
            void send_ping_message();

            /**
             * Sends a pong message.
             * @param nonce The nonce.
             */
            void send_pong_message(const std::uint64_t & nonce);
        
            /**
             * Sends a getdata message if there are any in the queue.
             */
            void send_getdata_message();
        
            /**
             * Sends a block message.
             * @param blk The block.
             */
            void send_block_message(const block & blk);
        
            /**
             * Sends a tx message.
             * @param tx The transaction.
             */
            void send_tx_message(const transaction & tx);
        
            /**
             * Sends a mempool message.
             */
            void send_mempool_message();
        
            /**
             * Relays a checkpoint message.
             * @param The checkpoint.
             */
            void relay_checkpoint(const checkpoint_sync & checkpoint);
        
            /**
             * Relays an alert message.
             * @param msg The alert.
             */
            void relay_alert(const alert & msg);
        
            /**
             * Relays an encoded inv given message command.
             * @param command The command.
             * @param
             */
            void relay_inv(
                const inventory_vector & inv, const data_buffer & buffer
            );
        
            /**
             * Handles a message.
             * @param msg The message.
             */
            bool handle_message(message & msg);
        
            /**
             * The ping timer handler.
             * @param ec The boost::system::error_code.
             */
            void do_ping(const boost::system::error_code & ec);
        
            /**
             * Sends getblocks if needed.
             * @param ec The boost::system::error_code.
             */
            void do_send_getblocks(const boost::system::error_code & ec);
        
            /**
             * Rebroadcasts addr messages every 24 hours.
             */
            void do_rebroadcast_addr_messages(const std::uint32_t & interval);
        
            /**
             * The tcp_transport.
             */
            std::weak_ptr<tcp_transport> m_tcp_transport;
        
            /**
             * The direction.
             */
            direction_t m_direction;
        
            /**
             * The (remote) protocol version.
             */
            std::uint32_t m_protocol_version;
        
            /**
             * The (remote) protocol version services.
             */
            std::uint64_t m_protocol_version_services;
        
            /**
             * The (remote) protocol version timestamp.
             */
            std::uint64_t m_protocol_version_timestamp;
        
            /**
             * The (remote) protocol version start height.
             */
            std::int32_t m_protocol_version_start_height;
        
            /**
             * The (remote) protocol version user agent.
             */
            std::string m_protocol_version_user_agent;
        
            /**
             * The (remote) protocol version source address.
             */
            protocol::network_address_t m_protocol_version_addr_src;
        
            /**
             * Our public address as advertised in the version message.
             */
            boost::asio::ip::address m_address_public;
        
            /**
             * The hash of the known checkpoint.
             */
            sha256 m_hash_checkpoint_known;
        
            /**
             * The hash continue for getblocks and getdata.
             */
            sha256 m_hash_continue;
        
            /**
             * If true we sent a getaddr message.
             */
            bool m_sent_getaddr;
        
            /**
             * The "seen" protocol::network_address_t objects.
             */
            std::set<protocol::network_address_t> m_seen_network_addresses;
        
            /**
             * The Denial-of-Service score.
             */
            std::uint8_t m_dos_score;
        
            /**
             * The seen alerts to prevent broadcasting duplicates.
             */
            std::set<sha256> m_seen_alerts;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;

            /**
             * The read queue.
             */
            std::deque<char> read_queue_;
        
            /**
             * The read_queue_ std::mutex.
             */
            std::mutex mutex_read_queue_;
        
            /**
             * The ping timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ping_;
        
            /**
             * The ping interval in seconds.
             */
            enum { interval_ping = 60 * 30 };
        
            /**
             * If true we have sent an initial getblock's message.
             */
            bool did_send_getblocks_;
        
            /**
             * The inventory_vector's used in getdata messages.
             */
            std::vector<inventory_vector> getdata_;
        
            /**
             * The getdata mutex.
             */
            std::recursive_mutex mutex_getdata_;
        
            /**
             * The inventory cache (known).
             */
            inventory_cache inventory_cache_;
        
            /**
             * The inventory_cache mutex.
             */
            std::mutex mutex_inventory_cache_;
        
            /**
             * The last getblocks index_begin.
             */
            std::shared_ptr<block_index> last_getblocks_index_begin_;
        
            /**
             * The last getblocks hash_end.
             */
            sha256 last_getblocks_hash_end_;
        
            /**
             * The time the last block was received.
             */
            std::time_t time_last_block_received_;
        
            /**
             * The delayed stop timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_delayed_stop_;
        
            /**
             * The getblocks timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_getblocks_;
        
            /**
             * The addr rebroadcast timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_addr_rebroadcast_;
        
            /**
             * The last time a getblocks was received.
             */
            std::time_t time_last_getblocks_received_;
        
            /**
             * The last time a getblocks was received.
             */
            std::time_t time_last_getblocks_sent_;
        
            /**
             * If true we need to send a getblocks message.
             */
            bool need_to_send_getblocks_;
    };
    
} // namespace coin

#endif // COIN_TCP_CONNECTION_HPP
