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

#ifndef COIN_TCP_CONNECTION_HPP
#define COIN_TCP_CONNECTION_HPP

#include <deque>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <coin/inventory_vector.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_bloom_filter.hpp>

namespace coin {
    
    class alert;
    class block;
    class block_index;
    class block_locator;
    class block_merkle;
    class checkpoint_sync;
    class incentive_answer;
    class incentive_collaterals;
    class message;
    class stack_impl;
    class tcp_transport;
    class transaction;
    class transaction_bloom_filter;
    class zerotime_answer;
    class zerotime_lock;
    class zerotime_question;
    class zerotime_vote;
    
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
            void start(const boost::asio::ip::tcp::endpoint ep);
        
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
             * @param hash_stop The hash stop.
             * @param locator The block locator.
             */
            void send_getblocks_message(
                const sha256 & hash_stop, const block_locator & locator
            );
        
            /**
             * Sends a getblocks message.
             * @param index_begin The start block index.
             * @param hash_end The end hash.
             */
            void send_getblocks_message(
                const block_index * index_begin, const sha256 & hash_end
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param hash_block The hash of the block.
             */
            void send_inv_message(
                const inventory_vector::type_t type, const sha256 hash_block
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param block_hashes The hashes of the blocks.
             */
            void send_inv_message(
                const inventory_vector::type_t type,
                const std::vector<sha256> block_hashes
            );
        
            /**
             * Sends a (relayed) encoded inv given command.
             * @param command The command.
             * @param
             */
            void send_relayed_inv_message(
                const inventory_vector inv, const data_buffer buffer
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
             * Sends a block message.
             * @param blk The block.
             */
            void send_block_message(const block blk);
        
            /**
             * Sends a filterload message.
             * @param filter The transaction_bloom_filter.
             */
            void send_filterload_message(
                const transaction_bloom_filter & filter
            );
        
            /**
             * Sens a filteradd message.
             * @param data The data.
             */
            void send_filteradd_message(
                const std::vector<std::uint8_t> & data
            );
        
            /**
             * Sends a filterclear message.
             */
            void send_filterclear_message();
        
            /**
             * Sends a cbbroadcast message.
             * @param cbbroadcast The chainblender_broadcast message.
             */
            void send_cbbroadcast_message(
                const std::shared_ptr<chainblender_broadcast> & cbbroadcast
            );
        
            /**
             * Sends a cbleave message.
             */
            void send_cbleave_message();
        
            /**
             * Sends a tx message.
             * @param tx The transaction.
             */
            void send_tx_message(const transaction tx);
            
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
             * The (remote) protocol version relay.
             */
            const bool & protocol_version_relay() const;
        
            /**
             * Sets the on probe handler (probe-only mode).
             * @param f The std::function.
             */
            void set_on_probe(
                const std::function<void (const std::uint32_t &,
                const std::string &, const std::uint64_t &,
                const std::int32_t &)> & f
            );
        
            /**
             * Sets the on ianswer handler (probe-only mode).
             * @param f The std::function.
             */
            void set_on_ianswer(
                const std::function< void (const incentive_answer &) > & f
            );
        
            /**
             * Sets the on cbbroadcast handler.
             * @param f The std::function.
             */
            void set_on_cbbroadcast(
                const std::function< void (
                const chainblender_broadcast &) > & f
            );
        
            /**
             * Sets the on cbstatus handler.
             * @param f The std::function.
             */
            void set_on_cbstatus(
                const std::function< void (const chainblender_status &) > & f
            );
        
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
             * Clears the "seen" protocol::network_address_t objects.
             */
            void clear_seen_network_addresses();
        
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
             * Sets the (SPV) Denial-of-Service score.
             * @param val The value.
             */
            void set_spv_dos_score(const double & val);
        
            /**
             * The (SPV) Denial-of-Service score.
             */
            const double & spv_dos_score() const;
        
            /**
             * If set to true the connection will stop after the initial
             * handshake and the address_manager will be informed.
             * @param val The value.
             */
            void set_probe_only(const bool & val);
        
            /**
             * Set's the one-shot ztquestion.
             * @param val The zerotime_question.
             */
            void set_oneshot_ztquestion(
                const std::shared_ptr<zerotime_question> & val
            );
        
            /**
             * Set's the cbjoin.
             * @param val The chainblender_join.
             */
            void set_cbjoin(
                const std::shared_ptr<chainblender_join> & val
            );
        
            /**
             * The chainblender session id.
             */
            const sha256 & hash_chainblender_session_id() const;
        
            /**
             * The identifier.
             */
            const std::uint32_t & identifier() const;

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
             * Starts direction_incoming.
             */
            void do_start();
        
            /**
             * Starts direction_outgoing.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            void do_start(const boost::asio::ip::tcp::endpoint ep);
        
            /**
             * Stops
             */
            void do_stop();
        
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
             * Sends an address message.
             * @param addr The address.
             */
            void do_send_addr_message(const protocol::network_address_t & addr);
        
            /**
             * Sends a cbbroadcast message.
             * @param cbbroadcast The chainblender_broadcast message.
             */
            void do_send_cbbroadcast_message(
                const std::shared_ptr<chainblender_broadcast> & cbbroadcast
            );
        
            /**
             * Sends a tx message.
             * @param tx The transaction.
             */
            void do_send_tx_message(const transaction & tx);
        
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
             * Sends a getheaders message.
             * @param hash_stop The hash stop.
             * @param locator The block locator.
             */
            void send_getheaders_message(
                const sha256 & hash_stop, const block_locator & locator
            );
        
            /**
             * Sends a headers message.
             * @param headers The block headers.
             */
            void send_headers_message(const std::vector<block> & headers);
        
            /**
             * Sends a merkleblock message.
             * @param merkleblock The block_merkle.
             */
            void send_merkleblock_message(const block_merkle & merkleblock);
        
            /**
             * Sends a ztlock message.
             * @param ztlock The zerotime_lock.
             */
            void send_ztlock_message(const zerotime_lock & ztlock);
        
            /**
             * Sends a ztquestion message.
             * @param ztquestion The zerotime_question.
             */
            void send_ztquestion_message(const zerotime_question & ztquestion);
        
            /**
             * Sends a ztanswer message.
             * @param ztanswer The zerotime_answer.
             */
            void send_ztanswer_message(const zerotime_answer & ztanswer);
        
            /**
             * Sends an ianswer message.
             */
            void send_ianswer_message();
        
            /**
             * Sends an iquestion message.
             */
            void send_iquestion_message();
        
            /**
             * Sends a ivote message.
             * @param ivote The incentive_vote.
             */
            void send_ivote_message(const incentive_vote & ivote);
        
            /**
             * Sends an isync message.
             */
            void send_isync_message();
        
            /**
             * Sends a icols message.
             * @param icols The incentive_collaterals.
             */
            void send_icols_message(
                const incentive_collaterals & icols
            );
        
            /**
             * Sends a cbjoin message.
             * @param cbjoin The chainblender_join message.
             */
            void send_cbjoin_message(const chainblender_join & cbjoin);
        
            /**
             * Sends a cbstatus message.
             * @param cbstatus The chainblender_status message.
             */
            void send_cbstatus_message(const chainblender_status & cbstatus);
        
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
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param hash_block The hash of the block.
             */
            void do_send_inv_message(
                const inventory_vector::type_t & type, const sha256 & hash_block
            );
        
            /**
             * Sends an inv message.
             * @param type The inventory_vector::type_t.
             * @param block_hashes The hashes of the blocks.
             */
            void do_send_inv_message(
                const inventory_vector::type_t & type,
                const std::vector<sha256> & block_hashes
            );
        
            /**
             * Sends a (relayed) encoded inv given command.
             * @param command The command.
             * @param
             */
            void do_send_relayed_inv_message(
                const inventory_vector & inv, const data_buffer & buffer
            );
        
            /**
             * Sends a block message.
             * @param blk The block.
             */
            void do_send_block_message(const block & blk);
        
            /**
             * Sends getheaders if needed.
             * @param ec The boost::system::error_code.
             */
            void do_send_getheaders(const boost::system::error_code & ec);
        
            /**
             * Rebroadcasts addr messages every 24 hours.
             */
            void do_rebroadcast_addr_messages(const std::uint32_t & interval);
        
            /**
             * The cbstatus timer handler.
             * @param interval The interval.
             */
            void do_send_cbstatus(const std::uint32_t & interval);
        
            /**
             * The isync timer handler.
             * @param interval The interval.
             */
            void do_send_isync(const std::uint32_t & interval);
    
            /**
             * Inserts a seen inventor_vector object.
             * @param inv The inventory_vector.
             */
            bool insert_inventory_vector_seen(const inventory_vector & inv);
        
            /**
             * The identifier.
             */
            std::uint32_t m_identifier;
        
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
             * The (remote) protocol version relay.
             */
            bool m_protocol_version_relay;
        
            /**
             * The probe handler (probe-only mode).
             */
            std::function<
                void (const std::uint32_t &, const std::string &,
                const std::uint64_t &, const std::int32_t &)
            > m_on_probe;
        
            /**
             * The ianswer handler (probe-only mode).
             */
            std::function<
                void (const incentive_answer &)
            > m_on_ianswer;
        
            /**
             * The cbbroadcast handler.
             */
            std::function<
                void (const chainblender_broadcast &)
            > m_on_cbbroadcast;
        
            /**
             * The cbstatus handler.
             */
            std::function<
                void (const chainblender_status &)
            > m_on_cbstatus;
        
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
             * The (SPV) Denial-of-Service score.
             */
            double m_spv_dos_score;
        
            /**
             * The seen alerts to prevent broadcasting duplicates.
             */
            std::set<sha256> m_seen_alerts;
        
            /**
             * If set to true the connection will stop after the initial
             * handshake occurs and the address_manager will be informed.
             */
            bool m_probe_only;
        
            /**
             * The one-shot ztquestion (if any).
             */
            std::shared_ptr<zerotime_question> m_oneshot_ztquestion;
        
            /**
             * The cbjoin (if any).
             */
            std::shared_ptr<chainblender_join> m_chainblender_join;
        
            /**
             * The chainblender session id.
             */
            sha256 m_hash_chainblender_session_id;
        
            /**
             * The state.
             */
            enum
            {
                state_none,
                state_starting,
                state_started,
                state_stopping,
                state_stopped,
            } m_state;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;

            /**
             * The read queue.
             */
            std::deque<char> read_queue_;
        
            /**
             * The ping timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ping_;
        
            /**
             * The ping timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_ping_timeout_;
        
            /**
             * The ping interval in seconds.
             */
            enum { interval_ping = 120 };
        
            /**
             * If true we have sent an initial getblock's message.
             */
            bool did_send_getblocks_;
        
            /**
             * The inventory_vector's used in getdata messages.
             */
            std::vector<inventory_vector> getdata_;
        
            /**
             * The last getblocks index_begin.
             */
            block_index * last_getblocks_index_begin_;
        
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
             * The version timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_version_timeout_;
        
            /**
             * The getblocks timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_getblocks_;
        
            /**
             * The getheaders timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_getheaders_;
        
            /**
             * The addr rebroadcast timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_addr_rebroadcast_;
        
            /**
             * The last time a getblocks was sent.
             */
            std::time_t time_last_getblocks_sent_;
        
            /**
             * The last time a headers was received.
             */
            std::time_t time_last_headers_received_;
        
            /**
             * The cbstatus timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_cbstatus_;
        
            /**
             * If true we have sent a cbstatus message with a code of
             * chainblender_status::code_ready.
             */
            bool did_send_cbstatus_cbready_code_;
        
            /**
             * The BIP-0037 transaction bloom filter.
             */
            std::unique_ptr<transaction_bloom_filter>
                transaction_bloom_filter_
            ;
        
            /**
             * The transaction hashes from merkle block matches,
             */
            std::set<sha256> spv_transactions_matched_;

            /**
             * The (SPV) getheaders timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_spv_getheader_timeout_;
        
            /**
             * The (SPV) getblocks timeout timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_spv_getblocks_timeout_;

            /**
             * The seen inventory_vector object set.
             */
            std::set<inventory_vector> inventory_vectors_seen_set_;
        
            /**
             * The seen inventory_vector object set.
             */
            std::deque<inventory_vector> inventory_vectors_seen_queue_;
        
            /**
             * The isync timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > timer_isync_;
        
            /**
             * If true we sent an isync message.
             */
            bool did_send_isync_;
    };
    
} // namespace coin

#endif // COIN_TCP_CONNECTION_HPP
