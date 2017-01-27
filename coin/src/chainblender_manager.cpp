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

#include <random>
#include <sstream>

#include <coin/chainblender.hpp>
#include <coin/chainblender_broadcast.hpp>
#include <coin/chainblender_join.hpp>
#include <coin/chainblender_leave.hpp>
#include <coin/chainblender_manager.hpp>
#include <coin/chainblender_status.hpp>
#include <coin/coin_control.hpp>
#include <coin/db_tx.hpp>
#include <coin/globals.hpp>
#include <coin/hc256.hpp>
#include <coin/key_reserved.hpp>
#include <coin/logger.hpp>
#include <coin/random.hpp>
#include <coin/script.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>
#include <coin/whirlpool.hpp>

using namespace coin;

chainblender_manager::chainblender_manager(
    boost::asio::io_service & ios, boost::asio::strand & s, stack_impl & owner
    )
    : m_blend_state(chainblender_manager::blend_state_none)
    , io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
    , timer_restart_(ios)
    , timer_blend_(ios)
    , timer_tx_(ios)
    , timer_ecdhe_(ios)
    , ecdhe_rto_(500)
    , tx_rto_(500)
    , time_last_denominate_(std::time(0) - 60)
    , last_block_height_(0)
{
    // ...
}

void chainblender_manager::start()
{
    if (globals::instance().is_chainblender_enabled())
    {
        log_info("ChainBlender manager is starting.");
          
        session_.hash_id.clear();
        session_.denomination = 0;
        session_.sum = 0;
        session_.participants = 0;
        session_.public_keys.clear();
        session_.coin_control_inputs = 0;
        session_.transactions.clear();
        session_.transaction_mine = transaction();
        session_.transaction_blended = transaction();
        session_.signatures = 0;
        session_.ecdhe_acks = 0;
        session_.tx_acks = 0;
        session_.sig_acks = 0;
        session_.chainblender_broadcast_type_tx = 0;
        
        /**
         * Generate the ECDHE public key.
         */
        auto public_key = ecdhe_.public_key();
        
        log_info("ChainBlender generated ECDHE public key:\n" << public_key);
        
        /**
         * Start the timer.
         */
        do_tick(60);
    }
}

void chainblender_manager::stop()
{
    if (globals::instance().is_chainblender_enabled())
    {
        log_info("ChainBlender manager is stopping.");
        
        if (tcp_connection_)
        {
            tcp_connection_->stop();
        }
        
        timer_.cancel();
        timer_restart_.cancel();
        timer_blend_.cancel();
        session_.hash_id.clear();
        session_.denomination = 0;
        session_.sum = 0;
        session_.participants = 0;
        session_.public_keys.clear();
        session_.coin_control_inputs = 0;
        session_.transactions.clear();
        session_.transaction_mine.set_null();
        session_.transaction_blended.set_null();
        session_.signatures = 0;
        session_.ecdhe_acks = 0;
        session_.tx_acks = 0;
        session_.sig_acks = 0;
        session_.chainblender_broadcast_type_tx = 0;
        timer_tx_.cancel();
        timer_ecdhe_.cancel();
    }
}

void chainblender_manager::restart(const std::uint32_t & interval)
{
    log_info("ChainBlender manager blend state is restarting.");
    
    auto self(shared_from_this());
    
    /**
     * Stop
     */
    set_blend_state(blend_state_none);
    
    /**
     * After random seconds set_blend_state to blend_state_active.
     */
    timer_restart_.expires_from_now(std::chrono::seconds(interval));
    timer_restart_.async_wait(strand_.wrap(
        [this, self]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            log_info("ChainBlender manager blend state is active.");
            
            /**
             * Start
             */
            set_blend_state(blend_state_active);
        }
    }));
}

void chainblender_manager::set_blend_state(
    const chainblender_manager::blend_state_t & val
    )
{
    if (globals::instance().is_chainblender_enabled())
    {
        m_blend_state = val;
        
        switch (m_blend_state)
        {
            case blend_state_none:
            {
                if (tcp_connection_)
                {
                    /**
                     * Send a cbleave message.
                     */
                    tcp_connection_->send_cbleave_message();
                    
                    /**
                     * Stop the connection after a delay.
                     */
                    tcp_connection_->stop_after(2);
                    
                    /**
                     * Deallocate the tcp_connection.
                     */
                    tcp_connection_.reset();
                }
                
                std::lock_guard<std::recursive_mutex> l1(mutex_nodes_tried_);
                
                nodes_tried_.clear();
        
                timer_restart_.cancel();
                timer_blend_.cancel();
                
                session_.hash_id.clear();
                session_.denomination = 0;
                session_.sum = 0;
                session_.participants = 0;
                session_.public_keys.clear();
                session_.coin_control_inputs = 0;
                session_.transactions.clear();
                session_.transaction_mine.set_null();
                session_.transaction_blended.set_null();
                session_.signatures = 0;
                session_.ecdhe_acks = 0;
                session_.tx_acks = 0;
                session_.sig_acks = 0;
                session_.chainblender_broadcast_type_tx = 0;
                
                timer_tx_.cancel();
                timer_ecdhe_.cancel();
            }
            break;
            case blend_state_active:
            {
                /**
                 * Start the timer.
                 */
                do_tick_blend(0);
            }
            break;
            case blend_state_passive:
            {
                // ...
            }
            break;
            default:
            break;
        }
    }
}

const chainblender_manager::blend_state_t &
    chainblender_manager::blend_state() const
{
    return m_blend_state;
}

void chainblender_manager::connect(const boost::asio::ip::tcp::endpoint & ep)
{
    /**
     * Allocate tcp_transport.
     */
    auto transport = std::make_shared<tcp_transport> (io_service_, strand_);

    /**
     * Allocate the tcp_connection.
     */
    tcp_connection_ =
        std::make_shared<tcp_connection> (io_service_, stack_impl_,
        tcp_connection::direction_outgoing, transport
    );

    if (tcp_connection_)
    {
        log_info(
            "ChainBlender manager is connecting "
            "to " << ep << "."
        );
        
        /**
         * Create the chainblender_join message.
         */
        auto cbjoin = std::make_shared<chainblender_join> ();
        
        /**
         * Set the denomination.
         */
        cbjoin->set_denomination(session_.denomination);
        
        /**
         * Set the cbjoin message.
         */
        tcp_connection_->set_cbjoin(cbjoin);

        auto self(shared_from_this());
        
        /**
         * Set the on cbbroadcast.
         */
        tcp_connection_->set_on_cbbroadcast(
            [this, self](const chainblender_broadcast & cbbroadcast)
            {
                log_debug(
                    "ChainBlender manager got type " <<
                    (int)cbbroadcast.type()
                );
                
                switch (cbbroadcast.type())
                {
                    case chainblender_broadcast::type_ecdhe:
                    {
                        log_debug(
                            "ChainBlender manager got "
                            "chainblender_broadcast::type_ecdhe"
                        );
                        
                        if (cbbroadcast.length() > 0)
                        {
                            if (
                                session_.hash_id ==
                                cbbroadcast.hash_session_id()
                                )
                            {
                                /**
                                 * Copy the public key.
                                 */
                                std::string public_key(
                                    cbbroadcast.value().begin(),
                                    cbbroadcast.value().end()
                                );
                            
                                log_debug(
                                    "ChainBlender manager got public key:\n" <<
                                    public_key
                                );
                                
                                /**
                                 * Save the public key for this session.
                                 */
                                auto is_new_public_key =
                                    session_.public_keys.insert(
                                    public_key).second
                                ;
                                
                                if (
                                    is_new_public_key &&
                                    session_.participants - 1 ==
                                    session_.public_keys.size()
                                    )
                                {
                                    log_info(
                                        "ChainBlender manager got all public "
                                        "keys, sending type_ecdhe_ack."
                                    );
                                    
                                    /**
                                     * Allocate the cbbroadcast message.
                                     */
                                    auto cbbroadcast =
                                        std::make_shared<
                                        chainblender_broadcast> ()
                                    ;
                                    
                                    /**
                                     * Set the type to
                                     * chainblender_broadcast::type_ecdhe_ack.
                                     */
                                    cbbroadcast->set_type(
                                        chainblender_broadcast::type_ecdhe_ack
                                    );
                                    
                                    /**
                                     * Send the cbbroadcast message.
                                     */
                                    if (tcp_connection_)
                                    {
                                        tcp_connection_->send_cbbroadcast_message(
                                            cbbroadcast
                                        );
                                    }
                                }
                                else
                                {
                                    log_info(
                                        "ChainBlender manager session is "
                                        "waiting for public keys from all "
                                        "participants."
                                    );
                                }
                            }
                            else
                            {
                                log_error(
                                    "ChainBlender manager got session id "
                                    "mismatch, dropping cbbroadcast message."
                                );
                            }
                        }
                    }
                    break;
                    case chainblender_broadcast::type_ecdhe_ack:
                    {
                        /**
                         * Increment the ECHDE acks.
                         */
                        session_.ecdhe_acks += 1;
                        
                        log_info(
                            "ChainBlender manager got " <<
                            static_cast<std::uint32_t>(session_.ecdhe_acks) <<
                            " ECDHE acks."
                        );
                        
                        if (session_.participants - 1 == session_.ecdhe_acks)
                        {
                            /**
                             * Cancel the ECDHE timer.
                             */
                            timer_ecdhe_.cancel();
                            
                            log_info(
                                "ChainBlender manager got all ECDHE acks."
                            );
                            
                            /**
                             * Start the type_tx retransmission timer.
                             */
                            if (session_.chainblender_broadcast_type_tx == 0)
                            {
                                do_tick_tx(tx_rto_);
                            }
                        }
                    }
                    break;
                    case chainblender_broadcast::type_tx:
                    {
                        log_debug(
                            "ChainBlender manager got "
                            "chainblender_broadcast::type_tx"
                        );
                        
                        if (cbbroadcast.length() > 0)
                        {
                            if (
                                session_.hash_id ==
                                cbbroadcast.hash_session_id()
                                )
                            {
                                /**
                                 * Allocate the buffer.
                                 */
                                data_buffer buffer(
                                    reinterpret_cast<const char *>(
                                    &cbbroadcast.value()[0]),
                                    cbbroadcast.value().size()
                                );

                                while (buffer.remaining() > 0)
                                {
                                    /**
                                     * Read the length.
                                     */
                                    auto len = buffer.read_var_int();
                                    
                                    /**
                                     * Read the encrypted buffer.
                                     */
                                    auto encrypted = buffer.read_bytes(len);

                                    /**
                                     * Read the checksum.
                                     */
                                    auto checksum = buffer.read_uint32();

                                    for (auto & i : session_.public_keys)
                                    {
                                        /**
                                         * Derive the shared secret bytes
                                         * from the participants public key.
                                         */
                                        auto bytes =
                                            ecdhe_.derive_secret_key(i)
                                        ;

                                        /**
                                         * Hash the shared secret bytes.
                                         */
                                        whirlpool w(&bytes[0], bytes.size());
                                        
                                        /**
                                         * Set the hash to the first 32
                                         * bytes of the hexidecimal
                                         * representation of the digest.
                                         */
                                        auto shared_secret =
                                            w.to_string().substr(0,
                                            whirlpool::digest_length / 2
                                        );
                                        
                                        log_info(
                                            "ChainBlender manager "
                                            "calculated shared secret " <<
                                            shared_secret << " for:\n " <<
                                            i
                                        );
                                        
                                        /**
                                         * Allocate the hc256 context.
                                         */
                                        hc256 ctx(
                                            shared_secret, shared_secret,
                                            "l7tH9JXEuGuB96wkA343jor4KJv"
                                            "XDV4j"
                                        );
                                        
                                        /**
                                         * Decrypt the buffer.
                                         */
                                        auto decrypted = ctx.decrypt(
                                            std::string(encrypted.data(),
                                            encrypted.size())
                                        );

                                        /**
                                         * Allocate the decrypted buffer.
                                         */
                                        data_buffer buffer_decrypted(
                                            decrypted.data(), decrypted.size()
                                        );
                                        
                                        if (
                                            checksum ==
                                            buffer_decrypted.checksum()
                                            )
                                        {
                                            log_debug(
                                                "ChainBlender manager "
                                                "decrypted transaction "
                                                "with:\n" << i
                                            );
                                            
                                            /**
                                             * Allocate the transaction.
                                             */
                                            transaction tx;
                                            
                                            /**
                                             * Decode the transaction.
                                             */
                                            tx.decode(buffer_decrypted);

                                            if (tx.check() == true)
                                            {
                                                auto ret =
                                                    transaction_pool::instance(
                                                    ).acceptable(tx)
                                                ;
                                                
                                                if (ret.first == true)
                                                {
                                                    /**
                                                     * Retain the session
                                                     * transaction.
                                                     */
                                                    if (
                                                        session_.transactions.count(
                                                        tx.get_hash()) == 0
                                                        )
                                                    {
                                                        session_.transactions[
                                                            tx.get_hash()] = tx
                                                        ;
                                                    }
                                                }
                                                else
                                                {
                                                    log_error(
                                                        "ChainBlender manager "
                                                        "got (unacceptable) "
                                                        "transaction (" <<
                                                        ret.second <<
                                                        "), stopping."
                                                    );
                                                    
                                                   /**
                                                    * Stop
                                                    */
                                                    set_blend_state(
                                                        blend_state_none
                                                    );
                                                }
                                            }
                                            else
                                            {
                                                log_error(
                                                    "ChainBlender manager "
                                                    "check failed for "
                                                    "encrypted transaction."
                                                );
                                            }
                                            
                                            break;
                                        }
                                        else
                                        {
                                            log_error(
                                                "ChainBLender manager got "
                                                "invalid checksum = " <<
                                                checksum << ":" <<
                                                buffer_decrypted.checksum()
                                            );
                                        }
                                    }
                                }
                            }
                        }

                        /**
                         * If the number of participants matches the number of
                         * transactions send a
                         * chainblender_broadcast::type_tx_ack.
                         */
                        if (
                            session_.participants ==
                            session_.transactions.size()
                            )
                        {
                            log_info(
                                "ChainBlender manager got all transactions, "
                                "sending type_tx_ack."
                            );
                            
                            /**
                             * Allocate the cbbroadcast message.
                             */
                            auto cbbroadcast =
                                std::make_shared<
                                chainblender_broadcast> ()
                            ;
                            
                            /**
                             * Set the type to
                             * chainblender_broadcast::type_tx_ack.
                             */
                            cbbroadcast->set_type(
                                chainblender_broadcast::type_tx_ack
                            );
                            
                            /**
                             * Send the cbbroadcast message.
                             */
                            if (tcp_connection_)
                            {
                                tcp_connection_->send_cbbroadcast_message(
                                    cbbroadcast
                                );
                            }
                        }
                    }
                    break;
                    case chainblender_broadcast::type_tx_ack:
                    {
                        /**
                         * Increment the Tx acks.
                         */
                        session_.tx_acks += 1;
                        
                        log_info(
                            "ChainBlender manager got " <<
                            static_cast<std::uint32_t> (session_.tx_acks) <<
                            " Tx acks."
                        );
                        
                        if (session_.participants - 1 == session_.tx_acks)
                        {
                            /**
                             * Cancel the Tx timer.
                             */
                            timer_tx_.cancel();
                            
                            log_info(
                                "ChainBlender manager got all Tx acks."
                            );

                            /**
                             * Our transaction_in signatures.
                             */
                            std::vector<transaction_in> tx_in_signatures;
                            
                            /**
                             * Allocate the blended transaction.
                             */
                            transaction tx_blended;
                            
                            /**
                             * Set the blended transaction time to that of the
                             * transaction at the front.
                             */
                            if (session_.transactions.size() > 0)
                            {
                                /**
                                 * Set the time.
                                 */
                                tx_blended.set_time(
                                    session_.transactions.begin()->second.time()
                                );
                            }
                            
                            /**
                             * Blend the transactions.
                             */
                            for (auto & i : session_.transactions)
                            {
                                tx_blended.transactions_in().insert(
                                    tx_blended.transactions_in().end(),
                                    i.second.transactions_in().begin(),
                                    i.second.transactions_in().end()
                                );
                                
                                tx_blended.transactions_out().insert(
                                    tx_blended.transactions_out().end(),
                                    i.second.transactions_out().begin(),
                                    i.second.transactions_out().end()
                                );
                            }

                            std::sort(
                                tx_blended.transactions_in().begin(),
                                tx_blended.transactions_in().end(),
                                [](const transaction_in & a,
                                const transaction_in & b) -> bool
                            { 
                                return
                                    a.previous_out().get_hash() >
                                    b.previous_out().get_hash()
                                ;
                            });

                            log_debug(
                                "ChainBlender manager blended "
                                "transaction:\n" << tx_blended.to_string()
                            );
                            
                            /**
                             * Transactions are ordered by hash therefore each
                             * blended transaction will be ordered by it's
                             * "original" hash before the signature was
                             * updated.
                             */
                            
                            /**
                             * Sign the transaction.
                             */
                            for (
                                auto & j :
                                session_.transaction_mine.transactions_in()
                                )
                            {
                                auto n = -1;

                                transaction_in tx_in;
                                
                                auto index = 0;
                                
                                for (auto & k : tx_blended.transactions_in())
                                {
                                    if (
                                        k.previous_out() == j.previous_out() &&
                                        k.sequence() == j.sequence()
                                        )
                                    {
                                        n = index;
                                    }
                                    
                                    index++;
                                }
            
                                if (n > -1)
                                {
                                    db_tx tx_db("r");
                                    
                                    transaction tx_previous;
                                    
                                    transaction_index tx_index;
                                    
                                    if (
                                        tx_previous.read_from_disk(tx_db,
                                        j.previous_out(), tx_index) == true
                                        )
                                    {
                                        if (
                                            script::sign_signature(
                                            *globals::instance().wallet_main(),
                                            tx_previous, tx_blended, n) == true
                                            )
                                        {
                                            log_info(
                                                "ChainBlender manager signed "
                                                "transaction: " <<
                                                tx_blended.get_hash(
                                                ).to_string().substr(0, 8)
                                            );
                                            
                                            tx_in_signatures.push_back(
                                                tx_blended.transactions_in()[n]
                                            );
                                        }
                                        else
                                        {
                                            log_error(
                                                "ChainBlender, blend "
                                                "transaction failed, sign "
                                                "signature failed, stopping."
                                            );
                                            
                                            /**
                                             * Stop
                                             */
                                            set_blend_state(blend_state_none);
                                            
                                            return;
                                        }
                                    }
                                }
                            }
                            
                            /**
                             * Set the session blended transaction.
                             */
                            session_.transaction_blended = tx_blended;
                            
                            std::stringstream ss;
                            
                            for (auto & i : tx_in_signatures)
                            {
                                ss << i.to_string() << "\n";
                            }
                            
                            log_info(
                                "ChainBlender manager generated " <<
                                tx_in_signatures.size() << " signatures:\n" <<
                                ss.str()
                            );
                            
                            /**
                             * Update the session transaction signatures.
                             */
                            if (tx_in_signatures.size() > 0)
                            {
                                for (auto & i : session_.transactions)
                                {
                                    for (auto & j : i.second.transactions_in())
                                    {
                                        for (auto & k : tx_in_signatures)
                                        {
                                            if (
                                                j.previous_out() ==
                                                k.previous_out() &&
                                                j.sequence() ==
                                                k.sequence()
                                                )
                                            {
                                                log_info(
                                                    "ChainBlender manager "
                                                    "updated blended "
                                                    "transaction signature "
                                                    "for input."
                                                );
                                                
                                                j.set_script_signature(
                                                    k.script_signature()
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            
                            /**
                             * Increment the number of signatures (participant
                             * submissions).
                             */
                            session_.signatures += 1;
                            
                            /**
                             * Broadcast the updated signatures.
                             */
                            broadcast_signatures(tx_in_signatures);
                        }
                    }
                    break;
                    case chainblender_broadcast::type_sig:
                    {
                        if (cbbroadcast.length() > 0)
                        {
                            if (
                                session_.hash_id ==
                                cbbroadcast.hash_session_id()
                                )
                            {
                                /**
                                 * Allocate the buffer.
                                 */
                                data_buffer buffer(
                                    reinterpret_cast<const char *>(
                                    &cbbroadcast.value()[0]),
                                    cbbroadcast.value().size()
                                );

                                while (buffer.remaining() > 0)
                                {
                                    /**
                                     * Read the length.
                                     */
                                    auto len = buffer.read_var_int();

                                    /**
                                     * Read the encrypted buffer.
                                     */
                                    auto encrypted = buffer.read_bytes(len);

                                    /**
                                     * Read the checksum.
                                     */
                                    auto checksum = buffer.read_uint32();

                                    for (auto & i : session_.public_keys)
                                    {
                                        /**
                                         * Derive the shared secret bytes
                                         * from the participants public key.
                                         */
                                        auto bytes =
                                            ecdhe_.derive_secret_key(i)
                                        ;

                                        /**
                                         * Hash the shared secret bytes.
                                         */
                                        whirlpool w(&bytes[0], bytes.size());
                                        
                                        /**
                                         * Set the hash to the first 32
                                         * bytes of the hexidecimal
                                         * representation of the digest.
                                         */
                                        auto shared_secret =
                                            w.to_string().substr(0,
                                            whirlpool::digest_length / 2
                                        );
                                        
                                        log_debug(
                                            "ChainBlender manager "
                                            "calculated shared secret " <<
                                            shared_secret << " for:\n " <<
                                            i
                                        );
                                        
                                        /**
                                         * Allocate the hc256 context.
                                         */
                                        hc256 ctx(
                                            shared_secret, shared_secret,
                                            "l7tH9JXEuGuB96wkA343jor4KJv"
                                            "XDV4j"
                                        );
                                        
                                        /**
                                         * Decrypt the buffer.
                                         */
                                        auto decrypted = ctx.decrypt(
                                            std::string(encrypted.data(),
                                            encrypted.size())
                                        );

                                        /**
                                         * Allocate the decrypted buffer.
                                         */
                                        data_buffer buffer_decrypted(
                                            decrypted.data(), decrypted.size()
                                        );
                                        
                                        if (
                                            checksum ==
                                            buffer_decrypted.checksum()
                                            )
                                        {
                                            log_debug(
                                                "ChainBlender manager "
                                                "decrypted signature "
                                                "with:\n" << i
                                            );
                                            
                                            /**
                                             * Allocate the transaction_in(s).
                                             */
                                            std::vector<transaction_in> tx_ins;
                                            
                                            /**
                                             * Decode the number of
                                             * transaction_in(s).
                                             */
                                            auto count =
                                                buffer_decrypted.read_var_int()
                                            ;
                                            
                                            for (auto i = 0; i < count; i++)
                                            {
                                                transaction_in tx_in;
                                                
                                                tx_in.decode(buffer_decrypted);

                                                tx_ins.push_back(tx_in);
                                            }
  
                                            /**
                                             * Update the session transaction
                                             * signatures.
                                             */
                                            for (
                                                auto & i :
                                                session_.transactions
                                                )
                                            {
                                                for (
                                                    auto & j :
                                                    i.second.transactions_in()
                                                    )
                                                {
                                                    for (auto & k : tx_ins)
                                                    {
                                                        if (
                                                            j.previous_out() ==
                                                            k.previous_out() &&
                                                            j.sequence() ==
                                                            k.sequence()
                                                            )
                                                        {
                                                            log_info(
                                                                "ChainBlender "
                                                                "manager "
                                                                "updated blended "
                                                                "transaction "
                                                                "signature "
                                                                "for input."
                                                            );
                                                            
                                                            j.set_script_signature(
                                                                k.script_signature()
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            
                                            /**
                                             * Increment the number of
                                             * signatures (participant
                                             * submissions).
                                             */
                                            session_.signatures += 1;

                                            if (
                                                session_.participants ==
                                                session_.signatures
                                                )
                                            {
                                                log_info(
                                                    "ChainBlender manager got "
                                                    "all signatures, sending "
                                                    "type_sig_ack."
                                                );
                                    
                                                /**
                                                 * Allocate the cbbroadcast message.
                                                 */
                                                auto cbbroadcast =
                                                    std::make_shared<
                                                    chainblender_broadcast> ()
                                                ;
                                                
                                                /**
                                                 * Set the type to
                                                 * chainblender_broadcast::type_sig_ack.
                                                 */
                                                cbbroadcast->set_type(
                                                    chainblender_broadcast::type_sig_ack
                                                );
                                                
                                                /**
                                                 * Send the cbbroadcast message.
                                                 */
                                                if (tcp_connection_)
                                                {
                                                    tcp_connection_->send_cbbroadcast_message(
                                                        cbbroadcast
                                                    );
                                                }
                                                
                                                /**
                                                 * Allocate the blended
                                                 * transaction.
                                                 */
                                                transaction tx_blended;
                                                
                                                /**
                                                 * Set the blended transaction
                                                 * time to that of the
                                                 * transaction at the front.
                                                 */
                                                if (
                                                    session_.transactions.size() > 0
                                                    )
                                                {
                                                    /**
                                                     * Set the time.
                                                     */
                                                    tx_blended.set_time(
                                                        session_.transactions.begin(
                                                        )->second.time()
                                                    );
                                                }
                            
                                                /**
                                                 * Blend the transactions.
                                                 */
                                                for (
                                                    auto & i : session_.transactions
                                                    )
                                                {
                                                    tx_blended.transactions_in().insert(
                                                        tx_blended.transactions_in().end(),
                                                        i.second.transactions_in().begin(),
                                                        i.second.transactions_in().end()
                                                    );
                                                    
                                                    tx_blended.transactions_out().insert(
                                                        tx_blended.transactions_out().end(),
                                                        i.second.transactions_out().begin(),
                                                        i.second.transactions_out().end()
                                                    );
                                                }

                                                std::sort(
                                                    tx_blended.transactions_in().begin(),
                                                    tx_blended.transactions_in().end(),
                                                    [](const transaction_in & a,
                                                    const transaction_in & b) -> bool
                                                { 
                                                    return
                                                        a.previous_out().get_hash() >
                                                        b.previous_out().get_hash()
                                                    ;
                                                });

                                                /**
                                                 * Set the session blended
                                                 * transaction.
                                                 */
                                                session_.transaction_blended =
                                                    tx_blended
                                                ;
                                                
                                                /**
                                                 * Commit the blended
                                                 * transaction.
                                                 */
                                                if (
                                                    commit_transaction(
                                                    tx_blended) == true
                                                    )
                                                {
                                                    log_info(
                                                        "ChainBlender manager "
                                                        "comitted blended "
                                                        "transaction."
                                                    );
                                                    
                                                    /**
                                                     * Restart
                                                     */
                                                    restart();
                                                }
                                                else
                                                {
                                                    log_error(
                                                        "ChainBlender manager "
                                                        "failed to commit "
                                                        "blended transaction, "
                                                        "restarting."
                                                    );
                                
                                                    /**
                                                     * Restart
                                                     */
                                                    restart();
                                                }
                                            }

                                            break;
                                        }
                                        else
                                        {
                                            log_error(
                                                "ChainBlender manager got "
                                                "invalid checksum = " <<
                                                checksum << ":" <<
                                                buffer_decrypted.checksum()
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                    break;
                    case chainblender_broadcast::type_sig_ack:
                    {
                        /**
                         * Increment the sig acks.
                         */
                        session_.sig_acks += 1;
                        
                        log_info(
                            "ChainBlender manager got " <<
                            static_cast<std::uint32_t> (session_.sig_acks) <<
                            " sig acks."
                        );
                        
                        if (session_.participants - 1 == session_.sig_acks)
                        {
                            log_info(
                                "ChainBlender manager got all sig acks."
                            );
                            
                            /**
                             * Allocate the blended
                             * transaction.
                             */
                            transaction tx_blended;
                            
                            /**
                             * Set the blended transaction time to that of the
                             * transaction at the front.
                             */
                            if (session_.transactions.size() > 0)
                            {
                                /**
                                 * Set the time.
                                 */
                                tx_blended.set_time(
                                    session_.transactions.begin()->second.time()
                                );
                            }
                            
                            /**
                             * Blend the transactions.
                             */
                            for (auto & i : session_.transactions)
                            {
                                tx_blended.transactions_in().insert(
                                    tx_blended.transactions_in().end(),
                                    i.second.transactions_in().begin(),
                                    i.second.transactions_in().end()
                                );
                                
                                tx_blended.transactions_out().insert(
                                    tx_blended.transactions_out().end(),
                                    i.second.transactions_out().begin(),
                                    i.second.transactions_out().end()
                                );
                            }

                            std::sort(
                                tx_blended.transactions_in().begin(),
                                tx_blended.transactions_in().end(),
                                [](const transaction_in & a,
                                const transaction_in & b) -> bool
                            { 
                                return
                                    a.previous_out().get_hash() >
                                    b.previous_out().get_hash()
                                ;
                            });

                            /**
                             * Set the session blended transaction.
                             */
                            session_.transaction_blended = tx_blended;

                            /**
                             * Commit the blended
                             * transaction.
                             */
                            if (commit_transaction(tx_blended) == true)
                            {
                                log_info(
                                    "ChainBlender manager comitted blended "
                                    "transaction."
                                );
                                
                                /**
                                 * Restart
                                 */
                                restart();
                            }
                            else
                            {
                                log_error(
                                    "ChainBlender manager failed to commit "
                                    "blended transaction, restarting."
                                );
            
                                /**
                                 * Restart
                                 */
                                restart();
                            }
                        }
                    }
                    break;
                    default:
                    {
                        /**
                         * Stop the connection (we must use stop_after since we
                         * may be calling back to ourselves this will go through
                         * the io service).
                         */
                        tcp_connection_->stop_after(0);
                    }
                    break;
                }
            }
        );
        
        /**
         * Set the on cbstatus.
         */
        tcp_connection_->set_on_cbstatus(
            [this, self](const chainblender_status & cbstatus)
            {
                if (cbstatus.code() == chainblender_status::code_accepted)
                {
                    log_info(
                        "ChainBlender manager got status accepted, "
                        "session id = " <<
                        cbstatus.hash_session_id().to_string().substr(0, 8) <<
                        ", participants = " << static_cast<std::uint32_t> (
                        cbstatus.participants()) << "."
                    );
                    
                    /**
                     * Set the session id.
                     */
                    session_.hash_id = cbstatus.hash_session_id();
                    
                    /**
                     * Set the session participants.
                     */
                    session_.participants = cbstatus.participants();
                    
                    /**
                     * Stop the connection after N seconds while waiting for a 
                     * chainblender_status::code_ready
                     */
                    tcp_connection_->stop_after(60);
                }
                else if (cbstatus.code() == chainblender_status::code_declined)
                {
                    /**
                     * Stop the connection (we must use stop_after since we
                     * may be calling back to ourselves this will go through
                     * the io service).
                     */
                    tcp_connection_->stop_after(0);
                }
                else if (cbstatus.code() == chainblender_status::code_ready)
                {
                    /**
                     * Stop the connection after N seconds (this session should
                     * complete in this time).
                     */
                    tcp_connection_->stop_after(60);

                    log_info(
                        "ChainBlender manager got cbstatus, code = "
                        "code_ready, session id = " <<
                        cbstatus.hash_session_id().to_string().substr(0, 8) <<
                        ", participants = " <<
                        static_cast<std::uint32_t> (cbstatus.participants()) <<
                        "."
                    );
                    
                    /**
                     * Set the session participants.
                     */
                    session_.participants = cbstatus.participants();

                    /**
                     * Start the ECDHE timer.
                     */
                    do_tick_ecdhe(ecdhe_rto_);
                }
                else if (cbstatus.code() == chainblender_status::code_update)
                {
                    log_info(
                        "ChainBlender manager got cbstatus, code = "
                        "code_update, session id = " <<
                        cbstatus.hash_session_id().to_string().substr(0, 8) <<
                        ", participants = " <<
                        static_cast<std::uint32_t> (cbstatus.participants()) <<
                        "."
                    );

                    /**
                     * If the number of session participants dropped send
                     * a cbleave and disconnect.
                     */
                    if (session_.participants > cbstatus.participants())
                    {
                        /**
                         * Send a cbleave message.
                         */
                        tcp_connection_->send_cbleave_message();
                        
                        /**
                         * Stop the connection after N seconds.
                         */
                        tcp_connection_->stop_after(4);
                    }
                    else
                    {
                        /**
                         * Set the session participants.
                         */
                        session_.participants = cbstatus.participants();
                    }
                }
            }
        );
        
        /**
         * Start the tcp_connection.
         */
        tcp_connection_->start(ep);
        
        /**
         * Stop the connection after 8 seconds, if we receive a cbstatus
         * we will update the stop after time.
         */
        tcp_connection_->stop_after(8);
    }
}

void chainblender_manager::do_tick(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(interval));
    timer_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (globals::instance().is_chainblender_enabled())
            {
                auto it = chainblender::instance().sessions().begin();
            
                while (it != chainblender::instance().sessions().end())
                {
                    /**
                     * First check for a stalled (inactive and is at least 56
                     * seconds old) session and then old sessions.
                     */
                    if (
                        it->second.is_active == false &&
                        std::time(0) - it->second.time >= 56
                        )
                    {
                        it = chainblender::instance().sessions().erase(it);
                    }
                    else if (std::time(0) - it->second.time > 64)
                    {
                        it = chainblender::instance().sessions().erase(it);
                    }
                    else
                    {
                        ++it;
                    }
                }
                
                /**
                 * Start the timer.
                 */
                do_tick(8);
            }
        }
    }));
}

void chainblender_manager::do_tick_ecdhe(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_ecdhe_.expires_from_now(std::chrono::milliseconds(interval));
    timer_ecdhe_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            ecdhe_rto_ = 500;
        }
        else
        {
            /**
             * Allocate the cbbroadcast message.
             */
            auto cbbroadcast =
                std::make_shared<chainblender_broadcast> ()
            ;
            
            /**
             * Set the type to
             * chainblender_broadcast::type_ecdhe.
             */
            cbbroadcast->set_type(
                chainblender_broadcast::type_ecdhe
            );
            
            /**
             * Copy the ECDHE public key into the value.
             */
            std::vector<std::uint8_t> value(
                ecdhe_.public_key().begin(),
                ecdhe_.public_key().end()
            );
            
            /**
             * Set the length.
             */
            cbbroadcast->set_length(value.size());
            
            /**
             * Set the value.
             */
            cbbroadcast->set_value(value);
            
            /**
             * Send the cbbroadcast message.
             */
            if (tcp_connection_)
            {
                tcp_connection_->send_cbbroadcast_message(
                    cbbroadcast
                );
            }
            
            /**
             * A client SHOULD retransmit a ECDHE request message starting with
             * an interval of RTO ("Retransmission TimeOut"), doubling after
             * each retransmission.
             */
            ecdhe_rto_ *= 2;
    
            log_info("ChainBlender manager ECDHE RTO = " << ecdhe_rto_ << ".");
    
            if (ecdhe_rto_ < 2000)
            {
                /**
                 * Start the ECDHE timer.
                 */
                do_tick_ecdhe(ecdhe_rto_);
            }
            else
            {
                ecdhe_rto_ = 500;
            }
        }
    }));
}

void chainblender_manager::do_tick_tx(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_tx_.expires_from_now(std::chrono::milliseconds(interval));
    timer_tx_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            tx_rto_ = 500;
        }
        else
        {
            if (session_.public_keys.size() == 0)
            {
                log_error(
                    "ChainBlender manager tried to send transaction with "
                    "no public keys."
                );
            }
            else if (session_.chainblender_broadcast_type_tx == 0)
            {
                log_info(
                    "ChainBlender manager session is "
                    "forming transaction."
                );

                /**
                 * Form our transaction, encrypt it for
                 * each participant and broadcast with
                 * chainblender_broadcast::type_tx.
                 */

                /**
                 * Get the key_reserved.
                 */
                key_reserved reserved_key(
                    *globals::instance().wallet_main()
                );
                
                /**
                 * Allocate the script.
                 */
                script script_pub_key;
                
                /**
                 * Send back to a change address.
                 */
                address addr(reserved_key.get_reserved_key().get_id());

                /**
                 * Set the destination.
                 */
                script_pub_key.set_destination(addr.get());
        
                reserved_key.keep_key();

                /**
                 * Allocate the transaction.
                 */
                transaction_wallet tx_new;

                /**
                 * The fee.
                 */
                std::int64_t fee_out = 0;
                
                /**
                 * Empty filter.
                 */
                std::set<std::int64_t> filter;

                /**
                 * Try to create the transaction.
                 * @note We do not use already blended
                 * coins.
                 */
                if (
                    globals::instance().wallet_main(
                    )->create_transaction(
                    script_pub_key,
                    session_.sum, tx_new,
                    reserved_key, fee_out, filter,
                    session_.coin_control_inputs, false, false)
                    )
                {
                    log_info(
                        "ChainBlender manager success, "
                        "tx: " << tx_new.get_hash(
                        ).to_string().substr(0, 8)
                    );
                    
                    /**
                     * Allocate the buffer (value) for
                     * the cbbroadcast of the encrypted
                     * transaction.
                     */
                    data_buffer buffer;
                    
                    /**
                     * Encode the transaction.
                     */
                    reinterpret_cast<transaction *> (
                        &tx_new)->encode(buffer)
                    ;
                    
                    /**
                     * Insert the session transaction.
                     */
                    session_.transactions[
                        tx_new.get_hash()] = tx_new
                    ;
                    
                    /**
                     * Retain the session transaction.
                     */
                    session_.transaction_mine = tx_new;
                    
                    /**
                     * The encrypted buffers.
                     */
                    std::vector<std::string>
                        encrypted_buffers
                    ;
                    
                    log_info(
                        "ChainBlender manager is encrypting transaction "
                        "for " << session_.public_keys.size() << " keys."
                    );
                    
                    for (auto & i : session_.public_keys)
                    {
                        /**
                         * Derive the shared secret bytes
                         * from the participants public key.
                         */
                        auto bytes =
                            ecdhe_.derive_secret_key(i)
                        ;

                        /**
                         * Hash the shared secret bytes.
                         */
                        whirlpool w(
                            &bytes[0], bytes.size()
                        );
                        
                        /**
                         * Set the hash to the first 32
                         * bytes of the hexidecimal
                         * representation of the digest.
                         */
                        auto shared_secret =
                            w.to_string().substr(0,
                            whirlpool::digest_length / 2
                        );
                        
                        log_debug(
                            "ChainBlender manager "
                            "calculated shared secret " <<
                            shared_secret << " for:\n " <<
                            i
                        );
                        
                        /**
                         * Allocate the hc256 context.
                         */
                        hc256 ctx(
                            shared_secret, shared_secret,
                            "l7tH9JXEuGuB96wkA343jor4KJv"
                            "XDV4j"
                        );
                        
                        /**
                         * Calculate the checksum prior to
                         * encryption.
                         */
                        auto checksum = buffer.checksum();
                        
                        /**
                         * Encrypt the buffer.
                         */
                        auto encrypted = ctx.encrypt(
                            std::string(buffer.data(),
                            buffer.size())
                        );
                        
                        /**
                         * Allocate memory for the checksum.
                         */
                        encrypted.resize(
                            encrypted.size() + sizeof(std::uint32_t)
                        );
                        
                        /**
                         * Copy the (plain-text
                         * little-endian) checksum to the
                         * end of the encrypted buffer.
                         */
                        std::memcpy(
                            &encrypted[encrypted.size() -
                            sizeof(std::uint32_t)],
                            &checksum, sizeof(std::uint32_t)
                        );
                        
                        /**
                         * Insert the encrypted buffer.
                         */
                        encrypted_buffers.push_back(encrypted);
                    }
                    
                    /**
                     * Allocate the cbbroadcast message.
                     */
                    session_.chainblender_broadcast_type_tx =
                        std::make_shared<chainblender_broadcast> ()
                    ;
                    
                    /**
                     * Set the type to
                     * chainblender_broadcast::type_tx.
                     */
                    session_.chainblender_broadcast_type_tx->set_type(
                        chainblender_broadcast::type_tx
                    );
                    
                    /**
                     * Allocate the value.
                     */
                    std::vector<std::uint8_t> value;
                    
                    /**
                     * Allocate the encrypted buffer.
                     */
                    data_buffer buffer_encrypted;
                    
                    for (auto & i : encrypted_buffers)
                    {
                        /**
                         * Write the (encrypted) length
                         * excluding checksum.
                         */
                        buffer_encrypted.write_var_int(
                            i.size() - sizeof(std::uint32_t)
                        );
                        
                        /**
                         * Write the encrypted transaction
                         * including checksum.
                         */
                        buffer_encrypted.write_bytes(
                            i.data(), i.size()
                        );
                    }
                    
                    /**
                     * Copy the encrypted buffer into the
                     * value.
                     */
                    value.insert(
                        value.end(),
                        buffer_encrypted.data(),
                        buffer_encrypted.data() + buffer_encrypted.size()
                    );
                    
                    /**
                     * Set the length.
                     */
                    session_.chainblender_broadcast_type_tx->set_length(
                        value.size()
                    );
                    
                    /**
                     * Set the value.
                     */
                    session_.chainblender_broadcast_type_tx->set_value(value);
                    
                    log_info(
                        "ChainBlender manager is broadcasting type_tx, "
                        "length = " <<
                        session_.chainblender_broadcast_type_tx->length() << "."
                    );
                
                    /**
                     * Send the cbbroadcast message.
                     */
                    if (tcp_connection_)
                    {
                        tcp_connection_->send_cbbroadcast_message(
                            session_.chainblender_broadcast_type_tx
                        );
                    }
                }
                else
                {
                    log_info(
                        "ChainBlender manager session failed to create "
                        "transaction, stopping."
                    );
                    
                    /**
                     * Stop
                     */
                    set_blend_state(blend_state_none);
                }
            }
            else
            {
                log_info(
                    "ChainBlender manager is rebroadcasting type_tx, "
                    "length = " <<
                    session_.chainblender_broadcast_type_tx->length() << "."
                );
                
                /**
                 * Send the cbbroadcast message.
                 */
                if (tcp_connection_)
                {
                    tcp_connection_->send_cbbroadcast_message(
                        session_.chainblender_broadcast_type_tx
                    );
                }
            }

            /**
             * A client SHOULD retransmit a Tx request message starting with
             * an interval of RTO ("Retransmission TimeOut"), doubling after
             * each retransmission.
             */
            tx_rto_ *= 2;
    
            log_info("ChainBlender manager Tx RTO = " << tx_rto_ << ".");
    
            if (tx_rto_ < 2000)
            {
                /**
                 * Start the Tx timer.
                 */
                do_tick_tx(tx_rto_);
            }
            else
            {
                tx_rto_ = 500;
            }
        }
    }));
}

void chainblender_manager::do_tick_blend(const std::uint32_t & interval)
{
    auto self(shared_from_this());
    
    timer_blend_.expires_from_now(std::chrono::seconds(interval));
    timer_blend_.async_wait(strand_.wrap([this, self, interval]
        (boost::system::error_code ec)
    {
        if (ec)
        {
            // ...
        }
        else
        {
            if (globals::instance().is_chainblender_enabled())
            {
                /**
                 * Check if the block height has changed.
                 */
                auto block_height_changed = false;
                
                if (
                    last_block_height_ < globals::instance().best_block_height()
                    )
                {
                    last_block_height_ =
                        globals::instance().best_block_height()
                    ;
                    
                    block_height_changed = true;
                }
                
                if (
                    tcp_connection_ && tcp_connection_->is_transport_valid()
                    )
                {
                    if (auto t = tcp_connection_->get_tcp_transport().lock())
                    {
                        log_info("ChainBlender manager connection is busy.");
                        
                        if (m_blend_state == blend_state_active)
                        {
                            /**
                             * Start the timer.
                             */
                            do_tick_blend(random::uint16_random_range(4, 8));
                        }
                        else if (m_blend_state == blend_state_passive)
                        {
                            // ...
                        }
                    }
                    else
                    {
                        /**
                         * Start the timer.
                         */
                        do_tick_blend(random::uint16_random_range(4, 8));
                    }
                }
                else
                {
                    /**
                     * Clear variables.
                     */
                    session_.hash_id.clear();
                    session_.denomination = 0;
                    session_.sum = 0;
                    session_.participants = 0;
                    session_.public_keys.clear();
                    session_.coin_control_inputs = 0;
                    session_.transactions.clear();
                    session_.transaction_mine.set_null();
                    session_.transaction_blended.set_null();
                    session_.signatures = 0;
                    session_.ecdhe_acks = 0;
                    session_.tx_acks = 0;
                    session_.sig_acks = 0;
                    session_.chainblender_broadcast_type_tx = 0;
                
                    /**
                     * Check if we have blendable coins.
                     */
                    auto coins = select_coins();
                    
                    /**
                     * Allocate the outputs.
                     */
                    std::vector<output> outputs;
                    
                    /**
                     * Get the denominations.
                     */
                    auto denominations =
                        chainblender::instance().denominations()
                    ;
                    
                    /**
                     * Using common output denominations can be
                     * configured by the end user.
                     */
                    auto use_common_output_denominations =
                        chainblender::instance(
                        ).use_common_output_denominations()
                    ;
                    
                    /**
                     * The sum.
                     */
                    std::int64_t sum = 0;
        
                    /**
                     * The number of fee denominated outputs we've found.
                     */
                    auto fee_denominations = 0;

                    auto rounds = 0;
                    
                    while (outputs.size() < 2 && rounds < denominations.size())
                    {
                        /**
                         * Pick a random denomination.
                         */
                        std::set<std::int64_t>::iterator it =
                            denominations.begin()
                        ;
            
                        std::advance(it, std::rand() % denominations.size());
                        
                        /**
                         * Make sure it is not the transaction fee denomination.
                         */
                        while (*it == globals::instance().transaction_fee())
                        {
                            std::advance(
                                it, std::rand() % denominations.size()
                            );
                        }
                    
                        /**
                         * Iterate the outputs.
                         */
                        for (auto & j : coins)
                        {
                            const auto & tx_out =
                                j.get_transaction_wallet().transactions_out()[
                                j.get_i()]
                            ;
                            
                            const auto & value = tx_out.value();
                            
                            /**
                             * If we found a fee denomination set that we have
                             * found one and add it.
                             */
                            if (value == globals::instance().transaction_fee())
                            {
                                if (++fee_denominations < 2)
                                {
                                    log_info(
                                        "ChainBlender manager found fee "
                                        "denomination for output, adding."
                                    );

                                    outputs.push_back(j);
                                    
                                    sum += value;
                                }
                                
                                log_debug(
                                    "ChainBlender manager found " <<
                                    fee_denominations << " fee denominations."
                                );
                            }
                            else if (*it == value)
                            {
                                log_info(
                                    "ChainBlender manager is adding (random) "
                                    "output " << static_cast<double> (*it) /
                                    constants::coin << "."
                                );
                                
                                outputs.push_back(j);
                                
                                sum += value;

                                break;
                            }
                        }
                        
                        rounds++;
                    }
                    
                    log_info(
                        "ChainBlender manager took " << rounds <<
                        " rounds to generate outputs."
                    );

                    /**
                     * Get our (on-chain + non-denominated) balance.
                     */
                    auto on_chain_nondenominated_balance =
                        globals::instance().wallet_main(
                        )->get_on_chain_nondenominated_balance()
                    ;
                    
                    /**
                     * Get our (on-chain + blended) balance.
                     */
                    auto on_chain_blended_balance =
                        globals::instance().wallet_main(
                        )->get_on_chain_blended_balance()
                    ;
                    
                    /**
                     * Calculate the balance.
                     */
                    auto balance =
                        on_chain_nondenominated_balance -
                        on_chain_blended_balance
                    ;
                    
                    /**
                     * Check if we do not need to blend or denominate.
                     * @note Rounds == Denominations should indicate we do
                     * not have enough denominated transactions left over.
                     */
                    if (
                        (static_cast<double> (balance) /
                        constants::coin <= 9.0 &&
                        static_cast<double> (balance) /
                        constants::coin > 0.0) &&
                        (rounds == denominations.size()
                        ))
                    {
                        log_info(
                            "ChainBlender manager has nothing to blend or "
                            "denominate, restarting."
                        );
                        
                        /**
                         * Restart
                         */
                        restart();
                    }
                    else
                    {
                        /**
                         * If we have no outputs or it took the same number of
                         * rounds as denominations force a denomination to
                         * occur.
                         * @note Rounds == Denominations should indicate we do
                         * not have enough denominated transactions left over.
                         */
                        auto force_denomination =
                            outputs.size() == 0 ||
                            (rounds == denominations.size())
                        ;

                        /**
                         * Require at least one denominated outputs and at least
                         * one fee denominated outputs and at least one fee
                         * denomination in our wallet.
                         */
                        if (
                            force_denomination == false && outputs.size() > 1 &&
                            fee_denominations > 1
                            )
                        {
                            log_info(
                                "ChainBlender manager has " << outputs.size() <<
                                " denominations, "
                                "use_common_output_denominations = " <<
                                use_common_output_denominations << "."
                            );
                            
                            if (m_blend_state == blend_state_active)
                            {
                                std::int64_t sum = 0;

                                for (auto & i : outputs)
                                {
                                    const auto & tx_out =
                                        i.get_transaction_wallet(
                                        ).transactions_out()[i.get_i()]
                                    ;
                                    
                                    const auto & value = tx_out.value();
                                    
                                    sum += value;
                                }
                                
                                if (use_common_output_denominations == false)
                                {
                                    /**
                                     * Set the session denomination (sent in
                                     * cbjoin).
                                     * @note Using a denomination of zero will
                                     * enable us to join any blender session.
                                     */
                                    session_.denomination = 0;
                                }
                                else
                                {
                                    /**
                                     * Set the session denomination (sent in
                                     * cbjoin).
                                     */
                                    session_.denomination = sum;
                                }
                                
                                /**
                                 * Set the session sum.
                                 */
                                session_.sum = sum;
                                
                                log_info(
                                    "ChainBlender manager has prepared " <<
                                    outputs.size() << " outputs, sum = " <<
                                    static_cast<double> (sum) / constants::coin
                                    << "."
                                );

                                /**
                                 * Get our best block height.
                                 */
                                auto block_height = globals::instance(
                                    ).best_block_height()
                                ;
                                
                                /**
                                 * Get the recent good endpoints.
                                 */
                                auto recent_good_endpoints =
                                    stack_impl_.get_address_manager(
                                    )->recent_good_endpoints()
                                ;
              
                                /**
                                 * Get the K closest nodes to the current block
                                 * height.
                                 */
                                auto kclosest = k_closest(
                                    recent_good_endpoints, block_height,
                                    chainblender::k
                                );
                                
                                std::lock_guard<std::recursive_mutex> l1(
                                    mutex_nodes_tried_
                                );
                                
                                std::stringstream ss;
                                
                                auto index = 0;
                                
                                /**
                                 * The current node.
                                 */
                                address_manager::recent_endpoint_t current_node;
                                
                                /**
                                 * Erase recently tried nodes.
                                 */
                                auto it = kclosest.begin();
                                
                                while (it != kclosest.end())
                                {
                                    if (
                                        nodes_tried_.count(*it) > 0 &&
                                        std::time(0) - nodes_tried_[*it] <
                                        constants::work_and_stake_target_spacing
                                        )
                                    {
                                       it = kclosest.erase(it);
                                    }
                                    else
                                    {
                                        nodes_tried_[*it] = std::time(0);
                                        
                                        current_node = *it;
                                        
                                        break;
                                    }
                                }
                                
                                if (kclosest.size() > 0)
                                {
                                    for (auto & i : kclosest)
                                    {
                                        ss <<
                                            "\t" << ++index << ". " <<
                                            i.addr.ipv4_mapped_address(
                                            ).to_string() + ":" + std::to_string(
                                            i.addr.port) << std::endl
                                        ;
                                    }
                                    
                                    log_info(
                                        "ChainBlender manager relay nodes:\n" <<
                                        ss.str()
                                    );
                                    
                                    boost::asio::ip::tcp::endpoint ep;
                                    
                                    /**
                                     * If we are not in debug options mode
                                     * connect to one of the static nodes.
                                     */
                                    if (
                                        stack_impl_.get_configuration(
                                        ).chainblender_debug_options() == true
                                        )
                                    {
                                        ep = boost::asio::ip::tcp::endpoint(
                                            boost::asio::ip::address::from_string(
                                            "23.254.243.105"), 32809
                                        );
                                    }
                                    else
                                    {
                                        ep = boost::asio::ip::tcp::endpoint(
                                            current_node.addr.ipv4_mapped_address(),
                                            current_node.addr.port
                                        );
                                    }
                                    
                                    /**
                                     * Connect to the current node.
                                     */
                                    connect(ep);
                                }
                                else
                                {
                                    log_error(
                                        "ChainBlender manager failed to find "
                                        "kclosest nodes, restarting."
                                    );
                                    
                                    /**
                                     * Restart
                                     */
                                    restart();
                                }
                            }
                            else if (m_blend_state == blend_state_passive)
                            {
                                // ...
                            }
                        }
                        else
                        {
                            /**
                             * Limit denomination operations to once every 8 x 8
                             * = 64 seconds + one block change.
                             */
                            if (
                                (block_height_changed &&
                                std::time(0) - time_last_denominate_ >= 64) ||
                                (std::time(0) - time_last_denominate_ >=
                                constants::work_and_stake_target_spacing)
                                )
                            {
                                /**
                                 * Set the last time we denominated.
                                 */
                                time_last_denominate_ = std::time(0);
                                
                                /**
                                 * Require at least one full coin.
                                 */
                                if (
                                    static_cast<double> (balance) /
                                    constants::coin >= 1.0
                                    )
                                {
                                    log_info(
                                        "ChainBlender manager needs to create "
                                        "denominations:\n " <<
                                        "on_chain_nondenominated_balance: " <<
                                        static_cast<double> (
                                        on_chain_nondenominated_balance) /
                                        constants::coin <<
                                        "\non_chain_blended_balance: " <<
                                        static_cast<double> (
                                        on_chain_blended_balance) /
                                        constants::coin << "\nbalance: " <<
                                        static_cast<double> (balance) /
                                        constants::coin << "."
                                    );
                                
                                    /**
                                     * We denominate a random amount from 9 to
                                     * 999 unless a fee denomination was not
                                     * found we use random amount from 9 to 99.
                                     */
                                    std::int64_t amount = 0;
                                    
                                    if (fee_denominations > 1)
                                    {
                                        amount =
                                            static_cast<double> (
                                            random::uint16_random_range(
                                            99, std::min(static_cast<int> (
                                            balance / constants::coin), 999))) *
                                            constants::coin
                                        ;
                                        
                                        if (amount > balance)
                                        {
                                            amount = balance;
                                        }
                                    }
                                    else
                                    {
                                        amount =
                                            static_cast<double> (
                                            random::uint16_random_range(
                                            9, 99)) * constants::coin
                                        ;
                                        
                                        if (amount > balance)
                                        {
                                            amount = balance;
                                        }
                                    }

                                    log_info(
                                        "ChainBlender manager is attempting to "
                                        "denominate " <<
                                        static_cast<double> (amount) /
                                        constants::coin << "."
                                    );
                                    
                                    auto success = false;
                                    
                                    for (auto i = 0; i < 8; i++)
                                    {
                                        if (amount < balance)
                                        {
                                            success = globals::instance(
                                                ).wallet_main(
                                                )->chainblender_denominate(amount
                                            );
                                            
                                            if (success)
                                            {
                                                break;
                                            }
                                            else
                                            {
                                                amount /= 2;
                                                
                                                if (amount < constants::coin)
                                                {
                                                    break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            amount /= 2;
                                            
                                            if (amount < constants::coin)
                                            {
                                                break;
                                            }
                                        }
                                    }
                                    
                                    if (success == true)
                                    {
                                        log_info(
                                            "ChainBlender manager "
                                            "denominated " <<
                                            static_cast<double> (amount) /
                                            constants::coin << "."
                                        );
                                        
                                        /**
                                         * Restart
                                         */
                                        restart();
                                    }
                                    else
                                    {
                                        log_info(
                                            "ChainBlender manager denomination "
                                            "failed " <<
                                            static_cast<double> (amount) /
                                            constants::coin << ", restarting."
                                        );

                                        /**
                                         * Restart
                                         */
                                        restart(
                                            constants::work_and_stake_target_spacing
                                        );
                                    }
                                }
                                else
                                {
                                    log_error(
                                        "ChainBlender manager failed to "
                                        "denominate, balance too low, "
                                        "restarting."
                                    );
                                    
                                    /**
                                     * Restart
                                     */
                                    restart(
                                        constants::work_and_stake_target_spacing
                                    );
                                }
                            }
                            else
                            {
                                log_info(
                                    "ChainBlender manager needs to wait to "
                                    "create denominations."
                                );
                            }
                        }
                    }

                    if (m_blend_state == blend_state_active)
                    {
                        /**
                         * Start the timer.
                         */
                        do_tick_blend(random::uint16_random_range(4, 8));
                    }
                    else if (m_blend_state == blend_state_passive)
                    {
                        // ...
                    }
                }
            }
        }
    }));
}

std::vector<address_manager::recent_endpoint_t> chainblender_manager::k_closest(
    const std::vector<address_manager::recent_endpoint_t> & nodes,
    const std::uint32_t & block_height, const std::uint32_t & k
    )
{
    std::vector<address_manager::recent_endpoint_t> ret;
    
    std::map<std::uint32_t, address_manager::recent_endpoint_t> entries;
    
    /**
     * Sort all nodes by distance.
     */
    for (auto & i : nodes)
    {
        if (
            i.addr.ipv4_mapped_address().is_loopback() ||
            i.addr.ipv4_mapped_address().is_multicast() ||
            i.addr.ipv4_mapped_address().is_unspecified())
        {
            continue;
        }
        else
        {
            auto distance =
                block_height ^ chainblender::instance().calculate_score(
                boost::asio::ip::tcp::endpoint(i.addr.ipv4_mapped_address(),
                i.addr.port)
            );

            entries.insert(std::make_pair(distance, i));
        }
    }
    
    /**
     * Limit the number to K.
     */
    for (auto & i : entries)
    {
        ret.push_back(i.second);
        
        if (ret.size() >= k)
        {
            break;
        }
    }
    
    return ret;
}

std::vector<output> chainblender_manager::select_coins()
{
    std::vector<output> ret;
    
    std::vector<output> coins;
    
    /**
     * Do not use ZeroTime (we are not creating a transaction).
     */
    auto use_zerotime = false;

    /**
     * Do not filter any coin denominations.
     */
    std::set<std::int64_t> filter;
    
    /**
     * Get the available coins.
     */
    globals::instance().wallet_main()->available_coins(
        coins, true, filter, 0, use_zerotime, false, false
    );

    /**
     * Get all coin denominations.
     */
    auto denominations = chainblender::instance().denominations();
    
    for (auto & i : denominations)
    {
        for (auto & j : coins)
        {
            const auto & wtx = j.get_transaction_wallet();
            
            /**
             * We want at least one (on-chain) confirmation.
             */
            if (wtx.is_in_main_chain() == false)
            {
                continue;
            }
            
            const auto & tx_out = wtx.transactions_out()[j.get_i()];
            
            if (tx_out.value() == i)
            {
                log_debug(
                    "ChainBlender manager found candidate " <<
                    static_cast<double> (tx_out.value()) /
                    constants::coin << " for blending."
                );
                
                ret.push_back(j);
            }
        }
    }
    
    return ret;
}

void chainblender_manager::broadcast_signatures(
    const std::vector<transaction_in> & tx_ins
    )
{
    log_info(
        "ChainBlender manager is broadcasting signatures, "
        "public keys = " << session_.public_keys.size() << "."
    );
    
    if (verify_my_blended_transaction_signatures() == false)
    {
        log_error(
            "ChainBlender manager failed to verify my blended "
            "transaction signature, restarting."
        );
        
        /**
         * Restart
         */
        restart();
    }
    else
    {
        /**
         * Allocate the buffer (value) for the cbbroadcast of the encrypted
         * transaction_in(s).
         */
        data_buffer buffer;
        
        /**
         * Encode the number of transaction_in(s).
         */
        buffer.write_var_int(tx_ins.size());
        
        /**
         * Encode the transaction_in(s).
         */
        for (auto & i : tx_ins)
        {
            i.encode(buffer);
        }
        
        /**
         * The encrypted buffers.
         */
        std::vector<std::string> encrypted_buffers;
        
        for (auto & i : session_.public_keys)
        {
            /**
             * Derive the shared secret bytes
             * from the participants public key.
             */
            auto bytes = ecdhe_.derive_secret_key(i);

            /**
             * Hash the shared secret bytes.
             */
            whirlpool w(&bytes[0], bytes.size());
            
            /**
             * Set the hash to the first 32 bytes of the hexidecimal
             * representation of the digest.
             */
            auto shared_secret =
                w.to_string().substr(0, whirlpool::digest_length / 2
            );
            
            log_debug(
                "ChainBlender manager calculated shared secret " <<
                shared_secret << " for:\n " << i
            );
            
            /**
             * Allocate the hc256 context.
             */
            hc256 ctx(
                shared_secret, shared_secret,
                "l7tH9JXEuGuB96wkA343jor4KJvXDV4j"
            );
            
            /**
             * Calculate the checksum prior to encryption.
             */
            auto checksum = buffer.checksum();
            
            /**
             * Encrypt the buffer.
             */
            auto encrypted = ctx.encrypt(
                std::string(buffer.data(), buffer.size())
            );
            
            /**
             * Allocate memory for the checksum.
             */
            encrypted.resize(encrypted.size() + sizeof(std::uint32_t));
            
            /**
             * Copy the (plain-text little-endian) checksum to the end of the
             * encrypted buffer.
             */
            std::memcpy(
                &encrypted[encrypted.size() - sizeof(std::uint32_t)],
                &checksum, sizeof(std::uint32_t)
            );
            
            /**
             * Insert the encrypted buffer.
             */
            encrypted_buffers.push_back(encrypted);
        }
        
        /**
         * Allocate the cbbroadcast message.
         */
        auto cbbroadcast = std::make_shared<chainblender_broadcast> ();
        
        /**
         * Set the type to
         * chainblender_broadcast::type_sig.
         */
        cbbroadcast->set_type(chainblender_broadcast::type_sig);
        
        /**
         * Allocate the value.
         */
        std::vector<std::uint8_t> value;
        
        /**
         * Allocate the encrypted buffer.
         */
        data_buffer buffer_encrypted;
        
        for (auto & i : encrypted_buffers)
        {
            /**
             * Write the (encrypted) length
             * excluding checksum.
             */
            buffer_encrypted.write_var_int(i.size() - sizeof(std::uint32_t));
            
            /**
             * Write the encrypted transaction_in(s) including checksum.
             */
            buffer_encrypted.write_bytes(i.data(), i.size());
        }
        
        /**
         * Copy the encrypted buffer into the
         * value.
         */
        value.insert(
            value.end(), buffer_encrypted.data(),
            buffer_encrypted.data() + buffer_encrypted.size()
        );
        
        /**
         * Set the length.
         */
        cbbroadcast->set_length(value.size());
        
        /**
         * Set the value.
         */
        cbbroadcast->set_value(value);
        
        /**
         * Send the cbbroadcast message.
         */
        if (tcp_connection_)
        {
            tcp_connection_->send_cbbroadcast_message(cbbroadcast);
        }
    }
}

bool chainblender_manager::commit_transaction(transaction & tx_blended)
{
    /**
     * Make sure at least 2 outputs exist.
     */
    if (tx_blended.transactions_out().size() >= 2)
    {
        /**
         * First checkthat each of my signatures in the final blended
         * transaction are valid.
         */
        if (verify_my_blended_transaction_signatures() == true)
        {
            log_info("ChainBlender manager validated our signatures.");
            
            /**
             * Do not use ZeroTime for
             * denominate operations.
             */
            auto use_zerotime = false;

            /**
             * Create the transaction_wallet.
             */
            auto wtx = transaction_wallet(globals::instance(
                ).wallet_main().get(), tx_blended
            );

            /**
             * Set that the transaction_wallet is chainblender blended.
             */
            wtx.values()["blended"] = "1";
            
            /**
             * Get the key_reserved.
             */
            key_reserved reserved_key(*globals::instance().wallet_main());

            /**
             * Commit the transaction.
             */
            auto ret_pair = globals::instance(
                ).wallet_main()->commit_transaction(wtx, reserved_key,
                use_zerotime
            );

            if (ret_pair.first == true)
            {
                log_info("ChainBlender manager commited transaction.");
                
                return true;
            }
        }
        else
        {
            log_error(
                "ChainBlender manager failed to commit transaction, "
                "signature verification failed, restarting."
            );
            
            /**
             * Restart
             */
            restart();
        }
    }
    
    return false;
}

bool chainblender_manager::verify_my_blended_transaction_signatures()
{
    for (auto & i : session_.transaction_mine.transactions_in())
    {
        auto n = -1;

        transaction_in tx_in;
        
        auto index = 0;
        
        for (
            auto & j : session_.transaction_blended.transactions_in()
            )
        {
            if (
                j.previous_out() == i.previous_out() &&
                j.sequence() == i.sequence()
                )
            {
                n = index;
            }
            
            index++;
        }

        if (n > -1)
        {
            db_tx tx_db("r");
            
            transaction tx_previous;
            
            transaction_index tx_index;
            
            if (
                tx_previous.read_from_disk(tx_db, i.previous_out(),
                tx_index) == true
                )
            {
                if (
                    script::verify_signature(
                    tx_previous, session_.transaction_blended, n, true, 0
                    ) == false)
                {
                    return false;
                }
            }
        }
    }

    return true;
}
