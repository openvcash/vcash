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

#ifndef COIN_TRANSACTION_WALLET_HPP
#define COIN_TRANSACTION_WALLET_HPP

#include <cstdint>
#include <vector>

#include <coin/transaction_merkle.hpp>

namespace coin {

    class data_buffer;
    class tcp_connection_manager;
    class wallet;
    
    /**
     * Implements a wallet transaction. It includes any unrecorded transactions
     * needed to link it back to the block chain.
     */
    class transaction_wallet : public transaction_merkle
    {
        public:
        
            /**
             * Constructor
             */
            transaction_wallet();
        
            /**
             * Constructor
             */
            transaction_wallet(const wallet * ptr_wallet);
        
            /**
             * Constructor
             */
            transaction_wallet(
                const wallet * ptr_wallet, const transaction & tx_in
            );
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);

            /**
             * Initialize
             * @param ptr_wallet The wallet.
             */
            void initialize(const wallet * ptr_wallet);

            /**
             * Gets the amounts.
             * @param generated_immature The number of coins generated but not
             * yet matured.
             * @param generated_mature The number of coins generated and
             * matured.
             * @param received The coins received.
             * @param sent The coins sent.
             * @param fee The transaction fee.
             * @param account_sent The account sent.
             */
            void get_amounts(
                std::int64_t & generated_immature, std::int64_t & generated_mature,
                std::list< std::pair<destination::tx_t, std::int64_t> > & received,
                std::list< std::pair<destination::tx_t, std::int64_t> > & sent,
                std::int64_t & fee, std::string & account_sent
            ) const;

            /**
             * Gets the amounts from the give account.
             * @param account The account name.
             * @param generated The number of coins generated.
             * @param received The number of coins received.
             * @param sent The number of coins sent.
             * @param fee The fee.
             */
            void get_account_amounts(
                const std::string & account, std::int64_t & generated,
                std::int64_t & received, std::int64_t & sent, std::int64_t & fee
            ) const;

            /**
             * Adds supporting transactions.
             * @param tx_db The db_tx.
             */
            void add_supporting_transactions(db_tx & tx_db);
        
            /**
             * Adds supporting transactions.
             */
            void spv_add_supporting_transactions();
        
            /**
             * Accepts a wallet transaction.
             * @param tx_db The db_tx.
             */
            std::pair<bool, std::string> accept_wallet_transaction(
                db_tx & tx_db
            );

            /**
             * Accepts a wallet transaction.
             */
            std::pair<bool, std::string> accept_wallet_transaction();

            /**
             * Marks certain transaction out's as spent.
             * @param spent_new The new spent.
             */
            bool update_spent(const std::vector<char> & spent_new) const;
    
            /**
             * Marks dirty so balances are recalculated.
             */
            void mark_dirty();

            /**
             * Binds a wallet.
             * @param value The wallet.
             */
            void bind_wallet(const wallet & value);
        
            /** 
             * Marks spent.
             * @param out The out.
             */
            bool mark_spent(const std::uint32_t & out);
    
            /** 
             * Marks unspent.
             * @param out The out.
             */
            void mark_unspent(const std::uint32_t & out);

            /**
             * If true it is spent.
             * @param out The out.
             */
            bool is_spent(const std::uint32_t & out) const;
        
            /**
             * Gets debit.
             */
            std::int64_t get_debit() const;

            /**
             * Gets credit.
             * @param use_cache If true the cache will be used.
             */
            std::int64_t get_credit(const bool & use_cache = true) const;

            /**
             * Gets the available credit.
             * @param use_cache If true the cache will be used.
             */
            std::int64_t
                get_available_credit(const bool & use_cache = true) const
            ;
        
            /**
             * Gets the available (denominated) credit.
             * @param use_cache If true the cache will be used.
             */
            std::int64_t
                get_available_denominated_credit(
                    const bool & use_cache = true
            ) const;
        
            /**
             * Gets the available (chainblended) credit.
             * @param use_cache If true the cache will be used.
             */
            std::int64_t
                get_available_chainblended_credit(
                    const bool & use_cache = true
            ) const;
    
            /**
             * Writes to disk.
             */
            bool write_to_disk();
        
            /**
             * Relays a wallet transaction.
             * @param connection_manager The tcp_connection_manager.
             * @param use_udp If true it will be broadcast over UDP.
             */
            void relay_wallet_transaction(
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager, const bool & use_udp
            );
        
            /**
             * Relays a wallet transaction.
             * @param tx_db The db_tx.
             * @param connection_manager The tcp_connection_manager.
             * @param use_udp If true it will be broadcast over UDP.
             */
            void relay_wallet_transaction(
                db_tx & tx_db,
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager, const bool & use_udp
            );
        
            /**
             * Relays a wallet transaction.
             * @param connection_manager The tcp_connection_manager.
             */
            void spv_relay_wallet_transaction(
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager
            );
        
            /**
             * Relays a zerotime_lock for the wallet transaction.
             * @param connection_manager The tcp_connection_manager.
             * @param use_udp If true it will be broadcast over UDP.
             */
            void relay_wallet_zerotime_lock(
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager, const bool & use_udp
            );

            /**
             * The previous transactions.
             */
            const std::vector<transaction_merkle> &
                previous_transactions() const
            ;
        
            /**
             * The values.
             */
            std::map<std::string, std::string> & values();
        
            /**
             * The values.
             */
            const std::map<std::string, std::string> & values() const;
        
            /**
             * Sets the time received is trnsaction time.
             * @param value The value.
             */
            void set_time_received_is_tx_time(
                const std::uint32_t & value
            );
        
            /**
             * The time received is transaction time.
             */
            const std::uint32_t & time_received_is_tx_time() const;
        
            /**
             * Set the time received.
             * @param value The value.
             */
            void set_time_received(const std::uint32_t & value);
        
            /**
             * The time received (by this node).
             */
            const std::uint32_t & time_received() const;
        
            /**
             * Set the time smart.
             * @param value The value.
             */
            void set_time_smart(const std::uint32_t & value);
        
            /**
             * The time smart.
             */
            const std::uint32_t & time_smart() const;
        
            /**
             * Sets is from me.
             * @Param value The value.
             */
            void set_is_from_me(const bool & value);
        
            /**
             * If true it is from me.
             */
            const bool & is_from_me() const;
        
            /**
             * Set the from account.
             * @param val The value.
             */
            void set_from_account(const std::string & val);
        
            /**
             * The from account.
             */
            std::string & from_account();
        
            /**
             * If true it is confirmed.
             */
            bool is_confirmed() const;
        
            /**
             * The outputs which are already spent.
             */
            const std::vector<char> & spent() const;
        
            /**
             * Sets the order position.
             * @param value The value.
             */
            void set_order_position(const std::int64_t & value);
        
            /** 
             * The position in the ordered transaction list.
             */
            const std::int64_t & order_position() const;
        
            /**
             * friend bool operator <
             */
            friend bool operator < (
                const transaction_wallet & left,
                const transaction_wallet & right
                )
            {
                /**
                 * @note This is only used for std::set compatibility.
                 */
                return &left < &right;
            }
        
            /**
             * The number of blocks before it is confirmed.
             */
            enum { confirmations = 1 };
        
        private:
        
            /**
             * The previous transactions.
             */
            std::vector<transaction_merkle> m_previous_transactions;
        
            /**
             * The values.
             */
            std::map<std::string, std::string> m_values;
        
            /**
             *
             */
            std::vector< std::pair<std::string, std::string> > m_order_form;
        
            /**
             * The time received is transaction time.
             */
            std::uint32_t m_time_received_is_tx_time;
        
            /**
             * The time received (by this node).
             */
            std::uint32_t m_time_received;
        
            /**
             * The time smart.
             */
            std::uint32_t m_time_smart;
        
            /**
             * If true it is from me.
             */
            bool m_is_from_me;
        
            /**
             * The from account.
             */
            std::string m_from_account;
    
            /**
             * The outputs which are already spent.
             */
            mutable std::vector<char> m_spent;
        
            /** 
             * The position in the ordered transaction list.
             */
            std::int64_t m_order_position;
        
        protected:
        
            /**
             * The wallet.
             */
            const wallet * wallet_;
        
            /**
             * If true the credit is cached.
             */
            mutable bool credit_is_cached_;
        
            /**
             * The amount of cached credit.
             */
            mutable std::int64_t credit_cached_;
        
            /**
             * If true the debit is cached.
             */
            mutable bool debit_is_cached_;
        
            /**
             * The amount of cached debit.
             */
            mutable std::int64_t debit_cached_;
        
            /**
             * If true available credit is cached.
             */
            mutable bool available_credit_is_cached_;
        
            /**
             * The amount of available cached credit
             */
            mutable std::int64_t available_credit_cached_;
        
            /**
             * If true available (denominated) credit is cached.
             */
            mutable bool available_denominated_credit_is_cached_;
        
            /**
             * The amount of available cached (denominated) credit
             */
            mutable std::int64_t available_denominated_credit_cached_;

            /**
             * If true available (chainblended) credit is cached.
             */
            mutable bool available_chainblended_credit_is_cached_;
        
            /**
             * The amount of available cached (chainblended) credit
             */
            mutable std::int64_t available_chainblended_credit_cached_;
        
            /**
             * If true if change is cached.
             */
            mutable bool change_is_cached_;
    };

} // namespace coin

#endif // COIN_TRANSACTION_WALLET_HPP
