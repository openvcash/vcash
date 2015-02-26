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

#ifndef COIN_TRANSACTION_HPP
#define COIN_TRANSACTION_HPP

#include <map>
#include <vector>

#include <coin/block_index.hpp>
#include <coin/data_buffer.hpp>
#include <coin/db_tx.hpp>
#include <coin/file.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_in.hpp>
#include <coin/transaction_index.hpp>
#include <coin/transaction_out.hpp>
#include <coin/transaction_position.hpp>

namespace coin {
    
    /**
     * Implements a transaction.
     */
    class transaction : public data_buffer
    {
        public:
        
            /**
             * A previous transaction.
             */
            typedef std::map<
                sha256, std::pair<transaction_index, transaction>
            > previous_t;
        
            /**
             * The current version.
             */
            enum { current_version = 1 };
        
            /**
             * The number confirmations.
             */
            enum { confirmations = 3 };
    
            /**
             * Constructor
             */
            transaction();
        
            /**
             * Encodes
             * @param encode_version If true the version is encoded.
             */
            void encode(const bool & encode_version = true);
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             * @param encode_version If true the version is encoded.
             */
            void encode(
                data_buffer & buffer, const bool & encode_version = true
            ) const;
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
        
            /**
             * Gets the hash.
             */
            sha256 get_hash() const;
        
            /**
             * The string representation.
             */
            std::string to_string();
        
            /**
             * Count ECDSA signature operations the old (version < 0.6) way.
             * @return The number of sigops this transaction's outputs will
             * produce when spent.
             */
            std::uint32_t get_legacy_sig_op_count() const;
        
            /**
             * If true it is final.
             * @param block_height The block height.
             * @param block_time The block time.
             */
            bool is_final(
                std::uint32_t block_height = 0, std::int64_t block_time = 0
            ) const;
        
            /**
             * If true it is newer.
             * @param other The transaction.
             */
            bool is_newer_than(const transaction & other) const;
        
            /**
             * If true it is coin base.
             */
            bool is_coin_base() const;
        
            /**
             * If true it is coin stake.
             */
            bool is_coin_stake() const;

            /**
             * Check for standard transaction types.
             * @return True if all outputs use only standard transactions forms.
             */
            bool is_standard() const;
    
            /**
             * are_inputs_standard
             * @param inputs The transaction::previous_t.
             */
            bool are_inputs_standard(
                const transaction::previous_t & inputs
            ) const;

            /**
             * Gets the value out (the sum of all outputs not including fee).
             */
            std::int64_t get_value_out() const;
        
            /**
             * gets the value in.
             * @param inputs The previous transactions.
             */
            std::int64_t get_value_in(
                const transaction::previous_t & inputs
            ) const;
        
            /**
             * get_p2sh_sig_op_count
             * @param inputs The previous_t.
             */
            std::uint32_t get_p2sh_sig_op_count(
                const previous_t & inputs
            ) const;

            /**
             * If true no fee us required.
             * @param priority The priority.
             */
            static bool allow_free(const double & priority);

            /**
             * Gets the minimum fee.
             * @param block_size The block size.
             * @param allow_free If true free is allowed.
             * @param mode The mode.
             * @param len The length.
             */
            std::int64_t get_minimum_fee(
                const std::uint32_t & block_size = 1,
                const bool & allow_free = false,
                const types::get_minimum_fee_mode_t & mode =
                types::get_minimum_fee_mode_block, const std::size_t & len = 0
            ) const;
        
            /**
             * Accepts the transaction into the transaction_pool.
             * @param tx_db The db_tx.
             * @param missing_inputs The missing inputs.
             */
            std::pair<bool, std::string> accept_to_transaction_pool(
                db_tx & tx_db, bool * missing_inputs = 0
            );
    
            /**
             * Reads a transaction from disk.
             * @param position The transaction_position.
             */
            bool read_from_disk(const transaction_position & position);
        
            /**
             * Reads a transaction from disk.
             * @param tx_db The db_tx.
             * @param previous_out The point_out.
             * @param tx_index The transaction_index.
             */
            bool read_from_disk(
                db_tx & tx_db, const point_out & previous_out,
                transaction_index & tx_index
            );
        
            /**
             * Fetch from memory and/or disk.
             * @param dbtx The db_tx.
             * @param test_pool	List of pending changes to the transaction
             * index database.
             * @param best_block True if being called to add a new best-block
             * to the chain.
             * @param create_block True if being called by create_new_block.
             * @param[out] inputs Pointers to this transaction's inputs.
             * @param[out] invalid True if transaction is invalid.
             * @return Returns true if all inputs are in db_tx or test_pool.
             */
            bool fetch_inputs(
                db_tx & dbtx,
                const std::map<sha256, transaction_index> & test_pool,
                const bool & best_block, const bool & create_block,
                transaction::previous_t & inputs, bool & invalid
            );
        
            /**
             * get_output_for
             * @param input The transaction_in.
             * @param inputs The previous_t.
             */
            const transaction_out & get_output_for(
                const transaction_in & input, const previous_t & inputs
            ) const;
        
            /**
             * Sanity check previous transactions, then, if all checks succeed,
             * mark them as spent by this transaction.
             * @param[in] inputs Previous transactions (from FetchInputs).
             * @param[out] test_pool Keeps track of inputs that need to be
             * updated on disk.
             * @param[in] position_this_tx Position of this transaction on disk.
             * @param[in] ptr_block_index The pointer to a block_index.
             * @param[in] connect_block	True if called from connect_block.
             * @param[in] create_new_block True if called from create_new_block.
             * @param[in] strict_pay_to_script_hash	true if fully validating
             * p2sh transactions.
             */
            bool connect_inputs(
                db_tx & txdb,
                std::map<sha256, std::pair<transaction_index, transaction> > & inputs,
                std::map<sha256, transaction_index> & test_pool,
                const transaction_position & position_this_tx,
                const std::shared_ptr<block_index> & ptr_block_index,
                const bool & connect_block, const bool & create_new_block,
                const bool & strict_pay_to_script_hash = true
            );
        
            /**
             * Connects client inputs.
             */
            bool client_connect_inputs();
        
            /**
             * Disconnects inputs.
             * @param tx_db The db_tx.
             */
            bool disconnect_inputs(db_tx & txdb);
        
            /**
             * Total coin age spent in transaction, in the unit of coin-days.
             * Only those coins meeting minimum age requirement counts. As those
             * transactions not in main chain are not currently indexed so we
             * might not find out about their coin age. Older transactions are
             * guaranteed to be in main chain by sync-checkpoint. This rule is
             * introduced to help nodes establish a consistent view of the coin
             * age (trust score) of competing branches. (ppcoin).
             */
            bool get_coin_age(db_tx & tx_db, std::uint64_t & coin_age) const;

            /**
             * Checks
             */
            bool check();
        
            /**
             * The version.
             */
            const std::uint32_t & version() const;
        
            /**
             * Sets the time.
             * @param value The value.
             */
            void set_time(const std::uint32_t & value);
        
            /**
             * The time.
             */
            const std::uint32_t & time() const;
        
            /**
             * The transactions in.
             */
            std::vector<transaction_in> & transactions_in();
        
            /**
             * The transactions out.
             */
            std::vector<transaction_out> & transactions_out();
    
            /**
             * The transactions in.
             */
            const std::vector<transaction_in> & transactions_in() const;
        
            /**
             * The transactions out.
             */
            const std::vector<transaction_out> & transactions_out() const;
        
            /**
             * The lock time.
             */
            const std::uint32_t & time_lock() const;
        
            /**
             * operator ==
             */
            friend bool operator == (
                const transaction & lhs, const transaction & rhs
                )
            {
                return
                    lhs.m_version == rhs.m_version &&
                    lhs.m_time == rhs.m_time &&
                    lhs.m_transactions_in == rhs.m_transactions_in &&
                    lhs.m_transactions_out == rhs.m_transactions_out &&
                    lhs.m_time_lock == rhs.m_time_lock
                ;
            }

            /**
             * operator !=
             */
            friend bool operator != (
                const transaction & lhs, const transaction & rhs
                )
            {
                return !(lhs == rhs);
            }
    
        private:
        
            /**
             * The version.
             */
            std::uint32_t m_version;
        
            /**
             * The time.
             */
            std::uint32_t m_time;
        
            /**
             * The transactions in.
             */
            std::vector<transaction_in> m_transactions_in;
        
            /**
             * The transactions out.
             */
            std::vector<transaction_out> m_transactions_out;
        
            /**
             * The lock time.
             */
            std::uint32_t m_time_lock;
        
        protected:
        
            // ...
    };
    
} // namespace transaction

#endif // COIN_TRANSACTION_HPP
