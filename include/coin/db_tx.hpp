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

#ifndef COIN_DB_TX_HPP
#define COIN_DB_TX_HPP

#include <string>

#include <coin/big_number.hpp>
#include <coin/db.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_index.hpp>

namespace coin {

    class block_index;
    class block_index_disk;
    class point_out;
    class sha256;
    class stack_impl;
    class transaction;
    
    /**
     * Implements a transaction database.
     */
    class db_tx : public db
    {
        public:
        
            /**
             * Constructor
             * @param file_mode The file mode.
             */
            db_tx(const std::string & file_mode = "r+");
        
            /**
             * Loads the block index.
             * @param impl The stack_impl.
             */
            bool load_block_index(stack_impl & impl);
        
            /**
             * Checks if the transaction is in the database.
             * @param hash The sha256.
             */
            bool contains_transaction(const sha256 & hash);

            /**
             * Reads a transaction from disk.
             * @param hash The sha256.
             * @param tx The transaction.
             * @param index The transaction_index.
             */
            bool read_disk_transaction(
                const sha256 & hash, transaction & tx, transaction_index & index
            );
        
            /**
             * Reads a transaction from disk.
             * @param hash The sha256.
             * @param tx The transaction.
             */
            bool read_disk_transaction(const sha256 & hash, transaction & tx);
        
            /**
             * Reads a transaction from disk.
             * @param out_point The point_out.
             * @param tx The transaction.
             * @param index The transaction_index.
             */
            bool read_disk_transaction(
                const point_out & out_point, transaction & tx,
                transaction_index & index
            );
        
            /**
             * Reads a transaction from disk.
             * @param out_point The point_out.
             * @param tx The transaction.
             */
            bool read_disk_transaction(
                const point_out & out_point, transaction & tx
            );
    
            /**
             * Reads a transaction_index.
             * @param hash The sha256 hash.
             * @param index The transaction_index.
             */
            bool read_transaction_index(
                const sha256 & hash, transaction_index & index
            );
        
            /**
             * Updates a transaction index.
             * @param hash The sha256 hash.
             * @param index The transaction_index.
             */
            bool update_transaction_index(
                const sha256 & hash, transaction_index & index
            );

            /**
             * Erases a transaction index.
             * @param tx The transaction.
             */
            bool erase_transaction_index(const transaction & tx) const;
        
            /**
             * Writes the hash of the best chain.
             * @param hash The sha256 hash.
             */
            bool write_hash_best_chain(const sha256 & hash);
        
            /**
             * Writes the best invalid trust.
             * @param bn The big_number.
             */
            bool write_best_invalid_trust(big_number & bn);
        
            /**
             * Writes a blockindex.
             * @param value The block_index_disk.
             */
            bool write_blockindex(block_index_disk value);
        
            /**
             * Writes a hashsynccheckpoint.
             * @param hash The sha256 hash.
             */
            bool write_hashsynccheckpoint(const sha256 & hash);

            /**
             * Reads a checkpoint public key.
             * @param val The value.
             */
            bool read_checkpoint_public_key(std::string & val);
        
            /**
             * Writes a checkpoint public key.
             * @param val.
             */
            bool write_checkpoint_public_key(const std::string & val);
        
            /**
             * Reorganizes the transactions.
             * @param tx_db The db_tx.
             * @param index_new The new block_index.
             */
            static bool reorganize(
                db_tx & tx_db, std::shared_ptr<block_index> & index_new
            );
        
        private:
        
            /**
             * Loads the block index guts.
             */
            bool load_block_index_guts();
        
            /**
             * Read the hash of the best chain.
             * @param hash The sha256 hash.
             */
            bool read_best_hash_chain(sha256 & hash);
        
            /**
             * Read the sync checkpoint.
             * @param hash The sha256 hash.
             */
            bool read_sync_checkpoint(sha256 & hash);
        
            /**
             * Reads the best invalid trust.
             * @param bn The big_number.
             */
            bool read_best_invalid_trust(big_number & bn);
        
        protected:
        
            /**
             * Reads a string.
             * @param key The key.
             * @param val The value.
             */
            bool read_string(const std::string & key, std::string & val);
        
            /**
             * Writes a string.
             * @param key The key.
             * @param val The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write_string(
                const std::string & key, const std::string & val,
                const bool & overwrite = true
            );
        
            /**
             * reads a sha256 hash.
             * @param key The key.
             * @param value The value.
             */
            bool read_sha256(const std::string & key, sha256 & val);
        
            /**
             * Writes a sha256 hash.
             * @param key The data_buffer.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write_sha256(
                const std::string & key, const sha256 & val,
                const bool & overwrite = true
            );
        
            /**
             * Reads a big_number.
             * @param key The key.
             * @param value The big_number.
             */
            bool read_big_number(const std::string & key, big_number & value);

            /**
             * Reads a key/value pair.
             * @param key The data_buffer.
             * @param value The value.
             */
            template<typename T>
            bool read(const data_buffer & key, T & value);
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1, typename T2>
            bool write(
                const T1 & key, T2 & value, const bool & overwrite = true
            );
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1>
            bool write(
                const std::pair<std::string, sha256> & key, T1 & value,
                const bool & overwrite = true
            );
    
    };

} // namespace coin

#endif // COIN_DB_TX_HPP
