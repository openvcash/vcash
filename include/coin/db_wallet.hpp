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

#ifndef COIN_DB_WALLET_HPP
#define COIN_DB_WALLET_HPP

#include <list>
#include <string>
#include <vector>

#include <coin/accounting_entry.hpp>
#include <coin/db.hpp>
#include <coin/filesystem.hpp>
#include <coin/key.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    class account;
    class block_locator;
    class data_buffer;
    class db_env;
    class key_pool;
    class key_public;
    class key_wallet_master;
    class transaction_wallet;
    class script;
    class wallet;
    
    /**
     * Implement a wallet database.
     */
    class db_wallet : public db
    {
        public:
        
            /**
             * Error codes.
             */
            typedef enum
            {
                error_load_ok,
                error_corrupt,
                error_noncritical_error,
                error_too_new,
                error_load_fail,
                error_need_rewrite
            } error_t;
        
            /**
             * Constructor
             * @param file_name The file name.
             * @param file_mode The file mode.
             */
            db_wallet(
                const std::string & file_name,
                const std::string & file_mode = "+r"
            );
        
            /**
             * Loads a wallet from the database into the wallet class.
             * @param w The wallet.
             */
            error_t load(wallet & w);
        
            /**
             * Reorders the transactions.
             * @param w The wallet.
             */
            error_t reorder_transactions(wallet & w);
        
            /**
             * Performs a wallet backup operation.
             * @param w The wallet.
             * @param root_path The root path.
             */
            static bool backup(
                const wallet & w,
                const std::string & root_path = filesystem::data_path()
            );
        
            /**
             * Attempts to recover a wallet database file.
             * @param env The db_env.
             * @param file_name The file name.
             * @param keys_only If true only the keys will attempted to be
             * recovered.
             */
            static bool recover(
                db_env & env, const std::string & file_name,
                const bool & keys_only
            );
        
            /**
             * Attempts to recover a wallet database file.
             * @param env The db_env.
             * @param file_name The file name.
             */
            static bool recover(db_env & env, const std::string & file_name);
    
            /**
             * Reads a key/value pair.
             * @param w The wallet.
             * @param buffer_key The data_buffer.
             * @param buffer_value The buffer value.
             * @param file_version The file version.
             * @param wallet_upgrade The wallet upgrade.
             * @param is_encrypted If true it is encrypted.
             * @param any_unordered It true there are some unordered.
             * @param type The type.
             * @param err The error.
             */
            static bool read_key_value(
                wallet & w, data_buffer & buffer_key,
                data_buffer & buffer_value, std::int32_t & file_version,
                std::vector<sha256> & wallet_upgrade, bool & is_encrypted,
                bool & any_unordered, std::string & type, std::string & err
            );
        
            /**
             * Writes the name.
             * @param addr The address.
             * @param name The name.
             */
            bool write_name(const std::string & addr, const std::string & name);
        
            /**
             * Reads an account.
             * @param name The name of the account.
             * @param acct The account.
             */
            bool read_account(const std::string & name, account & acct);
        
            /**
             * Writes an account.
             * @param name The name of the account.
             * @param acct The account.
             */
            bool write_account(const std::string & name, account & acct);
    
            /**
             * Erases a transaction.
             * @param val The sha256.
             */
            bool erase_tx(const sha256 & val);
        
            /**
             * Writes a transaction.
             * @param val The sha256.
             * @param tx_w The transaction_wallet.
             */
            bool write_tx(const sha256 & val, transaction_wallet & tx_w);
    
            /**
             * Writes the order position next.
             * @param value The value.
             */
            bool write_orderposnext(const std::int64_t & value);
        
            /**
             * Writes the default key.
             * @param value the key_public.
             */
            bool write_defaultkey(const key_public & value);
    
            /**
             * Writes a key.
             * @param pub_key The key_public.
             * @param pri_key The key::private_t.
             */
            bool write_key(
                const key_public & pub_key, const key::private_t & pri_key
            );

            /**
             * Writes a crypted key.
             * @param pub_key The key_public.
             * @param crypted_secret The crypted secret.
             * @param erase_unencrypted_key If true the unencrypted key will
             * be erased.
             */
            bool write_crypted_key(
                const key_public & pub_key,
                const std::vector<std::uint8_t> & crypted_secret,
                const bool & erase_unencrypted_key = true
            );

            /**
             * Writes a master key.
             * @param id The id.
             * @param key_master The key_wallet_master.
             */
            bool write_master_key(
                const std::uint32_t & id, const key_wallet_master & key_master
            );
        
            /**
             * Writes a c script.
             * @param h The ripemd160.
             * @param script_redeem The script
             */
            bool write_c_script(
                const ripemd160 & h, const script & script_redeem
            );

            /**
             * Reads the best block.
             * @param val The value.
             */
            bool read_bestblock(block_locator & val);
        
            /**
             * Writes the best block.
             * @param value The value.
             */
            bool write_bestblock(const block_locator & val);
    
            /**
             * Reads a key_pool.
             * @param pool The pool.
             * @param keypool The key_pool.
             */
            bool read_pool(const std::int64_t & pool, key_pool & keypool);
            
            /**
             * Writes a key_pool.
             * @param pool The pool.
             * @param keypool The key_pool.
             */
            bool write_pool(
                const std::int64_t & pool, key_pool & keypool
            );

            /**
             * Erases a key_pool.
             * @param pool The pool.
             */
            bool erase_pool(const std::int64_t & pool);
    
            /**
             * Writes the minimum version.
             */
            bool write_minversion(const std::int32_t & value);
    
            /**
             * Writes an accounting_entry.
             * @param entry_number The entry number.
             * @param entry The accounting_entry.
             * @param overwrite If true the previous entry will be overwritten.
             */
            bool write_accounting_entry(
                const std::uint64_t & entry_number, accounting_entry & entry,
                const bool & overwrite = true
            );

            /**
             * Writes an accounting_entry.
             * @param entry The accounting_entry.
             */
            bool write_accounting_entry(accounting_entry & entry);
        
            /**
             * Gets the given account's credit and debit.
             * @param account The account name.
             */
            std::int64_t get_account_credit_debit(const std::string & account);

            /**
             * Builds a list of account entries (credits and debits).
             * @param account The account.
             * @param entries The entries.
             */
            void list_account_credit_debit(
                const std::string & account,
                std::list<accounting_entry> & entries
            );
        
        private:
        
            /**
             * The number of times the wallet has been updated.
             */
            std::uint32_t m_wallet_updated;
        
        protected:
        
            /**
             * Returns true if the input is the key type.
             * @param type The type.
             */
            static bool is_key_type(const std::string & type);
        
            /**
             * The accounting entry number.
             */
            static std::uint64_t g_accounting_entry_number;
    };
    
} // namespace coin

#endif // COIN_DB_WALLET_HPP
