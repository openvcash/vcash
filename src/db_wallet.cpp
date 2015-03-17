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

#include <coin/account.hpp>
#include <coin/accounting_entry.hpp>
#include <coin/address.hpp>
#include <coin/block_locator.hpp>
#include <coin/data_buffer.hpp>
#include <coin/db_env.hpp>
#include <coin/db_wallet.hpp>
#include <coin/key_wallet.hpp>
#include <coin/key_wallet_master.hpp>
#include <coin/stack_impl.hpp>
#include <coin/transaction_wallet.hpp>
#include <coin/wallet.hpp>

using namespace coin;

std::uint64_t db_wallet::g_accounting_entry_number = 0;

db_wallet::db_wallet(
    const std::string & file_name, const std::string & file_mode
    )
    : db(file_name, file_mode)
    , m_wallet_updated(0)
{
    // ...
}

db_wallet::error_t db_wallet::load(wallet & w)
{
    /**
     * Set the default key.
     */
    w.set_key_public_default(key_public());

    std::int32_t file_version = 0;
    
    std::vector<sha256> wallet_upgrade;
    
    bool is_encrypted = false;
    
    bool any_unordered = false;
    
    bool noncritical_errors = false;
    
    db_wallet::error_t result = db_wallet::error_load_ok;

    try
    {
        std::int32_t min_version = 0;
        
        if (db::read("minversion", min_version))
        {
            if (min_version > constants::version_client)
            {
                return db_wallet::error_too_new;
            }
            
            w.load_minimum_version(min_version);
        }

        auto cursor = get_cursor();
        
        if (cursor == 0)
        {
            log_error("Database wallet load failed to get cursor.");
            
            return db_wallet::error_corrupt;
        }

        for (;;)
        {
            if (globals::instance().state() >= globals::state_stopping)
            {
                log_debug(
                    "Wallet database load is aborting, state >= state_stopping."
                );
                
                return db_wallet::error_noncritical_error;
            }
            
            /**
             * Read the next record.
             */
            data_buffer buffer_key, buffer_value;

            auto ret = read_at_cursor(cursor, buffer_key, buffer_value);
            
            if (ret == DB_NOTFOUND)
            {
                break;
            }
            else if (ret != 0)
            {
                log_error("Database wallet load failed to read next record.");
                
                return db_wallet::error_corrupt;
            }

            std::string type, err;
            
            if (
                read_key_value(w, buffer_key, buffer_value, file_version,
                wallet_upgrade, is_encrypted, any_unordered, type, err) == false
                )
            {
                /**
                 * If the type is a key then the error is considered fatal.
                 */
                if (is_key_type(type))
                {
                    result = db_wallet::error_corrupt;
                }
                else
                {
                    /**
                     * Set that we have some noncritical error.
                     */
                    noncritical_errors = true;
                    
                    if (type == "tx")
                    {
                        /**
                         * Rescan if there is a bad transaction record.
                         */
                        globals::instance().set_option_rescan(true);
                    }
                }
            }
            
            if (err.size() > 0)
            {
                log_error(
                    "Database wallet load got error " << err << " while "
                    "reading key/value pairs."
                );
            }
        }
        
        cursor->close();
    }
    catch (std::exception & e)
    {
        result = db_wallet::error_corrupt;
    }

    if (noncritical_errors && result == db_wallet::error_load_ok)
    {
        result = db_wallet::error_noncritical_error;
    }
    
    /**
     * If we failed due to corruption do not continue any further as it may
     * worsen the problem.
     */
    if (result != db_wallet::error_load_ok)
    {
        return result;
    }
    
    log_info("Database wallet file version = " << file_version << ".");

    for (auto & i : wallet_upgrade)
    {
        write_tx(i, w.transactions()[i]);
    }
    
    /**
     * Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc.
     */
    if (is_encrypted && (file_version == 40000 || file_version == 50000))
    {
        return db_wallet::error_need_rewrite;
    }
    
    /**
     * Update the version.
     */
    if (file_version < constants::version_client)
    {
        write_version(constants::version_client);
    }
    
    if (any_unordered)
    {
        result = reorder_transactions(w);
    }
    
    return result;
}

db_wallet::error_t db_wallet::reorder_transactions(wallet & w)
{
    /**
     * Sort all wallet transactions and accouting entries by time.
     */
    typedef std::pair<transaction_wallet *, accounting_entry *> tx_pair_t;
    typedef std::multimap<std::int64_t, tx_pair_t> tx_items_t;
    
    tx_items_t sorted_by_time;

    for (auto it = w.transactions().begin(); it != w.transactions().end(); ++it)
    {
        transaction_wallet * wtx = &it->second;
        
        sorted_by_time.insert(
            std::make_pair(wtx->time_received(), tx_pair_t(wtx, 0))
        );
    }
    
    std::list<accounting_entry> acentries;
    
    list_account_credit_debit("", acentries);
    
    for (auto & i : acentries)
    {
        sorted_by_time.insert(std::make_pair(i.time(), tx_pair_t(0, &i)));
    }

    w.set_order_position_next(0);
    
    std::vector<std::int64_t> order_position_offsets;
    
    for (auto it = sorted_by_time.begin(); it != sorted_by_time.end(); ++it)
    {
        transaction_wallet * ptr_wtx = it->second.first;
        
        accounting_entry * ptr_acentry = it->second.second;
        
        const std::int64_t & order_position =
            ptr_wtx ? ptr_wtx->order_position() : ptr_acentry->order_position()
        ;

        if (order_position == -1)
        {
            w.set_order_position_next(w.order_position_next() + 1);
            
            if (ptr_wtx)
            {
                ptr_wtx->set_order_position(w.order_position_next());
            }
            else
            {
                ptr_acentry->set_order_position(w.order_position_next());
            }
            
            order_position_offsets.push_back(order_position);

            if (ptr_acentry)
            {
                /**
                 * We have to write accounting to disk since we don't store
                 * it in memory.
                 */
                if (
                    write_accounting_entry(ptr_acentry->entry_number(),
                    *ptr_acentry) == false
                    )
                {
                    return error_load_fail;
                }
            }
        }
        else
        {
            std::int64_t order_position_off = 0;
            
            for (auto & i : order_position_offsets)
            {
                if (order_position >= i)
                {
                    ++order_position_off;
                }
            }
            
            if (ptr_wtx)
            {
                ptr_wtx->set_order_position(
                    ptr_wtx->order_position() + order_position_off
                );
            }
            else
            {
                ptr_acentry->set_order_position(
                    ptr_acentry->order_position() + order_position_off
                );
            }

            w.set_order_position_next(
                std::max(w.order_position_next(), order_position + 1)
            );
            
            if (order_position_off == 0)
            {
                continue;
            }
            
            /**
             * Since we're changing the order, write it back.
             */
            if (ptr_wtx)
            {
                if (write_tx(ptr_wtx->get_hash(), *ptr_wtx) == false)
                {
                    return error_load_fail;
                }
            }
            else
            {
                if (
                    write_accounting_entry(ptr_acentry->entry_number(),
                    *ptr_acentry) == false
                    )
                {
                    return error_load_fail;
                }
            }
        }
    }

    return error_load_ok;
}

bool db_wallet::backup(const wallet & w, const std::string & root_path)
{
    if (w.is_file_backed() == true)
    {
        /**
         * The path to the wallet file.
         */
        std::string path;
        
        /**
         * If the root path contains a "." then they must be passing in the
         * entire path (or at least the file name).
         */
        if (root_path.find(".") != std::string::npos)
        {
            /**
             * Use the name that was passed in.
             */
            path = root_path;
        }
        else
        {
            /**
             * Create a timestamped name.
             */
            path =
                root_path + "wallet." + std::to_string(std::time(0)) + ".dat"
            ;
        }
        
        /**
         * Lock the db_env mutex.
         */
        std::lock_guard<std::recursive_mutex> l1(
            stack_impl::get_db_env()->mutex_DbEnv()
        );
        
        if (
            stack_impl::get_db_env()->file_use_counts(
            ).count("wallet.dat") == 0 ||
            stack_impl::get_db_env()->file_use_counts(
            )["wallet.dat"] == 0
            )
        {
            /**
             * Close the database.
             */
            stack_impl::get_db_env()->close_Db("wallet.dat");
    
            /**
             * Checkpoint
             */
            stack_impl::get_db_env()->checkpoint_lsn("wallet.dat");
            
            /**
             * Erase use counts.
             */
            stack_impl::get_db_env()->file_use_counts().erase("wallet.dat");

            /**
             * Attempt to copy the wallet file.
             */
            if (
                filesystem::copy_file(filesystem::data_path() + "wallet.dat",
                path) == true
                )
            {
                log_info(
                    "Database wallet backed up wallet to " << path << "."
                );
                
                return true;
            }
        }
        else
        {
            log_warn(
                "Database wallet unable to perform backup, "
                "database is in use, try again later."
            );
        }
    }
    
    return false;
}

bool db_wallet::recover(
    db_env & env, const std::string & file_name, const bool & keys_only
    )
{
    // :TODO:
    
    return false;
}

bool db_wallet::recover(db_env & env, const std::string & file_name)
{
    return recover(env, file_name, false);
}

bool db_wallet::read_key_value(
    wallet & w, data_buffer & buffer_key,
    data_buffer & buffer_value, std::int32_t & file_version,
    std::vector<sha256> & wallet_upgrade, bool & is_encrypted,
    bool & any_unordered, std::string & type, std::string & err
    )
 {
    type.clear();
    type.resize(buffer_key.read_var_int());
    
    buffer_key.read_bytes(
        const_cast<char *> (type.data()), type.size()
    );

    if (type == "name")
    {
        std::string addr;
        
        auto len = buffer_key.read_var_int();
        
        if (len > 0)
        {
            addr.resize(len);
            
            buffer_key.read_bytes(
                const_cast<char *> (addr.data()), addr.size()
            );
        }
        
        std::string value;
        
        len = buffer_value.read_var_int();
        
        if (len > 0)
        {
            value.resize(len);
            
            buffer_value.read_bytes(
                const_cast<char *> (value.data()), value.size()
            );
        }
        
        w.address_book()[address(addr).get()] = value;
    }
    else if (type == "tx")
    {
        sha256 hash = buffer_key.read_sha256();

        auto & wtx = w.transactions()[hash];
        
        wtx.decode(buffer_value);

        if (wtx.check() && (wtx.get_hash() == hash))
        {
            wtx.bind_wallet(w);
        }
        else
        {
            w.transactions().erase(hash);
            
            return false;
        }

        /**
         * Undo serialize changes in 31600.
         */
        if (
            31404 <= wtx.time_received_is_tx_time() &&
            wtx.time_received_is_tx_time() <= 31703
            )
        {
            if (buffer_value.remaining() > 0)
            {
                char tmp;
                char unused;
                
                buffer_value.read_bytes(&tmp, sizeof(tmp));
                buffer_value.read_bytes(&unused, sizeof(unused));
                
                wtx.from_account().clear();
                wtx.from_account().resize(buffer_value.read_var_int());
                
                buffer_value.read_bytes(
                    const_cast<char *> (wtx.from_account().data()),
                    wtx.from_account().size()
                );
                
                wtx.set_time_received_is_tx_time(tmp);
            }
            else
            {
                wtx.set_time_received_is_tx_time(0);
            }
            
            wallet_upgrade.push_back(hash);
        }

        if (wtx.order_position() == -1)
        {
            any_unordered = true;
        }
    }
    else if (type == "acentry")
    {
        std::string acct;
        
        auto len = buffer_key.read_var_int();
        
        if (len > 0)
        {
            acct.resize(len);
            
            buffer_key.read_bytes(
                const_cast<char *> (acct.data()), acct.size()
            );
        }
        
        std::uint64_t entry_number = buffer_key.read_uint64();
        
        if (entry_number > g_accounting_entry_number)
        {
            g_accounting_entry_number = entry_number;
        }
        
        if (any_unordered == false)
        {
            accounting_entry entry;
            
            entry.decode(buffer_value);
            
            if (entry.order_position() == -1)
            {
                any_unordered = true;
            }
        }
    }
    else if (type == "key" || type == "wkey")
    {
        std::vector<std::uint8_t> pub_key;
        
        auto len_public_key = buffer_key.read_var_int();
        
        if (len_public_key > 0)
        {
            pub_key.resize(len_public_key);
            
            buffer_key.read_bytes(
                reinterpret_cast<char *>(&pub_key[0]), pub_key.size()
            );
        }
        
        key k;
        
        if (type == "key")
        {
            key::private_t pkey;
            
            auto len_private_key = buffer_value.read_var_int();
            
            if (len_private_key > 0)
            {
                pkey.resize(len_private_key);
                
                buffer_value.read_bytes(
                    reinterpret_cast<char *>(&pkey[0]), pkey.size()
                );
            }
            
            k.set_public_key(pub_key);
            
            if (k.set_private_key(pkey) == false)
            {
                err = "private key is corrupt";
                
                return false;
            }
            if (k.get_public_key() != pub_key)
            {
                err = "public key inconsistency";
                
                return false;
            }
            if (k.is_valid() == false)
            {
                err = "invalid private key";
                
                return false;
            }
        }
        else
        {
            key_wallet wkey;
            
            wkey.decode(buffer_value);
            
            k.set_public_key(pub_key);
            
            if (k.set_private_key(wkey.key_private()) == false)
            {
                err = "private key is corrupt";
                
                return false;
            }
            
            if (k.get_public_key() != pub_key)
            {
                err = "public key inconsistency";
                
                return false;
            }
            
            if (k.is_valid() == false)
            {
                err = "invalid wallet key";
                
                return false;
            }
        }
        
        if (w.load_key(k) == false)
        {
            err = "load key failed";
            
            return false;
        }
    }
    else if (type == "mkey")
    {
        auto id = buffer_key.read_uint32();
        
        key_wallet_master master_key;
        
        master_key.decode(buffer_value);
        
        if (w.master_keys().count(id) != 0)
        {
            err = "duplicate master key id " + std::to_string(id);
            
            return false;
        }
        
        w.master_keys()[id] = master_key;
        
        if (w.master_key_max_id() < id)
        {
            w.set_master_key_max_id(id);
        }
    }
    else if (type == "ckey")
    {
        std::vector<std::uint8_t> pub_key;
        
        auto len = buffer_key.read_var_int();
        
        if (len > 0)
        {
            pub_key.resize(len);
            buffer_key.read_bytes(
                reinterpret_cast<char *> (&pub_key[0]), pub_key.size()
            );
        }
        
        std::vector<std::uint8_t> pri_key;
        
        len = buffer_value.read_var_int();
        
        if (len > 0)
        {
            pri_key.resize(len);
            buffer_value.read_bytes(
                reinterpret_cast<char *> (&pri_key[0]), pri_key.size()
            );
        }
        
        if (w.load_crypted_key(pub_key, pri_key) == false)
        {
            err = "load crypted key failed";
            
            return false;
        }
        
        is_encrypted = true;
    }
    else if (type == "defaultkey")
    {
        /**
         * Allocate the default public key.
         */
        key_public key_public_default;

        /**
         * Decode the default public key.
         */
        if (key_public_default.decode(buffer_value))
        {
            /**
             * Set the default public key.
             */
            w.set_key_public_default(key_public_default);
        }
    }
    else if (type == "pool")
    {
        auto index = buffer_key.read_int64();
        
        w.get_key_pool().insert(index);
    }
    else if (type == "version")
    {
        file_version = buffer_value.read_uint32();
        
        if (file_version == 10300)
        {
            file_version = 300;
        }
    }
    else if (type == "cscript")
    {
        auto digest = buffer_key.read_bytes(ripemd160::digest_length);
    
        auto len = buffer_value.read_var_int();
        
        if (len > 0)
        {
            script s(len);
            
            buffer_value.read_bytes(reinterpret_cast<char *> (&s[0]), s.size());

            if (w.load_c_script(s) == false)
            {
                err = "load c script failed";
                
                return false;
            }
        }
    }
    else if (type == "orderposnext")
    {
        std::int64_t order_position_next = buffer_value.read_int64();
        
        w.set_order_position_next(order_position_next);
    }

    return true;
}

bool db_wallet::write_name(const std::string & addr, const std::string & name)
{
    m_wallet_updated++;
    
    return write(std::make_pair(std::string("name"), addr), name);
}

bool db_wallet::read_account(const std::string & name, account & acct)
{
    std::string key_prefix = "acc";
    
    data_buffer buffer;

    buffer.write_var_int(key_prefix.size());
    buffer.write_bytes(key_prefix.data(), key_prefix.size());
    buffer.write_var_int(name.size());
    buffer.write_bytes(name.data(), name.size());
    
    return read(buffer, acct);
}

bool db_wallet::write_account(const std::string & name, account & acct)
{
    if (m_Db == 0)
    {
        return false;
    }

    if (m_is_read_only)
    {
        assert(!"Write called on database in read-only mode!");
    }

    data_buffer key_data;
    
    std::string key_prefix = "acc";
    
    key_data.write_var_int(key_prefix.size());
    key_data.write((void *)key_prefix.data(), key_prefix.size());
    key_data.write_var_int(name.size());
    key_data.write((void *)name.data(), name.size());
    
    Dbt dat_key(
        (void *)key_data.data(), static_cast<std::uint32_t> (key_data.size())
    );
    
    data_buffer value_data;

    acct.encode(value_data);

    Dbt dat_value(
        (void *)value_data.data(),
        static_cast<std::uint32_t> (value_data.size())
    );

    auto ret = m_Db->put(m_DbTxn, &dat_key, &dat_value, 0);

    std::memset(dat_key.get_data(), 0, dat_key.get_size());
    std::memset(dat_value.get_data(), 0, dat_value.get_size());
    
    return ret == 0;
}

bool db_wallet::erase_tx(const sha256 & val)
{
    m_wallet_updated++;
    
    std::string key_prefix = "tx";
    
    data_buffer buffer;

    buffer.write_var_int(key_prefix.size());
    buffer.write_bytes(key_prefix.data(), key_prefix.size());
    
    buffer.write_sha256(val);
    
    return erase(buffer);
}

bool db_wallet::write_tx(const sha256 & val, transaction_wallet & tx_w)
{
    m_wallet_updated++;
    
    return write(std::make_pair(std::string("tx"), val), tx_w);
}

bool db_wallet::write_orderposnext(const std::int64_t & value)
{
    m_wallet_updated++;
    
    return write(std::string("orderposnext"), value);
}

bool db_wallet::write_defaultkey(const key_public & value)
{
    m_wallet_updated++;
    
    return write(std::string("defaultkey"), value.bytes());
}

bool db_wallet::write_key(
    const key_public & pub_key, const key::private_t & pri_key
    )
{
    m_wallet_updated++;
    
    return write(
        std::make_pair(std::string("key"), pub_key.bytes()), pri_key, false
    );
}

bool db_wallet::write_crypted_key(
    const key_public & pub_key,
    const std::vector<std::uint8_t> & crypted_secret,
    const bool & erase_unencrypted_key
    )
{
    m_wallet_updated++;
    
    if (
        write(std::make_pair(std::string("ckey"), pub_key.bytes()),
        crypted_secret, false) == false
        )
    {
        return false;
    }

    if (erase_unencrypted_key)
    {
        erase(std::make_pair(std::string("key"), pub_key.bytes()));
        erase(std::make_pair(std::string("wkey"), pub_key.bytes()));
    }

    return true;
}

bool db_wallet::write_master_key(
    const std::uint32_t & id, const key_wallet_master & key_master
    )
{
    m_wallet_updated++;
    
    return write(std::make_pair(std::string("mkey"), id), key_master, true);
}

bool db_wallet::write_c_script(const ripemd160 & h, const script & script_redeem)
{
    m_wallet_updated++;
    
    return write(
        std::make_pair(std::string("cscript"), h), script_redeem, false
    );
}

bool db_wallet::read_bestblock(block_locator & val)
{
    return read("bestblock", val);
}

bool db_wallet::write_bestblock(const block_locator & val)
{
    m_wallet_updated++;
    
    return write(std::string("bestblock"), val);
}

bool db_wallet::read_pool(const std::int64_t & pool, key_pool & keypool)
{    
    std::string key_prefix = "pool";
    
    data_buffer buffer;

    buffer.write_var_int(key_prefix.size());
    buffer.write_bytes(key_prefix.data(), key_prefix.size());
    buffer.write_int64(pool);
    
    return read(buffer, keypool);
}

bool db_wallet::write_pool(const std::int64_t & pool, key_pool & keypool)
{
    m_wallet_updated++;
    
    return write(std::make_pair(std::string("pool"), pool), keypool);
}

bool db_wallet::erase_pool(const std::int64_t & pool)
{
    m_wallet_updated++;

    std::string key_prefix = "pool";
    
    data_buffer buffer;

    buffer.write_var_int(key_prefix.size());
    buffer.write_bytes(key_prefix.data(), key_prefix.size());
    buffer.write_int64(pool);
    
    return erase(buffer);
}

bool db_wallet::write_minversion(const std::int32_t & value)
{
    return write(std::string("minversion"), value);
}

bool db_wallet::write_accounting_entry(
    const std::uint64_t & entry_number, accounting_entry & entry,
    const bool & overwrite
    )
{
    if (m_Db == 0)
    {
        return false;
    }

    if (m_is_read_only)
    {
        assert(!"Write called on database in read-only mode!");
    }

    data_buffer key_data;
    
    std::string key_prefix = "acentry";
    
    key_data.write_var_int(key_prefix.size());
    key_data.write((void *)key_prefix.data(), key_prefix.size());
    key_data.write_var_int(entry.account().size());
    key_data.write((void *)entry.account().data(), entry.account().size());
    key_data.write_uint64(entry_number);
    
    Dbt dat_key(
        (void *)key_data.data(), static_cast<std::uint32_t> (key_data.size())
    );
    
    data_buffer value_data;

    entry.encode(value_data);

    Dbt dat_value(
        (void *)value_data.data(),
        static_cast<std::uint32_t> (value_data.size())
    );

    auto ret = m_Db->put(
        m_DbTxn, &dat_key, &dat_value, overwrite ? 0 : DB_NOOVERWRITE
    );

    std::memset(dat_key.get_data(), 0, dat_key.get_size());
    std::memset(dat_value.get_data(), 0, dat_value.get_size());
    
    return ret == 0;
}

bool db_wallet::write_accounting_entry(accounting_entry & entry)
{
    return write_accounting_entry(++g_accounting_entry_number, entry);
}

std::int64_t db_wallet::get_account_credit_debit(const std::string & account)
{
    std::int64_t ret = 0;
    
    std::list<accounting_entry> entries;
    
    list_account_credit_debit(account, entries);

    for (auto & i : entries)
    {
        ret += i.credit_debit();
    }
    
    return ret;
}

void db_wallet::list_account_credit_debit(
    const std::string & account, std::list<accounting_entry> & entries
    )
{
    bool all_accounts = account == "*";

    auto ptr_cursor = get_cursor();
    
    if (ptr_cursor == 0)
    {
        throw std::runtime_error(
            "db_wallet::list_account_credit_debit() : cannot create DB cursor"
        );
    }
    else
    {
        std::uint32_t flags = DB_SET_RANGE;
        
        for (;;)
        {
            /**
             * Read next key.
             */
            data_buffer buffer_key;
            
            if (flags == DB_SET_RANGE)
            {
                buffer_key.write_var_int(strlen("acentry"));
                buffer_key.write_bytes("acentry", strlen("acentry"));
                
                if (all_accounts)
                {
                    buffer_key.write_var_int(0);
                }
                else
                {
                    buffer_key.write_var_int(account.size());
                    buffer_key.write_bytes(account.data(), account.size());
                }
                
                buffer_key.write_uint64(0);
            }
            
            /**
             * Read the value.
             */
            data_buffer buffer_value;
            
            /**
             * Read the next record.
             */
            auto ret = read_at_cursor(
                ptr_cursor, buffer_key, buffer_value, flags
            );
            
            flags = DB_NEXT;
            
            if (ret == DB_NOTFOUND)
            {
                break;
            }
            else if (ret != 0)
            {
                ptr_cursor->close();
            
                throw std::runtime_error(
                    "db_wallet::list_account_credit_debit() : error scanning DB"
                );
            }

            /**
             * Read the type.
             */
            std::string type(buffer_key.read_var_int(), 0);
            
            buffer_key.read_bytes(
                const_cast<char *> (type.data()), type.size()
            );

            if (type != "acentry")
            {
                break;
            }
            
            accounting_entry acentry;
            
            /**
             * Read the account.
             */
            acentry.account().resize(buffer_key.read_var_int());
            
            buffer_key.read_bytes(
                const_cast<char *> (acentry.account().data()),
                acentry.account().size()
            );
            
            if (all_accounts == false && acentry.account() != account)
            {
                break;
            }
            
            /**
             * Decode the entry.
             */
            acentry.decode(buffer_value);
            
            /**
             * Read and set the entry number.
             */
            acentry.set_entry_number(buffer_key.read_uint64());
            
            /**
             * Retain the entry.
             */
            entries.push_back(acentry);
        }

        ptr_cursor->close();
    }
}

bool db_wallet::is_key_type(const std::string & type)
{
    return
        type == "key" || type == "wkey" || type == "mkey" || type == "ckey"
    ;
}
