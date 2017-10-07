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

/**
 * Workaround bug in gcc 4.7:  https://gcc.gnu.org/bugzilla/show_bug.cgi?id=52680
 */
#if (defined __linux__)
#define _GLIBCXX_USE_NANOSLEEP 1
#endif // __linux__

#include <thread>

#include <coin/db.hpp>
#include <coin/db_env.hpp>
#include <coin/stack_impl.hpp>
#include <coin/utility.hpp>

using namespace coin;

db::db(const std::string & file_name, const std::string & file_mode
    )
    : m_is_read_only(false)
    , m_file_name(file_name)
    , m_Db(0)
    , m_DbTxn(0)
    , state_(state_none)
{
    int ret;

    m_is_read_only = (
        !strchr(file_mode.c_str(), '+') && !strchr(file_mode.c_str(), 'w')
    );
    
    auto db_create = strchr(file_mode.c_str(), 'c');
    
    std::int32_t flags = DB_THREAD;
    
    if (db_create)
    {
        flags |= DB_CREATE;
    }
    
    /**
     * Make sure no other threads can access the db_env for this scope.
     */
    std::lock_guard<std::recursive_mutex> l1(db_env::mutex_DbEnv());
    
    if (stack_impl::get_db_env()->open() == false)
    {
        throw std::runtime_error("database environment failed to open");
    }

    ++stack_impl::get_db_env()->file_use_counts()[m_file_name];
    
    m_Db = stack_impl::get_db_env()->Dbs()[m_file_name];
    
    if (m_Db == 0)
    {
        m_Db = new Db(&stack_impl::get_db_env()->get_DbEnv(), 0);
        
        ret = m_Db->open(
            0, file_name.c_str(), "main", DB_BTREE, flags, 0
        );

        if (ret != 0)
        {
            delete m_Db, m_Db = 0;
            
            --stack_impl::get_db_env()->file_use_counts()[m_file_name];
            
            m_file_name = "";

            throw std::runtime_error(
                "failed to open database file " + file_name + ", ret = " +
                std::to_string(ret)
            );
        }
        
        if (db_create && exists("version") == false)
        {
            auto tmp = m_is_read_only;
            
            m_is_read_only = false;
            
            write_version(constants::version_client);
            
            m_is_read_only = tmp;
        }

        stack_impl::get_db_env()->Dbs()[file_name] = m_Db;
    }

    /**
     * Set state to state_opened.
     */
    state_ = state_opened;
}

db::~db()
{
    if (state_ == state_opened)
    {
        close();
    }
}

void db::close()
{
    if (m_Db && state_ == state_opened)
    {
        /**
         * Set state to state_closed.
         */
        state_ = state_closed;
        
        if (m_DbTxn)
        {
            m_DbTxn->abort(), m_DbTxn = 0;
        }
        
        m_Db = 0;
        
        /**
         * Flush database activity from memory pool to disk log.
         */
        auto minutes = 0;

        if (m_is_read_only)
        {
            minutes = 1;
        }
        
        if (utility::is_chain_file(m_file_name))
        {
            minutes = 2;
        }
        
        if (
            utility::is_chain_file(m_file_name) &&
            utility::is_initial_block_download()
            )
        {
            minutes = 5;
        }

        /**
         * Make sure no other threads can access the db_env for this scope.
         */
        std::lock_guard<std::recursive_mutex> l1(db_env::mutex_DbEnv());
    
        if (stack_impl::get_db_env())
        {
            /**
             * -dblogsize
             */
            stack_impl::get_db_env()->get_DbEnv().txn_checkpoint(
                minutes ? 100 * 1024 : 0, minutes, 0
            );

            --stack_impl::get_db_env()->file_use_counts()[m_file_name];
        }
    }
}

Db & db::get_Db()
{
    return *m_Db;
}

Dbc * db::get_cursor()
{
    if (m_Db)
    {
        Dbc * ptr_cursor = 0;
        
        auto ret = m_Db->cursor(0, &ptr_cursor, 0);
        
        if (ret != 0)
        {
            return 0;
        }
        
        return ptr_cursor;
    }

    return 0;
}

int db::read_at_cursor(
    Dbc * ptr_cursor, data_buffer & key, data_buffer & value,
    const std::int32_t flags
    )
{
    Dbt datKey;
    
    if (
        flags == DB_SET || flags == DB_SET_RANGE || flags == DB_GET_BOTH ||
        flags == DB_GET_BOTH_RANGE
        )
    {
        datKey.set_data(key.data());
        datKey.set_size(static_cast<std::uint32_t> (key.size()));
    }
    
    Dbt datValue;
    
    if (flags == DB_GET_BOTH || flags == DB_GET_BOTH_RANGE)
    {
        datValue.set_data(value.data());
        datValue.set_size(static_cast<std::uint32_t> (value.size()));
    }
    
    datKey.set_flags(DB_DBT_MALLOC);
    datValue.set_flags(DB_DBT_MALLOC);
    
    int ret = ptr_cursor->get(&datKey, &datValue, flags);
    
    if (ret != 0)
    {
        return ret;
    }
    else if (datKey.get_data() == 0 || datValue.get_data() == 0)
    {
        return 99999;
    }

    key.clear();
    key.write(reinterpret_cast<char *>(datKey.get_data()), datKey.get_size());
    
    value.clear();
    value.write(
        reinterpret_cast<char *>(datValue.get_data()), datValue.get_size()
    );

    std::memset(datKey.get_data(), 0, datKey.get_size());
    std::memset(datValue.get_data(), 0, datValue.get_size());
    
    free(datKey.get_data());
    free(datValue.get_data());
    
    return 0;
}

bool db::txn_begin()
{
    if (m_Db == 0 || m_DbTxn)
    {
        return false;
    }
    
    auto ptxn = stack_impl::get_db_env()->txn_begin();
    
    if (ptxn == 0)
    {
        return false;
    }
    
    m_DbTxn = ptxn;
    
    return true;
}

bool db::txn_commit()
{
    if (m_Db == 0 || m_DbTxn == 0)
    {
        return false;
    }
    
    auto ret = m_DbTxn->commit(0);
    
    m_DbTxn = 0;
    
    return ret == 0;
}

bool db::txn_abort()
{
    if (m_Db == 0 || m_DbTxn == 0)
    {
        return false;
    }
    
    auto ret = m_DbTxn->abort();
    
    m_DbTxn = 0;
    
    return ret == 0;
}

bool db::rewrite(const std::string & file_name, const char * key_skip)
{
    while (globals::instance().state() < globals::state_stopping)
    {
        if (
            stack_impl::get_db_env()->file_use_counts().count(file_name) == 0 ||
            stack_impl::get_db_env()->file_use_counts()[file_name] == 0
            )
        {
            stack_impl::get_db_env()->close_Db(file_name);
            stack_impl::get_db_env()->checkpoint_lsn(file_name);
            stack_impl::get_db_env()->file_use_counts().erase(file_name);

            auto success = true;
            
            log_debug("DB is rewriting " << file_name << ".");
            
            std::string file_name_tmp = file_name + ".tmp";
            
            db d(file_name.c_str(), "r");
            
            Db * ptr_Db_copy = new Db(
                &stack_impl::get_db_env()->get_DbEnv(), 0
            );

            auto ret = ptr_Db_copy->open(
                0, file_name_tmp.c_str(), "main", DB_BTREE, DB_CREATE, 0
            );
            
            if (ret > 0)
            {
                log_error(
                    "DB is failed copying database " << file_name_tmp << "."
                );
                
                success = false;
            }

            auto ptr_cursor = d.get_cursor();
           
            if (ptr_cursor)
            {
                while (success)
                {
                    /**
                     * Read the next record.
                     */
                    data_buffer key, value;
                    
                    auto ret = d.read_at_cursor(
                        ptr_cursor, key, value, DB_NEXT
                    );

                    if (ret == DB_NOTFOUND)
                    {
                        ptr_cursor->close();
                        
                        break;
                    }
                    else if (ret != 0)
                    {
                        ptr_cursor->close();
                        
                        success = false;
                        
                        break;
                    }
                    
                    if (
                        key_skip && std::strncmp(key.data(), key_skip,
                        (std::min)(key.size(), std::strlen(key_skip))) == 0
                        )
                    {
                        continue;
                    }
                    
                    /**
                     * Check if the version needs to be updated.
                     */
                    if (std::strncmp(key.data(), "\x07version", 8) == 0)
                    {
                        value.clear();
                        
                        /**
                         * Write the version.
                         */
                        value.write_uint32(constants::version_client);
                    }
                    
                    Dbt dbt_key(
                        key.data(), static_cast<std::uint32_t> (key.size())
                    );
                    
                    Dbt dbt_value(
                        value.data(), static_cast<std::uint32_t> (value.size())
                    );

                    auto ret2 = ptr_Db_copy->put(
                        0, &dbt_key, &dbt_value, DB_NOOVERWRITE
                    );
                    
                    if (ret2 > 0)
                    {
                        success = false;
                    }
                }
            }
            
            if (success)
            {
                d.close();
                
                stack_impl::get_db_env()->close_Db(file_name);
                
                if (ptr_Db_copy->close(0))
                {
                    success = false;
                }
                
                delete ptr_Db_copy;
            }
            
            if (success)
            {
                Db dbA(&stack_impl::get_db_env()->get_DbEnv(), 0);
                
                if (dbA.remove(file_name.c_str(), 0, 0))
                {
                    success = false;
                }
                
                Db dbB(&stack_impl::get_db_env()->get_DbEnv(), 0);
                
                if (
                    dbB.rename(file_name_tmp.c_str(), 0, file_name.c_str(), 0)
                    )
                {
                    success = false;
                }
            }
            
            if (success == false)
            {
                log_error("DB rewrite " << file_name_tmp << " failed.");
            }

            return success;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return false;
}

const std::string & db::file_name() const
{
    return m_file_name;
}

bool db::write_version(const std::int32_t & version)
{
    return write(std::string("version"), version);
}
