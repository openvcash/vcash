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

#if (defined _MSC_VER)
#ifndef S_IRUSR
#define S_IRUSR 0400
#define S_IWUSR 0200
#endif // S_IRUSR
#else
#include <sys/stat.h>
#endif // _MSC_VER

#include <cassert>
#include <sstream>

#include <coin/db_env.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/utility.hpp>

static void errcall(const DbEnv *, const char * arg1, const char * arg2)
{
    if (arg1 && arg2)
    {
        log_error(
            "Database environment, arg1 = " << arg1 << ", arg2 = " << arg2
        );
    }
    
    if (arg1)
    {
        log_error("Database environment, arg1 = " << arg1 << ".");
    }

    if (arg2)
    {
        log_error("Database environment, arg2 = " << arg2 << ".");
    }
}

using namespace coin;

std::recursive_mutex db_env::g_mutex_DbEnv;

db_env::db_env()
    : m_DbEnv(DB_CXX_NO_EXCEPTIONS)
    , state_(state_closed)
{
    // ...
}

db_env::~db_env()
{
    close_DbEnv();
}

bool db_env::open(const std::int32_t & cache_size)
{
    if (state_ == state_closed)
    {
        auto data_path = filesystem::data_path();
        
        filesystem::create_path(data_path);
        
        auto log_path = data_path + "database";
        
        log_info("Database environment log path = " << log_path << ".");
        
        filesystem::create_path(log_path);

        log_info("Database environment cache size = " << cache_size << ".");

#if (defined _MSC_VER)
        std::wstring w_data_path = filesystem::w_data_path();
        std::wstring w_log_path = w_data_path + L"database";
#endif

        std::int32_t flags = 0;
        
        flags |=
            DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL |
            DB_INIT_TXN | DB_THREAD | DB_RECOVER
        ;

        if (globals::instance().is_client_spv() == true)
        {
            flags |= DB_PRIVATE;
        }
        else if (globals::instance().db_private() == true)
        {
            flags |= DB_PRIVATE;
        }
        
        std::lock_guard<std::recursive_mutex> l1(g_mutex_DbEnv);
        
        /**
         * set_lg_dir
         */
#if (defined _MSC_VER)
        int t_len = WideCharToMultiByte(CP_UTF8, 0, &w_log_path[0], (int)w_log_path.size(), NULL, 0, NULL, NULL);
        std::string utf8_log_path(t_len, 0);
        WideCharToMultiByte(CP_UTF8, 0, &w_log_path[0], (int)w_log_path.size(), &utf8_log_path[0], t_len, NULL, NULL);
        m_DbEnv.set_lg_dir(utf8_log_path.c_str());
#else
        m_DbEnv.set_lg_dir(log_path.c_str());
#endif
        
        /**
         * Configure according to the cache size.
         */
        if (cache_size == 1)
        {
            m_DbEnv.set_cachesize(0, 0x100000, 1);
            m_DbEnv.set_lg_bsize(0x10000);
            m_DbEnv.set_lg_max(1048576);
            m_DbEnv.set_lk_max_locks(10000);
            m_DbEnv.set_lk_max_objects(10000);
        }
        else
        {
            m_DbEnv.set_cachesize(
                cache_size / 1024, (cache_size % 1024) * 1048576, 1
            );
            m_DbEnv.set_lg_bsize(1048576);
            m_DbEnv.set_lg_max(10485760);
            m_DbEnv.set_lk_max_locks(537000);
            m_DbEnv.set_lk_max_objects(10000);
        }
        
        m_DbEnv.set_errfile(0);
        m_DbEnv.set_errcall(&errcall);
        m_DbEnv.set_flags(DB_AUTO_COMMIT, 1);
        m_DbEnv.set_flags(DB_TXN_WRITE_NOSYNC, 1);
        m_DbEnv.log_set_config(DB_LOG_AUTO_REMOVE, 1);

#if (defined _MSC_VER)
        int t_len_2 = WideCharToMultiByte(CP_UTF8, 0, &w_data_path[0], (int)w_data_path.size(), NULL, 0, NULL, NULL);
        std::string utf8_data_path(t_len_2, 0);
        WideCharToMultiByte(CP_UTF8, 0, &w_data_path[0], (int)w_data_path.size(), &utf8_data_path[0], t_len_2, NULL, NULL);
        auto ret = m_DbEnv.open(utf8_data_path.c_str(), flags, S_IRUSR | S_IWUSR);
#else
        auto ret = m_DbEnv.open(data_path.c_str(), flags, S_IRUSR | S_IWUSR);
#endif
        
        if (ret != 0)
        {
            log_error(
                "Database environment open failed, error = " <<
                DbEnv::strerror(ret) << "."
            );
        }
        else
        {
            state_ = state_opened;
        }

        return ret == 0;
    }
    else if (state_ == state_opened)
    {
        return true;
    }
    
    return false;
}

void db_env::close_DbEnv()
{
    if (state_ == state_opened)
    {
        state_ = state_closed;
        
        std::lock_guard<std::recursive_mutex> l1(g_mutex_DbEnv);
        
        auto ret = m_DbEnv.close(0);
        
        if (ret != 0)
        {
            log_error(
                "Database environment closed failed, error = " <<
                DbEnv::strerror(ret) << "."
            );
        }
        
        auto data_path = filesystem::data_path();
        
        DbEnv(0).remove(data_path.c_str(), 0);
        
        std::lock_guard<std::recursive_mutex> l2(mutex_file_use_counts_);
        
        m_file_use_counts.clear();
    }
}

void db_env::close_Db(const std::string & file_name)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_m_Dbs_);
    
    auto & ptr_Db = m_Dbs[file_name];
    
    if (ptr_Db)
    {
        ptr_Db->close(0);
        
        delete ptr_Db, ptr_Db = 0;
    }
}

bool db_env::remove_Db(const std::string & file_name)
{
    this->close_Db(file_name);

    std::lock_guard<std::recursive_mutex> l1(g_mutex_DbEnv);
    
    int ret = m_DbEnv.dbremove(0, file_name.c_str(), 0, DB_AUTO_COMMIT);
    
    return ret == 0;
}

bool db_env::verify(const std::string & file_name)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
    
    assert(m_file_use_counts.count(file_name) == 0);

    std::lock_guard<std::recursive_mutex> l2(g_mutex_DbEnv);
    
    Db db(&m_DbEnv, 0);
    
    auto result = db.verify(file_name.c_str(), 0, 0, 0);

    return result == 0;
}

bool db_env::salvage(
    const std::string & file_name, const bool & aggressive,
    std::vector< std::pair< std::vector<std::uint8_t>,
    std::vector<std::uint8_t> > > & result
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
    
    assert(m_file_use_counts.count(file_name) == 0);

    std::lock_guard<std::recursive_mutex> l2(g_mutex_DbEnv);
    
    std::uint32_t flags = DB_SALVAGE;
    
    if (aggressive)
    {
        flags |= DB_AGGRESSIVE;
    }
    
    std::stringstream dump;

    Db db(&m_DbEnv, 0);
    
    int ret = db.verify(file_name.c_str(), 0, &dump, flags);
    
    if (ret != 0)
    {
        log_error("Database environment salvage failed.");
        
        return false;
    }

    std::string line;
    
    while (dump.eof() == false && line != "HEADER=END")
    {
        getline(dump, line);
    }
    
    std::string key, value;
    
    while (dump.eof() == false && key != "DATA=END")
    {
        getline(dump, key);

        if (key != "DATA=END")
        {
            getline(dump, value);

            result.push_back(
                std::make_pair(utility::from_hex(key),
                utility::from_hex(value))
            );
        }
    }

    return ret == 0;
}

void db_env::checkpoint_lsn(const std::string & file_name)
{
    std::lock_guard<std::recursive_mutex> l2(g_mutex_DbEnv);
    
    m_DbEnv.txn_checkpoint(0, 0, 0);

    m_DbEnv.lsn_reset(file_name.c_str(), 0);
}

void db_env::flush(const bool & detach_db)
{
    if (state_ == state_opened)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
        
        auto it = m_file_use_counts.begin();
        
        while (it != m_file_use_counts.end())
        {
            auto file_name = it->first;
            
            auto reference_count = it->second;
            
            log_info(
                "Database environment " << file_name <<
                ", reference count = " << reference_count << "."
            );

            if (reference_count == 0)
            {
                /**
                 * Move the log data to the dat file.
                 */
                close_Db(file_name);

                log_info(
                    "Database environment checkpoint " << file_name << "."
                );
                
                std::lock_guard<std::recursive_mutex> l2(g_mutex_DbEnv);
                
                m_DbEnv.txn_checkpoint(0, 0, 0);
                
                if (
                    utility::is_chain_file(file_name) == false || detach_db
                    )
                {
                    log_info(
                        "Database environment detach " << file_name << "."
                    );

                    m_DbEnv.lsn_reset(file_name.c_str(), 0);
                }

                log_info("Database environment closed " << file_name << ".");
                
                m_file_use_counts.erase(it++);
            }
            else
            {
                it++;
            }
        }
        
        if (globals::instance().state() > globals::state_started)
        {
            if (m_file_use_counts.empty())
            {
                char ** list;
                
                std::lock_guard<std::recursive_mutex> l3(g_mutex_DbEnv);
                
                m_DbEnv.log_archive(&list, DB_ARCH_REMOVE);
                
                close_DbEnv();
            }
        }
    }
}

DbEnv & db_env::get_DbEnv()
{
    std::lock_guard<std::recursive_mutex> l1(g_mutex_DbEnv);
    
    return m_DbEnv;
}

std::map<std::string, std::uint32_t> & db_env::file_use_counts()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
    
    return m_file_use_counts;
}

std::map<std::string, Db *> & db_env::Dbs()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_m_Dbs_);
    
    return m_Dbs;
}

std::recursive_mutex & db_env::mutex_DbEnv()
{
    return g_mutex_DbEnv;
}

DbTxn * db_env::txn_begin(int flags)
{
    DbTxn * ptr = 0;
    
    std::lock_guard<std::recursive_mutex> l1(g_mutex_DbEnv);
    
    int ret = m_DbEnv.txn_begin(0, &ptr, flags);
    
    if (ret == ENOMEM)
    {
        log_debug("Database environment txn_begin failed, ENOMEM.");
    
        return 0;
    }
    else if (ret != 0)
    {
        return 0;
    }
    
    return ptr;
}
