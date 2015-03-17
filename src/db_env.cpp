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

using namespace coin;

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

bool db_env::open(const std::string & data_path)
{
    if (state_ == state_closed)
    {
        filesystem::create_path(data_path);
        
        auto log_path = data_path + "/database";
        
        filesystem::create_path(log_path);
        
        auto errfile_path = data_path + "/db.log";
        
        std::int32_t flags =
            DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL |
            DB_INIT_TXN | DB_THREAD | DB_RECOVER
        ;

        auto cache = 25;
        
        std::lock_guard<std::recursive_mutex> l1(m_mutex_DbEnv);
        
        m_DbEnv.set_lg_dir(log_path.c_str());
        m_DbEnv.set_cachesize(cache / 1024, (cache % 1024) * 1048576, 1);
        m_DbEnv.set_lg_bsize(1048576);
        m_DbEnv.set_lg_max(10485760);
        m_DbEnv.set_lk_max_locks(10000);
        m_DbEnv.set_lk_max_objects(10000);
        m_DbEnv.set_errfile(fopen(errfile_path.c_str(), "a"));
        m_DbEnv.set_flags(DB_AUTO_COMMIT, 1);
        m_DbEnv.set_flags(DB_TXN_WRITE_NOSYNC, 1);

        auto ret = m_DbEnv.open(data_path.c_str(), flags, S_IRUSR | S_IWUSR);
        
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
        
        std::lock_guard<std::recursive_mutex> l1(m_mutex_DbEnv);
        
        auto ret = m_DbEnv.close(0);
        
        if (ret != 0)
        {
            log_error(
                "Database environment closed failed, error = " <<
                DbEnv::strerror(ret) << "."
            );
        }
        
        std::string data_path = filesystem::data_path();
        
        DbEnv(0).remove(data_path.c_str(), 0);
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

    std::lock_guard<std::recursive_mutex> l1(m_mutex_DbEnv);
    
    int ret = m_DbEnv.dbremove(0, file_name.c_str(), 0, DB_AUTO_COMMIT);
    
    return ret == 0;
}

bool db_env::verify(const std::string & file_name)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
    
    assert(m_file_use_counts.count(file_name) == 0);

    std::lock_guard<std::recursive_mutex> l2(m_mutex_DbEnv);
    
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

    std::lock_guard<std::recursive_mutex> l2(m_mutex_DbEnv);
    
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
    std::lock_guard<std::recursive_mutex> l2(m_mutex_DbEnv);
    
    m_DbEnv.txn_checkpoint(0, 0, 0);

    m_DbEnv.lsn_reset(file_name.c_str(), 0);
}

void db_env::flush()
{
    if (state_ == state_opened)
    {
        globals::instance().io_service().post(globals::instance().strand().wrap(
            [this]()
        {
            std::lock_guard<std::recursive_mutex> l1(mutex_file_use_counts_);
            
            auto it = m_file_use_counts.begin();
            
            while (it != m_file_use_counts.end())
            {
                auto file_name = it->first;
                
                auto reference_count = it->second;
                
                log_debug(
                    "Db Env " << file_name << ", reference count = " <<
                    reference_count << "."
                );

                if (reference_count == 0)
                {
                    /**
                     * Move the log data to the dat file.
                     */
                    close_Db(file_name);

                    log_debug("Db Env checkpoint " << file_name << ".");
                    
                    std::lock_guard<std::recursive_mutex> l2(m_mutex_DbEnv);
                    
                    m_DbEnv.txn_checkpoint(0, 0, 0);
                    
                    static bool detach_db = true;
                    
                    if (
                        utility::is_chain_file(file_name) == false || detach_db
                        )
                    {
                        log_debug("Db Env detach " << file_name << ".");

                        m_DbEnv.lsn_reset(file_name.c_str(), 0);
                    }

                    log_debug("Db Env closed " << file_name << ".");
                    
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
                    
                    std::lock_guard<std::recursive_mutex> l3(m_mutex_DbEnv);
                    
                    m_DbEnv.log_archive(&list, DB_ARCH_REMOVE);
                    
                    close_DbEnv();
                }
            }
        }));
    }
}

DbEnv & db_env::get_DbEnv()
{
    std::lock_guard<std::recursive_mutex> l1(m_mutex_DbEnv);
    
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
    return m_mutex_DbEnv;
}

DbTxn * db_env::txn_begin(int flags)
{
    DbTxn * ptr = 0;
    
    std::lock_guard<std::recursive_mutex> l1(m_mutex_DbEnv);
    
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
