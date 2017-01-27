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

#ifndef COIN_DB_HPP
#define COIN_DB_HPP

#include <cstdint>
#include <mutex>
#include <string>

#include <db_cxx.h>

#include <boost/noncopyable.hpp>

#include <coin/data_buffer.hpp>
#include <coin/key_pool.hpp>
#include <coin/key_wallet_master.hpp>
#include <coin/logger.hpp>
#include <coin/ripemd160.hpp>

namespace coin {
    
    /**
     * Implements a berkley database Db object wrapper.
     */
    class db : private boost::noncopyable
    {
        public:
        
            /**
             * Constructor
             * @param file_name The file name.
             * @param file_mode The file mode.
             */
            db(const std::string & file_name, const std::string & file_mode);
        
            /**
             * Destructor
             */
            ~db();
        
            /**
             * Closes the Db.
             */
            void close();
        
            /**
             * The Db.
             */
            Db & get_Db();
        
            /**
             * Gets the cursor.
             */
            Dbc * get_cursor();
        
            /**
             * read_at_cursor
             * @param ptr_cursor A pointer to the Dbc object.
             * @param key The key.
             * @param value The value.
             * @param flags The flags.
             */
            int read_at_cursor(
                Dbc * ptr_cursor, data_buffer & key, data_buffer & value,
                const std::int32_t flags = DB_NEXT
            );
        
            /**
             * txn_begin
             */
            bool txn_begin();

            /**
             * txn_commit
             */
            bool txn_commit();

            /**
             * txn_abort
             */
            bool txn_abort();
    
            /**
             * Reads a key/value pair.
             * @param key The key.
             * @param value The value.
             */
            template<typename T>
            bool read(const data_buffer & key, T & value)
            {
                if (m_Db == 0)
                {
                    return false;
                }
                
                Dbt dbt_key(
                    key.data(), static_cast<std::uint32_t> (key.size())
                );

                Dbt dbt_value;
                
                dbt_value.set_flags(DB_DBT_MALLOC);
                
                auto ret = m_Db->get(m_DbTxn, &dbt_key, &dbt_value, 0);
                
                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                if (dbt_value.get_data() == 0)
                {
                    return false;
                }
                
                try
                {
                    /**
                     * Allocate the data_buffer.
                     */
                    data_buffer buffer(
                        static_cast<char *>(dbt_value.get_data()),
                        dbt_value.get_size()
                    );
                    
                    /**
                     * Decode the value from the buffer.
                     */
                    value.decode(buffer);
                }
                catch (std::exception & e)
                {
                    log_error("DB read failed, what = " << e.what() << ".");
                    
                    return false;
                }

                std::memset(dbt_value.get_data(), 0, dbt_value.get_size());
                
                free(dbt_value.get_data());
                
                return ret == 0;
            }
        
            /**
             * Reads a key/value pair.
             * @param key The key.
             * @param value The value.
             */
            template<typename T>
            bool read(const std::string & key, T & value)
            {
                if (m_Db == 0)
                {
                    return false;
                }
                
                Dbt dbt_key(
                    const_cast<char *> (key.data()),
                    static_cast<std::uint32_t> (key.size())
                );

                Dbt dbt_value;
                
                dbt_value.set_flags(DB_DBT_MALLOC);
                
                auto ret = m_Db->get(m_DbTxn, &dbt_key, &dbt_value, 0);
                
                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                if (dbt_value.get_data() == 0)
                {
                    return false;
                }
                
                try
                {
                    /**
                     * Allocate the data_buffer.
                     */
                    data_buffer buffer(
                        static_cast<char *>(dbt_value.get_data()),
                        dbt_value.get_size()
                    );
                    
                    /**
                     * Decode the value from the buffer.
                     */
                    value.decode(buffer);
                }
                catch (std::exception & e)
                {
                    log_error("DB read failed, what = " << e.what() << ".");
                    
                    return false;
                }

                std::memset(dbt_value.get_data(), 0, dbt_value.get_size());
                
                free(dbt_value.get_data());
                
                return ret == 0;
            }
        
            /**
             * Reads a key/value pair.
             * @param key The key.
             * @param value The value.
             */
            bool read(const std::string & key, std::int32_t & value)
            {
                if (m_Db == 0)
                {
                    return false;
                }
                
                Dbt dbt_key(
                    const_cast<char *> (key.data()),
                    static_cast<std::uint32_t> (key.size())
                );

                Dbt dbt_value;
                
                dbt_value.set_flags(DB_DBT_MALLOC);
                
                auto ret = m_Db->get(m_DbTxn, &dbt_key, &dbt_value, 0);
                
                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                if (dbt_value.get_data() == 0)
                {
                    return false;
                }
                
                try
                {
                    assert(dbt_value.get_size() == sizeof(std::int32_t));
                    
                    std::memcpy(
                        &value, dbt_value.get_data(), dbt_value.get_size()
                    );
                }
                catch (std::exception & e)
                {
                    log_error("DB read failed, what = " << e.what() << ".");
                    
                    return false;
                }

                std::memset(dbt_value.get_data(), 0, dbt_value.get_size());
                
                free(dbt_value.get_data());
                
                return ret == 0;
            }

            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write(
                const std::pair<std::string, std::string> & key,
                const std::string & value,
                const bool & overwrite = true
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
                
                auto k1 = key.first;
                auto k2 = key.second;

                data_buffer key_data;

                key_data.reserve(1000);
                
                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_var_int(k2.size());
                key_data.write_bytes(k2.data(), k2.size());

                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value_data.write_var_int(value.size());
                value_data.write_bytes(value.data(), value.size());

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
            
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
                
                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;
                
                key_data.reserve(1000);

                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_sha256(k2);
                
                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value.encode(value_data);

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1>
            bool write(
                const std::pair<std::string, std::int64_t> & key, T1 & value,
                const bool & overwrite = true
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
                
                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;

                key_data.reserve(1000);
                
                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_int64(k2);
                
                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value.encode(value_data);

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }

            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1>
            bool write(
                const std::pair<std::string, std::uint32_t> & key, T1 & value,
                const bool & overwrite = true
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
                
                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;

                key_data.reserve(1000);
                
                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_uint32(k2);
                
                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value.encode(value_data);

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write(
                const std::pair<std::string, ripemd160> & key,
                const std::vector<std::uint8_t> & value,
                const bool & overwrite = true
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
                
                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;

                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_bytes(
                    reinterpret_cast<char *>(&k2.digest()[0]),
                    ripemd160::digest_length
                );
                
                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.write_var_int(value.size());
                value_data.write_bytes(
                    reinterpret_cast<const char *>(&value[0]), value.size()
                );

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write(
                const std::pair<std::string, std::vector<std::uint8_t> > & key,
                const std::vector<std::uint8_t> & value,
                const bool & overwrite = true
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
                
                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;

                key_data.reserve(1000);
                
                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_var_int(k2.size());
                key_data.write_bytes(
                    reinterpret_cast<char *>(&k2[0]), k2.size()
                );
                
                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value_data.write_var_int(value.size());
                value_data.write_bytes(
                    reinterpret_cast<const char *>(&value[0]), value.size()
                );

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
        
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            bool write(
                const std::string & key, const std::vector<std::uint8_t> & value,
                const bool & overwrite = true
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

                key_data.reserve(1000);
                
                key_data.write_var_int(key.size());
                key_data.write((void *)key.data(), key.size());

                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );
                
                data_buffer value_data;

                value_data.reserve(10000);
                
                value_data.write_var_int(value.size());
                value_data.write_bytes(
                    reinterpret_cast<const char *>(&value[0]), value.size()
                );

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
            
            /**
             * Writes a key/value pair.
             * @param key The key.
             * @param value The value.
             * @param overwrite If true an existing value will be overwritten.
             */
            template<typename T1>
            bool write(
                const std::string & key, const T1 & value,
                const bool & overwrite = true
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

                key_data.reserve(1000);
                
                key_data.write_var_int(key.size());
                key_data.write((void *)key.data(), key.size());

                Dbt dat_key(
                    (void *)key_data.data(),
                    static_cast<std::uint32_t> (key_data.size())
                );

                data_buffer value_data;

                value_data.reserve(10000);
                
                value_data.write(
                    const_cast<void *> (static_cast<const void *> (&value)),
                    sizeof(value)
                );

                Dbt dat_value(
                    (void *)value_data.data(),
                    static_cast<std::uint32_t> (value_data.size())
                );

                auto ret = m_Db->put(
                    m_DbTxn, &dat_key, &dat_value, overwrite ?
                    0 : DB_NOOVERWRITE
                );

                std::memset(dat_key.get_data(), 0, dat_key.get_size());
                std::memset(dat_value.get_data(), 0, dat_value.get_size());
                
                return ret == 0;
            }
    
            /**
             * Erase the given key.
             * @param key The data_buffer.
             */
            bool erase(const data_buffer & key) const
            {
                if (m_Db == 0)
                {
                    return false;
                }

                Dbt dbt_key(
                    key.data(), static_cast<std::uint32_t> (key.size())
                );

                auto ret = m_Db->del(m_DbTxn, &dbt_key, 0);

                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                return ret == 0 || ret == DB_NOTFOUND;
            }
        
            /**
             * Erase the given key.
             * @param key The std::pair.
             */
            bool erase(
                const std::pair<std::string, std::vector<std::uint8_t> > & key
                ) const
            {
                if (m_Db == 0)
                {
                    return false;
                }

                auto k1 = key.first;
                auto k2 = key.second;
                
                data_buffer key_data;
                
                key_data.reserve(1000);

                key_data.write_var_int(k1.size());
                key_data.write_bytes(k1.data(), k1.size());
                key_data.write_var_int(k2.size());
                key_data.write_bytes(
                    reinterpret_cast<char *>(&k2[0]), k2.size()
                );
                
                Dbt dbt_key(
                    key_data.data(), static_cast<std::uint32_t> (key_data.size())
                );

                auto ret = m_Db->del(m_DbTxn, &dbt_key, 0);

                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                return ret == 0 || ret == DB_NOTFOUND;
            }
    
            /**
             * Checks if the key exists.
             * @param key The data_buffer.
             */
            bool exists(const data_buffer & key)
            {
                if (m_Db == 0)
                {
                    return false;
                }
                
                Dbt dbt_key(
                    key.data(), static_cast<std::uint32_t> (key.size())
                );

                auto ret = m_Db->exists(m_DbTxn, &dbt_key, 0);

                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                return ret == 0;
            }
        
            /**
             * Checks if the key exists.
             * @param key The std::string.
             */
            bool exists(const std::string & key)
            {
                if (m_Db == 0)
                {
                    return false;
                }
                
                data_buffer buffer;

                buffer.reserve(1000);
                
                buffer.write_var_int(key.size());
                buffer.write_bytes(key.data(), key.size());
    
                Dbt dbt_key(
                    buffer.data(), static_cast<std::uint32_t> (buffer.size())
                );

                auto ret = m_Db->exists(m_DbTxn, &dbt_key, 0);

                std::memset(dbt_key.get_data(), 0, dbt_key.get_size());
                
                return ret == 0;
            }
        
            /**
             * Rewrites the database.
             * @param file_name The file name.
             * @param key_skip The key (if any) to skip.
             */
            bool static rewrite(
                const std::string & file_name, const char * key_skip = 0
            );
        
            /**
             * The file name.
             */
            const std::string & file_name() const;
        
        private:
        
            friend class db_tx;
            friend class db_wallet;
        
            /**
             * If true the database is read-only.
             */
            bool m_is_read_only;
        
            /**
             * The file name.
             */
            std::string m_file_name;
        
            /**
             * The Db.
             */
            Db * m_Db;
        
            /**
             * The DbTxn.
             */
            DbTxn * m_DbTxn;
        
        protected:
      
            /**
             * Writes the version.
             * @param version The version.
             */
            bool write_version(const std::int32_t & version);
        
            /**
             * The state.
             */
            enum
            {
                state_none,
                state_opened,
                state_closed,
            } state_;
        
            /**
             * The std::mutex.
             */
            std::mutex mutex_;
    };
}

#endif // COIN_DB_HPP
