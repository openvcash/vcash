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

#ifndef DATABASE_ENTRY_HPP
#define DATABASE_ENTRY_HPP

#include <chrono>
#include <cstdint>
#include <map>
#include <string>

#include <boost/asio.hpp>

namespace database {

    class storage;
    
    /**
     * Implements an entry.
     */
    class entry : public std::enable_shared_from_this<entry>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The storage.
             * @param query The query.
             */
            explicit entry(
                boost::asio::io_service &, const std::shared_ptr<storage> &,
                const std::string &
            );
            
            /**
             * Destrcutor
             */
            ~entry();
            
            /**
             * Start
             */
            void start();
        
            /**
             * Stop
             */
            void stop();
        
            /**
             * The query.
             */
            const std::string & query_string() const;
        
            /**
             * The value.
             */
            const std::string & value() const;
        
            /**
             * The lifetime.
             */
            const std::uint32_t & lifetime() const;
        
            /**
             * Set the timestamp.
             * @param val The value.
             */
            void set_timestamp(const std::time_t &);
        
            /**
             * The timestamp.
             */
            const std::time_t & timestamp() const;
        
            /**
             * The key/value pairs.
             */
            std::map<std::string, std::string> & pairs();
        
            /**
             * The time remaining until expire.
             */
            const std::uint32_t expires() const;
        
            /**
             * If true the entry is expired.
             */
            const bool & expired() const;
        
            /**
             * The minimum lifetime.
             */
            enum { min_lifetime = 1 };
        
            bool operator == (const entry & rhs) const
            {
                return this->m_query_string == rhs.m_query_string;
            }
        
        private:

            /**
             * The expire timer handler
             * @param ec The boost::system::error_code.
             */
            void expire_tick(const boost::system::error_code &);

            /**
             * The query string.
             */
            std::string m_query_string;

            /**
             * The lifetime.
             */
            std::uint32_t m_lifetime;
        
            /**
             * The allocation time.
             */
            std::time_t m_allocation_time;
        
            /**
             * The timestamp.
             */
            std::time_t m_timestamp;
        
            /**
             * The key/value pairs.
             */
            std::map<std::string, std::string> m_pairs;
        
            /**
             * If true the entry is expired.
             */
            bool m_expired;
        
            /**
             * The maximum lifetime.
             */
            enum { max_lifetime = 72 * 60 * 60 };
            
        protected:
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The storage.
             */
            std::weak_ptr<storage> storage_;
            
            /**
             * The expire timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > expire_timer_;
    };
    
} // namespace database

#endif // DATABASE_ENTRY_HPP
