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

#ifndef DATABASE_DATABASE_HPP
#define DATABASE_DATABASE_HPP

#include <chrono>
#include <map>
#include <set>
#include <string>
#include <mutex>

#include <boost/asio.hpp>

namespace database {

    class entry;
    
    /**
     * Implements a storage.
     */
    class storage
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             */
            storage(boost::asio::io_service &);
            
            /**
             * Starts the database.
             */
            void start();
            
            /**
             * Stops the database.
             */
            void stop();
            
            /**
             * Stores a entry.
             * @param entry The entry.
             */
            void store(const std::shared_ptr<entry>);
            
            /**
             * Finds a set of entry objects by key id and kind id.
             * @param query The query.
             */
            const std::vector< std::shared_ptr<entry> > find(
                const std::string &
            );
        
            /**
             * The entries.
             */
            const std::vector< std::shared_ptr<entry> > & entries() const;
        
            /**
             * Runs the test case.
             */
            static int run_test();

        private:
        
            /**
             * The timer tick handler.
             * @param ec The boost::system::error_code.
             */
            void tick(const boost::system::error_code &);
        
            /**
             * The entries.
             */
            std::vector< std::shared_ptr<entry> > m_entries;
        
        protected:
        
            /**
             * The io service reference.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The std::recursive_mutex.
             */
            std::recursive_mutex mutex_;
            
            /**
             * The timer.
             */
            boost::asio::basic_waitable_timer<std::chrono::steady_clock> timer_;
    };
    
} // namespace database

#endif // DATABASE_DATABASE_HPP
