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

#ifndef DATABASE_KEY_POOL_HPP
#define DATABASE_KEY_POOL_HPP

#include <chrono>
#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include <boost/asio.hpp>

namespace database {

    /**
     * Implements a key pool for shared secrets.
     */
    class key_pool
    {
        public:

            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             */
            explicit key_pool(boost::asio::io_service & ios);
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Finds a shared secret by endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            std::string find(const boost::asio::ip::udp::endpoint & ep);
        
            /**
             * Inserts a shared secret by endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param shared_secret The shared secret.
             */
            void insert(
                const boost::asio::ip::udp::endpoint & ep,
                const std::string & shared_secret
            );
        
            /**
             * Erases all expired shared secrets.
             */
            void erase_expired_shared_secrets();
        
        private:
        
            /**
             * Limit the number of shared secrets to 64K.
             */
            enum { max_shared_secrets = 64000 };
    
            /**
             * The maximum shared secret lifetime.
             */
            enum { max_shared_secret_lifetime = 72 * 60 * 60 };
        
            /**
             * The cleanup timer handler.
             * @param ec The boost::system::error_code.
             */
            void cleanup_tick(const boost::system::error_code &);
        
            /**
             * The shared secrets.
             */
            std::map<
                boost::asio::ip::udp::endpoint,
                std::pair<std::string, std::time_t>
            > m_shared_secrets;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The shared secrets mutex.
             */
            std::mutex mutex_shared_secrets_;
        
            /**
             * The cleanup timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > cleanup_timer_;
    };
    
} // namespace database

#endif // DATABASE_KEY_POOL_HPP
