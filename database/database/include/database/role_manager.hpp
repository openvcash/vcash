/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#ifndef database_role_manager_hpp
#define database_role_manager_hpp

#include <chrono>

#include <boost/asio.hpp>

namespace database {

    class node_impl;

    class role_manager : public std::enable_shared_from_this<role_manager>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param impl The node_impl.
             */
            explicit role_manager(
                boost::asio::io_service &, std::shared_ptr<node_impl>
            );
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();

        private:
        
            /**
             * Starts the manager after some delay.
             * @param ec The boost::system::error_code.
             */
            void do_start(const boost::system::error_code &);
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::io_service::stand.
             */
            boost::asio::io_service::strand strand_;
        
            /**
             * The node_impl.
             */
            std::weak_ptr<node_impl> node_impl_;
        
            /**
             * The delayed start timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > delayed_start_timer_;
    };
    
} // namespace database

#endif // database_role_manager_hpp
