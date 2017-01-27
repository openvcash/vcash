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
 
#ifndef DATABASE_OPERATION_QUEUE_HPP
#define DATABASE_OPERATION_QUEUE_HPP

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>

#include <boost/asio.hpp>

#include <database/operation.hpp>

namespace database {

    class message;
    
    /**
     * Implemens an operation queue.
     */
    class operation_queue
        : public std::enable_shared_from_this<operation_queue>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             */
            explicit operation_queue(boost::asio::io_service &);
            
            /**
             * Starts the queue.
             */
            void start();
            
            /**
             * Stops the queue.
             */
            void stop();
        
            /**
             * Stops the queue.
             */
            void do_stop();
            
            /**
             * Inserts an operation.
             * @param op The operation.
             */
            void insert(std::shared_ptr<operation>);
        
            /**
             * Inserts an operation.
             * @param op The operation.
             */
            void do_insert(std::shared_ptr<operation>);
        
            /**
             * Removes an operation given it's transaction identifier.
             * @param tid The operation transaction identifier.
             */
            void remove(const std::uint16_t &);
            
            /**
             * Finds an operation given the message transaction identifier.
             * @param mtid The message transaction identifier.
             */
            const std::shared_ptr<operation> find(const std::uint16_t &);
            
        private:
        
            /**
             * The cleanup timer handler.
             * @param ec The boost::system::error_code.
             */
            void cleanup_tick(const boost::system::error_code &);
            
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
             * The cleanup timer.
             */
            boost::asio::basic_waitable_timer<
                std::chrono::steady_clock
            > cleanup_timer_;
            
            /**
             * The std::recursive_mutex.
             */
            std::recursive_mutex mutex_;
            
            /**
             * The operation map.
             */
            std::map<std::uint16_t, std::shared_ptr<operation> > operations_;
    };
    
} // namespace database

#endif // DATABASE_OPERATION_QUEUE_HPP
