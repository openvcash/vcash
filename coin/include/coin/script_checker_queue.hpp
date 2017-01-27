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

#ifndef SCRIPT_CHECKER_QUEUE_HPP
#define SCRIPT_CHECKER_QUEUE_HPP

#include <cassert>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <coin/script_checker.hpp>

namespace coin {

    /**
     * Implements a script_checker singleton queue.
     */
    class script_checker_queue
    {
        public:
        
            /**
             * Constructor
             */
            script_checker_queue();
        
            /**
             * The singleton accessor.
             */
            static script_checker_queue & instance();
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Performs a synchronous wait until the queue is fully processed
             * returning the result.
             */
            bool sync_wait();
        
            /**
             * If true the queue is in an idle state.
             */
            bool is_idle();
        
            /**
             * Inserts an array of script_checker objects into the queue.
             * @param checks The script_checker's.
             */
            void insert(std::vector<script_checker> & checks);
        
            /**
             * Implements a RAII script checker queue context.
             */
            class context
            {
                public:
            
                    /**
                     * Constructor
                     */
                    context()
                        : done_(false)
                    {
                        assert(
                            script_checker_queue::instance().is_idle() == true
                        );
                    }

                    /**
                     * Performs a synchronous wait until the queue is fully
                     * processed returning the result.
                     */
                    bool sync_wait()
                    {
                        auto ret = script_checker_queue::instance().sync_wait();
                        
                        done_ = true;
                        
                        return ret;
                    }

                    /**
                     * Inserts an array of script_checker objects into the
                     * queue.
                     * @param checks The script_checker's.
                     */
                    void insert(std::vector<script_checker> & checks)
                    {
                        script_checker_queue::instance().insert(checks);
                    }

                    /**
                     * Destructor
                     */
                    ~context()
                    {
                        if (done_ == false)
                        {
                            sync_wait();
                        }
                    }
                
                private:
                
                    // ...
                
                protected:
                
                    /**
                     * If true we are done.
                     */
                    bool done_;
            };
        
        private:
        
            // ...
        
        protected:
        
            /**
             * The main loop.
             */
            bool loop(const bool & is_main_thread = false);
        
            /**
             * The state.
             */
            enum
            {
                state_stopped,
                state_starting,
                state_started,
                state_stopping
            } state_;
        
            /**
             * The std::thread's.
             */
            std::vector< std::shared_ptr<std::thread> > threads_;
        
            /**
             * The std::mutex.
             */
            std::mutex mutex_;

            /**
             * Blocks worker thread when no work is available.
             */
            std::condition_variable condition_variable_worker_;

            /**
             * Blocks main thread when no work is available.
             */
            std::condition_variable condition_variable_main_;

            /**
             * Blocks until all workers are finished.
             */
            std::condition_variable condition_variable_quit_;

            /**
             * The script_checker queue.
             */
            std::vector<script_checker> queue_;

            /**
             * The number of idle workers.
             */
            std::int32_t idle_workers_;

            /**
             * The number of workers.
             */
            std::int32_t total_workers_;

            /**
             * If true ok.
             */
            bool is_ok_;

            /**
             * The number of remaning checks to complete.
             */
            std::uint32_t remaining_;

            /**
             * The maximum batch of work to process.
             */
            std::uint32_t batch_size_maximum_;
    };
    
} // namespace coin

#endif // SCRIPT_CHECKER_QUEUE_HPP
