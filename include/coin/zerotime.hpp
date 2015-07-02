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

#ifndef COIN_ZEROTIME_HPP
#define COIN_ZEROTIME_HPP

#include <map>
#include <mutex>

#include <coin/point_out.hpp>
#include <coin/zerotime_lock.hpp>

namespace coin {

    class transaction;
    
    /**
     * Implements the ZeroTime algorithm.
     */
    class zerotime
    {
        public:
        
            /**
             * The number of confirmations required for a transaction to be
             * considered final.
             */
            enum { confirmations = 64 };
        
            /**
             * The singleton accessor.
             */
            static zerotime & instance();
        
            /**
             * The locked inputs.
             */
            std::map<point_out, sha256> & locked_inputs();
        
            /**
             * The zerotime_lock's.
             */
            std::map<sha256, zerotime_lock> & locks();
        
            /**
             * Checks a transaction for a locked input mismatch.
             * @param tx The transaction.
             */
            bool has_lock_conflict(const transaction & tx);
        
            /**
             * Clears expired input locks.
             */
            void clear_expired_input_locks();
        
        private:
        
            /**
             * The locked inputs.
             */
            std::map<point_out, sha256> m_locked_inputs;
        
            /**
             * The zerotime_lock's.
             */
            std::map<sha256, zerotime_lock> m_locks;
        
        protected:
        
            /**
             * The std::mutex.
             */
            static std::mutex mutex_;
        
            /**
             * The locked inputs std::recursive_mutex.
             */
            std::recursive_mutex recursive_mutex_locked_inputs_;
        
            /**
             * The locks std::recursive_mutex.
             */
            std::recursive_mutex recursive_mutex_locks_;
    };
    
} // namespace

#endif // COIN_ZEROTIME_HPP
