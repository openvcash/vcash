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

#ifndef COIN_ZEROTIME_HPP
#define COIN_ZEROTIME_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include <coin/key.hpp>
#include <coin/point_out.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_in.hpp>
#include <coin/zerotime_lock.hpp>
#include <coin/zerotime_vote.hpp>

namespace coin {

    class key_public;
    class transaction;
    
    /**
     * Implements the ZeroTime algorithm.
     */
    class zerotime
    {
        public:

            /**
             * K
             */
            enum { k = 12 };
        
            /**
             * The depth.
             */
            enum { depth = 1 };
            
            /**
             * The number of answers required for a transaction to be
             * considered confirmed equivalent to 6 block confirmations.
             */
            enum { answers_minimum = 1 };
        
            /**
             * The number of maximum answers.
             */
            enum { answers_maximum = 8 };
        
            /**
             * Constructor
             */
            zerotime();
            
            /**
             * The singleton accessor.
             */
            static zerotime & instance();
        
            /**
             * The zerotime key.
             */
            key & get_key();
        
            /**
             * The locked inputs.
             */
            std::map<point_out, sha256> & locked_inputs();
        
            /**
             * The zerotime_lock's.
             */
            std::map<sha256, zerotime_lock> & locks();
        
            /**
             * The zerotime_vote's.
             */
            std::map<sha256, zerotime_vote> & votes();
        
            /**
             * The number of confirmations.
             */
            std::map<sha256, std::size_t> & confirmations();
        
            /**
             * Checks a transaction for a locked input mismatch.
             * @param tx The transaction.
             */
            bool has_lock_conflict(const transaction & tx);
        
            /**
             * Checks inputs for a lock mismatch.
             * @param transactions_in The transactions in.
             * @param hash_tx The transaction hash.
             */
            bool has_lock_conflict(
                const std::vector<transaction_in> & transactions_in,
                const sha256 & hash_tx
            );
        
            /**
             * Resolves lock conflicts.
             * @param transactions_in The transactions in.
             * @param hash_tx The transaction hash.
             */
            void resolve_conflicts(
                const std::vector<transaction_in> & transactions_in,
                const sha256 & hash_tx
            );

            /**
             * Clears expired input locks.
             */
            void clear_expired_input_locks();
        
            /**
             * Calculates the score of a key_public.
             * @param val public_key The key_public.
             */
            std::int16_t calculate_score(const key_public & public_key);
        
            /**
             * Calculates the score of a zerotime_vote.
             * @param val ztvote The zerotime_vote.
             */
            std::int16_t calculate_score(const zerotime_vote & ztvote);
        
            /**
             * Signs
             * @param hash_value The hash of the value.
             * @param signature The signature.
             */
            bool sign(
                const sha256 & hash_value,
                std::vector<std::uint8_t> & signature
            );

            /**
             * Verifies
             * @param public_key The public key.
             * @param hash_value The hash of the value.
             * @param signature The signature.
             */
            bool verify(
                const key_public & public_key,
                const sha256 & hash_value,
                const std::vector<std::uint8_t> & signature
            );
        
            /**
             * Prints
             */
            void print();

        private:
        
            /**
             * The zerotime key.
             */
            key m_key;
        
            /**
             * The locked inputs.
             */
            std::map<point_out, sha256> m_locked_inputs;
        
            /**
             * The zerotime_lock's.
             */
            std::map<sha256, zerotime_lock> m_locks;

            /**
             * The zerotime_vote's.
             */
            std::map<sha256, zerotime_vote> m_votes;

            /**
             * The number of confirmations.
             */
            std::map<sha256, std::size_t> m_confirmations;
        
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
        
            /**
             * The locks std::recursive_mutex.
             */
            std::recursive_mutex recursive_mutex_votes_;
        
            /**
             * The confirmations std::recursive_mutex.
             */
            std::recursive_mutex recursive_mutex_confirmations_;
    };
    
} // namespace

#endif // COIN_ZEROTIME_HPP
