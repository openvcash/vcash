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

#ifndef COIN_TRANSACTION_POOL_HPP
#define COIN_TRANSACTION_POOL_HPP

#include <mutex>
#include <string>
#include <vector>

#include <coin/db_tx.hpp>
#include <coin/point_in.hpp>
#include <coin/point_out.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction.hpp>

namespace coin {

    /**
     * Implements an "in memory" transaction pool. It is ok for this to be a
     * singleton even in the presence of multiple instances in the same
     * memory space.
     */
    class transaction_pool
    {
        public:
        
            /**
             * Constructor
             */
            transaction_pool();
        
            /**
             * The singleton accessor.
             */
            static transaction_pool & instance();
        
            /**
             * Accepts a transaction.
             * @param dbtx The db_tx.
             * @param missing_inputs If set to true there are inputs missing.
             */
            std::pair<bool, std::string> accept(
                db_tx & dbtx, transaction & tx, bool * missing_inputs
            );
        
            /**
             * Checks the transaction to see if it is acceptable.
             * @param tx The transaction.
             */
            std::pair<bool, std::string> acceptable(transaction & tx);
        
            /**
             * Removes a transaction.
             * @param tx The transaction.
             */
            bool remove(transaction & tx);
        
            /**
             * Clears
             */
            void clear();
        
            /**
             * Queries hashes.
             * @param transaction_ids The transaction_id's.
             */
            void query_hashes(std::vector<sha256> & transaction_ids);

            /**
             * The size.
             */
            std::size_t size();
    
            /**
             * If true the transaction given hash exists.
             */
            bool exists(const sha256 & hash);

            /**
             *
             */
            transaction & lookup(const sha256 & hash);
        
            /**
             * The transactions.
             */
            std::map<sha256, transaction> & transactions();
        
            /**
             * The next transactions.
             */
            const std::map<point_out, point_in> & transactions_next() const;
        
            /**
             * The number of transactons updated.
             */
            std::uint32_t & transactions_updated();
        
        private:
        
            /**
             * Add to pool without checking anything. Call accept to check the
             * transaction first.
             */
            bool add_unchecked(const sha256 & hash, transaction & tx);
        
            /**
             * The transactions.
             */
            std::map<sha256, transaction> m_transactions;
        
            /**
             * The next transactions.
             */
            std::map<point_out, point_in> m_transactions_next;
        
            /**
             * The number of transactons updated.
             */
            std::uint32_t m_transactions_updated;
    
        protected:
        
            /**
             * The std::recursive_mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_TRANSACTION_POOL_HPP
