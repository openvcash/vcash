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
             * Removes a transaction.
             * @param tx The transaction.
             */
            bool remove(transaction & tx);
        
            /**
             *
             */
            void clear();
        
            /**
             *
             */
            void query_hashes(std::vector<sha256> & transaction_ids);

            /**
             *
             */
            std::size_t size();
    
            /**
             *
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
             * The number of transactons updated.
             */
            std::uint32_t m_transactions_updated;
    
        protected:
        
            /**
             * The std::recursive_mutex.
             */
            std::recursive_mutex mutex_;

            /**
             * The next transactions.
             */
            std::map<point_out, point_in> transactions_next_;
    };
    
} // namespace coin

#endif // COIN_TRANSACTION_POOL_HPP
