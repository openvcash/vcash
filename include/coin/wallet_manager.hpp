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

#ifndef COIN_WALLET_MANAGER_HPP
#define COIN_WALLET_MANAGER_HPP

#include <mutex>
#include <set>

#include <coin/block_locator.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction.hpp>
#include <coin/wallet.hpp>

namespace coin {

    class block;
    class transaction_wallet;
    
    /**
     * Implements a wallet manager.
     */
    class wallet_manager
    {
        public:
        
            /**
             * The singleton accessor.
             */
            static wallet_manager & instance();
        
            /**
             * Registers a wallet.
             * @param val The wallet.
             */
            void register_wallet(const std::shared_ptr<wallet> & val);

            /**
             * Unregisters a wallet.
             * @param val The wallet.
             */
            void unregister_wallet(const std::shared_ptr<wallet> & val);

            /**
             * If true the transaction is from us.
             * @param tx The transaction.
             */
            bool is_from_me(const transaction & tx) const;
        
            /**
             * Erases the value from the wallets.
             * @param val The sha256.
             */
            void erase_from_wallets(const sha256 & val) const;
        
            /**
             * Make sure all wallets know about the given transaction in
             * the given block.
             * @param tx The tranaction.
             * @param blk The block.
             * @param update If true it will be updated.
             * @param connect If true it will be connected.
             */
            void sync_with_wallets(
                const transaction & tx, block * blk,
                const bool & update = false, const bool & connect = true
            );
        
            /**
             * Gets a transaction given hash.
             * @param hash_tx The hash of the transaction.
             * @param wtx_out The transaction_wallet (out)
             */
            bool get_transaction(
                const sha256 & hash_tx, transaction_wallet & wtx_out
            );
        
            /**
             * Sets the best chain.
             * @param val The value.
             */
            void set_best_chain(const block_locator val);
        
            /**
             * Called when a transaction has been updated.
             * @param val The sha256.
             */
            void on_transaction_updated(const sha256 & val);
        
            /**
             * Called when inventory has changed.
             * @param val The sha256.
             */
            void on_inventory(const sha256 & val);
        
        private:
        
            /**
             * The wallets.
             */
            std::set< std::shared_ptr<wallet> > m_wallets;
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_WALLET_MANAGER_HPP
