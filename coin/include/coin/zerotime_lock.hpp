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

#ifndef COIN_ZEROTIME_LOCK_HPP
#define COIN_ZEROTIME_LOCK_HPP

#include <cstdint>
#include <ctime>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_in.hpp>

namespace coin {

    /**
     * Implements a ZeroTime lock.
     */
    class zerotime_lock : public data_buffer
    {
        public:
        
            /**
             * The minimum expire interval.
             */
            enum { interval_min_expire = 30 * 60 };
        
            /**
             * The maximum expire interval.
             */
            enum { interval_max_expire = 1 * 60 * 60 };
            
            /**
             * Constructor
             */
            zerotime_lock();
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            bool decode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Set's null.
             */
            void set_null();
        
            /**
             * Set the transaction.
             * @param val The transaction.
             */
            void set_transaction(const transaction & val);
        
            /**
             * The transactions in.
             */
            const std::vector<transaction_in> & transactions_in() const;
        
            /**
             * Sets the transaction hash.
             */
            void set_hash_tx(const sha256 & val);
        
            /**
             * The transaction hash.
             */
            const sha256 & hash_tx() const;
        
            /**
             *  The expiration.
             */
            const std::time_t & expiration() const;
        
        private:
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * The version.
             */
            std::uint32_t m_version;
            
            /**
             * The transaction.
             */
            transaction m_transaction;
        
            /**
             * The transaction hash.
             */
            sha256 m_hash_tx;
        
            /**
             *  The expiration.
             */
            std::time_t m_expiration;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_ZEROTIME_LOCK_HPP
