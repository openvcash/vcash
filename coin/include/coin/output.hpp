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

#ifndef COIN_OUTPUT_HPP
#define COIN_OUTPUT_HPP

#include <cstdint>

namespace coin {

    class transaction_wallet;
    
    /**
     * Implements an output.
     */
    class output
    {
        public:
        
            /**
             * Constructor
             * @param tx The transaction_wallet.
             * @param i The i.
             * @param depth The depth.
             */
            output(
                const transaction_wallet & tx, const std::int32_t & i,
                const std::int32_t & depth
                )
                : m_transaction_wallet(&tx)
                , m_i(i)
                , m_depth(depth)
            {
                // ...
            }
        
            /**
             * The transaction_wallet.
             */
            const transaction_wallet & get_transaction_wallet()
            {
                return *m_transaction_wallet;
            }
        
            /**
             * The transaction_wallet.
             */
            const transaction_wallet & get_transaction_wallet() const
            {
                return *m_transaction_wallet;
            }
        
            /**
             * The i.
             */
            const std::int32_t & get_i() const
            {
                return m_i;
            }
        
            /**
             * The depth.
             */
            const std::int32_t & get_depth() const
            {
                return m_depth;
            }
        
        private:
        
            /**
             * The transaction_wallet.
             */
            const transaction_wallet * m_transaction_wallet;
        
            /**
             * The i.
             */
            std::int32_t m_i;
        
            /**
             * The depth.
             */
            std::int32_t m_depth;
    
        protected:
    
            // ...
    };
    
} // namespace coin

#endif // COIN_OUTPUT_HPP
