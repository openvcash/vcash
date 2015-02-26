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

#ifndef COIN_POINT_IN_HPP
#define COIN_POINT_IN_HPP

#include <cstdint>

namespace coin {

    class transaction;
    
    /**
     * Implements a combination of a transaction and an index n into it's
     * transaction_in.
     */
    class point_in
    {
        public:
        
            /**
             * Constructor
             */
            point_in();
        
            /**
             * Constructor
             * @param tx The transaction.
             * @param n The n.
             */
            point_in(transaction & tx, const std::uint32_t & n);
    
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
    
            /**
             * The transaction.
             */
            const transaction & get_transaction() const;
        
        private:
        
            /**
             * The transaction.
             */
            transaction * m_transaction;
        
            /**
             * The n.
             */
            std::uint32_t m_n;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_POINT_IN_HPP
