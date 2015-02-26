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

#ifndef COIN_BLOCK_ORPHAN_HPP
#define COIN_BLOCK_ORPHAN_HPP

#include <set>

#include <coin/sha256.hpp>

namespace coin {

    class transaction;
    
    /**
     * Implements an orphan block.
     */
    class block_orphan
    {
        public:
        
            /**
             * Constructor
             */
            block_orphan(const transaction & tx_in)
                : m_transaction(tx_in)
                , m_priority(0.0f)
                , m_fee_per_kilobyte(0.0f)
            {
                // ...
            }
        
            /**
             * The transaction.
             */
            const transaction & get_transaction() const
            {
                return m_transaction;
            }
        
            /**
             * Sets the priority.
             * @param val The value.
             */
            void set_priority(const double & val)
            {
                m_priority = val;
            }
        
            /**
             * The priority.
             */
            const double & priority() const
            {
                return m_priority;
            }
    
            /**
             * Sets the fee per kilobyte.
             * @param val The value.
             */
            void set_fee_per_kilobyte(const double & val)
            {
                m_fee_per_kilobyte = val;
            }
        
            /** 
             * The fee per kilobyte.
             */
            const double & fee_per_kilobyte() const
            {
                return m_fee_per_kilobyte;
            }
        
            /**
             * The hashes of the blocks we depend on,
             */
            std::set<sha256> & dependencies()
            {
                return m_dependencies;
            }
        
        private:
        
            /**
             * The transaction.
             */
            const transaction & m_transaction;
        
            /**
             * The priority.
             */
            double m_priority;
    
            /** 
             * The fee per kilobyte.
             */
            double m_fee_per_kilobyte;
        
            /**
             * The hashes of the blocks we depend on.
             */
            std::set<sha256> m_dependencies;
    
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_BLOCK_ORPHAN_HPP
