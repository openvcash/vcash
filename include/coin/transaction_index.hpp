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

#ifndef COIN_TRANSACTION_INDEX_HPP
#define COIN_TRANSACTION_INDEX_HPP

#include <cstdint>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/transaction_position.hpp>

namespace coin {

    /**
     * Implements a transaction database record that contains the disk
     * location of a transaction and the locations of transactions that
     * spend its outputs.
     */
    class transaction_index : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            transaction_index();

            /**
             * Constructor
             * @param position The transaction_position.
             * @param outputs The outputs.
             */
            transaction_index(
                const transaction_position & position,
                const std::uint32_t & outputs
            );
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);
        
            /**
             * set_null
             */
            void set_null();

            /**
             * is_null
             */
            bool is_null();
    
            /**
             * Gets the depth in the main chain.
             */
            std::int32_t get_depth_in_main_chain() const;
        
            /**
             * The transaction position.
             */
            const transaction_position & get_transaction_position() const;
        
            /**
             * The spent transaction positions.
             */
            std::vector<transaction_position> & spent();
        
            /**
             * operator ==
             */
            friend bool operator == (
                const transaction_index & lhs, const transaction_index & rhs
                )
            {
                return
                    lhs.m_transaction_position == rhs.m_transaction_position &&
                    lhs.m_spent == rhs.m_spent
                ;
            }

            /**
             * operator !=
             */
            friend bool operator != (
                const transaction_index & lhs, const transaction_index & rhs
                )
            {
                return !(lhs == rhs);
            }
    
        private:
        
            /**
             * The transaction position.
             */
            transaction_position m_transaction_position;
        
            /**
             * The spent transaction positions.
             */
            std::vector<transaction_position> m_spent;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_TRANSACTION_INDEX_HPP
