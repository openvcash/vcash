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

#ifndef COIN_TRANSACTION_POSITION_HPP
#define COIN_TRANSACTION_POSITION_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>

namespace coin {
    
    /**
     * Implements a transaction position on disk.
     */
    class transaction_position : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            transaction_position();

            /**
             * Constructor
             * @param file_index
             * @param block_position
             * @param tx_position
             */
            transaction_position(
                const std::uint32_t & file_index,
                const std::uint32_t & block_position,
                const std::uint32_t & tx_position
            );
    
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
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
    
            /**
             * Returns the string representation.
             */
            std::string to_string() const;
    
            /**
             * The file index.
             */
            const std::uint32_t & file_index() const;
        
            /**
             * The block position.
             */
            const std::uint32_t & block_position() const;
        
            /**
             * The transaction position.
             */
            const std::uint32_t & tx_position() const;
        
            /**
             * operator ==
             */
            friend bool operator == (
                const transaction_position & lhs,
                const transaction_position & rhs
                )
            {
                return
                    lhs.m_file_index == rhs.m_file_index &&
                    lhs.m_block_position == rhs.m_block_position &&
                    lhs.m_tx_position == rhs.m_tx_position
                ;
            }

            /**
             * operator !=
             */
            friend bool operator != (
                const transaction_position & a, const transaction_position & b
                )
            {
                return !(a == b);
            }
    
        private:
        
            /**
             * The file index.
             */
            std::uint32_t m_file_index;
        
            /**
             * The block position.
             */
            std::uint32_t m_block_position;
        
            /**
             * The transaction position.
             */
            std::uint32_t m_tx_position;
    
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_TRANSACTION_POSITION_HPP
