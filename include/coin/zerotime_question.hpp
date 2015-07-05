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

#ifndef COIN_ZEROTIME_QUESTION_HPP
#define COIN_ZEROTIME_QUESTION_HPP

#include <coin/data_buffer.hpp>
#include <coin/transaction_in.hpp>

namespace coin {

    /**
     * Implements a ZeroTime question message (ztquestion).
     */
    class zerotime_question : public data_buffer
    {
        public:
        
            /**
             * Constructor
             * @param tx_in The transaction_in.
             */
            explicit zerotime_question(const transaction_in & tx_in);
        
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
             * The transaction_in.
             */
            const transaction_in & get_transaction_in() const;
        
        private:
        
            /**
             * The transaction_in.
             */
            transaction_in m_transaction_in;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_ZEROTIME_QUESTION_HPP
