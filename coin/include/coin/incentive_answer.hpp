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

#ifndef COIN_INCENTIVE_ANSWER_HPP
#define COIN_INCENTIVE_ANSWER_HPP

#include <cstdint>
#include <string>
#include <vector>

#include <coin/data_buffer.hpp>
#include <coin/key_public.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_in.hpp>

namespace coin {
    
    /**
     * Implements an incentive answer.
     */
    class incentive_answer : public data_buffer
    {
        public:

            /**
             * Constructor
             */
            incentive_answer();
        
            /**
             * Constructor
             * @param public_key The key_public.
             */
            incentive_answer(
                const key_public & public_key, const transaction_in & tx_in
            );
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             * @param is_copy If true we are encoding a copy.
             */
            void encode(data_buffer & buffer, const bool & is_copy = false);
        
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
             * The public key.
             */
            const key_public & public_key() const;
        
            /**
             * The transaction_in.
             */
            const transaction_in & get_transaction_in() const;
        
            /**
             * The address.
             */
            const std::string get_address() const;
        
        private:
        
            /**
             * Signs
             * @param buffer The data_buffer.
             */
            bool sign(data_buffer & buffer);
        
            /**
             * Verifies
             * @param buffer The data_buffer.
             */
            bool verify(data_buffer & buffer);
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * The version.
             */
            std::uint32_t m_version;
            
            /**
             * The public key.
             */
            key_public m_public_key;
        
            /**
             * The transaction_in.
             */
            transaction_in m_transaction_in;
        
            /**
             * The signature (calculated by the wallet address).
             */
            std::vector<std::uint8_t> m_signature;
        
        protected:
        
            // ...
    };
}

#endif // COIN_INCENTIVE_ANSWER_HPP
