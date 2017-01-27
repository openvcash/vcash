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

#ifndef COIN_TRANSACTION_OUT_HPP
#define COIN_TRANSACTION_OUT_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/script.hpp>
#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements an output of a transaction. It contains the public key that
     * the next input must be able to sign with to claim it.
     */
    class transaction_out : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            transaction_out();
        
            /**
             * Constructor
             * @param value The value.
             * @param script_public_key The script public key.
             */
            transaction_out(
                const std::uint64_t & value, const script & script_public_key
            );
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const;
            
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
             * The string representation.
             */
            std::string to_string() const;
        
            /**
             * Sets the value.
             * @param val The value.
             */
            void set_value(const std::int64_t & val);
        
            /**
             * The value.
             */
            const std::int64_t & value() const;
        
            /**
             * The script public key.
             */
            script & script_public_key();
        
            /**
             * The script public key.
             */
            const script & script_public_key() const;
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null();

            /**
             * Set empty.
             */
            void set_empty();

            /**
             * If true it is empty.
             */
            bool is_empty() const;

            /**
             * Gets the hash.
             */
            sha256 get_hash() const;

            /**
             * operator ==
             */
            friend bool operator == (
                const transaction_out & a, const transaction_out & b
                )
            {
                return
                    a.m_value == b.m_value &&
                    a.m_script_public_key == b.m_script_public_key
                ;
            }

            /**
             * operator !=
             */
            friend bool operator != (
                const transaction_out & a, const  transaction_out & b
                )
            {
                return !(a == b);
            }
    
        private:
        
            /**
             * The value.
             */
            std::int64_t m_value;
        
            /**
             * The script public key.
             */
            script m_script_public_key;
        
        protected:
        
            // ...
    };
    
} //  namespace coin

#endif // COIN_TRANSACTION_OUT_HPP
