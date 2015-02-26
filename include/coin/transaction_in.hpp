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

#ifndef COIN_TRANSACTION_IN_HPP
#define COIN_TRANSACTION_IN_HPP

#include <cstdint>

#include <coin/data_buffer.hpp>
#include <coin/point_out.hpp>
#include <coin/script.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements an input of a transaction. It has the location of the
     * previous transaction's output that it claims and a signature that
     * matches the output's public key.
     */
    class transaction_in : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            transaction_in();
        
            /**
             * Constructor
             * @param point_out_previous The point_out_previous.
             * @param script_signature The script_signature.
             * @param sequence The sequence.
             */
            explicit transaction_in(
                point_out point_out_previous,
                script script_signature = script(),
                const std::uint32_t & sequence =
                std::numeric_limits<std::uint32_t>::max()
            );
        
            /**
             * Constructor
             * @param hash_previous_tx The hash_previous_tx.
             * @param out The out.
             * @param script_signature The script_signature.
             * @param sequence The sequence.
             */
            transaction_in(
                sha256 hash_previous_tx, std::uint32_t out,
                script script_signature = script(),
                const std::uint32_t & sequence =
                std::numeric_limits<std::uint32_t>::max()
            );
    
            /**
             * Encodes.
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
             * If true it is final.
             */
            bool is_final() const;
        
            /**
             * The previous out.
             */
            point_out & previous_out();
        
            /**
             * The previous out.
             */
            const point_out & previous_out() const;
        
            /**
             * Sets the script signature.
             * @param val The value.
             */
            void set_script_signature(const script & val);
        
            /**
             * The script signature.
             */
            script & script_signature();
        
            /**
             * The script signature.
             */
            const script & script_signature() const;
        
            /**
             * Sets the sequence.
             * @param val The value.
             */
            void set_sequence(const std::uint32_t & val);
        
            /**
             * The sequence.
             */
            const std::uint32_t & sequence() const;
        
            /**
             * The operator ==.
             */
            friend bool operator == (
                const transaction_in & a, const transaction_in & b
                )
            {
                return
                    a.m_previous_out == b.m_previous_out &&
                    a.m_script_signature == b.m_script_signature &&
                    a.m_sequence == b.m_sequence
                ;
            }

            /**
             * operator !=
             */
            friend bool operator != (
                const transaction_in & a, const transaction_in & b
                )
            {
                return !(a == b);
            }
    
        private:
        
            /**
             * The previous out.
             */
            point_out m_previous_out;
        
            /**
             * The script signature.
             */
            script m_script_signature;
        
            /**
             * The sequence.
             */
            std::uint32_t m_sequence;
        
        protected:
        
            // ...
    };
    
} //  namespace coin

#endif // COIN_TRANSACTION_IN_HPP
