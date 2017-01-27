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

#ifndef COIN_ACCOUNTING_ENTRY_HPP
#define COIN_ACCOUNTING_ENTRY_HPP

#include <cstdint>
#include <map>
#include <string>

#include <coin/data_buffer.hpp>

namespace coin {
    
    /**
     * Implements an accouting entry.
     */
    class accounting_entry : public data_buffer
    {
        public:

            /**
             * Constructor
             */
            accounting_entry();
        
            /**
             * Encodes.
             */
            void encode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void encode(
                data_buffer & buffer, const bool & encode_version = true
            );
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(
                data_buffer & buffer, const bool & decode_version = true
            );
        
            /**
             * Sets null.
             */
            void set_null();
        
            /**
             * The credit debit.
             */
            const std::int64_t & credit_debit() const;
        
            /**
             * The time.
             */
            const std::int64_t & time() const;
        
            /**
             * The account.
             */
            std::string & account();
        
            /**
             * The account.
             */
            const std::string & account() const;
        
            /**
             * The other account.
             */
            const std::string & other_account() const;
        
            /**
             * The comment.
             */
            const std::string & comment() const;
        
            /**
             * The value.
             */
            const std::map<std::string, std::string> & value() const;
        
            /**
             * Sets the order position.
             * @param val The value.
             */
            void set_order_position(const std::int64_t & val);
        
            /**
             * The position in ordered transaction list.
             */
            const std::int64_t & order_position() const;
        
            /**
             * Sets the entry number.
             * @param value The value.
             */
            void set_entry_number(const std::uint64_t & value);
        
            /**
             * The entry number.
             */
            const std::uint64_t & entry_number() const;
        
        private:
        
            /**
             * The credit debit.
             */
            std::int64_t m_credit_debit;
        
            /**
             * The time.
             */
            std::int64_t m_time;
        
            /**
             * The account.
             */
            std::string m_account;
        
            /**
             * The other account.
             */
            std::string m_other_account;
        
            /**
             * The comment.
             */
            std::string m_comment;
        
            /**
             * The value.
             */
            std::map<std::string, std::string> m_value;
        
            /**
             * The position in ordered transaction list.
             */
            std::int64_t m_order_position;
    
            /**
             * The entry number.
             */
            std::uint64_t m_entry_number;
        
        protected:
        
            /**
             * The extra.
             */
            std::vector<char> extra_;
    };
    
} // namespace coin

#endif // COIN_ACCOUNTING_ENTRY_HPP
