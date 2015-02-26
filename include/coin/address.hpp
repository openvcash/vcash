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

#ifndef COIN_ADDRESS_HPP
#define COIN_ADDRESS_HPP

#include <string>

#include <boost/variant/static_visitor.hpp>

#include <coin/base58.hpp>
#include <coin/constants.hpp>
#include <coin/destination.hpp>
#include <coin/types.hpp>

namespace coin {

    /**
     * Implements an address.
     */
    class address : public base58
    {
        public:
        
            /**
             * Implements a visitor.
             */
            class visitor : public boost::static_visitor<bool>
            {
                public:
                
                    /**
                     * Constructor
                     * @param addr The address.
                     */
                    visitor(address & addr) : m_address(addr)
                    {
                        // ...
                    }
                
                    bool operator()(const types::id_key_t & value) const
                    {
                        return m_address.set_id_key(value);
                    }
                
                    bool operator()(const types::id_script_t & value) const
                    {
                        return m_address.set_id_script(value);
                    }

                    bool operator()(const destination::none & value) const
                    {
                        return false;
                    }

                private:
                
                    /**
                     * The address.
                     */
                    address & m_address;
                
                protected:
                
                    // ...
            };
            
            /**
             * @param type_pubkey 'V'
             * @param type_script
             * @param type_pubkey_test 111
             * @param type_script_test 196
             */
            enum
            {
                type_pubkey = 71,
                type_script = 8,
                type_pubkey_test = 111,
                type_script_test = 196,
            } type_t;

            /**
             * Constructor
             */
            address();

            /**
             * Constructor
             * @param dest The destination::tx_t.
             */
            address(const destination::tx_t & dest);

            /**
             * Constructor
             * @param val The string.
             */
            address(const std::string & val);
        
            /**
             * Sets the types::id_key_t.
             * @param value The value.
             */
            bool set_id_key(const types::id_key_t & value);

            /**
             * Sets the types::id_script_t.
             * @param value The value.
             */
            bool set_id_script(const types::id_script_t & value);

            /**
             * Sets the destination::tx_t.
             * @param value The value.
             */
            bool set_destination_tx(const destination::tx_t & value);

            /**
             * If true it is valid.
             */
            bool is_valid();

            /**
             * Gets the destination.
             */
            destination::tx_t get();

            /**
             * Gets the id key.
             * @param id_key The types::id_key_t.
             */
            bool get_id_key(types::id_key_t & id_key);

            /**
             * If true it is script.
             */
            bool is_script();
    
        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_ADDRESS_HPP
