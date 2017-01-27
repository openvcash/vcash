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

#ifndef COIN_KEY_STORE_BASIC_HPP
#define COIN_KEY_STORE_BASIC_HPP

#include <map>
#include <set>

#include <coin/key.hpp>
#include <coin/key_store.hpp>
#include <coin/types.hpp>

namespace coin {

    class script;
    
    /**
     * Implements a basic key store.
     */
    class key_store_basic : public key_store
    {
        public:

            /**
             * Adds a key.
             * @param k The key.
             */
            bool add_key(const key & k);

            /**
             * Checks if we have the key belonging to the address.
             * @param address The types::id_key_t.
             */
            bool have_key(const types::id_key_t & address) const;
        
            /**
             * Gets keys.
             * @param addresses The types::id_key_t's.
             */
            void get_keys(std::set<types::id_key_t> & addresses) const;
        
            /**
             * Gets a key.
             * @param address The address.
             * @param key_out The key_out.
             */
            bool get_key(const types::id_key_t & address, key & key_out) const;
    
            /**
             * Adds a c script (bip-0013).
             * @param redeem_script The redeem script.
             */
            virtual bool add_c_script(const script & redeem_script);
        
            /**
             * Checks for the types::id_script_t.
             * @param h The types::id_script_t.
             */
            virtual bool have_c_script(const types::id_script_t & h) const;
        
            /**
             * Gets the types::id_script_t.
             * @param h The types::id_script_t.
             * @param redeem_script_out Set to true of redeem script out.
             */
            virtual bool get_c_script(
                const types::id_script_t & h, script & redeem_script_out
            ) const;
        
            /**
             * The keys.
             */
            std::map<types::id_key_t, std::pair<key::secret_t, bool> > & keys();
        
        private:
    
            /**
             * The keys.
             */
            std::map<types::id_key_t, std::pair<key::secret_t, bool> > m_keys;
        
            /**
             * The scripts.
             */
            std::map<types::id_script_t, script> m_scripts;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_KEY_STORE_BASIC_HPP
