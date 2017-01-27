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
 
#ifndef COIN_KEY_STORE_CRYPTO_HPP
#define COIN_KEY_STORE_CRYPTO_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include <coin/key_public.hpp>
#include <coin/key_store_basic.hpp>
#include <coin/types.hpp>

namespace coin {

    class key;
    
    /**
     * Implements a crypto key store.
     */
    class key_store_crypto : public key_store_basic
    {
        public:
    
            /**
             * A crypted key map.
             */
            typedef std::map<
                types::id_key_t,
                std::pair<key_public, std::vector<std::uint8_t> >
            > crypted_key_map_t;
        
            /**
             * Constructor
             */
            key_store_crypto();
    
            /**
             * Locks
             */
            bool lock();
        
            /**
             * Unlocks
             * @param master_key The master types::keying_material_t.
             */
            bool unlock(const types::keying_material_t & master_key);
        
            /**
             * Sets crypted.
             */
            bool set_crypted();

            /**
             * If true it is encrypted.
             */
            bool is_crypted() const;

            /**
             * If true it is locked.
             */
            bool is_locked() const;
    
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
             * Gets a key.
             * @param address The address.
             * @param key_out The key_out.
             */
            bool get_key(const types::id_key_t & address, key & key_out) const;
        
            /**
             * Gets keys.
             * @param addresses The types::id_key_t's.
             */
            void get_keys(std::set<types::id_key_t> & addresses) const;
        
            /**
             * Gets a public key.
             * @param address The address.
             * @param key_public_out The key_public_out.
             */
            bool get_public_key(
                const types::id_key_t & address, key_public & key_public_out
            ) const;
        
            /**
             * The crypted keys.
             */
            const crypted_key_map_t & crypted_keys() const;
        
            /**
             * Adds a crypted key.
             * @param public_key The key_public.
             * @param crypted_secret The crypted secret.
             */
            virtual bool add_crypted_key(
                const key_public & public_key,
                const std::vector<std::uint8_t> & crypted_secret
            );
        
            /**
             * Encrypts the keys.
             * @param master_key The master types::keying_material_t.
             */
            bool encrypt_keys(types::keying_material_t & master_key);
        
        private:
        
            /**
             * If true, m_crypted_keys must be empty. If false, m_master_key
             * must be empty.
             */
            bool m_use_crypto;
        
            /**
             * The master key.
             */
            types::keying_material_t m_master_key;
        
            /**
             * The crypted keys.
             */
            crypted_key_map_t m_crypted_keys;
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_KEY_STORE_CRYPTO_HPP
