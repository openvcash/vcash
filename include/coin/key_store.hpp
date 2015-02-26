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
 
#ifndef COIN_KEY_STORE_HPP
#define COIN_KEY_STORE_HPP

#include <mutex>
#include <set>

#include <coin/destination.hpp>
#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/script.hpp>

namespace coin {

    class script;
    
    /**
     * Implements a key store base functionality.
     */
    class key_store
    {
        public:
        
            /**
             * is_mine_visitor
             */
            class is_mine_visitor : public boost::static_visitor<bool>
            {
                public:
                
                    /**
                     *
                     */
                    is_mine_visitor(const key_store & value)
                        : key_store_(value)
                    {
                        // ...
                    }
                
                    /**
                     * operator ()
                     */
                    bool operator () (const destination::none & value) const
                    {
                        return false;
                    }
                
                    /**
                     * operator ()
                     */
                    bool operator () (const types::id_key_t & value) const
                    {
                        return key_store_.have_key(value);
                    }
                
                    /**
                     * operator ()
                     */
                    bool operator () (const types::id_script_t & value) const
                    {
                        return key_store_.have_c_script(value);
                    }
                
                private:
                
                    /**
                     * The key_store.
                     */
                    const key_store & key_store_;
                
                protected:
                
                    // ...
            };

            /**
             * Virtual Destructor
             */
            virtual ~key_store()
            {
                // ...
            }

            /**
             * Adds a key.
             * @param k The key.
             */
            virtual bool add_key(const key & value) =0;

            /**
             * Checks if we have the key belonging to the address.
             * @param address The types::id_key_t.
             */
            virtual bool have_key(const types::id_key_t & addr) const = 0;
        
            /**
             * Gets a key.
             * @param address The address.
             * @param key_out The key_out.
             */
            virtual bool get_key(
                const types::id_key_t & addr, key & keyOut
            ) const = 0;
        
            /**
             * Gets keys.
             * @param addresses The types::id_key_t's.
             */
            virtual void get_keys(std::set<types::id_key_t> & addrs) const = 0;

            /**
             * Gets a public key.
             * @param addr The types::id_key_t.
             * @param key_public_out The public key.
             */
            virtual bool get_pub_key(
                const types::id_key_t & addr, key_public & key_public_out
                ) const
            {
                key k;
                
                if (get_key(addr, k) == false)
                {
                    return false;
                }
                
                key_public_out = k.get_public_key();
                
                return true;
            }

            /**
             * Adds a c script (bip-0013).
             * @param redeem_script The redeem script.
             */
            virtual bool add_c_script(const script & redeem_script) = 0;
        
            /**
             * Checks for the types::id_script_t.
             * @param h The types::id_script_t.
             */
            virtual bool have_c_script(const types::id_script_t & h) const = 0;
        
            /**
             * Gets the types::id_script_t.
             * @param h The types::id_script_t.
             * @param redeem_script_out Set to true of redeem script out.
             */
            virtual bool get_c_script(
                const types::id_script_t & h, script& redeem_script_out
            ) const = 0;

            /**
             * Gets a secret
             * @param addr The types::id_key_t
             * @param secret The key::secret_t .
             * @param compress If true it is compressed.
             */
            virtual bool get_secret(
                const types::id_key_t & addr, key::secret_t & secret,
                bool & compressed
                ) const
            {
                key k;
                
                if (get_key(addr, k) == false)
                {
                    return false;
                }
                
                secret = k.get_secret(compressed);
                
                return true;
            }
    
        private:
        
            // ...
        
        protected:
        
            /**
             * The mutex.
             */
            mutable std::mutex mutex_;
    };

} // namespace coin

#endif // COIN_KEY_STORE_HPP
