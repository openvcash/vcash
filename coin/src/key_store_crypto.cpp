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

#include <coin/crypter.hpp>
#include <coin/key_store_crypto.hpp>
#include <coin/secret.hpp>

using namespace coin;

key_store_crypto::key_store_crypto()
    : m_use_crypto(false)
{
    // ...
}

bool key_store_crypto::lock()
{
    if (set_crypted() == true)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        m_master_key.clear();
        
        return true;
    }
    
    return false;
}

bool key_store_crypto::unlock(const types::keying_material_t & master_key)
{
    if (set_crypted() == true)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        for (auto & i : m_crypted_keys)
        {
            const auto & pub_key = i.second.first;
            
            const auto & crypted_secret = i.second.second;
            
            key::secret_t s;
            
            if (
                crypter::decrypt_secret(master_key, crypted_secret,
                pub_key.get_hash(), s) == false
                )
            {
                return false;
            }
            
            if (s.size() != 32)
            {
                return false;
            }
            
            key k;
            
            k.set_public_key(pub_key);
            
            k.set_secret(s);
            
            if (k.get_public_key() == pub_key)
            {
                break;
            }
            
            return false;
        }
        
        /**
         * Set the master key.
         */
        m_master_key = master_key;
    
        return true;
    }

    return false;
}

bool key_store_crypto::set_crypted()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);

    if (m_use_crypto)
    {
        return true;
    }
    
    if (m_crypted_keys.size() > 0)
    {
        return false;
    }
    
    m_use_crypto = true;
    
    return true;
}

bool key_store_crypto::is_crypted() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_use_crypto;
}

bool key_store_crypto::is_locked() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_use_crypto == false)
    {
        return false;
    }
    
    return m_master_key.size() == 0;
}

bool key_store_crypto::add_key(const key & k)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);

    if (is_crypted() == false)
    {
        return key_store_basic::add_key(k);
    }
    
    if (is_locked())
    {
        return false;
    }
    
    std::vector<std::uint8_t> crypted_secret;
    
    auto public_key = k.get_public_key();
    
    bool compressed = false;
    
    if (
        crypter::encrypt_secret(m_master_key, k.get_secret(compressed),
        public_key.get_hash(), crypted_secret) == false
        )
    {
        return false;
    }
    
    if (add_crypted_key(k.get_public_key(), crypted_secret) == false)
    {
        return false;
    }
    
    return true;
}

bool key_store_crypto::have_key(const types::id_key_t & address) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (is_crypted() == false)
    {
        return key_store_basic::have_key(address);
    }
    
    return m_crypted_keys.count(address) > 0;
}

void key_store_crypto::get_keys(std::set<types::id_key_t> & addresses) const
{
    if (is_crypted() == false)
    {
        key_store_basic::get_keys(addresses);
    }
    else
    {
        addresses.clear();

        std::lock_guard<std::recursive_mutex> l1(mutex_);
        
        auto it = m_crypted_keys.begin();
       
        while (it != m_crypted_keys.end())
        {
            addresses.insert(it->first);
            
            it++;
        }
    }
}

bool key_store_crypto::get_key(
    const types::id_key_t & address, key & key_out
    ) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (is_crypted() == false)
    {
        return key_store_basic::get_key(address, key_out);
    }
    
    auto it = m_crypted_keys.find(address);
    
    if (it != m_crypted_keys.end())
    {
        const auto & pub_key = it->second.first;
        
        const auto & crypted_secret = it->second.second;
        
        key::secret_t s;
        
        /**
         * Decrypt the secret.
         */
        if (
            crypter::decrypt_secret(m_master_key, crypted_secret,
            pub_key.get_hash(), s) == false
            )
        {
            return false;
        }
        
        if (s.size() != 32)
        {
            return false;
        }
        
        /**
         * Set the public key.
         */
        key_out.set_public_key(pub_key);
        
        /**
         * Set the secret.
         */
        key_out.set_secret(s);
        
        return true;
    }
    
    return false;
}

bool key_store_crypto::get_public_key(
    const types::id_key_t & address, key_public & key_public_out
    ) const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (is_crypted() == false)
    {
        return key_store::get_pub_key(address, key_public_out);
    }
    
    auto it = m_crypted_keys.find(address);
    
    if (it != m_crypted_keys.end())
    {
        key_public_out = it->second.first;
        
        return true;
    }

    return false;
}

const key_store_crypto::crypted_key_map_t &
    key_store_crypto::crypted_keys() const
{
    return m_crypted_keys;
}

bool key_store_crypto::add_crypted_key(
    const key_public & public_key,
    const std::vector<std::uint8_t> & crypted_secret
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (set_crypted() == false)
    {
        return false;
    }
    
    m_crypted_keys[public_key.get_id()] =
        std::make_pair(public_key, crypted_secret)
    ;
    
    return true;
}

bool key_store_crypto::encrypt_keys(types::keying_material_t & master_key)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_crypted_keys.size() > 0 || is_crypted())
    {
        return false;
    }
    
    m_use_crypto = true;
    
    for (auto & i : keys())
    {
        key k;
        
        if (k.set_secret(i.second.first, i.second.second) == false)
        {
            return false;
        }
        
        const auto pub_key = k.get_public_key();
        
        std::vector<std::uint8_t> crypted_secret;
        
        bool compressed;
        
        if (
            crypter::encrypt_secret(master_key, k.get_secret(compressed),
            pub_key.get_hash(), crypted_secret) == false
            )
        {
            return false;
        }
        
        if (add_crypted_key(pub_key, crypted_secret) == false)
        {
            return false;
        }
    }
    
    keys().clear();
        
    return true;
}
