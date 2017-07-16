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

#include <coin/key_store_basic.hpp>

using namespace coin;

bool key_store_basic::add_key(const key & k)
{
    bool compressed = false;
    
    auto sec = k.get_secret(compressed);
    
    std::lock_guard<std::mutex> m1(mutex_);
    
    m_keys[k.get_public_key().get_id()] = std::make_pair(sec, compressed);
    
    return true;
}

bool key_store_basic::have_key(const types::id_key_t & address) const
{
    std::lock_guard<std::mutex> m1(mutex_);
    
    return m_keys.count(address) > 0;
}

void key_store_basic::get_keys(std::set<types::id_key_t> & addresses) const
{
    addresses.clear();

    std::lock_guard<std::mutex> m1(mutex_);
    
    auto it = m_keys.begin();
   
    while (it != m_keys.end())
    {
        addresses.insert(it->first);
        
        it++;
    }
}

bool key_store_basic::get_key(
    const types::id_key_t & address, key & key_out
    ) const
{
    std::lock_guard<std::mutex> m1(mutex_);
    
    auto it = m_keys.find(address);
    
    if (it != m_keys.end())
    {
        key_out.reset();
        
        key_out.set_secret(it->second.first, it->second.second);
        
        return true;
    }
    
    return false;
}

bool key_store_basic::add_c_script(const script & redeem_script)
{
    if (redeem_script.size() > script::max_element_size)
    {
        return false;
    }

    std::lock_guard<std::mutex> m1(mutex_);

    m_scripts[redeem_script.get_id()] = redeem_script;
    
    return true;
}

bool key_store_basic::have_c_script(const types::id_script_t & h) const
{
    std::lock_guard<std::mutex> m1(mutex_);

    return m_scripts.count(h) > 0;
}

bool key_store_basic::get_c_script(
    const types::id_script_t & h, script & redeem_script_out
    ) const
{
    std::lock_guard<std::mutex> m1(mutex_);
    
    auto it = m_scripts.find(h);
    
    if (it != m_scripts.end())
    {
        redeem_script_out = it->second;
        
        return true;
    }

    return false;
}

std::map<types::id_key_t, std::pair<key::secret_t, bool> > &
    key_store_basic::keys()
{
    std::lock_guard<std::mutex> m1(mutex_);
    
    return m_keys;
}
