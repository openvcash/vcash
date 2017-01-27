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

#include <coin/hash.hpp>
#include <coin/signature_cache.hpp>

using namespace coin;

signature_cache & signature_cache::instance()
{
    static signature_cache g_signature_cache;
                
    return g_signature_cache;
}

bool signature_cache::get(
    sha256 hash, const std::vector<std::uint8_t> & signature,
    const std::vector<std::uint8_t> & public_key
    )
{
    std::lock_guard<std::mutex> l1(mutex_);

    signature_data_t k(hash, signature, public_key);

    return m_valid.find(k) != m_valid.end();
}

void signature_cache::set(
    sha256 hash, const std::vector<std::uint8_t> & signature,
    const std::vector<std::uint8_t> & public_key
    )
{
    std::lock_guard<std::mutex> l1(mutex_);

    while (static_cast<std::int64_t>(m_valid.size()) > max_cache_size)
    {
        /**
         * Evict a random entry to prevent attackers from knowing the internal
         * state.
         */
        sha256 randomHash = hash::sha256_random();
        
        std::vector<std::uint8_t> unused;
        
        auto it = m_valid.lower_bound(
            signature_data_t(randomHash, unused, unused)
        );
        
        if (it == m_valid.end())
        {
            it = m_valid.begin();
        }
        
        m_valid.erase(*it);
    }

    m_valid.insert(signature_data_t(hash, signature, public_key));
}
