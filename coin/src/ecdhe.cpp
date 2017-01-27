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

#include <cassert>

#include <coin/ecdhe.hpp>

using namespace coin;

ecdhe::ecdhe()
    : m_ecdhe(EC_DHE_new(NID_secp256k1))
{
    // ...
}

ecdhe::~ecdhe()
{
    if (m_ecdhe)
    {
        EC_DHE_free(m_ecdhe), m_ecdhe = 0;
    }
}

const std::string & ecdhe::public_key()
{
    if (m_public_key.size() == 0)
    {
        auto len = 0;
        
        auto buf = EC_DHE_getPublicKey(m_ecdhe, &len);
        
        m_public_key = std::string(buf, len);
    }
    
    return m_public_key;
}

std::vector<std::uint8_t> ecdhe::derive_secret_key(
    const std::string & peer_public_key
    )
{
    std::vector<std::uint8_t> ret;
    
    auto len = 0;
    
    auto buf = EC_DHE_deriveSecretKey(
        m_ecdhe, peer_public_key.c_str(),
        static_cast<int> (peer_public_key.size()), &len
    );
    
    ret.insert(ret.begin(), buf, buf + len);
    
    return ret;
}

EC_DHE * ecdhe::get_EC_DHE()
{
    return m_ecdhe;
}

int ecdhe::run_test()
{
    ecdhe ecdhe_a, ecdhe_b, ecdhe_c;
    
    printf("A: %s\n", ecdhe_a.public_key().c_str());
    printf("B: %s\n", ecdhe_b.public_key().c_str());
    printf("C: %s\n", ecdhe_c.public_key().c_str());
    
    printf("A Size: %zu\n", ecdhe_a.public_key().size());
    printf("B Size: %zu\n", ecdhe_b.public_key().size());
    printf("C Size: %zu\n", ecdhe_c.public_key().size());
    
    auto shared_secret1 = ecdhe_a.derive_secret_key(ecdhe_b.public_key());
    auto shared_secret2 = ecdhe_b.derive_secret_key(ecdhe_a.public_key());
    auto shared_secret3 = ecdhe_a.derive_secret_key(ecdhe_c.public_key());
    
    assert(shared_secret1 != shared_secret3);
    
    printf("SS1: %zu\n", shared_secret1.size());
    printf("SS2: %zu\n", shared_secret2.size());
    printf("SS3: %zu\n", shared_secret3.size());
    
    assert(shared_secret1.size() == 32);
    assert(shared_secret2.size() == 32);
    assert(shared_secret2.size() == 32);
    
    return 0;
}
