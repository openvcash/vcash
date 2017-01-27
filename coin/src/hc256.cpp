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
#include <cstdint>
#include <cstring>

#include <coin/hc256.hpp>
#include <coin/logger.hpp>

using namespace coin;

hc256::hc256(
    const std::string & encrypt_key, const std::string & decrypt_key,
    const std::string & iv
    )
{
    assert(encrypt_key.size() == sizeof(encryption_key_));
    assert(decrypt_key.size() == sizeof(decryption_key_));
    assert(iv.size() == sizeof(iv_));
    
    std::memcpy(encryption_key_, encrypt_key.data(), sizeof(encryption_key_));
    std::memcpy(decryption_key_, decrypt_key.data(), sizeof(decryption_key_));
    std::memcpy(iv_, iv.data(), sizeof(iv_));
    
    ECRYPT_keysetup(&encrypt_ctx_, encryption_key_, 128, 128);
    ECRYPT_ivsetup(&encrypt_ctx_, iv_);
    
    ECRYPT_keysetup(&decrypt_ctx_, decryption_key_, 128, 128);
    ECRYPT_ivsetup(&decrypt_ctx_, iv_);
}

std::string hc256::encrypt(const std::string & data)
{
    std::string ret(data);
    
    ECRYPT_process_bytes(
        0, &encrypt_ctx_,
        reinterpret_cast<const std::uint8_t *> (data.data()),
        (std::uint8_t *)ret.data(), ret.size()
    );
    
    return ret;
}

std::string hc256::decrypt(const std::string & data)
{
    std::string ret(data);
    
    ECRYPT_process_bytes(
        1, &decrypt_ctx_,
        reinterpret_cast<const std::uint8_t *> (data.data()),
        reinterpret_cast<std::uint8_t *> (const_cast<char *> (ret.data())),
        ret.size()
    );
    
    return ret;
}

int hc256::run_test()
{
    hc256 alice(
        "44vkIEt6YOvNFbO38ZSBzg23f3e6CXNn",
        "d7vC7D3Z0fPJEr20tJBI9OzZ9jU118o6",
        "u97WiCR6J4i3O0zF5roD2i23UQn5pFZJ"
    );
    hc256 bob(
        "d7vC7D3Z0fPJEr20tJBI9OzZ9jU118o6",
        "44vkIEt6YOvNFbO38ZSBzg23f3e6CXNn",
        "u97WiCR6J4i3O0zF5roD2i23UQn5pFZJ"
    );
 
    auto encrypted = alice.encrypt("Hello World!");

    auto decrypted = bob.decrypt(encrypted);
    
    printf("Test hc256: %s:%s\n", encrypted.c_str(), decrypted.c_str());
    
    assert(decrypted == "Hello World!");
    
    return 0;
}
