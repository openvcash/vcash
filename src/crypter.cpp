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

#include <openssl/aes.h>
#include <openssl/evp.h>

#include <coin/crypter.hpp>
#include <coin/logger.hpp>

using namespace coin;

crypter::crypter()
    : key_is_set_(false)
{
    // ...
}

crypter::~crypter()
{
    clear_keys();
}

bool crypter::set_key_from_passphrase(
    const secure_string_t & key_data, const std::vector<std::uint8_t> & salt,
    const std::uint32_t & rounds, const std::uint32_t & derivation_method
    )
{
    if (rounds < 1 || salt.size() != wallet_salt_size)
    {
        return false;
    }
    
    int i = 0;
    
    if (derivation_method == 0)
    {
        i = EVP_BytesToKey(
            EVP_aes_256_cbc(), EVP_sha512(), &salt[0],
            (std::uint8_t *)&key_data[0], static_cast<int> (key_data.size()),
            rounds, key_, iv_
        );
    }
    
    if (i != wallet_key_size)
    {
        std::memset(&key_, 0, sizeof(key_));
        std::memset(&iv_, 0, sizeof(iv_));
        
        return false;
    }

    key_is_set_ = true;
    
    return true;
}

bool crypter::encrypt(
    const types::keying_material_t & plain_text,
    std::vector<std::uint8_t> & cipher_text
    )
{
    if (key_is_set_ == false)
    {
        return false;
    }

    auto len = static_cast<int> (plain_text.size());
    
    int clen = len + AES_BLOCK_SIZE, flen = 0;
    
    cipher_text = std::vector<std::uint8_t> (clen);

    EVP_CIPHER_CTX ctx;

    bool ok = true;

    EVP_CIPHER_CTX_init(&ctx);
    
    if (ok)
    {
        ok = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), 0, key_, iv_);
    }
    
    if (ok)
    {
        ok = EVP_EncryptUpdate(
            &ctx, &cipher_text[0], &clen, &plain_text[0], len
        );
    }
    
    if (ok)
    {
        ok = EVP_EncryptFinal_ex(&ctx, &cipher_text[0] + clen, &flen);
    }
    
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (ok == false)
    {
        return false;
    }
    
    cipher_text.resize(clen + flen);
    
    return true;
}

bool crypter::decrypt(
    const std::vector<std::uint8_t> & cipher_text,
    types::keying_material_t & plain_text
    )
{
    if (key_is_set_ == false)
    {
        return false;
    }
    
    auto len = static_cast<int> (cipher_text.size());
    
    int plen = len, flen = 0;

    plain_text.resize(plen);

    EVP_CIPHER_CTX ctx;

    bool ok = true;

    EVP_CIPHER_CTX_init(&ctx);
    
    if (ok)
    {
        ok = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), 0, key_, iv_);
    }
    
    if (ok)
    {
        ok = EVP_DecryptUpdate(
            &ctx, &plain_text[0], &plen, &cipher_text[0], len
        );
    }
    
    if (ok)
    {
        ok = EVP_DecryptFinal_ex(&ctx, &plain_text[0] + plen, &flen);
    }
    
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (ok == false)
    {
        return false;
    }
    
    plain_text.resize(plen + flen);
    
    return true;
}

bool crypter::set_key(
    const types::keying_material_t & new_key,
    const std::vector<std::uint8_t> & new_iv
    )
{
    if (new_key.size() != wallet_key_size || new_iv.size() != wallet_key_size)
    {
        return false;
    }
    
    std::memcpy(&key_[0], &new_key[0], sizeof(key_));
    std::memcpy(&iv_[0], &new_iv[0], sizeof(iv_));

    key_is_set_ = true;
    
    return true;
}

void crypter::clear_keys()
{
    std::memset(&key_, 0, sizeof(key_));
    std::memset(&iv_, 0, sizeof(iv_));
    
    key_is_set_ = false;
}

bool crypter::encrypt_secret(
    types::keying_material_t & master_key, const key::secret_t & plain_text,
    const sha256 & iv, std::vector<std::uint8_t> & cipher_text
    )
{
    crypter crypter_key;
    
    std::vector<std::uint8_t> new_iv(wallet_key_size);
    
    std::memcpy(&new_iv[0], iv.digest(), wallet_key_size);
    
    if (crypter_key.set_key(master_key, new_iv) == false)
    {
        return false;
    }
    
    return
        crypter_key.encrypt((types::keying_material_t)plain_text, cipher_text)
    ;
}

bool crypter::decrypt_secret(
    const types::keying_material_t & master_key,
    const std::vector<std::uint8_t> & cipher_text,
    const sha256 & iv, key::secret_t & plain_text
    )
{
    crypter crypter_key;
    
    std::vector<std::uint8_t> new_iv(wallet_key_size);
    
    std::memcpy(&new_iv[0], iv.digest(), wallet_key_size);
    
    if (crypter_key.set_key(master_key, new_iv) == false)
    {
        return false;
    }

    return
        crypter_key.decrypt(cipher_text, (types::keying_material_t &)plain_text)
    ;
}
