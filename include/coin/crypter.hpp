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

#ifndef COIN_CRYPTER_HPP
#define COIN_CRYPTER_HPP

#include <cstdint>

#include <coin/key.hpp>
#include <coin/sha256.hpp>
#include <coin/types.hpp>

namespace coin {

    /**
     * Implements encryption/decryption routines.
     */
    class crypter
    {
        public:
        
            /**
             * The wallet key size.
             */
            enum { wallet_key_size = 32 };
        
            /**
             * The wallet sale size.
             */
            enum { wallet_salt_size = 8 };
        
            /**
             * :FIXME: Use secure allocator.
             */
            typedef std::string secure_string_t;
        
            /**
             * Constructor
             */
            crypter();
        
            /**
             * Destructor
             */
            ~crypter();
        
            /**
             * Sets the key from a passphrase.
             * @param key_data The key data.
             * @param salt The salt.
             * @param rounds The rounds.
             * @param derivation_method The derivation method.
             */
            bool set_key_from_passphrase(
                const secure_string_t & key_data,
                const std::vector<std::uint8_t> & salt,
                const std::uint32_t & rounds,
                const std::uint32_t & derivation_method
            );
        
            /**
             * Encrypts
             * @param plain_text The plain text.
             * @param cipher_text The cipher text.
             */
            bool encrypt(
                const types::keying_material_t & plain_text,
                std::vector<std::uint8_t> & cipher_text
            );
        
            /**
             * Decrypts
             * @param cipher_text The cipher text.
             * @param plain_text The plain text.
             */
            bool decrypt(
                const std::vector<std::uint8_t> & cipher_text,
                types::keying_material_t & plain_text
            );
        
            /**
             * Sets the key.
             * @param new_key The new key.
             * @param new_iv The new iv.
             */
            bool set_key(
                const types::keying_material_t & new_key,
                const std::vector<std::uint8_t> & new_iv
            );
    
            /**
             * Clears the keys.
             */
            void clear_keys();
    
            /**
             * Encrypts a secret.
             * @param master_key The master key.
             * @param plain_text The plain text.
             * @param iv The initialization vector.
             * @param cipher_text The cipher text.
             */
            static bool encrypt_secret(
                types::keying_material_t & master_key,
                const key::secret_t & plain_text, const sha256 & iv,
                std::vector<std::uint8_t> & cipher_text
            );
        
            /**
             * Decrypts a secret.
             * @param master_key The master key.
             * @param cipher_text The cipher text.
             * @param plain_text The plain text.
             */
            static bool decrypt_secret(
                const types::keying_material_t & master_key,
                const std::vector<std::uint8_t> & cipher_text,
                const sha256 & iv, key::secret_t & plain_text
            );

        private:
        
            // ...
        
        protected:
        
            /**
             * The key.
             */
            std::uint8_t key_[wallet_key_size];
        
            /**
             * The initialization vector.
             */
            std::uint8_t iv_[wallet_key_size];
        
            /**
             * If true the key is set.
             */
            bool key_is_set_;
    };

} // namespace coin

#endif // COIN_CRYPTER_HPP
