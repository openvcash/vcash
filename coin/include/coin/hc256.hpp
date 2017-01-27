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

#ifndef COIN_HC256_HPP
#define COIN_HC256_HPP

#include <cstdint>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif
#include <coin/ecrypt-sync.h>
#ifdef __cplusplus
}
#endif

namespace coin {

    /**
     * HC-256 is a stream cipher designed to provide bulk encryption in
     * software at high speeds while permitting strong confidence in its
     * security.
     */
    class hc256
    {
        public:
        
            /**
             * Constructor
             * @param encrypt_key The encrypt key.
             * @param decrypt_key The decrypt key.
             * @param iv The initialization vector.
             */
            explicit hc256(
                const std::string &, const std::string &, const std::string &
            );
        
            /**
             * Encrypts
             * @param data The data to encrypt.
             */
            std::string encrypt(const std::string & data);
        
            /**
             * Decrypts
             * @param data The data to decrypt.
             */
            std::string decrypt(const std::string & data);
        
            /**
             * Runs the test case.
             */
            static int run_test();
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The encrypt context.
             */
            ECRYPT_ctx encrypt_ctx_;
        
            /**
             * The decrypt context.
             */
            ECRYPT_ctx decrypt_ctx_;
        
            /**
             * The encryption key.
             */
            std::uint8_t encryption_key_[32];
        
            /**
             * The decryption key.
             */
            std::uint8_t decryption_key_[32];
        
            /**
             * The iv.
             */
            std::uint8_t iv_[32];
    };

} // coin

#endif // COIN_HC256_HPP
