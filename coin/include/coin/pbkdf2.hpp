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
 
#ifndef COIN_PBKDF2_HPP
#define COIN_PBKDF2_HPP

#include <cstdint>
#include <string>

#include <openssl/sha.h>

namespace coin {

    namespace pbkdf2
    {
        typedef struct HMAC_SHA256Context
        {
            SHA256_CTX ictx;
            SHA256_CTX octx;
        } HMAC_SHA256_CTX;

        /**
         * HMAC_SHA256_Init
         */
        void HMAC_SHA256_Init(
            HMAC_SHA256_CTX * ctx, const void * _K, std::size_t Klen
        );

        /**
         * HMAC_SHA256_Update
         */
        void HMAC_SHA256_Update(
            HMAC_SHA256_CTX * ctx, const void * in, std::size_t len
        );

        /**
         * HMAC_SHA256_Final
         */
        void HMAC_SHA256_Final(std::uint8_t digest[32], HMAC_SHA256_CTX * ctx);

        /**
         *
         */
        void SHA256(
            const std::uint8_t * passwd, size_t passwdlen,
            const uint8_t * salt, std::size_t saltlen, std::uint64_t c,
            std::uint8_t * buf, std::size_t dkLen
        );
    } // namespace pbkdf2

} // namespace coin

#endif // COIN_PBKDF2_HPP
