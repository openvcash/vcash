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

#ifndef COIN_KEY_HPP
#define COIN_KEY_HPP

#include <cstdint>
#include <vector>

#include <openssl/ec.h>

#include <coin/sha256.hpp>

namespace coin {

    class key_public;
    
    class key
    {
        public:
        
            /**
             * The serialized private key with all parameters included
             * (279 bytes).
             */
            typedef std::vector<std::uint8_t> private_t;
        
            /**
             * The serialized secret parameter (32 bytes).
             */
            typedef std::vector<std::uint8_t> secret_t;
        
            /**
             * Constructor
             */
            key();
        
            /**
             * Copy Constructor
             */
            key(const key & other);
        
            /**
             * destructor
             */
            ~key();
        
            /**
             * operator =
             */
            key & operator = (const key & other);
        
            /**
             * Resets
             */
            void reset();
        
            /**
             * is_null
             */
            bool is_null() const;
        
            /**
             * is_compressed
             */
            bool is_compressed() const;

            /**
             * make_new_key
             * @param compressed If true it will be compressed.
             */
            void make_new_key(const bool & compressed);
        
            /**
             * set_private_key
             * @param value The value.
             */
            bool set_private_key(const private_t & value);
        
            /**
             * set_secret
             * @param value The value.
             * @param @param compressed If true it is compressed.
             */
            bool set_secret(
                const secret_t & value, const bool & compressed = false
            );
        
            /**
             * get_secret
             * @param @param compressed If true it is compressed.
             */
            secret_t get_secret(bool & compressed) const;
        
            /**
             * get_private_key
             */
            private_t get_private_key() const;
        
            /**
             * set_public_key
             * @param value The value.
             */
            bool set_public_key(const key_public & value);
        
            /**
             * get_public_key
             */
            key_public get_public_key() const;

            /**
             * sign
             * @param h The sha256
             * @param signature The signature.
             */
            bool sign(const sha256 & h, std::vector<std::uint8_t> & signature);

            /**
             * Creates a compact signature (65 bytes) which allows for
             * reconstructing the used public key. The format is one header
             * byte followed by 2x32 bytes for the serialized r and s values.
             * The header byte:
             * 0x1B = first key with even y
             * 0x1C = first key with odd y
             * 0x1D = second key with even y
             * 0x1E = second key with odd y
             * @param h The sha256
             * @param signature The signature.
             */
            bool sign_compact(
                const sha256 & h, std::vector<std::uint8_t> & signature
            );

            /**
             * Reconstructs the public key from a compact signature. If this
             * function succeeds, the recovered public key is guaranteed to be
             * valid.
             * @param h The sha256
             * @param signature The signature.
             */
            bool set_compact_signature(
                const sha256 & h, const std::vector<std::uint8_t> & signature
            );

            /**
             * verify
             * @param h The sha256
             * @param signature The signature.
             */
            bool verify(
                const sha256 & h, const std::vector<std::uint8_t> & signature
            );

            /**
             * Verifies a compact signature.
             * @param h The sha256.
             * @param signature The signature
             */
            bool verify_compact(
                const sha256 & h, const std::vector<std::uint8_t> & signature
            );

            /**
             * is_valid
             */
            bool is_valid();
    
            /**
             * Runs the test case.
             */
            static int run_test();
            
        private:
        
            /**
             * The EC_KEY.
             */
            EC_KEY * m_EC_KEY;
        
            /**
             * If true it is set.
             */
            bool m_set;
        
            /**
             * If true it is compressed.
             */
            bool m_compressed;
        
        protected:
        
            /**
             * Sets the compressed public key.
             */
            void set_compressed_public_key();
    };
    
} // namespace coin

#endif // COIN_KEY_HPP
