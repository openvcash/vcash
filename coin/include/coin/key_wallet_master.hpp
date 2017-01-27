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

#ifndef COIN_WALLET_KEY_MASTER_HPP
#define COIN_WALLET_KEY_MASTER_HPP

#include <coin/data_buffer.hpp>

namespace coin {

    /**
     * Implements a master key for wallet encryption.
     */
    class key_wallet_master : public data_buffer
    {
        public:
        
            /**
             * Constrcutor
             */
            key_wallet_master();

            /**
             * Encodes.
             */
            void encode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const;
        
            /**
             * Decodes
             */
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);

            /**
             * The crypted key.
             */
            std::vector<std::uint8_t> & crypted_key();
        
            /**
             * The crypted key.
             */
            const std::vector<std::uint8_t> & crypted_key() const;
        
            /**
             * The salt.
             */
            std::vector<std::uint8_t> & salt();
        
            /**
             * The derivation method.
             */
            const std::uint32_t & derivation_method() const;
        
            /**
             * Sets the derive iterations.
             * @param val The value.
             */
            void set_derive_iterations(const std::uint32_t & val);
        
            /**
             * The derive iterations.
             */
            const std::uint32_t & derive_iterations() const;
        
        private:
        
            /**
             * The crypted key.
             */
            std::vector<std::uint8_t> m_crypted_key;
        
            /**
             * The salt.
             */
            std::vector<std::uint8_t> m_salt;
        
            /**
             * The derivation method.
             * 0. EVP_sha512
             * 1. scrypt
             */
            std::uint32_t m_derivation_method;
        
            /**
             * The derive iterations.
             */
            std::uint32_t m_derive_iterations;
        
            /**
             * Used for more parameters to key derivation, such as the
             * various parameters to scrypt.
             */
            std::vector<std::uint8_t> m_other_derivation_parameters;

        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_WALLET_KEY_MASTER_HPP
