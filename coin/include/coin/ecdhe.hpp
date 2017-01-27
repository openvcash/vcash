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

#ifndef COIN_ECDHE_HPP
#define COIN_ECDHE_HPP

#include <cstdint>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#include <coin/ecdhe.h>
}
#endif // __cplusplus

namespace coin {

    /**
     * Implements Elliptic Curve Diffie–Hellman Exchange.
     */
    class ecdhe
    {
        public:
        
            /**
             * Constructor
             */
            ecdhe();
        
            /**
             * Destructor
             */
            ~ecdhe();
        
            /**
             * Returns the public key generating if needed.
             */
            const std::string & public_key();
        
            /**
             * Derives a secret key from the remote peer's public key.
             * @param peer_public_key The remote peer's public key.
             */
            std::vector<std::uint8_t> derive_secret_key(
                const std::string & peer_public_key
            );

            /**
             * Gets the EC_DHE.
             */
            EC_DHE * get_EC_DHE();
        
            /**
             * Runs test case.
             */
            static int run_test();
        
        private:
        
            /**
             * The EC_DHE.
             */
            EC_DHE * m_ecdhe;
        
            /**
             * The public key.
             */
            std::string m_public_key;
        
        protected:
        
            // ...
    };
}

#endif // COIN_ECDHE_HPP
