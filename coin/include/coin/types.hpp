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

#ifndef COIN_TYPES_HPP
#define COIN_TYPES_HPP

#include <cstdint>
#include <vector>

#include <coin/ripemd160.hpp>

namespace coin {

    namespace types {
    
        /**
         * Signature hash types.
         */
        typedef enum
        {
            sighash_all = 1,
            sighash_none = 2,
            sighash_single = 3,
            sighash_anyonecanpay = 0x80,
        } sighash_t;
        
        /**
         * The transaction out types.
         */
        typedef enum
        {
            tx_out_nonstandard,
            tx_out_pubkey,
            tx_out_pubkeyhash,
            tx_out_scripthash,
            tx_out_multisig,
        } tx_out_t;
        
        /**
         * The minimum fee mode.
         */
        typedef enum
        {
            get_minimum_fee_mode_block,
            get_minimum_fee_mode_relay,
            get_minimum_fee_mode_send,
        } get_minimum_fee_mode_t;

        /**
         * A reference to a key, the ripemd160 of it's encoded public key.
         */
        class id_key : public ripemd160
        {
            public:
            
                /**
                 * Constructor
                 */
                id_key()
                    : ripemd160()
                {
                    // ...
                }
            
                /**
                 * Constructor
                 * @param value The ripemd160.
                 */
                id_key(const ripemd160 & value)
                    : ripemd160(value)
                {
                    // ...
                }
            
            private:
            
                // ...
            
            protected:
            
                // ...
        };
        
        typedef id_key id_key_t;
        
        /**
         * A reference to a script, the ripemd160 of it's encoded public key.
         */
        class id_script : public ripemd160
        {
            public:
            
                /**
                 * Constructor
                 */
                id_script()
                    : ripemd160()
                {
                    // ...
                }
            
                /**
                 * Constructor
                 * @param value The ripemd160.
                 */
                id_script(const ripemd160 & value)
                    : ripemd160(value)
                {
                    // ...
                }
            
            private:
            
                // ...
            
            protected:
            
                // ...
        };
        
        typedef id_script id_script_t;
    
        /**
         * The keying material.
         * @param :FIXME: Use secure_allocator.
         */
        typedef std::vector<std::uint8_t> keying_material_t;
        
    } // namespace types

} // namespace coin

#endif // COIN_TYPES_HPP
