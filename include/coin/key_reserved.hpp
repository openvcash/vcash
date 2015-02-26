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

#ifndef COIN_KEY_RESERVED_HPP
#define COIN_KEY_RESERVED_HPP

#include <cstdint>

#include <coin/key_public.hpp>

namespace coin {

    class wallet;
    
    /**
     * A pool allocated key.
     */
    class key_reserved
    {
        public:
        
            /**
             * Constructor
             * @param w The wallet.
             */
            key_reserved(wallet & w);

            /**
             * Destructor
             */
            ~key_reserved();

            /**
             * Returns the key.
             */
            void return_key();
        
            /** 
             * Gets the reserved key.
             */
            key_public get_reserved_key();
        
            /**
             * Keeps the key.
             */
            void keep_key();
    
        private:
        
            // ...
        
        protected:

            /**
             * The wallet.
             */
            wallet & wallet_;
        
            /**
             * The index.
             */
            std::int64_t index_;
        
            /**
             * The key_public.
             */
            key_public public_key_;
    };
    
} // namespace coin

#endif // COIN_KEY_RESERVED_HPP
