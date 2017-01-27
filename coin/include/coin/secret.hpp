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

#ifndef COIN_SECRET_HPP
#define COIN_SECRET_HPP

#include <coin/address.hpp>
#include <coin/base58.hpp>
#include <coin/key.hpp>

namespace coin {

    /**
     * A base58 encoded secret key.
     */
    class secret : public base58
    {
        public:
        
            /**
             * Constructor
             */
            secret();
        
            /**
             * Constructor
             * @param bytes The key::secret_t.
             * @param compressed The compressed.
             */
            secret(const key::secret_t & bytes, const bool & compressed);
        
            /**
             * set_secret
             * @param bytes The key::secret_t.
             * @param compressed The compressed.
             */
            void set_secret(
                const key::secret_t & bytes, const bool & compressed
            );

            /**
             * get_secret
             * @param compressed The compressed.
             */
            key::secret_t get_secret(bool & compressed);

            /**
             * is_valid
             */
            bool is_valid();

            /**
             * set_string
             * @param value The value.
             */
            bool set_string(const std::string & value);
    
        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_SECRET_HPP
