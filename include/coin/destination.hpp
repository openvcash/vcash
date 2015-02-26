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

#ifndef COIN_DESTINATION_HPP
#define COIN_DESTINATION_HPP

#include <boost/variant.hpp>

#include <coin/types.hpp>

namespace coin {

    /**
     * Implements a destination.
     */
    class destination
    {
        public:
        
            /**
             * Implements no destination.
             */
            class none
            {
                public:
                
                    friend bool operator == (
                        const destination::none & a, const destination::none & b
                        )
                    {
                        return true;
                    }
                
                    friend bool operator < (
                        const destination::none & a, const destination::none & b
                        )
                    {
                        return true;
                    }
                
                private:
                
                    // ...
                
                protected:
                
                    // ...
            };
        
            /**
             * A transaction out script template with a specific destination.
             */
            typedef boost::variant<
                destination::none, types::id_key_t, types::id_script_t
            > tx_t;
            
        private:
        
            // ...
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_DESTINATION_HPP
