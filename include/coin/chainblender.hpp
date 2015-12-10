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

#ifndef COIN_CHAINBLENDER_HPP
#define COIN_CHAINBLENDER_HPP

#include <mutex>

namespace coin {

    /**
     * Implements a chainblender mechanism.
     */
    class chainblender
    {
        public:
        
            /**
             * Constructor
             */
            chainblender();
            
            /**
             * The singleton accessor.
             */
            static chainblender & instance();
            
        private:
        
            // ...
        
        protected:
        
            /**
             * The std::mutex.
             */
            static std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CHAINBLENDER_HPP
