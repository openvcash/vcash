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

#ifndef COIN_INCENTIVE_COLLATERALS_HPP
#define COIN_INCENTIVE_COLLATERALS_HPP

#include <set>

#include <coin/address_manager.hpp>
#include <coin/data_buffer.hpp>

namespace coin {

    /**
     * Implements an icollateral message.
     */
    class incentive_collaterals : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            incentive_collaterals();
        
            /**
             * Constructor
             * @param filter The filter.
             */
            incentive_collaterals(
                const std::set<address_manager::recent_endpoint_t> &
                collaterals
            );
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            bool decode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Set's null.
             */
            void set_null();
        
            /**
             * The collaterals.
             */
            std::set<address_manager::recent_endpoint_t> & collaterals();
        
        private:
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * The version.
             */
            std::uint32_t m_version;
            
            /**
             * The collaterals.
             */
            std::set<address_manager::recent_endpoint_t> m_collaterals;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_INCENTIVE_COLLATERALS_HPP
