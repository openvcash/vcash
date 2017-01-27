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

#ifndef COIN_HD_CONFIGURATION_HPP
#define COIN_HD_CONFIGURATION_HPP

#include <cstdint>

#include <coin/types.hpp>

namespace coin {

    class data_buffer;
    
    /**
     * Implements an wallet configuration for storing BIP-0032 related 
     * parameters to the wallet database.
     */
    class hd_configuration
    {
        public:
        
            /**
             * Constructor
             */
            hd_configuration();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer) const;
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * The version.
             */
            const std::uint32_t & version() const;

            /**
             * Sets the index.
             * @param val The value.
             */
            void set_index(const std::uint32_t & val);
        
            /**
             * The index.
             */
            const std::uint32_t & index() const;

            /**
             * Sets the ID of the master key.
             * @param val The value.
             */
            void set_id_key_master(const types::id_key_t & val);
        
            /**
             * The ripemd160 hash (id) of the master key..
             */
            const types::id_key_t & id_key_master() const;
        
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
             * The index.
             */
            std::uint32_t m_index;

            /**
             * The ripemd160 hash (id) of the master key..
             */
            types::id_key_t m_id_key_master;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_HD_CONFIGURATION_HPP
