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

#ifndef COIN_INVENTORY_VECTOR_HPP
#define COIN_INVENTORY_VECTOR_HPP

#include <cstdint>

#include <coin/protocol.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class data_buffer;
    class db_tx;
    
    /**
     * The inventory vector structure.
     * type uint32_t Identifies the object type linked to this inventory.
     * hash char[32] Hash of the object.
     */
    class inventory_vector
    {
        public:
        
            /**
             * The types.
             * @param type_error Any data of with this number may be ignored.
             * @param type_msg_tx Hash is related to a transaction.
             * @param type_msg_block Hash is related to a data block.
             * @param type_msg_filtered_block Hash is related to a filtered
             * block.
             * @param type_msg_ztlock Hash is related to a zerotime lock.
             * @param type_msg_ztvote Hash is related to zerotime vote.
             * @param type_msg_ivote Hash is related to incentive vote.
             */
            typedef enum
            {
                type_error,
                type_msg_tx,
                type_msg_block,
#if 0 /* BIP-0037 */
                type_msg_filtered_block,
#endif
                type_msg_ztlock,
                type_msg_ztvote,
                type_msg_ivote,
#if 1 /* BIP-0037 */
                type_msg_filtered_block_nonstandard,
#endif
            } type_t;
    
            /**
             * Constructor
             */
            inventory_vector();
        
            /**
             * Constructor
             */
            inventory_vector(const type_t & type, const sha256 & hash);
        
            /**
             * Constructor
             */
            inventory_vector(
                const std::string & type, const sha256 & hash
            );

            /**
             * Encodes
             * buffer The data_buffer.
             */
            bool encode(data_buffer & buffer);
        
            /**
             * Decodes
             * buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);

            /**
             * Sets the type.
             * @param val.
             */
            void set_type(const type_t & val);
        
            /**
             * The type.
             */
            const type_t & type() const;
        
            /**
             * The hash.
             */
            const sha256 & hash() const;
        
            /**
             * If true it is of a known type.
             */
            bool is_know_type() const;
        
            /**
             * The command.
             */
            const std::string command() const;
        
            /**
             * Returns the string representation.
             */
            const std::string to_string() const;
    
            /**
             * Checks if we already have the transaction.
             * @param tx_db The transaction database.
             * @param inv The inventory_vector.
             */
            static bool already_have(
                db_tx & tx_db, const inventory_vector & inv
            );

            /**
             * Checks if we already have the transaction.
             * @param inv The inventory_vector.
             */
            static bool spv_already_have(const inventory_vector & inv);
        
            /**
             * operator ==
             */
            friend bool operator == (
                const inventory_vector & a, const inventory_vector & b
                )
            {
                return a.m_type == b.m_type && a.m_hash == b.m_hash;
            }
        
            /**
             * operator <
             */
            friend bool operator < (
                const inventory_vector & a, const inventory_vector & b
                )
            {
                return
                    a.m_type < b.m_type ||
                    (a.m_type == b.m_type && a.m_hash < b.m_hash)
                ;
            }
        
        private:
        
            /**
             * The type.
             */
            type_t m_type;
        
            /**
             * The hash.
             */
            sha256 m_hash;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_INVENTORY_VECTOR_HPP
