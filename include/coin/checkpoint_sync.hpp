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

#ifndef COIN_CHECKPOINT_SYNC_HPP
#define COIN_CHECKPOINT_SYNC_HPP

#include <cstdint>
#include <string>
#include <vector>

#include <coin/checkpoint_sync_unsigned.hpp>

namespace coin {

    class tcp_connection;
    
    /**
     * Implements a sync checkpoint.
     */
    class checkpoint_sync : public checkpoint_sync_unsigned
    {
        public:
        
            checkpoint_sync()
                : checkpoint_sync_unsigned()
            {
                // ...
            }
        
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
             * Sets null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
    
            /**
             * The master public key.
             */
            static const std::string & master_public_key();
        
            /**
             * The master private key.
             */
            static const std::string & master_private_key();
        
            /**
             * Sets the message.
             * @param val The value.
             */
            void set_message(const std::vector<std::uint8_t> & val);
        
            /**
             * The message.
             */
            const std::vector<std::uint8_t> & message() const;
        
            /**
             * Sets the signature.
             * @param val The value.
             */
            void set_signature(const std::vector<std::uint8_t> & val);
        
            /**
             * The signature.
             */
            std::vector<std::uint8_t> & signature();
        
            /**
             * The signature.
             */
            const std::vector<std::uint8_t> & signature() const;
        
            /**
             * Verify the signature of the sync-checkpoint message (ppcoin).
             */
            bool check_signature();

            /**
             * Processes a sync checkpoint.
             * @param connection The tcp_connection.
             */
            bool process_sync_checkpoint(
                const std::shared_ptr<tcp_connection> & connection
            );
        
        private:
        
            /**
             * The master public key.
             */
            static const std::string g_master_public_key;
        
            /**
             * The master private key.
             */
            static std::string g_master_private_key;

            /**
             * The message.
             */
            std::vector<std::uint8_t> m_message;
        
            /**
             * The signature.
             */
            std::vector<std::uint8_t> m_signature;
    
        protected:
      
            // ...
    };
    
} // namespace coin

#endif // COIN_CHECKPOINT_SYNC_HPP
