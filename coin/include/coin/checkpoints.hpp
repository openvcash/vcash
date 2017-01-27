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

#ifndef COIN_CHECKPOINTS_HPP
#define COIN_CHECKPOINTS_HPP

#include <cstdint>
#include <map>
#include <mutex>

#include <coin/sha256.hpp>
#include <coin/checkpoint_sync.hpp>


#include <coin/block_index.hpp>
#include <coin/globals.hpp>

namespace coin {

    class block_index;
    class tcp_connection;
    class tcp_connection_manager;
    
    /**
     * Implements checkpoints.
     */
    class checkpoints
    {
        public:
        
            /**
             * Constructor
             */
            checkpoints();
        
            /**
             * The singleton accessor.
             */
            static checkpoints & instance();
        
            /**
             * Checks hardend checkpoints.
             * @param height The block height.
             * @param hash The sha256.
             */
            bool check_hardened(
                const std::int32_t & height, const sha256 & hash
            );
        
            /**
             * Check against synchronized checkpoint.
             * @param hash_block The block hash.
             * @param index_previous The previous block index.
             */
            bool check_sync(
                const sha256 & hash_block, const block_index * index_previous
            );
    
            /**
             * Only descendant of current sync-checkpoint is allowed (ppcoin).
             * @param hash_checkpoint The hash of the checkpoint.
             */
            bool validate_sync_checkpoint(const sha256 & hash_checkpoint);
    
            /**
             * Returns an estimate of total number of blocks, 0 if unknown.
             */
            std::uint32_t get_total_blocks_estimate();

            /**
             * Returns (SPV) checkpoints (height, hash, timestamp).
             */
            std::map<std::int32_t, std::pair<sha256, std::time_t> >
                get_spv_checkpoints()
            ;

            /**
             * The hash sync checkpoint.
             */
            sha256 & get_hash_sync_checkpoint();
        
            /**
             * Sets the hash of the pending checkpoint.
             * @param val The sha256.
             */
            void set_hash_pending_checkpoint(const sha256 & val);
        
            /**
             * The hash of the pending checkpoint.
             */
            const sha256 & get_hash_pending_checkpoint() const;
        
            /**
             * Sets the checkpoint message.
             * @param val The checkpoint_sync.
             */
            void set_checkpoint_message(const checkpoint_sync & val);
        
            /**
             * The checkpoint message.
             */
            const checkpoint_sync & get_checkpoint_message() const;
        
            /**
             * Sets the checkpoint of the message pending.
             * @param val The checkpoint_sync.
             */
            void set_checkpoint_message_pending(const checkpoint_sync & val);
        
            /**
             * The checkpoint of the pending message.
             */
            checkpoint_sync & get_checkpoint_message_pending();
        
            /**
             * The checkpoint of the pending message.
             */
            const checkpoint_sync & get_checkpoint_message_pending() const;
        
            /**
             * Get last synchronized checkpoint (ppcoin).
             */
            const block_index * get_last_sync_checkpoint();
    
            /**
             * Sets the hash of the invalid checkpoint.
             * @param val The sha256.
             */
            void set_hash_invalid_checkpoint(const sha256 & val);
        
            /**
             * The hash of an invalid checkpoint.
             */
            const sha256 & get_hash_invalid_checkpoint() const;
        
            /**
             * The checkpoints.
             */
            std::map<int, sha256> get_checkpoints();
        
            /**
             * The test net check points.
             */
            std::map<int, sha256> get_checkpoints_test_net();
        
            /**
             * Ask's for the pending sync checkpoint.
             * @param connection The tcp_connection.
             */
            void ask_for_pending_sync_checkpoint(
                const std::shared_ptr<tcp_connection> & connection
            );
        
            /**
             * Send the sync checkpoint.
             * @param connection_manager The tcp_connection_manager.
             * @param hash_checkpoint The hash of the checkpoint.
             */
            bool send_sync_checkpoint(
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager, const sha256 & hash_checkpoint
            );
        
            /**
             * Writes the sync checkpoint.
             * @param hash_checkpoint The hash of the checkpoint.
             */
            bool write_sync_checkpoint(const sha256 & hash_checkpoint);
    
            /**
             * Accepts a pending sync chechpoint.
             * @param connection_manager The tcp_connection_manager.
             */
            bool accept_pending_sync_checkpoint(
                const std::shared_ptr<tcp_connection_manager> &
                connection_manager
            );
        
            /**
             * Automatically select a suitable sync-checkpoint.
             */
            sha256 auto_select_sync_checkpoint();
    
            /**
             * Reset synchronized checkpoint to last hardened checkpoint
             * (ppcoin).
             */
            bool reset_sync_checkpoint();
    
            /**
             * Checks if the hash is wanted by a pending checkpoint.
             * @param hash_block The hash of the block.
             */
            bool wanted_by_pending_sync_checkpoint(const sha256 & hash_block);
    
        private:
        
            /**
             * A maximum of 4 hours before latest block.
             */
            enum { checkpoint_max_span = 60 * 60 * 4 };
    
            /**
             * The hash sync checkpoint.
             */
            sha256 m_hash_sync_checkpoint;
        
            /**
             * The hash of the pending checkpoint.
             */
            sha256 m_hash_pending_checkpoint;
        
            /**
             * The checkpoint message.
             */
            checkpoint_sync m_checkpoint_message;
        
            /**
             * The checkpoint of the pending message.
             */
            checkpoint_sync m_checkpoint_message_pending;
        
            /**
             * The hash of an invalid checkpoint.
             */
            sha256 m_hash_invalid_checkpoint;
    
            /**
             * The checkpoints.
             */
            std::map<std::int32_t, sha256> m_checkpoints;
        
            /**
             * The test net checkpoints.
             */
            std::map<std::int32_t, sha256> m_checkpoints_test_net;
        
        protected:
        
            /**
             * The std::recursive_mutex.
             */
            mutable std::recursive_mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CHECKPOINTS_HPP
