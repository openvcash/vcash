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

#ifndef COIN_TRANSACTION_MERKLE_HPP
#define COIN_TRANSACTION_MERKLE_HPP

#include <cstdint>
#include <vector>

#include <coin/block.hpp>
#include <coin/configuration.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/stack_impl.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_index.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/zerotime.hpp>

namespace coin {

    /**
     * Implements a merkle transaction.
     */
    class transaction_merkle : public transaction
    {
        public:
        
            /**
             * Constructor
             */
            transaction_merkle();
        
            /**
             * Constructor
             */
            transaction_merkle(const transaction & tx);
        
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
            void decode();
        
            /**
             * Decodes
             * @param buffer The data_buffer.
             */
            void decode(data_buffer & buffer);
        
            /**
             * Accepts to the memory pool (transaction_pool).
             * @param tx_db The db_tx.
             */
            std::pair<bool, std::string> accept_to_memory_pool(db_tx & tx_db);
        
            /**
             * Accepts to the memory pool (transaction_pool).
             */
            std::pair<bool, std::string> accept_to_memory_pool();
    
            /**
             * Gets the number of blocks to maturity.
             */
            std::uint32_t get_blocks_to_maturity() const
            {
                if ((is_coin_base() || is_coin_stake()) == false)
                {
                    return 0;
                }
                
                if (constants::test_net == true)
                {
                    return std::max(
                        0, (constants::coinbase_maturity_test_network + 20) -
                        get_depth_in_main_chain(false)
                    );
                }
                
                return std::max(
                    0, (constants::coinbase_maturity + 20) -
                    get_depth_in_main_chain(false)
                );
            }
        
            /**
             * Gets the depth in the main chain.
             * @param is_zerotime If true this transaction is ZeroTime
             * protected.
             */
            int get_depth_in_main_chain(const bool & is_zerotime = true) const
            {
                if (globals::instance().is_client_spv() == true)
                {
                    int ret = -1;
                    
                    ret =
                        globals::instance().spv_best_block_height() -
                        m_spv_block_height + 1
                    ;
                    
                    if (m_spv_block_height <= 0)
                    {
                        ret = 0;
                    }
                    
                    /**
                     * ZeroTime protected transactions act as if they have a
                     * single confirmation.
                     */
                    if (
                        globals::instance().is_zerotime_enabled() && is_zerotime
                        )
                    {
                        if (ret < 1)
                        {
                            if (
                                zerotime::instance().confirmations()[
                                get_hash()] >= globals::instance(
                                ).zerotime_answers_minimum()
                                )
                            {
                                /**
                                 * Use the configured ZeroTime depth.
                                 */
                                ret = globals::instance().zerotime_depth();
                            }
                        }
                    }
                    
                    return ret > -1 ? ret : 0;
                }
                
                block_index * index_out = 0;
                
                return get_depth_in_main_chain(index_out, is_zerotime);
            }
        
            /**
             * Gets the depth in the main chain.
             * @param index_out The block_index.
             * @param is_zerotime If true this transaction is ZeroTime
             * protected.
             */
            int get_depth_in_main_chain(
                block_index * & index_out, const bool & is_zerotime
                ) const
            {
                auto ret = get_depth_in_main_chain_no_zerotime(index_out);
                
                if (ret == 0)
                {
                    if (
                        transaction_pool::instance().exists(get_hash()) == false
                        )
                    {
                        return -1;
                    }
                }

                /**
                 * ZeroTime protected transactions act as if they have a
                 * single confirmation.
                 */
                if (globals::instance().is_zerotime_enabled() && is_zerotime)
                {
                    if (ret < 1)
                    {
                        if (
                            zerotime::instance().confirmations()[get_hash()] >=
                            globals::instance().zerotime_answers_minimum()
                            )
                        {
                            /**
                             * Use the configured ZeroTime depth.
                             */
                            ret = globals::instance().zerotime_depth();
                        }
                    }
                }

                return ret;
            }
        
            /**
             * Gets the depth in the main chain.
             * @param index_out The block_index.
             */
            int get_depth_in_main_chain_no_zerotime(
                block_index * & index_out
                ) const
            {
                int ret = -1;
                
                if (m_block_hash == 0 || m_index == -1)
                {
                    return 0;
                }
                
                /**
                 * Find the block it claims to be in.
                 */
                auto it = globals::instance().block_indexes().find(
                    m_block_hash
                );
                
                if (it == globals::instance().block_indexes().end())
                {
                    return 0;
                }
                
                auto index = it->second;
                
                if (index == 0 || index->is_in_main_chain() == false)
                {
                    return 0;
                }
                
                /**
                 * Make sure the merkle branch connects to this block.
                 */
                if (m_merkle_verified == false)
                {
                    if (
                        block::check_merkle_branch(get_hash(), m_merkle_branch,
                        m_index) != index->hash_merkle_root()
                        )
                    {
                        return 0;
                    }
                    
                    m_merkle_verified = true;
                }

                index_out = index;

                ret =
                    stack_impl::get_block_index_best()->height() -
                    index->height() + 1
                ;

                return ret;
            }

            /**
             * If true it is in the main chain.
             */
            bool is_in_main_chain() const
            {
                return get_depth_in_main_chain(false) > 0;
            }

            /**
             * Sets the block hash.
             */
            void set_block_hash(const sha256 & value)
            {
                m_block_hash  = value;
            }
        
            /**
             * The block hash.
             */
            const sha256 & block_hash() const
            {
                return m_block_hash;
            }
        
            /**
             * Sets the merkle branch.
             * @param blk The block.
             */
            int set_merkle_branch(block * blk = 0)
            {
                if (globals::instance().is_client_spv() == true)
                {
                    if (m_block_hash == 0)
                    {
                        return 0;
                    }
                }
                else
                {
                    block blk_tmp;
                    
                    if (blk == 0)
                    {
                        /**
                         * Load the block this tx is in.
                         */
                        transaction_index tx_index;
                        
                        if (
                            db_tx("r").read_transaction_index(
                            get_hash(), tx_index) == false
                            )
                        {
                            return 0;
                        }
                        
                        if (
                            blk_tmp.read_from_disk(
                            tx_index.get_transaction_position().file_index(),
                            tx_index.get_transaction_position().block_position()
                            ) == false
                            )
                        {
                            return 0;
                        }
                        
                        blk = &blk_tmp;
                    }

                    /**
                     * Update the transaction's block hash.
                     */
                    m_block_hash = blk->get_hash();

                    /**
                     * Locate the transaction.
                     */
                    for (
                        m_index = 0; m_index < blk->transactions().size();
                        m_index++
                        )
                    {
                        if (
                            blk->transactions()[m_index] ==
                            *reinterpret_cast<transaction *>(this)
                            )
                        {
                            break;
                        }
                    }
                    
                    if (m_index == blk->transactions().size())
                    {
                        m_merkle_branch.clear();
                        
                        m_index = -1;
                        
                        log_error(
                            "Transaction merkle failed to set merkle branch, "
                            "unable to find transaction in block."
                        );

                        return 0;
                    }

                    /**
                     * Fill in the merkle branch.
                     */
                    m_merkle_branch = blk->get_merkle_branch(m_index);
                }

                /**
                 * Is the transaction in a block that's in the main chain?
                 */
                auto it = globals::instance().block_indexes().find(
                    m_block_hash
                );
                
                if (it == globals::instance().block_indexes().end())
                {
                    return 0;
                }

                if (!it->second || !it->second->is_in_main_chain())
                {
                    return 0;
                }
                
                return
                    stack_impl::get_block_index_best()->height() -
                    it->second->height() + 1
                ;
            }

            /**
             * Sets the merkle branch.
             */
            void set_merkle_branch(const std::vector<sha256> & value)
            {
                m_merkle_branch = value;
            }
        
            /**
             * The merkle branch.
             */
            const std::vector<sha256> & merkle_branch() const
            {
                return m_merkle_branch;
            }
        
            /**
             * Sets the index.
             */
            void set_index(const std::int32_t & value)
            {
                m_index = value;
            }
        
            /**
             * The index.
             */
            const std::int32_t & index() const
            {
                return m_index;
            }
        
            /**
             * Sets the (SPV) block height.
             * @param val The value.
             */
            void set_spv_block_height(const std::int32_t & val);
        
            /**
             * The (SPV) block height.
             */
            const std::int32_t & spv_block_height() const;
        
        private:
        
            /**
             * The block hash.
             */
            sha256 m_block_hash;
        
            /**
             * The merkle branch.
             */
            std::vector<sha256> m_merkle_branch;

            /**
             * The index.
             */
            std::int32_t m_index;

            /**
             * If true the merkle branch has been verified.
             */
            mutable bool m_merkle_verified;
    
            /**
             * Ths (SPV) block height.
             * @note This is not an encoded/decoded variable.
             */
            std::int32_t m_spv_block_height;
            
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_TRANSACTION_MERKLE_HPP
