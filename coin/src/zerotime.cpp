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

#include <cassert>

#include <coin/address.hpp>
#include <coin/block_merkle.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/time.hpp>
#include <coin/transaction.hpp>
#include <coin/types.hpp>
#include <coin/utility.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

std::mutex zerotime::mutex_;

zerotime::zerotime()
{
    /**
     * Generate a new key.
     */
    m_key.make_new_key(true);

    if (globals::instance().is_zerotime_enabled())
    {
        log_info(
            "ZeroTime generated new key = " <<
            address(m_key.get_public_key().get_id()
            ).to_string().substr(0, 8) << "."
        );
        
        /**
         * The signature.
         */
        std::vector<std::uint8_t> signature;
        
        /**
         * The nonce hash.
         */
        sha256 hash_nonce = hash::sha256_random();
        
        /**
         * Calculate the hash of the nonce hash.
         */
        auto digest = hash::sha256d(
            hash_nonce.digest(), sha256::digest_length
        );

        /**
         * Hash the encoded message buffer.
         */
        sha256 hash_value = sha256::from_digest(&digest[0]);
        
        auto success = sign(hash_value, signature);
        
        assert(success);
        
        success = verify(m_key.get_public_key(), hash_value, signature);
        
        assert(success);
    }
}

zerotime & zerotime::instance()
{
    static zerotime g_zerotime;
    
    std::lock_guard<std::mutex> l1(mutex_);
    
    return g_zerotime;
}

key & zerotime::get_key()
{
    return m_key;
}

std::map<point_out, sha256> & zerotime::locked_inputs()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    return m_locked_inputs;
}

std::map<sha256, zerotime_lock> & zerotime::locks()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locks_);
    
    return m_locks;
}

std::map<sha256, zerotime_vote> & zerotime::votes()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_votes_);
    
    return m_votes;
}

std::map<sha256, std::size_t> & zerotime::confirmations()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_confirmations_);
    
    return m_confirmations;
}

bool zerotime::has_lock_conflict(const transaction & tx)
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    for (auto & i : tx.transactions_in())
    {
        if (m_locked_inputs.count(i.previous_out()) > 0)
        {
            if (m_locked_inputs[i.previous_out()] != tx.get_hash())
            {
                return true;
            }
        }
    }

    return false;
}

bool zerotime::has_lock_conflict(
    const std::vector<transaction_in> & transactions_in, const sha256 & hash_tx
    )
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    for (auto & i : transactions_in)
    {
        if (m_locked_inputs.count(i.previous_out()) > 0)
        {
            if (m_locked_inputs[i.previous_out()] != hash_tx)
            {
                return true;
            }
        }
    }

    return false;
}

void zerotime::resolve_conflicts(
    const std::vector<transaction_in> & transactions_in, const sha256 & hash_tx
    )
{
    /**
     * If we've found a lock conflict then remove all related locked inputs, in
     * which case the transaction will wait to be confirmed via block event.
     */
    assert(has_lock_conflict(transactions_in, hash_tx));

    log_info(
        "ZeroTime has transaction lock conflict on " <<
        hash_tx.to_string().substr(0, 8) << ", resolving."
    );
    
    std::lock_guard<std::recursive_mutex> l1(
        recursive_mutex_locked_inputs_
    );
    
    for (auto & i : transactions_in)
    {
        if (m_locked_inputs.count(i.previous_out()) > 0)
        {
            m_locked_inputs.erase(i.previous_out());
        }
    }
}

void zerotime::clear_expired_input_locks()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    std::lock_guard<std::recursive_mutex> l2(recursive_mutex_locks_);
    
    std::lock_guard<std::recursive_mutex> l3(recursive_mutex_votes_);

    std::lock_guard<std::recursive_mutex> l4(recursive_mutex_confirmations_);
    
    auto it = m_locks.begin();

    while (it != m_locks.end())
    {
        /**
         * Remove locks that are either expired or have an invalid expiration.
         */
        if (
            time::instance().get_adjusted() > it->second.expiration() ||
            it->second.expiration() - time::instance().get_adjusted() >
            zerotime_lock::interval_max_expire
            )
        {
            auto hash_tx = it->second.hash_tx();
            
            log_info(
                "ZeroTime is removing expired transaction objects " <<
                hash_tx.to_string().substr(0, 8) << "."
            );
            
            const auto & transactions_in = it->second.transactions_in();

            for (auto & in : transactions_in)
            {
                if (m_locked_inputs.count(in.previous_out()) > 0)
                {
                    m_locked_inputs.erase(in.previous_out());
                }
            }

            if (m_votes.count(hash_tx) > 0)
            {
                m_votes.erase(hash_tx);
            }
            
            if (m_confirmations.count(hash_tx) > 0)
            {
                m_confirmations.erase(hash_tx);
            }

            it = m_locks.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

std::int16_t zerotime::calculate_score(const key_public & public_key)
{
	std::int16_t ret = -1;
    
    /**
     * Get the best block index.
     */
    block_index * index = 0;
    
    if (globals::instance().is_client_spv() == false)
    {
        index = utility::find_block_index_by_height(
            globals::instance().best_block_height()
        );
    }
    
    if (
        index || (globals::instance().is_client_spv() == true &&
        globals::instance().spv_block_last())
        )
    {
        const auto & hash_block =
            globals::instance().is_client_spv() == true ?
            globals::instance().spv_block_last()->get_hash() :
            index->get_block_hash()
        ;

        if (public_key.is_valid())
        {
            /**
             * Hash the hash public key.
             */
            auto digest1 = hash::sha256d(
                public_key.get_hash().digest(),
                sha256::digest_length
            );
            
            /**
             * Hash the hash of the block.
             */
            auto digest2 = hash::sha256d(
                hash_block.digest(), sha256::digest_length
            );
            
            auto hash2 = sha256::from_digest(&digest2[0]);

            auto digest3 = hash::sha256d(
                &digest2[0], &digest2[0] + digest2.size(),
                &digest1[0], &digest1[0] + digest1.size()
            );
            
            auto hash3 = sha256::from_digest(&digest3[0]);
            
            if (hash3 > hash2)
            {
                ret =
                    static_cast<std::int16_t> (
                    (hash3 - hash2).to_uint64())
                ;
            }
            else
            {
                ret =
                    static_cast<std::int16_t> (
                    (hash2 - hash3).to_uint64())
                ;
            }
        }
    }
    
    return ret;
}

std::int16_t zerotime::calculate_score(const zerotime_vote & ztvote)
{
	std::int16_t ret = -1;

	if (
        globals::instance().is_client_spv() == false &&
        ztvote.block_height() == 0 ||
        ztvote.block_height() > globals::instance().best_block_height()
        )
	{
        // ...
	}
	else if (
        globals::instance().is_client_spv() == true &&
        ztvote.block_height() == 0 ||
        ztvote.block_height() > globals::instance().spv_best_block_height()
        )
	{
        // ...
	}
	else
	{
        /**
         * Get the best block_index.
         */
        block_index * index = 0;
        
        /**
         * Get the best block_merkle (for SPV).
         */
        std::unique_ptr<block_merkle> merkle_block;
        
        if (globals::instance().is_client_spv() == false)
        {
            index = utility::find_block_index_by_height(ztvote.block_height());
        }
        else
        {
            for (auto & i : globals::instance().spv_block_merkles())
            {
                if (i.second && i.second->height() == ztvote.block_height())
                {
                    merkle_block.reset(new block_merkle(*i.second));
                    
                    break;
                }
            }
        }
        
        if (index || merkle_block)
        {
            const auto & hash_block =
                merkle_block ? merkle_block->get_hash() :
                index->get_block_hash()
            ;
            
            if (hash_block == ztvote.hash_block())
            {
                if (ztvote.public_key().is_valid())
                {
                    /**
                     * Hash the hash public key.
                     */
                    auto digest1 = hash::sha256d(
                        ztvote.public_key().get_hash().digest(),
                        sha256::digest_length
                    );
                    
                    /**
                     * Hash the hash of the block.
                     */
                    auto digest2 = hash::sha256d(
                        hash_block.digest(), sha256::digest_length
                    );
                    
                    auto hash2 = sha256::from_digest(&digest2[0]);

                    auto digest3 = hash::sha256d(
                        &digest2[0], &digest2[0] + digest2.size(),
                        &digest1[0], &digest1[0] + digest1.size()
                    );
                    
                    auto hash3 = sha256::from_digest(&digest3[0]);
                    
                    if (hash3 > hash2)
                    {
                        ret =
                            static_cast<std::int16_t> (
                            (hash3 - hash2).to_uint64())
                        ;
                    }
                    else
                    {
                        ret =
                            static_cast<std::int16_t> (
                            (hash2 - hash3).to_uint64())
                        ;
                    }
                }
            }
        }
    }

    return ret;
}

bool zerotime::sign(
    const sha256 & hash_value, std::vector<std::uint8_t> & signature
    )
{
    return m_key.sign(hash_value, signature);
}

bool zerotime::verify(
    const key_public & public_key, const sha256 & hash_value,
    const std::vector<std::uint8_t> & signature
    )
{
    key k;

    return
        k.set_public_key(public_key) && k.verify(hash_value, signature)
    ;
}

void zerotime::print()
{
    log_debug("m_locked_inputs = " << m_locked_inputs.size());
    log_debug("m_locks = " << m_locks.size());
    log_debug("m_votes = " << m_votes.size());
    log_debug("m_confirmations = " << m_confirmations.size());
}
