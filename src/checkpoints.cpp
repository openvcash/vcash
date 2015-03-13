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

#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/checkpoints.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>

using namespace coin;

checkpoints::checkpoints()
{
    m_checkpoints[0] = block::get_hash_genesis();
    m_checkpoints[4000] = sha256(
        "0000005daa461b5330897b9e8149142d6556fff12fcdf7b77eb40a6d76f1f3ad"
    );
    m_checkpoints[8120] = sha256(
        "00000239d4c857d35b3b83c05287cbbb80b4f57c3d1807507ea915e7492dfa80"
    );
    m_checkpoints[14800] = sha256(
        "73a4658541a0f01947333bdaad7702484109172f51cc1a1baadc1ed8b6b6dd33"
    );
    m_checkpoints[17200] = sha256(
        "0000005b0acba32e7f43e2f676e0f72b0d189232a719e292623abf373e198b4f"
    );
    m_checkpoints[23216] = sha256(
        "cf6621bd25c0270b382115a367823bab987ac472127265790673f1ba4e663345"
    );
    m_checkpoints[25037] = sha256(
        "000000f0316fc6613116f86bb9db5d0148b11fe656504c2dee7963bda6a7f49b"
    );
    m_checkpoints[39152] = sha256(
        "45efa8799d197cb8cf68434feb368ba915659466bed0c59a7501a5f44bbe637b"
    );
    m_checkpoints[42645] = sha256(
        "e19e67db37789791b2a73b88e66d3437e696cc41efb507fbef133af57c2dab51"
    );
    m_checkpoints[44709] = sha256(
        "a64bad605bd4964057b146af621fae6d4fa4325be74bb544480eba08211be8e1"
    );
    m_checkpoints[50308] = sha256(
        "0000000003a60f5afb4fdc3dfb6aad412ddda4500646461d5516aad433271f81"
    );
    m_checkpoints[73568] = sha256(
        "a9b99a0f9e04d0fdff3132d5e74fe8c7bc5b840e1c090644de704f774b53977f"
    );
    
    m_checkpoints_test_net[0] = block::get_hash_genesis_test_net();
}

checkpoints & checkpoints::instance()
{
    static checkpoints g_checkpoints;
            
    return g_checkpoints;
}

bool checkpoints::check_hardened(
    const std::int32_t & height, const sha256 & hash
    )
{
    auto & checkpoints =
        (constants::test_net ?
        m_checkpoints_test_net : m_checkpoints)
    ;

    auto it = checkpoints.find(height);
    
    if (it == checkpoints.end())
    {
        return true;
    }
    
    return hash == it->second;
}

bool checkpoints::check_sync(
    const sha256 & hash_block,
    const std::shared_ptr<block_index> & index_previous
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * The test net doesn't have checkpoints.
     */
    if (constants::test_net)
    {
        return true;
    }
    
    auto height = index_previous->height() + 1;

    /**
     * The sync-checkpoint should always be accepted block.
     */
    assert(
        globals::instance().block_indexes().count(m_hash_sync_checkpoint)
    );

    auto index_sync =
        globals::instance().block_indexes()[m_hash_sync_checkpoint]
    ;

    if (height > index_sync->height())
    {
        /**
         * Trace back to same height as sync-checkpoint.
         */
        auto index = index_previous;
        
        while (index->height() > index_sync->height())
        {
            if ((index = index->block_index_previous()) == 0)
            {
                log_error(
                    "Checkpoints, check sync failed, previous block "
                    "index is null (block index structure failure)."
                );
                
                return false;
            }
        }
        
        /**
         * Only descendant's of the a sync-checkpoint can pass.
         */
        if (
            index->height() < index_sync->height() ||
            index->get_block_hash() != m_hash_sync_checkpoint
            )
        {
            return false;
        }
    }
    
    /**
     * The same height with sync-checkpoint.
     */
    if (height == index_sync->height() && hash_block != m_hash_sync_checkpoint)
    {
        return false;
    }
    
    /**
     * Lower height than the sync-checkpoint
     */
    if (
        height < index_sync->height() &&
        globals::instance().block_indexes().count(hash_block) == false
        )
    {
        return false;
    }
    
    return true;
}

bool checkpoints::validate_sync_checkpoint(const sha256 & hash_checkpoint)
{
    if (globals::instance().block_indexes().count(m_hash_sync_checkpoint) == 0)
    {
        log_error(
            "Checkpoints, validate sync checkpoint failed, block index "
            "missing for current sync-checkpoint " <<
            m_hash_sync_checkpoint.to_string() << "."
        );
        
        return false;
    }
    
    if (globals::instance().block_indexes().count(hash_checkpoint) == 0)
    {
        log_error(
            "Checkpoints, validate sync checkpoint failed, block index "
            "missing for received sync-checkpoint " <<
            hash_checkpoint.to_string() << "."
        );
        
        return false;
    }

    auto index_sync_checkpoint =
        globals::instance().block_indexes()[m_hash_sync_checkpoint]
    ;
    
    auto index_checkpointRecv =
        globals::instance().block_indexes()[hash_checkpoint]
    ;

    if (index_checkpointRecv->height() <= index_sync_checkpoint->height())
    {
        /**
         * Received an older checkpoint, trace back from current checkpoint
         * to the same height of the received checkpoint to verify
         * that current checkpoint should be a descendant block.
        */
        auto pindex = index_sync_checkpoint;
        
        while (pindex->height() > index_checkpointRecv->height())
        {
            if (!(pindex = pindex->block_index_previous()))
            {
                 log_error(
                    "Checkpoints, validate sync checkpoint failed, "
                    "previous index is null - block index structure failure."
                );
                
                return false;
            }
        }
        
        if (pindex->get_block_hash() != hash_checkpoint)
        {
            m_hash_invalid_checkpoint = hash_checkpoint;
            
            log_error(
                "Checkpoints, validate sync checkpoint failed, new "
                "sync-checkpoint " << hash_checkpoint.to_string() <<
                " is conflicting with current sync-checkpoint " <<
                m_hash_sync_checkpoint.to_string().c_str()
            );
            
            return false;
        }
        
        /**
         * Ignore older checkpoint.
         */
        return false;
    }

    /**
     * Received checkpoint should be a descendant block of the current
     * checkpoint. Trace back to the same height of current checkpoint
     * to verify.
     */
    auto index = index_checkpointRecv;
    
    while (index->height() > index_sync_checkpoint->height())
    {
        if (!(index = index->block_index_previous()))
        {
            log_error(
                "Checkpoints, validate sync checkpoint failed, previous "
                "index is null - block index structure failure"
            );
            
            return false;
        }
    }
    
    if (index->get_block_hash() != m_hash_sync_checkpoint)
    {
        m_hash_invalid_checkpoint = hash_checkpoint;
        
        log_error(
            "Checkpoints, validate sync checkpoint failed, new "
            "sync-checkpoint " << hash_checkpoint.to_string() << " is not a "
            "descendant of current sync-checkpoint " <<
            m_hash_sync_checkpoint.to_string() << "."
        );
        
        return false;
    }
    
    return true;
}

std::uint32_t checkpoints::get_total_blocks_estimate()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return (
        constants::test_net ? m_checkpoints_test_net : m_checkpoints
    ).rbegin()->first;
}

sha256 & checkpoints::get_hash_sync_checkpoint()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_hash_sync_checkpoint;
}

void checkpoints::set_hash_pending_checkpoint(const sha256 & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_hash_pending_checkpoint = val;
}

const sha256 & checkpoints::get_hash_pending_checkpoint() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_hash_pending_checkpoint;
}

void checkpoints::set_checkpoint_message(const checkpoint_sync & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_checkpoint_message = val;
}

const checkpoint_sync & checkpoints::get_checkpoint_message() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_checkpoint_message;
}

void checkpoints::set_checkpoint_message_pending(const checkpoint_sync & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_checkpoint_message_pending = val;
}

checkpoint_sync & checkpoints::get_checkpoint_message_pending()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_checkpoint_message_pending;
}

const checkpoint_sync & checkpoints::get_checkpoint_message_pending() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_checkpoint_message_pending;
}

std::shared_ptr<block_index> checkpoints::get_last_sync_checkpoint()
{
    if (globals::instance().block_indexes().count(m_hash_sync_checkpoint) == 0)
    {
        log_debug(
            "Checkpoints get last sync checkpoint failed, block index missing "
            "for current sync-checkpoint " <<
            m_hash_sync_checkpoint.to_string() << "."
        );
        
        return std::shared_ptr<block_index> ();
    }
    
    return globals::instance().block_indexes()[m_hash_sync_checkpoint];
}

void checkpoints::set_hash_invalid_checkpoint(const sha256 & val)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    m_hash_invalid_checkpoint = val;
}

const sha256 & checkpoints::get_hash_invalid_checkpoint() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    return m_hash_invalid_checkpoint;
}

std::map<int, sha256> checkpoints::get_checkpoints()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_checkpoints.size() == 0)
    {
        /**
         * Add any checkpoints here.
         */
        m_checkpoints[0] = block::get_hash_genesis();
    }
    
    return m_checkpoints;
}

std::map<int, sha256> checkpoints::get_checkpoints_test_net()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_checkpoints_test_net.size() == 0)
    {
        /**
         * Add any checkpoints here.
         */
        m_checkpoints_test_net[0] =
            block::get_hash_genesis_test_net()
        ;
    }
    
    return m_checkpoints_test_net;
}

void checkpoints::ask_for_pending_sync_checkpoint(
    const std::shared_ptr<tcp_connection> & connection
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (
        connection && m_hash_pending_checkpoint != 0 &&
        (globals::instance().block_indexes().count(
        m_hash_pending_checkpoint) == 0) &&
        (globals::instance().orphan_blocks().count(
        m_hash_pending_checkpoint) == 0)
        )
    {
        std::vector<inventory_vector> getdata;

        inventory_vector inv(
            inventory_vector::type_msg_block, m_hash_pending_checkpoint
        );

        getdata.push_back(inv);

        connection->send_getdata_message(getdata);
    }
}

bool checkpoints::send_sync_checkpoint(
    const std::shared_ptr<tcp_connection_manager> & connection_manager,
    const sha256 & hash_checkpoint
    )
{
    checkpoint_sync checkpoint;
    
    /**
     * Set the checkpoint hash.
     */
    checkpoint.set_hash_checkpoint(hash_checkpoint);

    /**
     * Allocate the buffer.
     */
    data_buffer buffer;
    
    /** 
     * Encode the base class into the buffer.
     */
    ((checkpoint_sync_unsigned)checkpoint).encode(buffer);
    
    /**
     * Set the message.
     */
    checkpoint.set_message(
        std::vector<std::uint8_t>(buffer.data(), buffer.data() + buffer.size())
    );

    /**
     * Check if we have the master private key.
     */
    if (checkpoint_sync::master_private_key().size() == 0)
    {
        log_error("SendSyncCheckpoint: Checkpoint master key unavailable.");
        
        return false;
    }
    
    /**
     * Convert the private key from hex.
     */
    std::vector<std::uint8_t> private_key = utility::from_hex(
        checkpoint_sync::master_private_key()
    );
    
    /**
     * Allocate the key.
     */
    key k;
    
    /**
     * Set the private key.
     */
    k.set_private_key(
        key::private_t(private_key.begin(), private_key.end())
    );
    
    /**
     * Calculate the signature.
     */
    auto sig = sha256::from_digest(&hash::sha256d(
        &checkpoint.message()[0],
        &checkpoint.message()[0] + checkpoint.message().size())[0]
    );
    
    /**
     * Sign the signature.
     */
    if (k.sign(sig, checkpoint.signature()) == false)
    {
        log_error(
            "Checkpoints send sync checkpoint failed, unable to sign "
            "checkpoint, possible invalid private key."
        );
        
        return false;
    }
    
    /**
     * Process the sync checkpoint.
     */
    if (checkpoint.process_sync_checkpoint(0) == false)
    {
        log_debug(
            "Checkpoints failed to send sync checkpoint, failed to process "
            "sync checkpoint."
        );
        
        return false;
    }

    /**
     * Relay the checkpoints.
     */
    for (auto & i : connection_manager->tcp_connections())
    {
        if (auto connection = i.second.lock())
        {
            if (connection->hash_checkpoint_known() != m_hash_sync_checkpoint)
            {
                connection->set_hash_checkpoint_known(m_hash_sync_checkpoint);
                
                connection->send_checkpoint_message(checkpoint);
            }
        }
    }

    return true;
}

bool checkpoints::write_sync_checkpoint(const sha256 & hash_checkpoint)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    db_tx tx_db;
    
    tx_db.txn_begin();
    
    if (tx_db.write_hashsynccheckpoint(hash_checkpoint) == false)
    {
        tx_db.txn_abort();
        
        log_error(
            "WriteSyncCheckpoint(): failed to write to db sync checkpoint " <<
            hash_checkpoint.to_string() <<  "."
        );
        
        return false;
    }
    
    if (tx_db.txn_commit() == false)
    {
        log_error(
            "WriteSyncCheckpoint(): failed to commit to db sync checkpoint " <<
            hash_checkpoint.to_string() << "."
        );
    
        return false;
    }
    
    tx_db.close();

    m_hash_sync_checkpoint = hash_checkpoint;
    
    return true;
}

bool checkpoints::accept_pending_sync_checkpoint(
    const std::shared_ptr<tcp_connection_manager> & connection_manager
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (
        m_hash_pending_checkpoint != 0 &&
        globals::instance().block_indexes().count(m_hash_pending_checkpoint) > 0
        )
    {
        if (validate_sync_checkpoint(m_hash_pending_checkpoint) == false)
        {
            m_hash_pending_checkpoint = 0;
            
            m_checkpoint_message_pending.set_null();
            
            return false;
        }

        db_tx tx_db;
        
        auto index_checkpoint =
            globals::instance().block_indexes()[m_hash_pending_checkpoint]
        ;
        
        if (index_checkpoint->is_in_main_chain() == false)
        {
            block blk;
            
            if (blk.read_from_disk(index_checkpoint) == false)
            {
                log_error(
                    "Checkpoints, accept pending sync checkpoint failed, "
                    "read_from_disk failed for sync checkpoint " <<
                    m_hash_pending_checkpoint.to_string() << "."
                );
            
                return false;
            }
            
            if (blk.set_best_chain(tx_db, index_checkpoint) == false)
            {
                m_hash_invalid_checkpoint = m_hash_pending_checkpoint;
                
                log_error(
                    "Checkpoints, accept pending sync checkpoint failed, "
                    "set_best_chain failed for sync checkpoint " <<
                    m_hash_pending_checkpoint.to_string() << "."
                );
                
                return false;
            }
        }
        
        tx_db.close();

        if (write_sync_checkpoint(m_hash_pending_checkpoint) == false)
        {
            log_error(
                "Checkpoints, accept pending sync checkpoint failed, "
                "failed to write sync checkpoint " <<
                m_hash_pending_checkpoint.to_string() << "."
            );
       
            return false;
        }
        
        m_hash_pending_checkpoint = 0;
        
        m_checkpoint_message = m_checkpoint_message_pending;
        
        m_checkpoint_message_pending.set_null();
        
        log_debug(
            "Checkpoints, accept pending sync checkpoint, sync "
            "checkpoint at " << m_hash_sync_checkpoint.to_string() << "."
        );
        
        /**
         * Broadcast the checkpoint to connected peers.
         */
        if (m_checkpoint_message.is_null() == false)
        {
            for (auto & i : connection_manager->tcp_connections())
            {
                if (auto connection = i.second.lock())
                {
                    connection->send_checkpoint_message(m_checkpoint_message);
                }
            }
        }
        
        return true;
    }
    
    return false;
}

sha256 checkpoints::auto_select_sync_checkpoint()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    /**
     * Proof-of-work blocks are immediately checkpointed to defend against 51%
     * attack which rejects other miners block.
     */

    /**
     * Select the last proof-of-work block.
     */
    auto index = utility::get_last_block_index(
        stack_impl::get_block_index_best(), false
    );
    
    /**
     * Search forward for a block within max span and maturity window.
     */
    while (
        index->block_index_next() &&
        (index->time() + checkpoint_max_span <=
        stack_impl::get_block_index_best()->time() || index->height() +
        std::min(6, constants::coinbase_maturity - 20) <=
        stack_impl::get_block_index_best()->height())
        )
    {
        index = index->block_index_next();
    }
    
    return index->get_block_hash();
}

bool checkpoints::reset_sync_checkpoint()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    assert(m_checkpoints.size());
    
    const auto & h = m_checkpoints.rbegin()->second;

    if (
        globals::instance().block_indexes().count(h) &&
        globals::instance().block_indexes()[h]->is_in_main_chain() == false
        )
    {
        /**
         * Checkpoint block accepted but not yet in main chain.
         */
        log_debug(
            "Checkpoints, setting best chain to hardened checkpoint " <<
            h.to_string() << "."
        );
        
        db_tx tx_db;
        
        block blk;
        
        if (
            blk.read_from_disk(globals::instance().block_indexes()[h]) == false
            )
        {
            log_error(
                "Checkpoints, failed to read from disk for hardened "
                "checkpoint " << h.to_string() << "."
            );
            
            return false;
        }
        
        if (
            blk.set_best_chain(tx_db,
            globals::instance().block_indexes()[h]) == false
            )
        {
            log_error(
                "Checkpoints, failed to set best chain for hardened "
                "checkpoint " << h.to_string() << "."
            );
            
            return false;
        }
        
        tx_db.close();
    }
    else if (globals::instance().block_indexes().count(h) == 0)
    {
        /**
         * Checkpoint block not yet accepted.
         */
        m_hash_pending_checkpoint = h;
        
        m_checkpoint_message_pending.set_null();
        
        log_debug(
            "Checkpoints, pending for sync-checkpoint " <<
            m_hash_pending_checkpoint.to_string() << "."
        );
    }

    for (auto it = m_checkpoints.rbegin(); it != m_checkpoints.rend(); ++it)
    {
        const auto & h = it->second;
        
        if (
            globals::instance().block_indexes().count(h) > 0 &&
            globals::instance().block_indexes()[h]->is_in_main_chain()
            )
        {
            if (write_sync_checkpoint(h) == false)
            {
                log_error(
                    "Checkpoints, failed to write sync checkpoint " <<
                    h.to_string() << "."
                );
                
                return false;
            }
            
            log_debug(
                "Checkpoints, sync-checkpoint reset to " <<
                m_hash_sync_checkpoint.to_string() << "."
            );
            
            return true;
        }
    }

    return false;
}

bool checkpoints::wanted_by_pending_sync_checkpoint(const sha256 & hash_block)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_);
    
    if (m_hash_pending_checkpoint == 0)
    {
        return false;
    }
    else if (hash_block == m_hash_pending_checkpoint)
    {
        return true;
    }
    else if (
        globals::instance().orphan_blocks().count(m_hash_pending_checkpoint) &&
        hash_block == utility::wanted_by_orphan(
        globals::instance().orphan_blocks()[m_hash_pending_checkpoint]))
    {
        return true;
    }
    
    return false;
}
