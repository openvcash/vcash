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
#include <coin/checkpoint_sync.hpp>
#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/utility.hpp>

using namespace coin;

/**
 * ppcoin
 */
const std::string checkpoint_sync::g_master_public_key =
    "04b8d49de838594c2289037043e5330f12f4cb98f0a2f0cda90a2a957c3358c95480b"
    "b6db13fd5a50368c1f24096495eb473be801e5c919b0668a2f7acf74ed291"
;

/**
 * ppcoin
 */
std::string checkpoint_sync::g_master_private_key = "";

void checkpoint_sync::encode()
{
    encode(*this);
}

void checkpoint_sync::encode(data_buffer & buffer)
{
    buffer.write_var_int(m_message.size());
    buffer.write_bytes(
        reinterpret_cast<char *>(&m_message[0]), m_message.size()
    );
    
    buffer.write_var_int(m_signature.size());
    buffer.write_bytes(
        reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
    );
}

bool checkpoint_sync::decode()
{
    return decode(*this);
}

bool checkpoint_sync::decode(data_buffer & buffer)
{
    auto len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_message.resize(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_message[0]), m_message.size()
        );
    }
    
    len = buffer.read_var_int();
    
    if (len > 0)
    {
        m_signature.resize(len);
        
        buffer.read_bytes(
            reinterpret_cast<char *>(&m_signature[0]), m_signature.size()
        );
    }
    
    return true;
}

void checkpoint_sync::set_null()
{
    checkpoint_sync_unsigned::set_null();
    m_message.clear();
    m_signature.clear();
}

bool checkpoint_sync::is_null() const
{
    return m_hash_checkpoint == 0;
}

const std::string & checkpoint_sync::master_public_key()
{
    return g_master_public_key;
}

const std::string & checkpoint_sync::master_private_key()
{
    return g_master_private_key;
}

void checkpoint_sync::set_message(const std::vector<std::uint8_t> & val)
{
    m_message = val;
}

const std::vector<std::uint8_t> & checkpoint_sync::message() const
{
    return m_message;
}

void checkpoint_sync::set_signature(const std::vector<std::uint8_t> & val)
{
    m_signature = val;
}

std::vector<std::uint8_t> & checkpoint_sync::signature()
{
    return m_signature;
}

const std::vector<std::uint8_t> & checkpoint_sync::signature() const
{
    return m_signature;
}

bool checkpoint_sync::check_signature()
{
    key k;
    
    /**
     * Set the public key.
     */
    if (
        k.set_public_key(key_public(utility::from_hex(
        checkpoint_sync::master_public_key()))) == false
        )
    {
        log_error(
            "Checkpoint sync failed to check signature, "
            "set_public_key failed."
        );
    
        return false;
    }
    
    /**
     * Calculate the hash of the message.
     */
    auto hash_message = sha256::from_digest(&hash::sha256d(
        &m_message[0], &m_message[0] + m_message.size())[0]
    );
    
    /** 
     * Verify the message against the signature.
     */
    if (k.verify(hash_message, m_signature) == false)
    {
        log_error("Checkpoint sync failed to check signature, verify failed.");
        
        return false;
    }

    return true;
}

bool checkpoint_sync::process_sync_checkpoint(
    const std::shared_ptr<tcp_connection> & connection
    )
{
    /**
     * Check the signature.
     */
    if (check_signature() == false)
    {
        return false;
    }
    
    if (globals::instance().block_indexes().count(m_hash_checkpoint) == 0)
    {
        /**
         * We haven't received the checkpoint chain, keep the
         * checkpoint as pending.
         */
        checkpoints::instance().set_hash_pending_checkpoint(
            m_hash_checkpoint
        );
        checkpoints::instance().set_checkpoint_message_pending(*this);
        
        log_debug(
            "Checkpoint sync, pending for sync checkpoint " <<
            m_hash_checkpoint.to_string() << "."
        );
        
        /**
         * Ask this guy to fill in what we're missing.
         */
        if (connection)
        {
            /**
             * Send getblocks.
             */
            connection->send_getblocks_message(
                stack_impl::get_block_index_best(), m_hash_checkpoint
            );
            
            /**
             * Ask directly as well in case rejected earlier by duplicate
             * proof-of-stake because getblocks may not get it this time.
             */
            connection->send_inv_message(
                inventory_vector::type_msg_block,
                globals::instance().orphan_blocks().count(
                m_hash_checkpoint) > 0 ? utility::wanted_by_orphan(
                globals::instance().orphan_blocks()[m_hash_checkpoint]) :
                m_hash_checkpoint
            );
        }
        
        return false;
    }

    if (
        checkpoints::instance().validate_sync_checkpoint(
        m_hash_checkpoint) == false
        )
    {
        return false;
    }
    
    db_tx tx_db;
    
    auto index_checkpoint =
        globals::instance().block_indexes()[m_hash_checkpoint]
    ;
    
    if (index_checkpoint->is_in_main_chain() == false)
    {
        /**
         * The checkpoint chain has been received but is not yet in the
         * main chain.
         */
        block blk;
        
        if (blk.read_from_disk(index_checkpoint) == false)
        {
            log_debug(
                "Checkpoint sync, process sync checkpoint failed, read "
                "from disk failed for sync checkpoint " <<
                m_hash_checkpoint.to_string() << "."
            );
       
            return false;
        }
        
        if (blk.set_best_chain(tx_db, index_checkpoint) == false)
        {
            checkpoints::instance().set_hash_invalid_checkpoint(
                m_hash_checkpoint
            );
            
            log_debug(
                "Checkpoint sync, process sync checkpoint failed, set best "
                "chain failed for sync checkpoint " <<
                m_hash_checkpoint.to_string() << "."
            );

            return false;
        }
    }
    
    tx_db.close();

    if (
        checkpoints::instance().write_sync_checkpoint(
        m_hash_checkpoint) == false
        )
    {
        log_debug(
            "Checkpoint sync, process sync checkpoint failed, failed "
            "to write sync checkpoint " << m_hash_checkpoint.to_string() << "."
        );
    
        return false;
    }
    
    checkpoints::instance().set_checkpoint_message(*this);
    checkpoints::instance().set_hash_pending_checkpoint(0);
    checkpoints::instance().get_checkpoint_message_pending().set_null();
    
    log_debug(
        "Checkpoint sync, processed at " << m_hash_checkpoint.to_string() <<
        "."
    );
    
    return true;
}
