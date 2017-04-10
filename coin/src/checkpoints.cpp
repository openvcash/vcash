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
    m_checkpoints[113966] = sha256(
        "1e62cbed032e20bd11fc8a9663739cc1ad1da441a4472a507e9663b34dffe86c"
    );
    m_checkpoints[127440] = sha256(
        "9cc61ef82c964da1ff42d720f81b2fb2f02f68dc172b0973dc2e4221d02d02a3"
    );
    m_checkpoints[193123] = sha256(
        "c30086972070db8ed6a41ee40c5513466b0fd2659807519085a3bdabd6e28dda"
    );
    m_checkpoints[210000] = sha256(
        "bf7966ccf7cba4c151cc6e990b320a1a097a886c15e2cc026c3f69690b375b67"
    );
    m_checkpoints[239306] = sha256(
        "00000000000258dc0931448a2c333a7f22a9e4ce68c3d1098a58ecd576d9714f"
    );
    m_checkpoints[249556] = sha256(
        "00000000000014d2a03f03655d6e47c7710f6bbd7080f645918f38fa1df8acca"
    );
    m_checkpoints[275000] = sha256(
        "000000000000b1511fbc2beb3c2eff0f9e8b356e065ca36aadaf2b15925f1530"
    );
    m_checkpoints[300000] = sha256(
        "7faf69f614805521e5c431ba215905a9027e89bd30f79b28a17bbdf98179919f"
    );
    m_checkpoints[325000] = sha256(
        "5b5328da4a16f07f5c47c449c17754d1c4fce77918aaa1944953eee12190649e"
    );
    m_checkpoints[340000] = sha256(
        "000000000000478dc5c5ead7ca6bb0421b61a8879c95a9e71c3cf161510d637c"
    );
    m_checkpoints[350000] = sha256(
        "fc35f333efc1c30ce4d61a85246fd88ca7854914b283f250f5a5151fe758f511"
    );
    m_checkpoints[388800] = sha256(
        "000000000000d7233c8735ecc5006fcd1aa4ecaf7c4525208c1459c9f4d21517"
    );
    m_checkpoints[400000] = sha256(
        "000000000000bed29e0493ec2ae5cb4622542b3b574c6e69a30dbcc25bd003a9"
    );
    m_checkpoints[404500] = sha256(
        "000000000001ec481b7427f43e57ea46a0e51b13c2d0395a6d0c2d7f15de2be1"
    );
    m_checkpoints[409500] = sha256(
        "0000000000004899e0ca41b2af07c371226cab9fd3b269016195f5db2327ad14"
    );
    m_checkpoints[410267] = sha256(
        "1144741b1fdf0f1336c9d398b69fcb74e81727697946b5295d296ccb8dd78a5b"
    );
    m_checkpoints[410776] = sha256(
        "0000000000017a405efcae2f2ac7a22f0b205d8a200ff1171f83cbeae62acb27"
    );
    m_checkpoints[463158] = sha256(
        "18c4b4b23c9783d2cd32436b333991f973a37897d1f501aa8d2a108770819840"
    );
    m_checkpoints[500000] = sha256(
        "f9c1fcd8dc68fd1dd6ad4650c3f3519e267aef43342c7827084e6322ec54e850"
    );
    m_checkpoints[550000] = sha256(
        "f57e010e4ad84a46be631b59fbdad73486f946760dc9e5f2d1cf391676cfb796"
    );
    m_checkpoints[590000] = sha256(
        "1a54f5906f8a281457d651ccdc57c6d18de59b65a9ae6e6bf8ce9e4ef195d2ac"
    );
    m_checkpoints[635000] = sha256(
        "00000000000dda8a8a6b8ffdb62048d074f89d99be1099d1f166d3459e99eeba"
    );
    m_checkpoints[635900] = sha256(
        "0000000000012144eeaf106d05b039953b4c899944efc619d8e5f11224bebf1f"
    );
    m_checkpoints[645000] = sha256(
        "fcc3b088fc3995619f00858feacd07e85ca2572e2137822a4f529340b8fa9563"
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
    const sha256 & hash_block, const block_index * index_previous
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
    
    auto index_checkpoint_recv =
        globals::instance().block_indexes()[hash_checkpoint]
    ;

    if (index_checkpoint_recv->height() <= index_sync_checkpoint->height())
    {
        /**
         * Received an older checkpoint, trace back from current checkpoint
         * to the same height of the received checkpoint to verify
         * that current checkpoint should be a descendant block.
        */
        auto pindex = index_sync_checkpoint;
        
        while (pindex->height() > index_checkpoint_recv->height())
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
    auto index = index_checkpoint_recv;
    
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

std::map<std::int32_t, std::pair<sha256, std::time_t> >
    checkpoints::get_spv_checkpoints()
{
    /**
     * The checkpoint timestamps.
     */
    std::map<std::int32_t, std::pair<sha256, std::time_t> > ret;
    
    /**
     * The test net doesn't have checkpoints.
     */
    if (constants::test_net == true)
    {
        return ret;
    }

	ret[0] = std::make_pair(sha256(
		"15e96604fbcf7cd7e93d072a06f07ccfe1f8fd0099270a075c761c447403a783"),
        1419310800
	);
	ret[4000] = std::make_pair(sha256(
        "0000005daa461b5330897b9e8149142d6556fff12fcdf7b77eb40a6d76f1f3ad"),
        1419506259
    );
    ret[8120] = std::make_pair(sha256(
        "00000239d4c857d35b3b83c05287cbbb80b4f57c3d1807507ea915e7492dfa80"),
        1419784967
    );
    ret[14800] = std::make_pair(sha256(
        "73a4658541a0f01947333bdaad7702484109172f51cc1a1baadc1ed8b6b6dd33"),
        1420103865
    );
    ret[17200] = std::make_pair(sha256(
        "0000005b0acba32e7f43e2f676e0f72b0d189232a719e292623abf373e198b4f"),
        1420159457
    );
    ret[23216] = std::make_pair(sha256(
        "cf6621bd25c0270b382115a367823bab987ac472127265790673f1ba4e663345"),
        1420445140
    );
    ret[25037] = std::make_pair(sha256(
        "000000f0316fc6613116f86bb9db5d0148b11fe656504c2dee7963bda6a7f49b"),
        1420610942
    );
    ret[39152] = std::make_pair(sha256(
        "45efa8799d197cb8cf68434feb368ba915659466bed0c59a7501a5f44bbe637b"),
        1421554015
    );
    ret[42645] = std::make_pair(sha256(
        "e19e67db37789791b2a73b88e66d3437e696cc41efb507fbef133af57c2dab51"),
        1421744137
    );
    ret[44709] = std::make_pair(sha256(
        "a64bad605bd4964057b146af621fae6d4fa4325be74bb544480eba08211be8e1"),
        1422148236
    );
    ret[50308] = std::make_pair(sha256(
        "0000000003a60f5afb4fdc3dfb6aad412ddda4500646461d5516aad433271f81"),
        1423702773
    );
    ret[73568] = std::make_pair(sha256(
        "a9b99a0f9e04d0fdff3132d5e74fe8c7bc5b840e1c090644de704f774b53977f"),
        1426207080
    );
    ret[113966] = std::make_pair(sha256(
        "1e62cbed032e20bd11fc8a9663739cc1ad1da441a4472a507e9663b34dffe86c"),
        1430629945
    );
    ret[127440] = std::make_pair(sha256(
        "9cc61ef82c964da1ff42d720f81b2fb2f02f68dc172b0973dc2e4221d02d02a3"),
        1433132338
    );
    ret[193123] = std::make_pair(sha256(
        "c30086972070db8ed6a41ee40c5513466b0fd2659807519085a3bdabd6e28dda"),
        1440815132
    );
    ret[210000] = std::make_pair(sha256(
        "bf7966ccf7cba4c151cc6e990b320a1a097a886c15e2cc026c3f69690b375b67"),
        1442676747
    );
    ret[239306] = std::make_pair(sha256(
        "00000000000258dc0931448a2c333a7f22a9e4ce68c3d1098a58ecd576d9714f"),
        1445990794
    );
    ret[249556] = std::make_pair(sha256(
        "00000000000014d2a03f03655d6e47c7710f6bbd7080f645918f38fa1df8acca"),
        1447163569
    );
    ret[275000] = std::make_pair(sha256(
        "000000000000b1511fbc2beb3c2eff0f9e8b356e065ca36aadaf2b15925f1530"),
        1450066441
    );
    ret[300000] = std::make_pair(sha256(
        "7faf69f614805521e5c431ba215905a9027e89bd30f79b28a17bbdf98179919f"),
        1452920121
    );
    ret[325000] = std::make_pair(sha256(
        "5b5328da4a16f07f5c47c449c17754d1c4fce77918aaa1944953eee12190649e"),
        1455781092
    );
    ret[340000] = std::make_pair(sha256(
        "000000000000478dc5c5ead7ca6bb0421b61a8879c95a9e71c3cf161510d637c"),
        1457394331
    );
    ret[350000] = std::make_pair(sha256(
        "fc35f333efc1c30ce4d61a85246fd88ca7854914b283f250f5a5151fe758f511"),
        1458477657
    );
    ret[388800] = std::make_pair(sha256(
        "000000000000d7233c8735ecc5006fcd1aa4ecaf7c4525208c1459c9f4d21517"),
        1462809732
    );
    ret[400000] = std::make_pair(sha256(
        "000000000000bed29e0493ec2ae5cb4622542b3b574c6e69a30dbcc25bd003a9"),
        1464073422
    );
    ret[404500] = std::make_pair(sha256(
        "000000000001ec481b7427f43e57ea46a0e51b13c2d0395a6d0c2d7f15de2be1"),
        1464586438
    );
    ret[409500] = std::make_pair(sha256(
        "0000000000004899e0ca41b2af07c371226cab9fd3b269016195f5db2327ad14"),
        1465150759
    );
    ret[410267] = std::make_pair(sha256(
        "1144741b1fdf0f1336c9d398b69fcb74e81727697946b5295d296ccb8dd78a5b"),
        1465236780
    );
    ret[410776] = std::make_pair(sha256(
        "0000000000017a405efcae2f2ac7a22f0b205d8a200ff1171f83cbeae62acb27"),
        1465294865
    );
    ret[463158] = std::make_pair(sha256(
        "18c4b4b23c9783d2cd32436b333991f973a37897d1f501aa8d2a108770819840"),
        1471224073
    );
    ret[500000] = std::make_pair(sha256(
        "f9c1fcd8dc68fd1dd6ad4650c3f3519e267aef43342c7827084e6322ec54e850"),
        1475362148
    );
    ret[550000] = std::make_pair(sha256(
        "f57e010e4ad84a46be631b59fbdad73486f946760dc9e5f2d1cf391676cfb796"),
        1480975915
    );
    ret[590000] = std::make_pair(sha256(
        "1a54f5906f8a281457d651ccdc57c6d18de59b65a9ae6e6bf8ce9e4ef195d2ac"),
        1485456470
    );
    ret[635000] = std::make_pair(sha256(
        "00000000000dda8a8a6b8ffdb62048d074f89d99be1099d1f166d3459e99eeba"),
        1490498159
    );
    ret[635900] = std::make_pair(sha256(
        "0000000000012144eeaf106d05b039953b4c899944efc619d8e5f11224bebf1f"),
        1490596328
    );
    ret[645000] = std::make_pair(sha256(
        "fcc3b088fc3995619f00858feacd07e85ca2572e2137822a4f529340b8fa9563"),
        1491624221
    );
    
    return ret;
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

const block_index * checkpoints::get_last_sync_checkpoint()
{
    if (globals::instance().block_indexes().count(m_hash_sync_checkpoint) == 0)
    {
        log_debug(
            "Checkpoints get last sync checkpoint failed, block index missing "
            "for current sync-checkpoint " <<
            m_hash_sync_checkpoint.to_string() << "."
        );
        
        return 0;
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
        log_error("Checkpoints,  master key unavailable.");
        
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
