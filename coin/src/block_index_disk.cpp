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
#include <coin/block_index_disk.hpp>
#include <coin/logger.hpp>

using namespace coin;

block_index_disk::block_index_disk(const char * buf, const std::size_t & len)
    : data_buffer(buf, len)
{
    // ...
}
            
block_index_disk::block_index_disk(block_index & index)
    : block_index(index)
    , data_buffer()
{
    m_hash_previous =
        m_block_index_previous == 0 ? sha256() :
        m_block_index_previous->get_block_hash()
    ;
    m_hash_next =
        m_block_index_next == 0 ? sha256() :
        m_block_index_next->get_block_hash()
    ;
}

void block_index_disk::encode()
{
    encode(*this);
}

void block_index_disk::encode(
    data_buffer & buffer, const bool & include_version
    )
{
    if (include_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(m_version);
    }
    
    /**
     * Write the next hash.
     */
    buffer.write_sha256(m_hash_next);
    
    /**
     * Write the file (index).
     */
    buffer.write_uint32(m_file);
    
    /**
     * Write the block position.
     */
    buffer.write_uint32(m_block_position);
    
    /**
     * Write the neight.
     */
    buffer.write_uint32(m_height);
    
    /**
     * Write the mint.
     */
    buffer.write_uint64(m_mint);
    
    /**
     * Write the money supply.
     */
    buffer.write_uint64(m_money_supply);
    
    /**
     * Write the flags.
     */
    buffer.write_uint32(m_flags);
    
    /**
     * Write the stake modifier.
     */
    buffer.write_uint64(m_stake_modifier);
    
    if (is_proof_of_stake())
    {
        /**
         * Write the previous out stake.
         */
        buffer.write_point_out(
            std::make_pair(m_previous_out_stake.get_hash(),
            m_previous_out_stake.n())
        );
        
        /**
         * Write the stake time.
         */
        buffer.write_uint32(m_stake_time);

        /**
         * Write the proof of stake hash.
         */
        buffer.write_sha256(m_hash_proof_of_stake);
    }
    else
    {
        m_previous_out_stake.set_null();
        m_stake_time = 0;
        m_hash_proof_of_stake.clear();
    }
    
    /**
     * Write the block header.
     */
    
    /**
     * Write the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Write the previous hash.
     */
    buffer.write_sha256(m_hash_previous);

    /**
     * Write the merkle root hash.
     */
    buffer.write_sha256(m_hash_merkle_root);
    
    /**
     * Write the time.
     */
    buffer.write_uint32(static_cast<std::uint32_t> (m_time));
    
    /**
     * Write the bits.
     */
    buffer.write_uint32(m_bits);
    
    /**
     * Write the nonce.
     */
    buffer.write_uint32(m_nonce);
}

void block_index_disk::decode()
{
    /**
     * Read the version.
     */
    m_version = read_uint32();
    
    /**
     * Read the next hash.
     */
    m_hash_next = read_sha256();
    
    /**
     * Read the file (index).
     */
    m_file = read_uint32();
    
    /**
     * Read the block position.
     */
    m_block_position = read_uint32();
    
    /**
     * Read the neight.
     */
    m_height = read_uint32();
    
    /**
     * Read the mint.
     */
    m_mint = read_uint64();
    
    /**
     * Read the money supply.
     */
    m_money_supply = read_uint64();
    
    /**
     * Read the flags.
     */
    m_flags = read_uint32();
    
    /**
     * Read the stake modifier.
     */
    m_stake_modifier = read_uint64();
    
    if (is_proof_of_stake())
    {
        /**
         * Read the previous out stake.
         */
        auto pair_point_out = read_point_out();
        
        /**
         * Convert the the point out pair to a point_out object.
         */
        m_previous_out_stake = point_out(
            pair_point_out.first, pair_point_out.second
        );
        
        /**
         * Read the stake time.
         */
        m_stake_time = read_uint32();

        /**
         * Read the proof of stake hash.
         */
        m_hash_proof_of_stake = read_sha256();
    }
    else
    {
        m_previous_out_stake.set_null();
        m_stake_time = 0;
        m_hash_proof_of_stake.clear();
    }
    
    /**
     * Read the block header.
     */
    
    /**
     * Read the version.
     */
    m_version = read_uint32();
    
    /**
     * Read the previous hash.
     */
    m_hash_previous = read_sha256();

    /**
     * Read the merkle root hash.
     */
    m_hash_merkle_root = read_sha256();
    
    /**
     * Read the time.
     */
    m_time = read_uint32();
    
    /**
     * Read the bits.
     */
    m_bits = read_uint32();
    
    /**
     * Read the nonce.
     */
    m_nonce = read_uint32();

    log_none(
        ", m_version = " << m_version <<
        ", hash = " << get_block_hash().to_string() <<
        ", previous = " << m_hash_previous.to_string() <<
        ", m_file = " << m_file <<
        ", m_block_position = " << m_block_position << ", m_height = " <<
        m_height << ", m_mint = " << m_mint << ", m_money_supply = " <<
        m_money_supply << ", m_time = " << m_time << "."
    );
}

void block_index_disk::set_hash_previous(const sha256 & value)
{
    m_hash_previous = value;
}

const sha256 & block_index_disk::hash_previous() const
{
    return m_hash_previous;
}

void block_index_disk::set_hash_next(const sha256 & value)
{
    m_hash_next = value;
}

const sha256 & block_index_disk::hash_next() const
{
    return m_hash_next;
}

sha256 block_index_disk::get_block_hash() const
{
    block blk;
    
    blk.m_header.version = m_version;
    blk.m_header.hash_previous_block = m_hash_previous;
    blk.m_header.hash_merkle_root = m_hash_merkle_root;
    blk.m_header.timestamp = m_time;
    blk.m_header.bits = m_bits;
    blk.m_header.nonce = m_nonce;

    return blk.get_hash();
}