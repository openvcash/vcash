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

#include <ctime>
#include <random>
#include <vector>

#include <coin/alert.hpp>
#include <coin/block.hpp>
#include <coin/checkpoint_sync.hpp>
#include <coin/constants.hpp>
#include <coin/endian.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/protocol.hpp>
#include <coin/stack_impl.hpp>
#include <coin/time.hpp>

using namespace coin;

message::message(const char * buf, const std::size_t & len)
    : data_buffer(buf, len)
{
    // ...
}

message::message(const std::string & command)
{
    m_header.magic = header_magic();
    m_header.command = command;
}

message::message(
    const std::string & command, const data_buffer & payload
    )
    : m_payload(payload)
{
    m_header.magic = header_magic();
    m_header.command = command;
}

void message::encode()
{
    if (m_payload.size() == 0)
    {
        if (m_header.command == "verack")
        {
            // ...
        }
        else if (m_header.command == "version")
        {
            /**
             * Create the version.
             */
            m_payload = create_version();
        }
        else if (m_header.command == "addr")
        {
            /**
             * Create the addr.
             */
            m_payload = create_addr();
        }
        else if (m_header.command == "getaddr")
        {
            // ...
        }
        else if (m_header.command == "ping")
        {
            /**
             * Create the ping.
             */
            m_payload = create_ping();
        }
        else if (m_header.command == "pong")
        {
            /**
             * Create the pong.
             */
            m_payload = create_pong();
        }
        else if (m_header.command == "inv")
        {
            /**
             * Create the inv.
             */
            m_payload = create_inv();
        }
        else if (m_header.command == "getdata")
        {
            /**
             * Create the getdata.
             */
            m_payload = create_getdata();
        }
        else if (m_header.command == "getblocks")
        {
            /**
             * Create the getblocks.
             */
            m_payload = create_getblocks();
        }
        else if (m_header.command == "checkpoint")
        {
            /**
             * Create the checkpoint.
             */
            m_payload = create_checkpoint();
        }
        else if (m_header.command == "block")
        {
            /**
             * Create the block.
             */
            m_payload = create_block();
        }
        else if (m_header.command == "tx")
        {
            /**
             * Create the tx.
             */
            m_payload = create_tx();
        }
        else if (m_header.command == "alert")
        {
            /**
             * Create the alert.
             */
            m_payload = create_alert();
        }
    }
    
    /**
     * Encode the header magic to little endian.
     */
    auto header_magic = endian::to_little<std::uint32_t>(m_header.magic);
    
    /**
     * Write the header length.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_magic[0]), header_magic.size()
    );

    /**
     * Make sure the header command is 12 or less bytes in length.
     * @note We add one byte to the size for null-termination.
     */
    assert(m_header.command.size() + 1 <= 12);
    
    /**
     * Write the header command.
     * @note We add one byte to the size for null-termination.
     */
    write_bytes(m_header.command.c_str(), m_header.command.size() + 1);
    
    /**
     * Pad the rest of the 12 byte command with zeros.
     */
    for (auto i = 0; i < 12 - (m_header.command.size() + 1); i++)
    {
       write_byte(0);
    }
    
    /**
     * Set the header length.
     */
    m_header.length = static_cast<std::uint32_t> (m_payload.size());
    
    /**
     * Encode the header length to little endian.
     */
    auto header_length = endian::to_little<std::uint32_t>(m_header.length);
    
    /**
     * Write the header length.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_length[0]), header_length.size()
    );
    
    /**
     * Calculate the header checksum.
     */
    m_header.checksum = hash::sha256d_checksum(
        reinterpret_cast<const std::uint8_t *>(m_payload.data()),
        m_payload.size()
    );
    
    /**
     * Encode the header checksum to little endian.
     */
    auto header_checksum = endian::to_little<std::uint32_t>(m_header.checksum);
            
    /**
     * Write the header checksum.
     */
    write_bytes(reinterpret_cast<char *> (
        &header_checksum[0]), header_checksum.size()
    );
    
    /**
     * Write the payload.
     */
    write_bytes(m_payload.data(), m_payload.size());
}

void message::decode()
{
    /**
     * Decode the header magic from little endian.
     */
    m_header.magic = read_uint32();
    
    log_none("Message got header magic = " << m_header.magic << ".");
    
    if (verify_header_magic() == false)
    {
        throw std::runtime_error("invalid header magic");
    }
    
    /**
     * Allocate memory for the header command.
     */
    char header_command[12];
    
    std::memset(header_command, 0, sizeof(header_command));
    
    /**
     * Read the header command.
     */
    read_bytes(header_command, sizeof(header_command));
    
    /**
     * Set the header command.
     */
    if (header_command[12 - 1] == 0)
    {
        m_header.command = std::string(
            header_command, header_command + strlen(header_command)
        );
    }
    else
    {
        m_header.command = std::string(header_command, header_command + 12);
    }
    
    for (auto i = 0; i < 12; i++)
    {
        if (header_command[i] == 0)
        {
            /**
             * There must be all zeros after the first zero.
             */
            for (auto j = i; j < 12; j++)
            {
                if (header_command[j] != 0)
                {
                    throw std::runtime_error(
                        "invalid header command (missing null)"
                    );
                }
            }
        }
        else if (header_command[i] < ' ' || header_command[i] > 0x7E)
        {
            throw std::runtime_error(
                "invalid header command (characters out of range)"
            );
        }
    }
    
    log_none("Message got header command = " << m_header.command << ".");
    
    /**
     * Decode the header length from little endian.
     */
    m_header.length = read_uint32();
    
    log_none("Message got header length = " << m_header.length << ".");
    
    /**
     * Read the header checksum.
     */
    m_header.checksum = read_uint32();
    
    log_none("Message got header checksum = " << m_header.checksum << ".");

    if (remaining() < m_header.length)
    {
        throw std::runtime_error(
            "(" + m_header.command + ") underrun, header len = " +
            std::to_string(m_header.length) +
            ", remaining = " + std::to_string(remaining())
        );
    }
    
    if (m_header.length > 0)
    {
        /**
         * Calculate the header checksum.
         */
        auto checksum = hash::sha256d_checksum(
            reinterpret_cast<const std::uint8_t *>(read_ptr()), m_header.length
        );

        if (m_header.checksum != checksum)
        {
            throw std::runtime_error("invalid header checksum");
        }
        
        if (m_header.command == "verack")
        {
            // ...
        }
        else if (m_header.command == "version")
        {
            m_protocol_version.version = read_uint32();
            m_protocol_version.services = read_uint64();
            m_protocol_version.timestamp = read_uint64();
            m_protocol_version.addr_src = read_network_address(true, false);
            m_protocol_version.addr_dst = read_network_address(true, false);
            m_protocol_version.nonce = read_uint64();
            m_protocol_version.user_agent.resize(read_var_int());
            read_bytes(
                const_cast<char *> (m_protocol_version.user_agent.data()),
                m_protocol_version.user_agent.size()
            );
            m_protocol_version.start_height = read_uint32();

            log_none("version = " << m_protocol_version.version);
            log_none("services = " << m_protocol_version.services);
            log_none("timestamp = " << m_protocol_version.timestamp);
            log_none("addr_src.port = " << m_protocol_version.addr_src.port);
            log_none("nonce = " << m_protocol_version.nonce);
            log_none("user_agent = " << m_protocol_version.user_agent);
            log_none("start_height = " << m_protocol_version.start_height);
        }
        else if (m_header.command == "addr")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_addr.count = read_var_int();

            for (auto i = 0; i < m_protocol_addr.count; i++)
            {
                /**
                 * Read the network address, including the prefixed timestamp.
                 */
                protocol::network_address_t addr = read_network_address(
                    false, true
                );
                
                /**
                 * Retain the protocol::network_address_t.
                 */
                m_protocol_addr.addr_list.push_back(addr);
            }
        }
        else if (m_header.command == "getaddr")
        {
            // ...
        }
        else if (m_header.command == "ping")
        {
            /**
             * Read the nonce.
             */
            m_protocol_ping.nonce = read_uint64();
        }
        else if (m_header.command == "pong")
        {
            /**
             * Read the nonce.
             */
            m_protocol_pong.nonce = read_uint64();
        }
        else if (m_header.command == "inv")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_inv.count = read_var_int();
            
            for (auto i = 0; i < m_protocol_inv.count; i++)
            {
                inventory_vector inv = read_inventory_vector();

                if (inv.type() > inventory_vector::type_error)
                {
                    /**
                     * Retain the inventory_vector.
                     */
                    m_protocol_inv.inventory.push_back(inv);
                }
            }
        }
        else if (m_header.command == "getdata")
        {
            /**
             * Read the variable length integer.
             */
            m_protocol_getdata.count = read_var_int();
            
            for (auto i = 0; i < m_protocol_getdata.count; i++)
            {
                inventory_vector inv = read_inventory_vector();
                
                log_none("getdata inv.type = " << inv.type());
                
                if (inv.type() > inventory_vector::type_error)
                {
                    /**
                     * Retain the inventory_vector.
                     */
                    m_protocol_getdata.inventory.push_back(inv);
                }
            }
        }
        else if (m_header.command == "getblocks")
        {
            /**
             * Read the version.
             */
            m_protocol_getblocks.version = read_uint32();
            
            /**
             * Read the count.
             */
            m_protocol_getblocks.count = read_var_int();
            
            /**
             * Read the hashes.
             */
            for (auto i = 0; i < m_protocol_getblocks.count; i++)
            {
                m_protocol_getblocks.hashes.push_back(read_sha256());
            }
            
            /**
             * Read the hash stop.
             */
            m_protocol_getblocks.hash_stop = read_sha256();
        }
        else if (m_header.command == "block")
        {
            /**
             * Allocate the block.
             */
            m_protocol_block.blk = std::make_shared<block> ();
            
            /**
             * Decode the block.
             */
            if (m_protocol_block.blk->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode block.");
            }
        }
        else if (m_header.command == "checkpoint")
        {
            /**
             * Allocate the checkpoint_sync.
             */
            checkpoint_sync checkpoint;
            
            /**
             * Decode the checkpoint_sync.
             */
            if (checkpoint.decode(*this))
            {
                m_protocol_checkpoint.message = checkpoint.message();
                m_protocol_checkpoint.signature = checkpoint.signature();
            }
        }
        else if (m_header.command == "tx")
        {
            /**
             * Allocate the tx.
             */
            m_protocol_tx.tx = std::make_shared<transaction> ();
            
            /**
             * Decode the tx.
             */
            if (m_protocol_tx.tx->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode tx.");
            }
        }
        else if (m_header.command == "alert")
        {
            /**
             * Allocate the alert.
             */
            m_protocol_alert.a = std::make_shared<alert> ();
            
            /**
             * Decode the alert.
             */
            if (m_protocol_alert.a->decode(*this))
            {
                // ...
            }
            else
            {
                log_error("Message failed to decode alert.");
            }
        }
        else
        {
            log_error(
                "Message got invalid command = " << m_header.command << "."
            );
        }
    }
}

bool message::verify_header_magic()
{
    return m_header.magic == header_magic();
}

const std::uint32_t message::header_magic()
{
    static std::uint32_t ret = 0;
    
    if (ret == 0)
    {
        /**
         * The first four bytes of the header.
         */
        std::uint8_t magic[4] = { 0xce, 0xa9, 0xcf, 0x80 };
        
        /**
         * Copy into a 32-bit unsigned integer.
         */
        std::memcpy(&ret, &magic, sizeof(ret));
    }

    return ret;
}

message::header_t & message::header()
{
    return m_header;
}

protocol::version_t & message::protocol_version()
{
    return m_protocol_version;
}

protocol::addr_t & message::protocol_addr()
{
    return m_protocol_addr;
}

protocol::ping_t & message::protocol_ping()
{
    return m_protocol_ping;
}

protocol::pong_t & message::protocol_pong()
{
    return m_protocol_pong;
}

protocol::inv_t & message::protocol_inv()
{
    return m_protocol_inv;
}

protocol::getdata_t & message::protocol_getdata()
{
    return m_protocol_getdata;
}

protocol::getblocks_t & message::protocol_getblocks()
{
    return m_protocol_getblocks;
}

protocol::block_t & message::protocol_block()
{
    return m_protocol_block;
}

protocol::checkpoint_t & message::protocol_checkpoint()
{
    return m_protocol_checkpoint;
}

protocol::tx_t & message::protocol_tx()
{
    return m_protocol_tx;
}

protocol::alert_t & message::protocol_alert()
{
    return m_protocol_alert;
}

data_buffer message::create_version()
{
    data_buffer ret;
    
    /**
     * Set the payload version.
     */
    m_protocol_version.version = protocol::version;
    
    /**
     * Set the services based on the operation mode.
     */
    if (
        globals::instance().operation_mode() ==
        protocol::operation_mode_peer
        )
    {
        /**
         * Set the payload services.
         */
        m_protocol_version.services = protocol::operation_mode_peer;
    }
    else
    {
        /**
         * Set the payload services.
         */
        m_protocol_version.services = protocol::operation_mode_client;
    }

    /**
     * Set the payload timestamp (non-adjusted).
     */
    m_protocol_version.timestamp = std::time(0);
    
    /**
     * Set the services based on the operation mode.
     */
    if (
        globals::instance().operation_mode() ==
        protocol::operation_mode_peer
        )
    {
        /**
         * Set the payload addr_src services.
         */
        m_protocol_version.addr_src.services = protocol::operation_mode_peer;
    }
    else
    {
        /**
         * Set the payload addr_src services.
         */
        m_protocol_version.addr_src.services = protocol::operation_mode_client;
    }

    /**
     * Set the payload addr_src address.
     */
    m_protocol_version.addr_src.address =
    {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01}
    };

    /**
     * Set the payload addr_dst services.
     */
    m_protocol_version.addr_dst.services = protocol::operation_mode_peer;
    
    /**
     * Set the payload addr_dst port.
     */
    m_protocol_version.addr_dst.port = protocol::default_tcp_port;
    
    /**
     * Set the payload user_agent.
     */
    m_protocol_version.user_agent =
        "/" + constants::client_name + ":" + constants::version_string + "/"
    ;

    /**
     * Set the payload start height.
     */
    m_protocol_version.start_height = globals::instance().best_block_height();
    
    /**
     * Set the nonce.
     */
    if (m_protocol_version.nonce == 0)
    {
        m_protocol_version.nonce = std::rand();
    }
    
    /**
     * Encode the payload version to little endian.
     */
    auto payload_version = endian::to_little<std::uint32_t>(
        m_protocol_version.version
    );
    
    assert(payload_version.size() == 4);
    
    /**
     * Write the payload version.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_version[0]), payload_version.size()
    );
    
    /**
     * Encode the payload services to little endian.
     */
    auto payload_services = endian::to_little<std::uint64_t>(
        m_protocol_version.services
    );
    
    assert(payload_services.size() == 8);
    
    /**
     * Write the payload services.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_services[0]), payload_services.size()
    );

    /**
     * Encode the payload timestamp to little endian.
     */
    auto payload_timestamp = endian::to_little<std::uint64_t>(
        m_protocol_version.timestamp
    );
    
    assert(payload_timestamp.size() == 8);
    
    /**
     * Write the payload timestamp.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_timestamp[0]), payload_timestamp.size()
    );
    
    /**
     * Write the payload addr_src ommiting the timestamp.
     */
    ret.write_network_address(m_protocol_version.addr_src, true, false);
 
    /**
     * Write the payload addr_dst ommiting the timestamp.
     */
    ret.write_network_address(m_protocol_version.addr_dst, true, false);
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_version.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );

    /**
     * Write the payload user_agent's length.
     */
    ret.write_var_int(m_protocol_version.user_agent.size());
    
    /**
     * Write the payload user_agent.
     */
    ret.write_bytes(
        m_protocol_version.user_agent.data(),
        m_protocol_version.user_agent.size()
    );

    /**
     * Encode the payload start_height to little endian.
     */
    auto payload_start_height = endian::to_little<std::uint32_t>
        (m_protocol_version.start_height
    );
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_start_height[0]), payload_start_height.size()
    );
    
    return ret;
}

data_buffer message::create_addr()
{
    data_buffer ret;
    
    m_protocol_addr.count = m_protocol_addr.addr_list.size();
    
    ret.write_var_int(m_protocol_addr.count);
    
    auto addr_list = m_protocol_addr.addr_list;
    
    
    for (auto & i : addr_list)
    {
        ret.write_network_address(i, false);
    }
    
    return ret;
}

data_buffer message::create_ping()
{
    data_buffer ret;
    
    /**
     * Set the ping nonce.
     */
    m_protocol_ping.nonce = std::rand();
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_ping.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );
    
    return ret;
}

data_buffer message::create_pong()
{
    data_buffer ret;
    
    /**
     * Set the pong nonce.
     */
    m_protocol_pong.nonce = std::rand();
    
    /**
     * Encode the payload nonce to little endian.
     */
    auto payload_nonce = endian::to_little<std::uint64_t>(
        m_protocol_pong.nonce
    );
    
    assert(payload_nonce.size() == 8);
    
    /**
     * Write the payload nonce.
     */
    ret.write_bytes(reinterpret_cast<char *> (
        &payload_nonce[0]), payload_nonce.size()
    );
    
    return ret;
}

data_buffer message::create_inv()
{
    data_buffer ret;
    
    m_protocol_inv.count = m_protocol_inv.inventory.size();
    
    ret.write_var_int(m_protocol_inv.count);
    
    auto inventory = m_protocol_inv.inventory;
    
    for (auto & i : inventory)
    {
        i.encode(ret);
    }
    
    return ret;
}

data_buffer message::create_getdata()
{
    data_buffer ret;
    
    m_protocol_getdata.count = m_protocol_getdata.inventory.size();
    
    ret.write_var_int(m_protocol_getdata.count);
    
    auto inventory = m_protocol_getdata.inventory;
    
    for (auto & i : inventory)
    {
        i.encode(ret);
    }
    
    return ret;
}

data_buffer message::create_getblocks()
{
    data_buffer ret;
    
    m_protocol_getblocks.version = constants::version_client;
    
    ret.write_uint32(m_protocol_getblocks.version);
    
    m_protocol_getblocks.count = m_protocol_getblocks.hashes.size();
    
    ret.write_var_int(m_protocol_getblocks.count);
    
    auto hashes = m_protocol_getblocks.hashes;
    
    for (auto & i : hashes)
    {
        ret.write_sha256(i);
    }
    
    ret.write_sha256(m_protocol_getblocks.hash_stop);
    
    return ret;
}

data_buffer message::create_checkpoint()
{
    data_buffer ret;
    
    ret.write_var_int(m_protocol_checkpoint.message.size());
    ret.write_bytes(
        reinterpret_cast<const char *>(
        &m_protocol_checkpoint.message[0]),
        m_protocol_checkpoint.message.size()
    );
    ret.write_var_int(m_protocol_checkpoint.signature.size());
    ret.write_bytes(
        reinterpret_cast<const char *>(
        &m_protocol_checkpoint.signature[0]),
        m_protocol_checkpoint.signature.size()
    );
    
    return ret;
}

data_buffer message::create_block()
{
    data_buffer ret;
    
    if (m_protocol_block.blk)
    {
        m_protocol_block.blk->encode(ret);
    }
    
    return ret;
}

data_buffer message::create_tx()
{
    data_buffer ret;
    
    if (m_protocol_tx.tx)
    {
        m_protocol_tx.tx->encode(ret);
    }
    
    return ret;
}

data_buffer message::create_alert()
{
    data_buffer ret;
    
    ret.write_var_int(m_protocol_alert.a->message().size());
    ret.write_bytes(
        reinterpret_cast<const char *>(
        &m_protocol_alert.a->message()[0]),
        m_protocol_alert.a->message().size()
    );
    ret.write_var_int(m_protocol_alert.a->signature().size());
    ret.write_bytes(
        reinterpret_cast<const char *>(
        &m_protocol_alert.a->signature()[0]),
        m_protocol_alert.a->signature().size()
    );
    
    return ret;
}
