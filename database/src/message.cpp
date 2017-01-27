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
#include <iostream>

#include <database/compression.hpp>
#include <database/constants.hpp>
#include <database/hc256.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/protocol.hpp>

#if (defined _MSC_VER)
#undef min
#undef max
#endif

using namespace database;

message::message(const protocol::message_code_t & code)
{
    static std::uint16_t g_transaction_id = 0;
    
    std::memset(&m_header, 0, sizeof(m_header));
    
    m_header.code = code;
    m_header.flags = 0;
    m_header.transaction_id = ++g_transaction_id;
    
    /**
     * Always add the version attribute.
     */
    message::attribute_uint32 attr1;
    
    attr1.type = message::attribute_type_version;
    attr1.length = 0;
    attr1.value = version;
    
    m_uint32_attributes.push_back(attr1);
}

message::message(
    const protocol::message_code_t & code, const std::uint16_t & tid
    )
{
    std::memset(&m_header, 0, sizeof(m_header));
    
    m_header.code = code;
    m_header.flags = 0;
    m_header.transaction_id = tid;

    /**
     * Always add the version attribute.
     */
    message::attribute_uint32 attr1;
    
    attr1.type = message::attribute_type_version;
    attr1.length = 0;
    attr1.value = version;
    
    m_uint32_attributes.push_back(attr1);
}

message::message(const char * buf, const std::size_t & len)
    : byte_buffer_(buf, len)
{
    std::memset(&m_header, 0, sizeof(m_header));
    
    m_header.code = protocol::message_code_none;
}

void message::set_header_flags(const protocol::message_flag_t & flags)
{
    m_header.flags = flags;
}

const protocol::message_flag_t message::header_flags() const
{
    return static_cast<protocol::message_flag_t> (m_header.flags);
}

const protocol::message_code_t message::header_code() const
{
    return static_cast<protocol::message_code_t> (m_header.code);
}

void message::set_header_transaction_id(const std::uint16_t & val)
{
    m_header.transaction_id = val;
}

const std::uint16_t & message::header_transaction_id() const
{
    return m_header.transaction_id;
}

void message::set_source_endpoint(const boost::asio::ip::udp::endpoint & val)
{
    m_source_endpoint = val;
}

const boost::asio::ip::udp::endpoint & message::source_endpoint() const
{
    return m_source_endpoint;
}

std::vector<message::attribute_binary> & message::binary_attributes()
{
    return m_binary_attributes;
}

std::vector<message::attribute_string> & message::string_attributes()
{
    return m_string_attributes;
}

std::vector<message::attribute_uint32> & message::uint32_attributes()
{
    return m_uint32_attributes;
}

std::vector<message::attribute_endpoint> & message::endpoint_attributes()
{
    return m_endpoint_attributes;
}

bool message::encode()
{
    database::byte_buffer attributes;
    
    /**
     * Encode the attributes.
     */
    
    for (auto & i : m_binary_attributes)
    {
        attributes.write_uint16(i.type);
        attributes.write_uint16(i.length);
        attributes.write_bytes(
            reinterpret_cast<const char *> (&i.value[0]), i.value.size()
        );

        std::uint16_t padding = i.length % 4 == 0 ?
            0 : 4 - (i.length % 4)
        ;
        
        for (auto i = 0; i < padding; i++)
        {
            attributes.write_uint8(0);
        }
    }
    
    for (auto & i : m_string_attributes)
    {
        attributes.write_uint16(i.type);
        attributes.write_uint16(i.length);
        attributes.write_bytes(i.value.data(), i.value.size());

        std::uint16_t padding = i.length % 4 == 0 ?
            0 : 4 - (i.length % 4)
        ;
        
        for (auto i = 0; i < padding; i++)
        {
            attributes.write_uint8(0);
        }
    }
    
    for (auto & i : m_uint32_attributes)
    {
        attributes.write_uint16(i.type);
        attributes.write_uint16(i.length);
        attributes.write_uint32(i.value);
    }
    
    for (auto & i : m_endpoint_attributes)
    {
        encode_endpoint(attributes, i.value);
    }
    
    return encode(attributes);
}

bool message::decode()
{
    m_header.flags = byte_buffer_.read_uint8();

    m_header.code = byte_buffer_.read_uint8();
    m_header.transaction_id = byte_buffer_.read_uint16();
    
    if (!(m_header.flags & protocol::message_flag_0x01))
    {
        log_debug("Message got invalid flags, missing 0x01.");
        
        return false;
    }
    
    if ((m_header.flags & protocol::message_flag_0x02))
    {
        log_debug("Message got invalid flags, has 0x02.");
        
        return false;
    }
    
    if (!(m_header.flags & protocol::message_flag_0x40))
    {
        log_debug("Message got invalid flags, missing 0x40.");
        
        return false;
    }

    if (m_header.flags & protocol::message_flag_dontroute)
    {
        log_none("Got message_flag_dontroute.");
    }
    
    /**
     * Decompress the attributes if necessary.
     */
    if ((m_header.flags & protocol::message_flag_compressed))
    {
        if (byte_buffer_.remaining() > 0)
        {
            std::string in(
                byte_buffer_.read_position(), byte_buffer_.remaining()
            );
            
            std::string out = compression::decompress(in);
            
            byte_buffer_.clear();
            
            if (out.size() > 0)
            {
                byte_buffer_.write_bytes(out.data(), out.size());
            }
        }
    }

    try
    {
        /**
         * Decode the attributes.
         */
        while (byte_buffer_.remaining() > sizeof(std::uint32_t))
        {
            /**
             * The attribute type.
             */
            std::uint16_t attribute_type = byte_buffer_.read_uint16();
            
            /**
             * The attribute length.
             */
            std::uint16_t attribute_length = byte_buffer_.read_uint16();
            
            /**
             * Decode the attribute.
             */
            switch (attribute_type)
            {
                case attribute_type_none:
                {
                    // ...
                }
                break;
                case attribute_type_slot:
                {
                    log_none("Message got attribute_type_slot.");
                    
                    attribute_uint32 attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value = byte_buffer_.read_uint32();

                    m_uint32_attributes.push_back(attr);
                }
                break;
                case attribute_type_endpoint:
                {
                    log_none("Message got attribute_type_endpoint.");
                    
                    attribute_endpoint attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value = decode_endpoint(byte_buffer_);

                    log_none(attr.value);
                    
                    m_endpoint_attributes.push_back(attr);
                }
                break;
                case attribute_type_broadcast_buffer:
                {
                    log_none("Message got attribute_type_broadcast_buffer.");
                    
                    attribute_binary attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value.resize(attribute_length);
                    
                    byte_buffer_.read_bytes(
                        reinterpret_cast<char *> (&attr.value[0]),
                        attribute_length
                    );
                    
                    m_binary_attributes.push_back(attr);
                }
                break;
                case attribute_type_version:
                {
                    log_none("Message got attribute_type_version.");
                    
                    attribute_uint32 attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value = byte_buffer_.read_uint32();

                    m_uint32_attributes.push_back(attr);
                    
                    if (attr.value < version_minimum)
                    {
                        log_info("Message got too low version.");
                        
                        return false;
                    }
                }
                break;
                case attribute_type_public_key:
                {
                    log_none("Message got attribute_type_public_key.");
                    
                    attribute_string attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value.resize(attribute_length);
                    
                    byte_buffer_.read_bytes(
                        const_cast<char *> (attr.value.data()), attribute_length
                    );
                    
                    m_string_attributes.push_back(attr);
                }
                break;
                case attribute_type_storage_query:
                {
                    log_none("Message got attribute_type_storage_query.");
                    
                    attribute_string attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value.resize(attribute_length);
                    
                    byte_buffer_.read_bytes(
                        const_cast<char *> (attr.value.data()), attribute_length
                    );
                    
                    m_string_attributes.push_back(attr);
                }
                break;
                case attribute_type_stats_udp_bps_inbound:
                {
                    log_none(
                        "Message got attribute_type_stats_udp_bps_inbound."
                    );
                    
                    attribute_uint32 attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value = byte_buffer_.read_uint32();

                    m_uint32_attributes.push_back(attr);
                }
                break;
                case attribute_type_stats_udp_bps_outbound:
                {
                    log_none(
                        "Message got attribute_type_stats_udp_bps_outbound."
                    );
                    
                    attribute_uint32 attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value = byte_buffer_.read_uint32();

                    m_uint32_attributes.push_back(attr);
                }
                break;
                case attribute_type_error:
                {
                    log_none("Message got attribute_type_error.");
                    
                    attribute_string attr;
                    
                    attr.type = attribute_type;
                    attr.length = attribute_length;
                    attr.value.resize(attribute_length);
                    
                    byte_buffer_.read_bytes(
                        const_cast<char *> (attr.value.data()), attribute_length
                    );
                    
                    m_string_attributes.push_back(attr);
                }
                break;
                default:
                {
                    /**
                     * We don't know how to handle this attribute, read the data
                     * and discard it.
                     */
                    std::unique_ptr<char> buf(
                        new (std::nothrow) char[attribute_length]
                    );
                    
                    if (buf)
                    {
                        byte_buffer_.read_bytes(buf.get(), attribute_length);
                    }
                }
                break;	
            }

            std::uint16_t padding = attribute_length % 4 == 0 ? 0 : 4 -
                (attribute_length % 4)
            ;
            
            for (std::uint8_t i = 0; i < padding; i++)
            {
                byte_buffer_.read_uint8();
            }
        }
    }
    catch (std::exception & e)
    {
        log_error("Message decoding failed, what = " << e.what() << ".");
        
        return false;
    }
    
    return true;
}
            
bool message::encode(const database::byte_buffer & attributes)
{
    /**
     * Clear
     */
    byte_buffer_.clear();
    
    /**
     * Set the header flags.
     * 01000001
     */
    m_header.flags =
        m_header.flags | protocol::message_flag_0x01 |
        protocol::message_flag_0x40
    ;

    /**
     * Encode the flags.
     */
    byte_buffer_.write_uint8(m_header.flags);
    
    /**
     * Encode the code.
     */
    byte_buffer_.write_uint8(m_header.code);
    
    /**
     * Encode the transaction_id.
     */
    byte_buffer_.write_uint16(m_header.transaction_id);

    /**
     * Compress the attributes if necessary.
     */
    if ((m_header.flags & protocol::message_flag_compressed))
    {
        if (attributes.size() > 0)
        {
            std::string in(attributes.data(), attributes.size());
            
            std::string out = compression::compress(in);
            
            if (out.size() > 0)
            {
                /**
                 * Write the attributes.
                 */
                byte_buffer_.write_bytes(out.data(), out.size());
            }
        }
    }
    else
    {
        /**
         * Write the attributes.
         */
        byte_buffer_.write_bytes(attributes.data(), attributes.size());
    }
    
    return true;
}

void message::encode_string(
    database::byte_buffer & body, const std::string & val
    )
{
    assert(0);
    
    /**
     * Write the type.
     */
    body.write_uint16(0);
    
    /**
     * Write the length.
     */
    body.write_uint16(val.size());
    
    /**
     * Write the string.
     */
    body.write_bytes(val.data(), val.size());
    
    /**
     * Calculate the padding.
     */
    std::size_t padding = val.size() % 4 == 0 ? 0 : 4 - val.size() % 4;
    
    /**
     * Write the padding.
     */
    for (std::size_t i = 0; i < padding; i++)
    {
        body.write_uint8(0);
    }
}

void message::decode_string(
    database::byte_buffer & body, std::string & val,
    const std::uint16_t & attribute_length
    )
{
    /**
     * Allocate the string.
     */
    val.resize(attribute_length);
    
    /**
     * Read the node string.
     */
    body.read_bytes(const_cast<char *> (val.data()), val.size());
    
    /**
     * Calculate the padding.
     */
    std::uint16_t padding = attribute_length % 4 == 0 ? 0 :
        4 - (attribute_length % 4)
    ;
    
    for (std::uint8_t i = 0; i < padding; i++)
    {
        /**
         * Read the padding.
         */
        body.read_uint8();
    }
}

void message::encode_endpoint(
    database::byte_buffer & body, const boost::asio::ip::udp::endpoint & ep
    )
{
    /**
     * Write the type.
     */
    body.write_uint16(attribute_type_endpoint);
    
    /**
     * Write the length.
     */
    body.write_uint16(ep.address().is_v4() ? 8 : 20);
    
    /**
     * Encode the padding.
     */
    body.write_uint8(0);
    
    /**
     * Write the ip address version.
     */
    body.write_uint8(
        ep.address().is_v4() ? constants::ipv4 : constants::ipv6
    );
    
    /**
     * Write the port.
     */
    body.write_uint16(ep.port());
    
    /**
     * Write the ip address.
     */
    body.write_address(ep.address());
}

bool message::encrypt(const std::string & key)
{
    if (m_header.flags & protocol::message_flag_encrypted)
    {
        hc256 ctx(
            key, key, "n5tH9JWEuZuA96wkA747jsp4JLvXDV8j"
        );
        
        auto crc32 = byte_buffer_.checksum(byte_buffer_.size());
        
        auto encrypted = ctx.encrypt(
            std::string(byte_buffer_.data() + sizeof(protocol::header_t),
            byte_buffer_.size() - sizeof(protocol::header_t))
        );
        
        encrypted.insert(
            encrypted.begin(), byte_buffer_.data(),
            byte_buffer_.data() + sizeof(protocol::header_t)
        );
        
        byte_buffer_.clear();
        
        byte_buffer_.write_bytes(encrypted.data(), encrypted.size());
        
        byte_buffer_.write_uint32(crc32);

        return true;
    }
    
    return false;
}

bool message::decrypt(const std::string & key)
{
    hc256 ctx(
        key, key, "n5tH9JWEuZuA96wkA747jsp4JLvXDV8j"
    );

    auto decrypted = ctx.decrypt(
        std::string(byte_buffer_.data() + sizeof(protocol::header_t),
        byte_buffer_.size() - sizeof(protocol::header_t) -
        sizeof(std::uint32_t))
    );
    
    decrypted.insert(
        decrypted.begin(), byte_buffer_.data(),
        byte_buffer_.data() + sizeof(protocol::header_t)
    );
    
    byte_buffer_.seek(byte_buffer_.size() - sizeof(std::uint32_t));
    
    auto crc1 = byte_buffer_.read_uint32();
    
    byte_buffer_.clear();
    
    byte_buffer_.write_bytes(decrypted.data(), decrypted.size());
    
    auto crc2 = byte_buffer_.checksum(byte_buffer_.size());
    
    return crc1 == crc2;
}

boost::asio::ip::udp::endpoint message::decode_endpoint(
    database::byte_buffer & body
    )
{
    /**
     * Read the padding.
     */
    std::uint8_t padding = body.read_uint8();
    
    (void)padding;
    
    /**
     * Read the ip version.
     */
    std::uint8_t version = body.read_uint8();
    
    /**
     * Read the port.
     */
    std::uint16_t port = body.read_uint16();
    
    /**
     * Read the ip address.
     */
    boost::asio::ip::address addr;
    
    if (version == constants::ipv4)
    {
        addr = body.read_v4_address();
    }
    else if (version == constants::ipv6)
    {
        addr = body.read_v6_address();
    }
    
    return boost::asio::ip::udp::endpoint(addr, port);
}

const char * message::data() const
{
    return byte_buffer_.data();
}

const std::size_t & message::size() const
{
    return byte_buffer_.size();
}

int message::run_test()
{
    std::cerr << "Running message encode test case." << std::endl;
    
    return 0;
}
