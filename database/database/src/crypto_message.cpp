/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#include <database/crypto.hpp>
#include <database/crypto_message.hpp>

using namespace database;

crypto_message::crypto_message()
{
    std::memset(&m_header, 0, sizeof(m_header));
}

crypto_message::crypto_message(const char * buf, const std::size_t & len)
{
    std::memset(&m_header, 0, sizeof(m_header));
    
    byte_buffer_.write_bytes(buf, len);
}

void crypto_message::encode()
{
    crypto::dtls_header_t dtls_header;
    
    std::memset(&dtls_header, 0, crypto::dtls_header_length);
    
    dtls_header.content_type = crypto::content_type_application_data;
    dtls_header.version_major = crypto::version_major;
    dtls_header.version_minor = crypto::version_minor;

    dtls_header.epoch = std::rand() % std::numeric_limits<std::uint16_t>::max();
    
    dtls_header.sequence_number[0] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[1] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[2] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[3] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[4] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    dtls_header.sequence_number[5] = std::rand() % std::numeric_limits<std::uint8_t>::max();
    
    dtls_header.length = sizeof(header_t) + m_body.size() + sizeof(std::uint8_t);

    byte_buffer_.write_uint8(dtls_header.content_type);
    byte_buffer_.write_uint8(dtls_header.version_major);
    byte_buffer_.write_uint8(dtls_header.version_minor);
    byte_buffer_.write_uint16(dtls_header.epoch);
    byte_buffer_.write_uint8(dtls_header.sequence_number[0]);
    byte_buffer_.write_uint8(dtls_header.sequence_number[1]);
    byte_buffer_.write_uint8(dtls_header.sequence_number[2]);
    byte_buffer_.write_uint8(dtls_header.sequence_number[3]);
    byte_buffer_.write_uint8(dtls_header.sequence_number[4]);
    byte_buffer_.write_uint8(dtls_header.sequence_number[5]);
    byte_buffer_.write_uint16(dtls_header.length);
    byte_buffer_.write_uint8(std::rand()); /** Pad the DTLS header. */
    
    /**
     * Write the code.
     */
    byte_buffer_.write_uint8(m_header.code);
    
    /**
     * Write the flags.
     */
    byte_buffer_.write_uint8(m_header.flags);
    
    /**
     * Write the transaction id.
     */
    byte_buffer_.write_uint16(m_header.transaction_id);
    
    /**
     * Write the padding.
     */
    byte_buffer_.write_uint16(m_header.padding);
    
    /**
     * Write the length.
     */
    byte_buffer_.write_uint16(m_header.length);
    
    /**
     * Write the body.
     */
    byte_buffer_.write_bytes(m_body.data(), m_body.size());
}

void crypto_message::decode()
{
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint16();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint8();
    byte_buffer_.read_uint16();
    byte_buffer_.read_uint8(); /** Unpad the DTLS header. */

    /**
     * Read the code.
     */
    m_header.code = byte_buffer_.read_uint8();
    
    /**
     * Read the flags.
     */
    m_header.flags = byte_buffer_.read_uint8();

    /**
     * Read the transaction id.
     */
    m_header.transaction_id = byte_buffer_.read_uint16();

    /**
     * Read the padding.
     */
    m_header.padding = byte_buffer_.read_uint16();

    /**
     * Read the length.
     */
    m_header.length = byte_buffer_.read_uint16();

    if (byte_buffer_.remaining() < m_header.length)
    {
        std::stringstream ss;
        
        ss << byte_buffer_.remaining() << ":" << m_header.length;
        
        throw std::runtime_error(
            "Crypto message decode failed, not enough data (" + ss.str() + ")"
        );
    }
    
    /**
     * Allocate the temporary body.
     */
    std::auto_ptr<char> body(new char[m_header.length]);

    /**
     * Read the body.
     */
    byte_buffer_.read_bytes(body.get(), m_header.length);

    /**
     * Write the body.
     */
    m_body.write_bytes(body.get(), m_header.length);
}

crypto_message::header_t & crypto_message::header()
{
    return m_header;
}

void crypto_message::set_body(const char * buf, const std::size_t & len)
{
    /**
     * Write the body.
     */
    m_body.write_bytes(buf, len);
    
    /**
     * Set the length.
     */
    m_header.length = len;
}

byte_buffer & crypto_message::body()
{
    return m_body;
}

const char * crypto_message::data() const
{
    return byte_buffer_.data();
}

const std::size_t & crypto_message::size() const
{
    return byte_buffer_.size();
}
            
