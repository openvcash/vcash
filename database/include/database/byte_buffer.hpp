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
 
#ifndef DATABASE_BYTE_BUFFER_HPP
#define DATABASE_BYTE_BUFFER_HPP

#include <cstdint>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <boost/asio.hpp>

#include <boost/crc.hpp>

#include <database/logger.hpp>
#include <database/utility.hpp>

namespace database {

    /**
     * Implements a byte buffer.
     */
    class byte_buffer
    {
        public:
        
            /**
             * Constructor
             */
			byte_buffer()
			    : m_read_position(0)
			    , m_used(0)
			    , m_allocated(0)
			{
			    // ...
			}
            
            /**
             * Copy constructor
             * @param other The other byte_buffer.
             */
			byte_buffer(const byte_buffer & other)
			    : m_read_position(0)
			    , m_used(0)
			    , m_allocated(0)
			{
			    write_bytes(other.data(), other.size());
			}
            
            /**
             * Constructor
             * @param len The length.
             */
			byte_buffer(const std::size_t & len)
			    : m_read_position(0)
			    , m_used(0)
			    , m_allocated(0)
			{
			    for (std::size_t i = 0; i < len; i++)
			    {
			        write_byte(0);   
			    }
			}
            
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length
             */
			byte_buffer(const char * buf, const std::size_t & len)
			    : m_read_position(0)
			    , m_used(0)
			    , m_allocated(0)
			{
			    if (len > 0)
			    {
			        write_bytes(buf, len);
			    }
			}
            
            /**
             * Reads up to len bytes into buf.
             * @param buf The buffer.
             * @Param len The length.
             */
			void read_bytes(char * buf, const std::size_t & len)
			{
			    read(buf, len);
			}
            
			std::uint8_t read_uint8()
			{
			    std::uint8_t ret;
			    read(&ret, sizeof(ret));
			    return ret;
			}

			std::uint16_t read_uint16()
			{
			    std::uint16_t ret;
			    read(&ret, sizeof(ret));
			    return ntohs(ret);
			}

			std::uint32_t read_uint32()
			{
			    std::uint32_t ret;
			    read(&ret, sizeof(ret));
			    return ntohl(ret);
			}

			std::uint64_t read_uint64()
			{
			    std::uint64_t ret;
			    read(&ret, sizeof(ret));
				return
					((((std::uint64_t)ntohl((std::uint32_t)ret)) << 32) + ntohl(ret >> 32))
				;
			}
            
			void write_uint8(const std::uint8_t & val)
			{
			    write_byte(val);
			}

			void write_uint16(const std::uint16_t & val)
			{
			    std::uint16_t swapped = htons(val);
			    write(&swapped, sizeof(val));
			}

			void write_uint32(const std::uint32_t & val)
			{
			    std::uint32_t swapped = htonl(val);
			    write(&swapped, sizeof(val));
			}

			void write_uint64(const std::uint64_t & val)
			{
			    std::uint64_t swapped = (
                    (std::uint64_t)(((std::uint64_t)htonl(
                    (std::uint32_t)val)) << 32) + htonl(val >> 32)
                );
			    write(&swapped, sizeof(val));
			}
			
			void write_bytes(const char * str, const std::size_t & len)
			{    
			    write((void *)str, len);
			}

			void write_byte(const unsigned char byte)
			{
			    write((void *)&byte, 1);
			}

			char * data() const
			{
			    return m_data.get();
			}
        
            /**
             * Pointer to current read position.
             */
            const char * read_position() const
            {
                return m_read_position;
            }

			const std::size_t & size() const
			{
			    return m_used;
			}
			
            /**
             * The number of bytes allocated.
             */
            const std::size_t & allocated() const
			{
				return m_allocated;
			}

			bool empty() const
			{
			    return (m_used == 0);
			}

			void rewind()
			{
				m_read_position = m_data.get();
			}

			void seek(const std::size_t & offset)
			{
			    if (offset > m_used)
			    {
			        log_error("Byte buffer seek overrun");
			    }
			    else
			    {
			        m_read_position = m_data.get() + offset;
			    }
			}

			void truncate(const std::size_t & len)
			{
			    if (len > m_used)
			    {
			        log_error("Byte buffer truncation underrun");
			    }
			    else
			    {
			        m_used -= len;
			    }
			}

			void clear()
			{
			    m_data.reset();
			    m_read_position = 0;
			    m_used = 0;
			    m_allocated = 0;
			}

			std::size_t remaining() const
			{
			    return (m_used - (m_read_position - m_data.get()));
			}

			bool resize(const std::size_t & len)
			{
				std::size_t read_offset = 0;

			    /**
			     * Check if input length is already allocated.
			     */
				if (m_allocated >= len)
			    {
					return true;
			    }
			    else
			    {
			        std::size_t new_length = m_allocated;

			        new_length += len;

			        read_offset = m_read_position - m_data.get();

			        std::unique_ptr<char> tmp(new char[new_length]);

			        std::memcpy(tmp.get(), m_data.get(), m_allocated);

			        m_data.reset(new char[new_length]);

			        std::memcpy(m_data.get(), tmp.get(), m_allocated);

			        m_read_position = m_data.get() + read_offset;

			        m_allocated = new_length;

			        return true;
			    }

			    return false;
			}

			bool read(void * data, const std::size_t & len)
			{
				if (remaining() < len)
			    {
			        throw std::runtime_error(
						"Byte buffer read underflow remaining = " +
						utility::to_string(remaining()) +
						", len = " + utility::to_string(len)
					);

					return false;
			    }

			    /**
			     * Copy current read position of len bytes into data.
			     */
				std::memcpy(data, m_read_position, len);

			    /**
			     * Increment current read position.
			     */
				m_read_position += len;

				return true;
			}

			bool write(void * data, const std::size_t & len)
			{
			    /**
			     * Check if we can allocate more memory for writing.
			     */
				if (!resize(m_used + len))
			    {
			        log_error("Byte buffer out of memory");
                    
					return false;
			    }

			    /**
			     * Append data of size len to m_data.
			     */
				std::memcpy(m_data.get() + m_used, data, len);

			    /**
			     * Increment used count.
			     */
				m_used += len;

				return true;
			}

			void write_address(const boost::asio::ip::address & addr)
			{
			    if (addr.is_v4())
			    {
			        write_uint32(
                        static_cast<std::uint32_t> (addr.to_v4().to_ulong())
                    );
			    }
			    else if (addr.is_v6())
			    {
			        boost::asio::ip::address_v6::bytes_type
                        bytes = addr.to_v6().to_bytes()
                    ;
			        write_bytes(
                        reinterpret_cast<char *> (bytes.data()), bytes.size()
                    );
			    }
			}

			boost::asio::ip::address_v4 read_v4_address()
			{
			    unsigned long ip = read_uint32();
			    return boost::asio::ip::address_v4(ip);
			}

			boost::asio::ip::address_v6 read_v6_address()
			{
			   boost::asio::ip::address_v6::bytes_type bytes;

                auto it = bytes.begin();

			    for (; it != bytes.end(); ++it)
			    {
			        *it = read_uint8();
			    } 

			    return boost::asio::ip::address_v6(bytes);
			}

			std::uint32_t checksum(const std::size_t & len)
			{
			    if (len > m_used)
			    {
			        log_error("Byte buffer checksum overrun");

			        return 0;
			    }

			    /**
			     * Allocate the crc digest.
			     */
			    boost::crc_32_type digest;

			    /**
			     * Calculate the checksum.
			     */
			    digest.process_bytes(m_data.get(), len);

			    /**
			     * Return the checksum.
			     */
			    return digest.checksum();
			}

			void print() const
			{
			    std::stringstream ss;

			    ss << std::hex;

			    for (std::size_t i = 0; i < m_used; i++)
			    {
			        ss << m_data.get()[i] << " " << "(" <<
                    int(m_data.get()[i]) << ") ";
			    }

			    ss << std::dec;
			    ss << std::endl;

			    std::cout << ss.str() << std::endl;
			}

        private:
            
            /**
             * Pointer to allocated memory.
             */
            std::unique_ptr<char> m_data;
            
            /**
             * Pointer to current read position.
             */
            char * m_read_position;
            
            /**
             * The number of bytes used..
             */
            std::size_t m_used;
            
            /**
             * The number of bytes allocated.
             */
            std::size_t m_allocated;
            
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_BYTE_BUFFER_HPP
