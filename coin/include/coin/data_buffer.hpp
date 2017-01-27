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

#ifndef COIN_DATA_BUFFER_HPP
#define COIN_DATA_BUFFER_HPP

#if (defined _MSC_VER)
#undef max
#endif

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <limits>
#include <vector>

#include <boost/asio.hpp>
#include <boost/crc.hpp>

#include <coin/android.hpp>
#include <coin/endian.hpp>
#include <coin/file.hpp>
#include <coin/protocol.hpp>
#include <coin/sha256.hpp>

namespace coin {
    
    /**
     * Implements a data buffer.
     */
    class data_buffer
    {
        public:
        
            /**
             * Constructor
             */
			data_buffer()
			    : m_read_ptr(0)
                , file_offset_(0)
			{
			    // ...
			}
        
            /**
             * Constructor
             * @param f The file.
             */
            data_buffer(const std::shared_ptr<file> & f)
			    : m_read_ptr(0)
                , file_(f)
                , file_offset_(f->ftell())
            {
                // ...
            }
            
            /**
             * Copy constructor
             * @param other The other data_buffer.
             */
			data_buffer(const data_buffer & other)
			    : m_read_ptr(0)
                , file_offset_(other.file_offset_)
                , file_(other.file_)
			{
                clear();
                
                m_data.reserve(other.size());

			    write_bytes(other.data(), other.size());
                
                m_read_ptr = m_data.size() > 0 ? &m_data[0] : 0;
			}
        
            /**
             * Constructor
             * @param len The length.
             */
			data_buffer(const std::size_t & len)
			    : m_read_ptr(0)
                , file_offset_(0)
			{
                m_data.reserve(len);
                
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
			data_buffer(const char * buf, const std::size_t & len)
			    : m_read_ptr(0)
                , file_offset_(0)
			{
			    if (len > 0)
			    {
                    m_data.reserve(len);
                    
			        write_bytes(buf, len);
                    
                    m_read_ptr = m_data.size() > 0 ? &m_data[0] : 0;
			    }
			}

			void read_bytes(char * buf, const std::size_t & len)
			{
			    read(buf, len);
			}
        
			std::vector<char> read_bytes(const std::size_t & len)
			{
                std::vector<char> ret(len);
                
                if (ret.size() > 0)
                {
                    read(&ret[0], len);
                }
                
                return ret;
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
			    return ret;
			}

			std::int32_t read_int32()
			{
			    std::int32_t ret;
			    read(&ret, sizeof(ret));
			    return ret;
			}
        
			std::uint32_t read_uint32()
			{
			    std::uint32_t ret;
			    read(&ret, sizeof(ret));
			    return ret;
			}

			std::int64_t read_int64()
			{
			    std::int64_t ret;
			    read(&ret, sizeof(ret));
				return ret;
			}
        
			std::uint64_t read_uint64()
			{
			    std::uint64_t ret;
			    read(&ret, sizeof(ret));
				return ret;
			}
            
			void write_uint8(const std::uint8_t & val)
			{
			    write_byte(val);
			}

			void write_uint16(const std::uint16_t & val)
			{
			    write((void *)&val, sizeof(val));
			}

			void write_int32(const std::int32_t & val)
			{
			    write((void *)&val, sizeof(val));
			}
        
			void write_uint32(const std::uint32_t & val)
			{
			    write((void *)&val, sizeof(val));
			}

			void write_int64(const std::int64_t & val)
			{
			    write((void *)&val, sizeof(val));
			}
        
			void write_uint64(const std::uint64_t & val)
			{
			    write((void *)&val, sizeof(val));
			}
			
			void write_bytes(const char * buf, const std::size_t & len)
			{    
			    write((void *)buf, len);
			}

			void write_byte(const std::uint8_t val)
			{
			    write((void *)&val, 1);
			}

			char * data() const
			{
                if (m_data.size() > 0)
                {
                    return const_cast<char *>(&m_data[0]);
                }
                
                return 0;
			}
        
            const char * read_ptr() const
            {
                return m_read_ptr;
            }

			const std::size_t size() const
			{
			    return m_data.size();
			}

			bool empty() const
			{
			    return m_data.size() == 0;
			}

			void rewind()
			{
				m_read_ptr = m_data.size() > 0 ? &m_data[0] : 0;
			}

			void seek(const std::size_t & offset)
			{
			    if (offset > m_data.size())
			    {
                    assert(0);
			    }
			    else
			    {
			        m_read_ptr = &m_data[0] + offset;
			    }
			}

			void reserve(const std::size_t & len)
			{
                m_data.reserve(len);
			}
        
			void resize(const std::size_t & len)
			{
                m_data.resize(len);
			}

			void clear()
			{
                std::vector<char> empty;
                
                m_data.swap(empty);

			    m_read_ptr = 0;
			}

			std::size_t remaining() const
			{
			    return (m_data.size() - (m_read_ptr - &m_data[0]));
			}

			void read(void * data, const std::size_t & len)
			{
                if (file_)
                {
                    if (file_->read(reinterpret_cast<char *>(data), len))
                    {
                        file_offset_ += len;
                        
                        file_->seek_set(file_offset_);
                    }
                    else
                    {
                        throw std::runtime_error("read (file) failed");
                    }
                }
                else
                {
                    if (remaining() < len)
                    {
                        throw std::runtime_error(
                            "buffer underrun, len = " + std::to_string(len) +
                            ", remaining = " + std::to_string(remaining())
                        );
                    }

                    if (m_read_ptr == 0)
                    {
                        m_read_ptr = &m_data[0];
                    }
                    
                    std::memcpy(data, m_read_ptr, len);

                    m_read_ptr += len;
                }
			}

			void write(void * data, const std::size_t & len)
			{
                m_data.insert(
                    m_data.end(), reinterpret_cast<char *>(data),
                    reinterpret_cast<char *>(data) + len
                );
			}
        
            /**
             * Reads a variable length integer.
             */
            std::uint64_t read_var_int()
            {
                std::uint64_t ret = 0;
                
                std::uint8_t size = read_uint8();
                
                if (size < 253)
                {
                    ret = size;
                }
                else if (size == 253)
                {
                    ret = read_uint16();
                }
                else if (size == 254)
                {
                    ret = read_uint32();
                }
                else if (size == 255)
                {
                    ret = read_uint64();
                }
                else
                {
                    assert(0);
                }
                
                return ret;
            }
        
            /**
             * Writes a variable length integer.
             * @param size The size.
             */
            void write_var_int(const std::uint64_t & size)
            {
                if (size < 253)
                {
                    write_byte(size);
                }
                else if (size <= std::numeric_limits<std::uint16_t>::max())
                {
                    write_byte(253);
                    
                    auto little = endian::to_little<std::uint16_t>(
                        size
                    );
                    
                    write_bytes(
                        reinterpret_cast<const char *>(&little[0]),
                        sizeof(std::uint16_t)
                    );
                }
                else if (size <= std::numeric_limits<std::uint32_t>::max())
                {
                    write_byte(254);

                    auto little = endian::to_little<std::uint32_t>(
                        static_cast<std::uint32_t> (size)
                    );
                    
                    write_bytes(
                        reinterpret_cast<const char *>(&little[0]),
                        sizeof(std::uint32_t)
                    );
                }
                else if (size <= std::numeric_limits<std::uint64_t>::max())
                {
                    write_byte(255);

                    auto little = endian::to_little<std::uint64_t>(
                        size
                    );
                    
                    write_bytes(
                        reinterpret_cast<const char *>(&little[0]),
                        sizeof(std::uint64_t)
                    );
                }
                else
                {
                    assert(0);
                }
            }
        
            /**
             * Reads a network address.
             * @param prefix_timestamp If false the timestamp will be omitted.
             */
            protocol::network_address_t read_network_address(
                const bool & prefix_version, const bool & prefix_timestamp
                )
            {
                protocol::network_address_t ret;
                
                if (prefix_version)
                {
                    /**
                     * Read the version.
                     */
                    ret.version = read_uint32();
                }
                
                if (prefix_timestamp)
                {
                    /**
                     * Read the timestamp.
                     */
                    ret.timestamp = read_uint32();
                }
                
                /**
                 * Read the services.
                 */
                ret.services = read_uint64();

                /**
                 * Read the address.
                 */
                read_bytes(
                    reinterpret_cast<char *>(&ret.address[0]),
                    ret.address.size()
                );

                /**
                 * Read the port.
                 */
                ret.port = ntohs(read_uint16());
                
                return ret;
            }
        
            /**
             * Writes a network address.
             * @param addr The protocol::network_address_t.
             * @param prefix_version If false the version will be omitted.
             * @param prefix_timestamp If false the timestamp will be omitted.
             */
            void write_network_address(
                const protocol::network_address_t & addr,
                const bool & prefix_version,
                const bool & prefix_timestamp = true
                )
            {
                if (prefix_version)
                {
                    /**
                     * Encode the network address version to little endian.
                     */
                    auto addr_version = endian::to_little<std::uint32_t>(
                        addr.version
                    );
                    
                    assert(addr_version.size() == 4);
                    
                    /**
                     * Write the address version.
                     */
                    write_bytes(reinterpret_cast<char *> (
                        &addr_version[0]), addr_version.size()
                    );
                }
                
                if (prefix_timestamp)
                {
                    /**
                     * Encode the network address timestamp to little endian.
                     */
                    auto addr_timestamp = endian::to_little<std::uint32_t>(
                        addr.timestamp
                    );
                    
                    assert(addr_timestamp.size() == 4);
                    
                    /**
                     * Write the address timestamp.
                     */
                    write_bytes(reinterpret_cast<char *> (
                        &addr_timestamp[0]), addr_timestamp.size()
                    );
                }
                
                /**
                 * Encode the network address services to little endian.
                 */
                auto addr_services = endian::to_little<std::uint64_t>(
                    addr.services
                );
                
                assert(addr_services.size() == 8);
                
                /**
                 * Write the address services.
                 */
                write_bytes(reinterpret_cast<char *> (
                    &addr_services[0]), addr_services.size()
                );

                assert(addr.address.size() == 16);
                
                /**
                 * Write the address.
                 */
                write_bytes(
                    reinterpret_cast<const char *> (&addr.address[0]),
                    addr.address.size()
                );
                
                /**
                 * Encode the port in network byte order.
                 */
                write_uint16(htons(addr.port));
            }
        
            /**
             * Reads an inventory vector.
             */
            inventory_vector read_inventory_vector()
            {
                inventory_vector ret;
                
                ret.decode(*this);
                
                return ret;
            }
        
            /**
             * Reads a sha256 hash.
             */
            sha256 read_sha256()
            {
                sha256 ret;

                read_bytes(
                    reinterpret_cast<char *> (ret.digest()),
                    sha256::digest_length
                );
                
                return ret;
            }
        
            /**
             * Writes a sha256 hash.
             */
            void write_sha256(const sha256 & value)
            {
                write_bytes(
                    reinterpret_cast<const char *>(value.digest()),
                    value.digest_length
                );
            }
        
            /**
             * Reads a point_out.
             */
            std::pair<sha256, std::uint32_t> read_point_out()
            {
                auto first = read_sha256();
                auto second = read_uint32();
                
                return std::make_pair(first, second);
            }
        
            /**
             * Writes a point out.
             */
            void write_point_out(std::pair<sha256, std::uint32_t> pair)
            {
                write_sha256(pair.first);
                write_uint32(pair.second);
            }
        
            /**
             * Calculates the checksum of the data.
             */
			std::uint32_t checksum()
			{
			    /**
			     * Allocate the crc digest.
			     */
			    boost::crc_32_type digest;

			    /**
			     * Calculate the checksum.
			     */
			    digest.process_bytes(&m_data[0], m_data.size());

			    /**
			     * Return the checksum.
			     */
			    return digest.checksum();
			}

            /**
             * The file.
             */
            void set_file(const std::shared_ptr<file> & f)
            {
                /**
                 * Set the file.
                 */
                file_ = f;
                
                if (file_)
                {
                    /**
                     * Set the file offset.
                     */
                    file_offset_ = file_->ftell();
                }
            }
        
            /**
             * operator =
             */
            data_buffer & operator = (const data_buffer & other)
            {
                clear();
                
			    write_bytes(other.data(), other.size());
                
                m_read_ptr = m_data.size() > 0 ? &m_data[0] : 0;
                
                file_offset_ = other.file_offset_;
                file_ = other.file_;
                
                return *this;
            }
        
        private:
        
            /**
             * The data.
             */
            std::vector<char> m_data;

            /**
             * The read pointer.
             */
            char * m_read_ptr;
            
        protected:
        
            /**
             * The file.
             */
            std::shared_ptr<file> file_;
        
            /**
             * The file offset.
             */
            std::size_t file_offset_;
    };
    
} // namespace coin

#endif // COIN_DATA_BUFFER_HPP
