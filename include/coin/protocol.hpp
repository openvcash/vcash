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

#ifndef COIN_PROTOCOL_HPP
#define COIN_PROTOCOL_HPP

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include <coin/hash.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/sha256.hpp>

namespace coin {

class alert;
class block;
class transaction;

namespace protocol {

        /**
         * The version.
         */
        enum { version = 60029 };

        /**
         * The minimum version.
         */
        enum { minimum_version = 60027 };
    
        /**
         * The default peer port.
         */
        enum { default_tcp_port = 9194 };
    
        /**
         * The default rpc port.
         */
        enum { default_rpc_port = 9195 };
    
        /**
         * The operation modes.
         * 0x00|0|00000000
         * 0x01|1|00000001
         * 0x02|2|00000010
         * 0x04|4|00000100
         * 0x08|8|00001000
         * 0x10|16|00010000
         * 0x20|32|00100000
         * 0x40|64|01000000
         * 0x80|128|10000000
         */
        typedef enum operation_mode_s
        {
            operation_mode_client = 0x00,
            operation_mode_peer = 0x01,
            operation_mode_0x02 = 0x02,
            operation_mode_0x04 = 0x04,
            operation_mode_0x08 = 0x08,
            operation_mode_0x10 = 0x10,
            operation_mode_0x20 = 0x20,
            operation_mode_0x40 = 0x40,
            operation_mode_0x80 = 0x80,
        } operation_mode_t;
        
        /**
         * Ihe ipv4 mapped prefix.
         */
        static const std::array<uint8_t, 12> v4_mapped_prefix =
        {
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }
        };
    
        /**
         * The network address structure.
         */
        typedef struct network_address_s
        {
            /**
             * The version .
             */
            std::uint8_t version;
            
            /**
             * The timestamp.
             */
            std::uint32_t timestamp;
            
            /**
             * The services.
             */
            std::uint64_t services;
    
            /**
             * The address.
             */
            std::array<std::uint8_t, 16> address;
            
            /**
             * The port.
             */
            std::uint16_t port;
            
            /**
             * The address types.
             */
            typedef enum type_s
            {
                type_unroutable,
                type_ipv4,
                type_ipv6,
                type_tor,
                type_i2p,
                type_max,
                type_255 = 255,
            } type_t;
            
            /**
             * The type (internal).
             */
            type_t type;
            
            /**
             * The last timed tried.
             */
            std::uint64_t last_try;
                        
            /**
             * operator <
             */
            bool operator < (const network_address_s & rhs) const
            {
                return
                    std::memcmp(&this->address[0], &rhs.address[0], 16) < 0
                ;
            }
            
            /**
             * operator ==
             */
            bool operator == (const network_address_s & rhs) const
            {
                return
                    std::memcmp(&this->address[0], &rhs.address[0], 16) == 0
                ;
            }

            /**
             * operator !=
             */
            bool operator != (const network_address_s & rhs)
            {
                return
                    std::memcmp(&this->address[0], &rhs.address[0], 16) != 0
                ;
            }
            
            /**
             * Creates a network address from a boost::asio::ip::tcp::endpoint.
             */
            static network_address_s from_endpoint(
                const boost::asio::ip::tcp::endpoint & ep
                )
            {
                network_address_s ret;
                
                std::memset(&ret, 0, sizeof(ret));
                
                ret.timestamp = static_cast<std::uint32_t> (std::time(0));
                ret.services = operation_mode_peer;
                ret.last_try = 0;
                
                if (ep.address().is_v4())
                {
                    std::memcpy(
                        &ret.address[0], &protocol::v4_mapped_prefix[0],
                        protocol::v4_mapped_prefix.size()
                    );
                    
                    auto ip = ep.address().to_v4().to_ulong();
                    
                    // :FIXME:
                    ip = ntohl(ip);
                    
                    std::memcpy(
                        &ret.address[0] + protocol::v4_mapped_prefix.size(),
                        &ip, sizeof(ip)
                    );
                }
                else
                {
                    std::memcpy(
                        &ret.address[0], &ep.address().to_v6().to_bytes()[0],
                        ret.address.size()
                    );
                }
                
                ret.port = ep.port();
                
                return ret;
            }
            
            /**
             * Creates a network_address_t structure from an array of address
             * bytes.
             */
            static network_address_s from_array(
                const std::array<std::uint8_t, 16> & address
                )
            {
                network_address_s ret;
                
                std::memset(&ret, 0, sizeof(ret));
                
                ret.timestamp = static_cast<std::uint32_t> (std::time(0));
                ret.services = operation_mode_peer;
                ret.last_try = 0;
                ret.address = address;
                ret.port = 0;
                
                return ret;
            }
            
            /**
             * Returns the ipv4 mapped address.
             */
            boost::asio::ip::address ipv4_mapped_address() const
            {
                if (is_ipv4())
                {
                    boost::asio::ip::address_v4::bytes_type addr_bytes;
 
                    std::memcpy(addr_bytes.data(), &address[0] + 12, 4);
                    
                    return boost::asio::ip::address_v4(addr_bytes);
                }
    
                boost::asio::ip::address_v6::bytes_type addr_bytes;
 
                std::copy(
                    &address[0], &address[0] + addr_bytes.size(),
                    addr_bytes.data()
                );
                
                return boost::asio::ip::address_v6(addr_bytes);
            }
            
            /**
             * If true the network address is ipv4.
             */
            bool is_ipv4() const
            {
                return std::memcmp(&address, &v4_mapped_prefix, 12) == 0;
            }
            
            /**
             * If true the network address is ipv6.
             */
            bool is_ipv6() const
            {
                return
                    is_ipv4() == false && is_tor() == false &&
                    is_i2p() == false
                ;
            }

            /**
             * If true the network address is rfc1918.
             */
            bool is_rfc1918() const
            {
                return is_ipv4() &&
                    (byte_at(3) == 10 || (byte_at(3) == 192 &&
                    byte_at(2) == 168) || (byte_at(3) == 172 &&
                    (byte_at(2) >= 16 && byte_at(2) <= 31))
                );
            }

            /**
             * If true the network address is rfc3927.
             */
            bool is_rfc3927() const
            {
                return is_ipv4() && (byte_at(3) == 169 && byte_at(2) == 254);
            }

            /**
             * If true the network address is rfc3849.
             */
            bool is_rfc3849() const
            {
                return
                    byte_at(15) == 0x20 && byte_at(14) == 0x01 &&
                    byte_at(13) == 0x0D && byte_at(12) == 0xB8
                ;
            }

            /**
             * If true the network address is rfc3964.
             */
            bool is_rfc3964() const
            {
                return byte_at(15) == 0x20 && byte_at(14) == 0x02;
            }

            /**
             * If true the network address is rfc6052.
             */
            bool is_rfc6052() const
            {
                static const std::uint8_t g_rfc6052[] =
                {
                    0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0
                };
                
                return std::memcmp(&address, g_rfc6052, sizeof(g_rfc6052)) == 0;
            }

            /**
             * If true the network address is rfc4380.
             */
            bool is_rfc4380() const
            {
                return
                    byte_at(15) == 0x20 && byte_at(14) == 0x01 &&
                    byte_at(13) == 0 && byte_at(12) == 0
                ;
            }

            /**
             * If true the network address is rfc4862.
             */
            bool is_rfc4862() const
            {
                static const std::uint8_t g_rfc4862[] =
                {
                    0xFE, 0x80, 0, 0, 0, 0, 0, 0
                };
                return std::memcmp(&address, g_rfc4862, sizeof(g_rfc4862)) == 0;
            }

            /**
             * If true the network address is rfc4193.
             */
            bool is_rfc4193() const
            {
                return (byte_at(15) & 0xFE) == 0xFC;
            }

            /**
             * If true the network address is rfc6145.
             */
            bool is_rfc6145() const
            {
                static const std::uint8_t g_rfc6145[] =
                {
                    0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0
                };
                return std::memcmp(&address, g_rfc6145, sizeof(g_rfc6145)) == 0;
            }

            /**
             * If true the network address is rfc4843.
             */
            bool is_rfc4843() const
            {
                return
                    byte_at(15) == 0x20 && byte_at(14) == 0x01 &&
                    byte_at(13) == 0x00 && (byte_at(12) & 0xF0) == 0x10
                ;
            }

            /**
             * If true the network address is tor.
             */
            bool is_tor() const
            {
                static const std::uint8_t g_onion_cat[] =
                {
                    0xFD, 0x87, 0xD8, 0x7E, 0xEB, 0x43
                };
                return
                    std::memcmp(&address, g_onion_cat, sizeof(g_onion_cat)) == 0
                ;
            }

            /**
             * If true the network address is i2p.
             */
            bool is_i2p() const
            {
                static const std::uint8_t g_garli_cat[] =
                {
                    0xFD, 0x60, 0xDB, 0x4D, 0xDD, 0xB5
                };
                return
                    std::memcmp(&address, g_garli_cat, sizeof(g_garli_cat)) == 0
                ;
            }
            
            /**
             * If true the address is local.
             */
            bool is_local() const
            {
                if (is_ipv4() && (byte_at(3) == 127 || byte_at(3) == 0))
                {
                    return true;
                }

                static const std::uint8_t g_local[16] =
                {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
                };
                
                if (std::memcmp(&address, g_local, 16) == 0)
                {
                    return true;
                }
                
                return false;
            }
            
            /**
             * If true the address is routable.
             */
            bool is_routable() const
            {
                return
                    is_valid() &&
                    !(is_rfc1918() || is_rfc3927() || is_rfc4862() ||
                    (is_rfc4193() && !is_tor() && !is_i2p()) ||
                    is_rfc4843() || is_local())
                ;
            }
            
            /**
             * If true the address is valid.
             */
            bool is_valid() const
            {
                std::uint8_t ipv6_none[16] = { };
                
                if (std::memcmp(&address, ipv6_none, 16) == 0)
                {
                    return false;
                }
                
                if (is_rfc3849())
                {
                    return false;
                }
                
                if (is_ipv4())
                {
                    auto ipv4_none = INADDR_NONE;
                    
                    if (std::memcmp(&address[12], &ipv4_none, 4) == 0)
                    {
                        return false;
                    }
                    
                    ipv4_none = 0;
                    
                    if (std::memcmp(&address[12], &ipv4_none, 4) == 0)
                    {
                        return false;
                    }
                }

                return true;
            }
            
            /**
             * Gets the byte a index i.
             */
            std::uint8_t byte_at(const std::size_t & i) const
            {
                return address[15 - i];
            }

            /**
             * The key.
             */
            std::vector<std::uint8_t> key() const
            {
                 std::vector<std::uint8_t> ret;
                 ret.resize(18);
                 std::memcpy(&ret[0], &address[0], address.size());
                 ret[16] = port / 0x100;
                 ret[17] = port & 0x0FF;
                 return ret;
            }
            
            /**
             * The canonical identifier of an address group.
             */
            std::vector<std::uint8_t> group() const
            {
                std::vector<std::uint8_t> ret;
                
                auto type = type_ipv6;
                auto start_byte = 0;
                auto bits = 16;

                /**
                 * Local addresses belong to the same group.
                 */
                if (is_local())
                {
                    type = type_255, bits = 0;
                }

                /**
                 * All unroutable addresses belong to the same group.
                 */
                if (is_routable() == false)
                {
                    type = type_unroutable, bits = 0;
                }
                else if (is_ipv4() || is_rfc6145() || is_rfc6052())
                {
                    type = type_ipv4, start_byte = 12;
                }
                else if (is_rfc3964())
                {
                    type = type_ipv4, start_byte = 2;
                }
                else if (is_rfc4380())
                {
                    ret.push_back(type_ipv4);
                    ret.push_back(byte_at(3) ^ 0xFF);
                    ret.push_back(byte_at(2) ^ 0xFF);
                    
                    return ret;
                }
                else if (is_tor())
                {
                    type = type_tor, start_byte = 6, bits = 4;
                }
                else if (is_i2p())
                {
                    type = type_i2p, start_byte = 6, bits = 4;
                }
                else if (
                    byte_at(15) == 0x20 && byte_at(14) == 0x11 &&
                    byte_at(13) == 0x04 && byte_at(12) == 0x70
                    )
                {
                    bits = 36;
                }
                else
                {
                    bits = 32;
                }
                
                ret.push_back(type);
                
                while (bits >= 8)
                {
                    ret.push_back(byte_at(15 - start_byte));
                    
                    start_byte++;
                    
                    bits -= 8;
                }
                
                if (bits > 0)
                {
                    ret.push_back(
                        byte_at(15 - start_byte) | ((1 << bits) - 1)
                    );
                }
                
                return ret;
            }
            
            /**
             * Calculates the hash.
             */
            std::uint64_t get_hash() const
            {
                std::uint64_t ret;
                
                auto h = sha256::from_digest(
                    &hash::sha256d(&address[0], address.size())[0]
                );
                
                std::memcpy(&ret, h.digest(), sizeof(ret));
                
                return ret;
            }
            
        } network_address_t;

        /**
         * The inventory vector string representations.
         */
        static const char * inventory_type_names[] =
        {
            "ERROR",
            "tx",
            "block",
        };
    
        /** Message Structures */
    
        /**
         * The version structure.
         */
        typedef struct
        {
            std::uint32_t version;
            std::uint64_t services;
            std::uint64_t timestamp;
            network_address_t addr_src;
            network_address_t addr_dst;
            std::uint64_t nonce;
            std::string user_agent;
            std::uint32_t start_height;
        } version_t;
    
        /**
         * The addr structure.
         */
        typedef struct
        {
            std::uint64_t count;
            std::vector<network_address_t> addr_list;
        } addr_t;
    
        /**
         * The ping structure.
         */
        typedef struct
        {
            std::uint64_t nonce;
        } ping_t;
    
        /**
         * The pong structure.
         */
        typedef struct
        {
            std::uint64_t nonce;
        } pong_t;
    
        /**
         * The inv structure.
         * count var_int Number of inventory entries.
         * inventory inv_vect[] Inventory vectors.
         */
        typedef struct
        {
            std::uint64_t count;
            std::vector<inventory_vector> inventory;
        } inv_t;
    
        /**
         * The getdata structure.
         */
        typedef struct
        {
            std::uint64_t count;
            std::vector<inventory_vector> inventory;
        } getdata_t;
    
        /**
         * The getblocks structure.
         */
        typedef struct
        {
            std::uint32_t version;
            std::uint64_t count;
            std::vector<sha256> hashes;
            sha256 hash_stop;
        } getblocks_t;
    
        /**
         * The block structure.
         */
        typedef struct
        {
            std::shared_ptr<block> blk;
        } block_t;
    
        /**
         * The checkpoint structure.
         */
        typedef struct
        {
            std::vector<std::uint8_t> message;
            std::vector<std::uint8_t> signature;
        } checkpoint_t;
    
        /**
         * The tx structure.
         */
        typedef struct
        {
            std::shared_ptr<transaction> tx;
        } tx_t;

        /**
         * The alert structure.
         */
        typedef struct
        {
            std::shared_ptr<alert> a;
        } alert_t;

        /**
         * The maximum inventory size.
         */
        enum { max_inv_size = 50000 };
    
    } // namespace protocol
} // namespace coin

#endif // COIN_PROTOCOL_HPP
