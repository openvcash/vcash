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
 
#ifndef DATABASE_NETWORK_HPP
#define DATABASE_NETWORK_HPP

#if (defined _MSC_VER)
    // ...
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#endif

#include <cstdint>

#include <boost/asio.hpp>

namespace database {

    class network
    {
        public:
        
            /**
             * If true the address is private.
             */
            static bool address_is_private(
                const boost::asio::ip::address & addr
                )
            {
                if (addr.is_v6())
                {
                    return addr.to_v6().is_link_local();
                }
                else
                {
                    std::uint32_t ip = addr.to_v4().to_ulong();
                    
                    return (
                        (ip & 0xff000000) == 0x0a000000 || 
                        (ip & 0xfff00000) == 0xac100000 || 
                        (ip & 0xffff0000) == 0xc0a80000
                    );
                }
                
                return false;
            }

            /**
             * If true the address is loopback.
             */
            static bool address_is_loopback(
                const boost::asio::ip::address & addr
                )
            {
                if (addr.is_v4())
                {
                    return addr.to_v4() ==
                        boost::asio::ip::address_v4::loopback()
                    ;
                }
                else
                {
                    return addr.to_v6() ==
                        boost::asio::ip::address_v6::loopback()
                    ;
                }
            }

            /**
             * If true the address is multicast.
             */
            static bool address_is_multicast(
                const boost::asio::ip::address & addr
                )
            {
                if (addr.is_v4())
                {
                    return addr.to_v4().is_multicast();
                }
                else
                {
                    return addr.to_v6().is_multicast();
                }
            }

            static boost::asio::ip::address inaddr_to_address(
                const in_addr * addr
                )
            {
                typedef boost::asio::ip::address_v4::bytes_type bytes_t;
                bytes_t b;
                std::memcpy(&b[0], addr, b.size());
                return boost::asio::ip::address_v4(b);
            }

            static boost::asio::ip::address inaddr6_to_address(
                const in6_addr * addr
                )
            {
                typedef boost::asio::ip::address_v6::bytes_type bytes_t;
                bytes_t b;
                std::memcpy(&b[0], addr, b.size());
                return boost::asio::ip::address_v6(b);
            }

            /**
             * If true the address is any.
             */
            static bool address_is_any(const boost::asio::ip::address & addr)
            {
                if (addr.is_v4())
                {
                    return addr.to_v4() == boost::asio::ip::address_v4::any();
                }
                else
                {
                    return addr.to_v6() == boost::asio::ip::address_v6::any();
                }
            }

            static boost::asio::ip::address sockaddr_to_address(
                const sockaddr * addr
                )
            {
                if (addr->sa_family == AF_INET)
                {
                    return inaddr_to_address(
                        &((const sockaddr_in *)addr)->sin_addr
                    );
                }
                else if (addr->sa_family == AF_INET6)
                {
                    return inaddr6_to_address(
                        &((const sockaddr_in6 *)addr)->sin6_addr
                    );
                }
                return boost::asio::ip::address();
            }
        
            typedef struct
            {
                /**
                 * The destination ip address.
                 */
                boost::asio::ip::address destination;
                
                /**
                 * The gateway ip address.
                 */
                boost::asio::ip::address gateway;
                
                /**
                 * The netmask of the network interface.
                 */
                boost::asio::ip::address netmask;

                /**
                 * The string representation of the network interface.
                 */
                char name[64];
                
            } interface_t;

            static std::vector<interface_t> local_interfaces(
                boost::system::error_code & ec
                )
            {
                std::vector<interface_t> ret;

            #if (defined __linux__) || (defined __APPLE__ || __MACH__)

                int s = socket(AF_INET, SOCK_DGRAM, 0);
                
                if (s < 0)
                {
                    ec = boost::asio::error::fault;
                    return ret;
                }
                
                ifconf ifc;
                char buf[1024];
                
                ifc.ifc_len = sizeof(buf);
                ifc.ifc_buf = buf;
                
                if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
                {
                    ec = boost::system::error_code(
                        errno, boost::asio::error::system_category
                    );
                    
                    close(s);
                    
                    return ret;
                }

                char *ifr = (char *)ifc.ifc_req;
                
                int remaining = ifc.ifc_len;

                while (remaining)
                {
                    const ifreq & item = *reinterpret_cast<ifreq *>(ifr);

                    if (
                        item.ifr_addr.sa_family == AF_INET || 
                        item.ifr_addr.sa_family == AF_INET6
                        )
                    {
                        interface_t iface;

                        iface.destination = sockaddr_to_address(&item.ifr_addr);
                        
                        strcpy(iface.name, item.ifr_name);

                        ifreq netmask = item;
                        
                        if (ioctl(s, SIOCGIFNETMASK, &netmask) < 0)
                        {
                            if (iface.destination.is_v6())
                            {
                                iface.netmask = boost::asio::ip::address_v6::any();
                            }
                            else
                            {
                                ec = boost::system::error_code(
                                    errno, boost::asio::error::system_category
                                );
                                
                                close(s);
                                
                                return ret;
                            }
                        }
                        else
                        {
                            iface.netmask = sockaddr_to_address(
                                &netmask.ifr_addr
                            );
                        }
                        ret.push_back(iface);
                    }

            #if (defined __APPLE__ || __MACH__)
                    std::size_t if_size = item.ifr_addr.sa_len + IFNAMSIZ;
            #elif defined __linux__
                    std::size_t if_size = sizeof(ifreq);
            #endif
                        ifr += if_size;
                        remaining -= if_size;
                    }
                    
                    close(s);

            #elif (defined _MSC_VER)

                    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
                    
                    if (s == SOCKET_ERROR)
                    {
                        ec = boost::system::error_code(
                            WSAGetLastError(), boost::asio::error::system_category
                        );
                        
                        return ret;
                    }

                    INTERFACE_INFO buf[30];
                    
                    DWORD size;
                
                    int err = WSAIoctl(
                        s, SIO_GET_INTERFACE_LIST, 0, 0, buf, sizeof(buf), &size, 0, 0
                    );
                
                    if (err != 0)
                    {
                        ec = boost::system::error_code(
                            WSAGetLastError(), boost::asio::error::system_category
                        );
                        
                        closesocket(s);
                        
                        return ret;
                    }
                    
                    closesocket(s);

                    std::size_t n = size / sizeof(INTERFACE_INFO);

                    interface_t iface;
                    
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        iface.destination = sockaddr_to_address(&buf[i].iiAddress.Address);
                        
                        iface.netmask = sockaddr_to_address(&buf[i].iiNetmask.Address);
                        
                        iface.name[0] = 0;
                        
                        if (iface.destination == boost::asio::ip::address_v4::any())
                        {
                            continue;
                        }
                        ret.push_back(iface);
                    }
            #else
            #error "Unsupported Device or Platform."
            #endif
                return ret;
            }

            static boost::asio::ip::address local_address()
            {
                boost::system::error_code ec;
                boost::asio::ip::address ret = boost::asio::ip::address_v4::any();
                
                const std::vector<interface_t> &
                    interfaces = local_interfaces(ec)
                ;
                    
                std::vector<interface_t>::const_iterator
                    it = interfaces.begin()
                ;
                    
                for (; it != interfaces.end(); ++it)
                {
                    const boost::asio::ip::address & a = (*it).destination;
                        
                    /**
                     * Skip loopback, multicast and any.
                     */
                    if (
                        address_is_loopback(a)|| address_is_multicast(a) ||
                        address_is_any(a)
                        )
                    {
                        continue;
                    }
                    
                    // Other flags, IFF_UP, etc...

                    /**
                     * Prefer an ipv4 address over v6.
                     */
                    if (a.is_v4())
                    {
                        ret = a;
                        break;
                    }

                    /**
                     * If this one is not any then return it.
                     */
                    if (ret != boost::asio::ip::address_v4::any())
                    {
                        ret = a;
                    }
                }
                
                return ret;
            }

        private:
        
            // ...
            
        protected:
        
            // ...
    };

} // namespace database

#endif // DATABASE_NETWORK_HPP
