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

#include <coin/gateway.hpp>
#include <coin/logger.hpp>

#if (defined __APPLE__ || __POSIX__ || __MACH__)
#if (defined __IPHONE_OS_VERSION_MIN_REQUIRED)
#ifndef _NET_ROUTE_H_
#define _NET_ROUTE_H_
#include <sys/appleapiopts.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

struct route;

struct rt_metrics
{
	u_int32_t rmx_locks;
	u_int32_t rmx_mtu;
	u_int32_t rmx_hopcount;
	int32_t rmx_expire;
	u_int32_t rmx_recvpipe;
	u_int32_t rmx_sendpipe;
	u_int32_t rmx_ssthresh;
	u_int32_t rmx_rtt;
	u_int32_t rmx_rttvar;
	u_int32_t rmx_pksent;
	u_int32_t rmx_filler[4];
};

struct rt_msghdr
{
	u_short	rtm_msglen;
	u_char	rtm_version;
	u_char	rtm_type;
	u_short	rtm_index;
	int	rtm_flags;
	int	rtm_addrs;
	pid_t	rtm_pid;
	int	rtm_seq;
	int	rtm_errno;
	int	rtm_use;
	u_int32_t rtm_inits;
	struct rt_metrics rtm_rmx;
};

#define RTM_VERSION	5

#define RTAX_DST 0
#define RTAX_GATEWAY 1
#define RTAX_NETMASK 2
#define RTAX_MAX 8

#endif
#else
#include <net/route.h>
#endif // 
#include <sys/sysctl.h>
#elif (defined _MSC_VER)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#elif (defined __linux__)
extern "C"
{
#include <asm/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <unistd.h>
}
#endif

using namespace coin;

boost::asio::ip::address gateway::default_route(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network_interface_t> ret = routes(ios, ec);
    
    auto it = ret.begin();
    
#if (defined _MSC_VER)
    for (; it != ret.end(); ++it)
    {    
        if (it->destination == boost::asio::ip::address())
        {
            continue;
        }

        if (address_is_loopback(it->destination) == false)
        {
			break;
        }
    }
#else
    for (; it != ret.end(); ++it)
    {
        if (it->destination == boost::asio::ip::address())
        {
            break;
        }
    }
#endif
    if (it == ret.end())
    {
        return boost::asio::ip::address();
    }
        
    return it->gateway;
}

boost::asio::ip::address gateway::local_address()
{
    boost::system::error_code ec;
    boost::asio::ip::address ret = boost::asio::ip::address_v4::any();
    
    const auto & interfaces = local_interfaces(ec);
        
    auto it = interfaces.begin();
        
    for (; it != interfaces.end(); ++it)
    {
        const boost::asio::ip::address & a = it->destination;
            
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

#if (defined __APPLE__ || __POSIX__ || __MACH__)

inline long round_up(long val)
{
    return 
        ((val) > 0 ? (1 + (((val) - 1) | (sizeof(long) - 1))) : sizeof(long))
    ;
}

bool parse_rt_msghdr(rt_msghdr * rtm, gateway::network_interface_t & rt_if)
{
    sockaddr * rti_info[RTAX_MAX];
    sockaddr * sa = (sockaddr*)(rtm + 1);
        
    for (auto i = 0; i < RTAX_MAX; ++i)
    {
        if ((rtm->rtm_addrs & (1 << i)) == 0)
        {
            rti_info[i] = 0;
            
            continue;
        }
        
        rti_info[i] = sa;

        sa = (sockaddr *)((char *)(sa) + round_up(sa->sa_len));
    }

    sa = rti_info[RTAX_GATEWAY];
        
    if (
        sa == 0 || rti_info[RTAX_DST] == 0 || rti_info[RTAX_NETMASK] == 0 || 
        (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
        )
    {
        return false;
    }

    rt_if.gateway = gateway::sockaddr_to_address(
        rti_info[RTAX_GATEWAY]
    );
    
    rt_if.netmask = gateway::sockaddr_to_address(
        rti_info[RTAX_NETMASK]
    );
    
    rt_if.destination = gateway::sockaddr_to_address(
        rti_info[RTAX_DST]
    );
    
    if_indextoname(rtm->rtm_index, rt_if.name);
        
    return true;
}

#elif (defined __linux__)

int read_netlink_sock(int sock, char * buf, int len, int seq, int pid)
{
    nlmsghdr * nl_hdr;

    int msg_len = 0;

    do
    {
        int read_len = recv(sock, buf, len - msg_len, 0);
            
        if (read_len < 0)
        {
            return -1;
        }

        nl_hdr = (nlmsghdr *)buf;

        if (
            (NLMSG_OK(nl_hdr, read_len) == 0) || 
            (nl_hdr->nlmsg_type == NLMSG_ERROR)
            )
        {
            return -1;
        }

        if (nl_hdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }

        buf += read_len;
            
        msg_len += read_len;

        if ((nl_hdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            break;
        }

    } while ((nl_hdr->nlmsg_seq != seq) || (nl_hdr->nlmsg_pid != pid));
        
    return msg_len;
}

bool parse_nlmsghdr(nlmsghdr * nl_hdr, gateway::network_interface_t & rt_if)
{
    rtmsg * rt_msg = (rtmsg *)NLMSG_DATA(nl_hdr);

    if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN))
    {
        return false;
    }

    int rt_len = RTM_PAYLOAD(nl_hdr);
        
    rtattr * rt_attr = (rtattr *)RTM_RTA(rt_msg);
    
    for (; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr, rt_len))
    {
        switch (rt_attr->rta_type)
        {
            case RTA_OIF:
            {
                if_indextoname(*(int*)RTA_DATA(rt_attr), rt_if.name);
            }
            break;
            case RTA_GATEWAY:
            {
                rt_if.gateway = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            }
            break;
            case RTA_DST:
            {
                rt_if.destination = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            }
            break;
        }
    }
    return true;
}

#endif

std::vector<gateway::network_interface_t> gateway::routes(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network_interface_t> ret;
    
#if (defined __APPLE__ || __POSIX__ || __MACH__)

    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0 };

    std::size_t len = 0;
	
    if (sysctl(mib, 6, 0, &len, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network_interface_t> ();
    }

    if (len <= 0)
    {
        return std::vector<network_interface_t> ();
    }

    std::shared_ptr<char> buf(new char[len]);

    if (sysctl(mib, 6, buf.get(), &len, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network_interface_t> ();
    }

    char * end = buf.get() + len;

    rt_msghdr * rtm;
	
    for (char * next = buf.get(); next < end; next += rtm->rtm_msglen)
    {
        rtm = (rt_msghdr *)next;
            
        if (rtm->rtm_version != RTM_VERSION)
        {
            continue;
        }
		
        network_interface_t r;
        
        if (parse_rt_msghdr(rtm, r))
        {
            ret.push_back(r);
        }
    }
	
#elif (defined _MSC_VER)
    HMODULE iphlp = LoadLibrary(TEXT("Iphlpapi.dll"));
        
    if (!iphlp)
    {
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network_interface_t>();
    }

    typedef DWORD(WINAPI * GetAdaptersInfo_t)(PIP_ADAPTER_INFO, PULONG);
        
    GetAdaptersInfo_t GetAdaptersInfo = (GetAdaptersInfo_t)GetProcAddress(
        iphlp, "GetAdaptersInfo"
    );
        
    if (GetAdaptersInfo == 0)
    {
        FreeLibrary(iphlp);
        
        ec = boost::asio::error::operation_not_supported;
        
        return std::vector<network_interface_t>();
    }

    PIP_ADAPTER_INFO adapter_info = 0;
        
    ULONG out_buf_size = 0;
   
    if (GetAdaptersInfo(adapter_info, &out_buf_size) != ERROR_BUFFER_OVERFLOW)
    {
        FreeLibrary(iphlp);
        
        ec = boost::asio::error::operation_not_supported;
        
        return std::vector<network_interface_t>();
    }

    adapter_info = new IP_ADAPTER_INFO[out_buf_size];

    if (GetAdaptersInfo(adapter_info, &out_buf_size) == NO_ERROR)
    {
        for (
            PIP_ADAPTER_INFO adapter = adapter_info; adapter != 0; 
            adapter = adapter->Next
            )
        {
            network_interface_t r;
				
			r.destination = boost::asio::ip::address::from_string(
                adapter->IpAddressList.IpAddress.String, ec
            );
                
			r.gateway = boost::asio::ip::address::from_string(
                adapter->GatewayList.IpAddress.String, ec
            );
                
			r.netmask = boost::asio::ip::address::from_string(
                adapter->IpAddressList.IpMask.String, ec
            );
				
            strncpy(r.name, adapter->AdapterName, sizeof(r.name));

            if (ec)
            {
                ec = boost::system::error_code();
                continue;
            }

            ret.push_back(r);
        }
    }
   
    delete adapter_info, adapter_info = 0;
    
    FreeLibrary(iphlp);

#elif (defined __linux__)

    enum { BUFSIZE = 8192 };

    int sock = socket(PF_ROUTE, SOCK_DGRAM, NETLINK_ROUTE);
    
    if (sock < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        
        return std::vector<network_interface_t> ();
    }

    int seq = 0;

    char msg[BUFSIZE];
        
    std::memset(msg, 0, BUFSIZE);
        
    nlmsghdr * nl_msg = (nlmsghdr*)msg;

    nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    nl_msg->nlmsg_type = RTM_GETROUTE;
    nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nl_msg->nlmsg_seq = seq++;
    nl_msg->nlmsg_pid = getpid();

    if (send(sock, nl_msg, nl_msg->nlmsg_len, 0) < 0)
    {
        ec = boost::system::error_code(
        	errno, boost::asio::error::system_category
        );
        
        close(sock);
        
        return std::vector<network_interface_t>();
    }

    int len = read_netlink_sock(sock, msg, BUFSIZE, seq, getpid());
        
    if (len < 0)
    {
        ec = boost::system::error_code(
        	errno, boost::asio::error::system_category
        );
        
        close(sock);
        
        return std::vector<network_interface_t> ();
    }

    for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len))
    {
        network_interface_t intf;
        
        if (parse_nlmsghdr(nl_msg, intf))
        {
            ret.push_back(intf);
        }
    }
    close(sock);

#endif // __linux__
    return ret;
}

std::vector<gateway::network_interface_t> gateway::local_interfaces(
    boost::system::error_code & ec
    )
{
    std::vector<network_interface_t> ret;

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
            network_interface_t iface;

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

        network_interface_t iface;
        
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


boost::asio::ip::address gateway::sockaddr_to_address(
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

boost::asio::ip::address gateway::inaddr_to_address(
    const in_addr * addr
    )
{
    boost::asio::ip::address_v4::bytes_type b;
    std::memcpy(&b[0], addr, b.size());
    return boost::asio::ip::address_v4(b);
}

boost::asio::ip::address gateway::inaddr6_to_address(
    const in6_addr * addr
    )
{
    boost::asio::ip::address_v6::bytes_type b;
    std::memcpy(&b[0], addr, b.size());
    
    return boost::asio::ip::address_v6(b);
}

bool gateway::address_is_loopback(
    const boost::asio::ip::address & addr
    )
{
    if (addr.is_v4())
    {
        return addr.to_v4() ==
            boost::asio::ip::address_v4::loopback()
        ;
    }

    return addr.to_v6() == boost::asio::ip::address_v6::loopback();
}

bool gateway::address_is_multicast(
    const boost::asio::ip::address & addr
    )
{
    if (addr.is_v4())
    {
        return addr.to_v4().is_multicast();
    }

    return addr.to_v6().is_multicast();
}

bool gateway::address_is_any(const boost::asio::ip::address & addr)
{
    if (addr.is_v4())
    {
        return addr.to_v4() == boost::asio::ip::address_v4::any();
    }


    return addr.to_v6() == boost::asio::ip::address_v6::any();
}
