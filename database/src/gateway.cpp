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

#include <database/logger.hpp>

#include <database/gateway.hpp>

#if (defined __APPLE__ || __POSIX__ || __MACH__)
#if (defined __IPHONE_OS_VERSION_MIN_REQUIRED && __IPHONE_OS_VERSION_MIN_REQUIRED >= 30200)
#ifndef _NET_ROUTE_H_
#define _NET_ROUTE_H_
#include <sys/appleapiopts.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

struct route;

struct rt_metrics {
	u_int32_t	rmx_locks;	/* Kernel must leave these values alone */
	u_int32_t	rmx_mtu;	/* MTU for this path */
	u_int32_t	rmx_hopcount;	/* max hops expected */
	int32_t		rmx_expire;	/* lifetime for route, e.g. redirect */
	u_int32_t	rmx_recvpipe;	/* inbound delay-bandwidth product */
	u_int32_t	rmx_sendpipe;	/* outbound delay-bandwidth product */
	u_int32_t	rmx_ssthresh;	/* outbound gateway buffer limit */
	u_int32_t	rmx_rtt;	/* estimated round trip time */
	u_int32_t	rmx_rttvar;	/* estimated rtt variance */
	u_int32_t	rmx_pksent;	/* packets sent using this route */
	u_int32_t	rmx_filler[4];	/* will be used for T/TCP later */
};

/*
 * Structures for routing messages.
 */
struct rt_msghdr {
	u_short	rtm_msglen;		/* to skip over non-understood messages */
	u_char	rtm_version;		/* future binary compatibility */
	u_char	rtm_type;		/* message type */
	u_short	rtm_index;		/* index for associated ifp */
	int	rtm_flags;		/* flags, incl. kern & message, e.g. DONE */
	int	rtm_addrs;		/* bitmask identifying sockaddrs in msg */
	pid_t	rtm_pid;		/* identify sender */
	int	rtm_seq;		/* for sender to identify action */
	int	rtm_errno;		/* why failed */
	int	rtm_use;		/* from rtentry */
	u_int32_t rtm_inits;		/* which metrics we are initializing */
	struct rt_metrics rtm_rmx;	/* metrics themselves */
};

#define RTM_VERSION	5	/* Up the ante and ignore older versions */

/*
 * Index offsets for sockaddr array for alternate internal encoding.
 */
#define RTAX_DST	0	/* destination sockaddr present */
#define RTAX_GATEWAY	1	/* gateway sockaddr present */
#define RTAX_NETMASK	2	/* netmask sockaddr present */
#define RTAX_MAX	8	/* size of array to allocate */

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

using namespace database;

boost::asio::ip::address gateway::default_route(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network::interface_t> ret = routes(ios, ec);
    
    auto it = ret.begin();
    
#if (defined _MSC_VER)
    for (; it != ret.end(); ++it)
    {    
        if (it->destination == boost::asio::ip::address())
        {
            continue;
        }

        if (!network::address_is_loopback(it->destination))
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


#if (defined __APPLE__ || __POSIX__ || __MACH__)

inline long round_up(long val)
{
    return 
        ((val) > 0 ? (1 + (((val) - 1) | (sizeof(long) - 1))) : sizeof(long))
    ;
}

bool parse_rt_msghdr(rt_msghdr * rtm, network::interface_t & rt_if)
{
    sockaddr * rti_info[RTAX_MAX];
    sockaddr * sa = (sockaddr*)(rtm + 1);
        
    for (unsigned int i = 0; i < RTAX_MAX; ++i)
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

    rt_if.gateway = network::sockaddr_to_address(
        rti_info[RTAX_GATEWAY]
    );
    
    rt_if.netmask = network::sockaddr_to_address(
        rti_info[RTAX_NETMASK]
    );
    
    rt_if.destination = network::sockaddr_to_address(
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

bool parse_nlmsghdr(nlmsghdr * nl_hdr, network::interface_t & rt_if)
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
                if_indextoname(*(int*)RTA_DATA(rt_attr), rt_if.name);
            break;
            case RTA_GATEWAY:
                rt_if.gateway = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            break;
            case RTA_DST:
                rt_if.destination = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            break;
        }
    }
    return true;
}

#endif

std::vector<network::interface_t> gateway::routes(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network::interface_t> ret;
    
#if (defined __APPLE__ || __POSIX__ || __MACH__)

    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0 };

    std::size_t needed = 0;
	
    if (sysctl(mib, 6, 0, &needed, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network::interface_t> ();
    }

    if (needed <= 0)
    {
        return std::vector<network::interface_t> ();
    }

    std::shared_ptr<char> buf(new char[needed]);

    if (sysctl(mib, 6, buf.get(), &needed, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network::interface_t> ();
    }

    char * end = buf.get() + needed;

    rt_msghdr * rtm;
	
    for (char * next = buf.get(); next < end; next += rtm->rtm_msglen)
    {
        rtm = (rt_msghdr *)next;
            
        if (rtm->rtm_version != RTM_VERSION)
        {
            continue;
        }
		
        network::interface_t r;
        
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
        return std::vector<network::interface_t>();
    }

    typedef DWORD(WINAPI * GetAdaptersInfo_t)(PIP_ADAPTER_INFO, PULONG);
        
    GetAdaptersInfo_t GetAdaptersInfo = (GetAdaptersInfo_t)GetProcAddress(
        iphlp, "GetAdaptersInfo"
    );
        
    if (!GetAdaptersInfo)
    {
        FreeLibrary(iphlp);
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network::interface_t>();
    }

    PIP_ADAPTER_INFO adapter_info = 0;
        
    ULONG out_buf_size = 0;
   
    if (GetAdaptersInfo(adapter_info, &out_buf_size) != ERROR_BUFFER_OVERFLOW)
    {
        FreeLibrary(iphlp);
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network::interface_t>();
    }

    adapter_info = new IP_ADAPTER_INFO[out_buf_size];

    if (GetAdaptersInfo(adapter_info, &out_buf_size) == NO_ERROR)
    {
        for (
            PIP_ADAPTER_INFO adapter = adapter_info; adapter != 0; 
            adapter = adapter->Next
            )
        {
            network::interface_t r;
				
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
        ec = boost::system::error_code(errno, boost::asio::error::system_category);
        return std::vector<network::interface_t>();
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
        
        return std::vector<network::interface_t>();
    }

    int len = read_netlink_sock(sock, msg, BUFSIZE, seq, getpid());
        
    if (len < 0)
    {
        ec = boost::system::error_code(
        	errno, boost::asio::error::system_category
        );
        
        close(sock);
        
        return std::vector<network::interface_t>();
    }

    for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len))
    {
        network::interface_t intf;
        
        if (parse_nlmsghdr(nl_msg, intf))
        {
            ret.push_back(intf);
        }
    }
    close(sock);

#endif
    return ret;
}
