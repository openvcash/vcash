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

#include <coin/address_manager.hpp>
#include <coin/configuration.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/network.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/time.hpp>
#include <coin/utility.hpp>

using namespace coin;

tcp_connection_manager::tcp_connection_manager(
    boost::asio::io_service & ios, stack_impl & owner
    )
    : m_time_last_inbound(0)
    , io_service_(ios)
    , resolver_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void tcp_connection_manager::start()
{
    std::vector<boost::asio::ip::tcp::resolver::query> queries;
    
    /**
     * Get the bootstrap nodes and ready them for DNS lookup.
     */
    auto bootstrap_nodes = stack_impl_.get_configuration().bootstrap_nodes();
    
    for (auto & i : bootstrap_nodes)
    {
        boost::asio::ip::tcp::resolver::query q(
            i.first, std::to_string(i.second)
        );
        
        queries.push_back(q);
    }

    /**
     * Randomize the host names.
     */
    std::random_shuffle(queries.begin(), queries.end());
    
    /**
     * Start host name resolution.
     */
    do_resolve(queries);

    /**
     * Start the timer.
     */
    auto self(shared_from_this());
    
    timer_.expires_from_now(std::chrono::seconds(1));
    timer_.async_wait(globals::instance().strand().wrap(
        std::bind(&tcp_connection_manager::tick, self,
        std::placeholders::_1))
    );
}

void tcp_connection_manager::stop()
{
    resolver_.cancel();
    timer_.cancel();
    
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            connection->stop();
        }
    }
    
    m_tcp_connections.clear();
}

void tcp_connection_manager::handle_accept(
    std::shared_ptr<tcp_transport> transport
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    try
    {
        if (
            transport->socket().remote_endpoint().address(
            ).is_loopback() == false && transport->socket().remote_endpoint(
            ).address().is_multicast() == false
            )
        {
            m_time_last_inbound = std::time(0);
        }
    }
    catch (...)
    {
        // ...
    }

    /**
     * Only peers accept incoming connections.
     */
    if (
        globals::instance().state() == globals::state_started &&
        globals::instance().operation_mode() == protocol::operation_mode_peer
        )
    {
        /**
         * We allow this many incoming connections per same IP address.
         */
        enum { maximum_per_same_ip = 6 };

        auto connections = 0;
        
        for (auto & i : m_tcp_connections)
        {
            try
            {
                if (auto t = i.second.lock())
                {
                    if (
                        t->is_transport_valid() && i.first.address() ==
                        transport->socket().remote_endpoint().address()
                        )
                    {
                        if (++connections == maximum_per_same_ip)
                        {
                            break;
                        }
                    }
                }
            }
            catch (...)
            {
                // ...
            }
        }
        
        if (connections > maximum_per_same_ip)
        {
            log_error(
                "TCP connection manager is dropping duplicate IP connection "
                "from " << transport->socket().remote_endpoint() << "."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            network::instance().is_address_banned(
            transport->socket().remote_endpoint().address().to_string())
            )
        {
            log_info(
                "TCP connection manager is dropping banned connection from " <<
                transport->socket().remote_endpoint() << ", limit reached."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            is_ip_banned(
            transport->socket().remote_endpoint().address().to_string())
            )
        {
            log_info(
                "TCP connection manager is dropping (static banned) "
                "connection from " << transport->socket().remote_endpoint() <<
                "."
            );
            
            /**
             * Stop the transport.
             */
            transport->stop();
        }
        else if (
            active_tcp_connections() >=
            stack_impl_.get_configuration().network_tcp_inbound_maximum()
            )
        {
            /**
             * Allow 16 (short term) connection slots beyond our maximum.
             */
            if (
                active_tcp_connections() >=
                stack_impl_.get_configuration(
                ).network_tcp_inbound_maximum() + 16
                )
            {
                log_info(
                    "TCP connection manager is dropping "
                    "connection from " <<
                    transport->socket().remote_endpoint() <<
                    ", limit reached."
                );
                
                /**
                 * Stop the transport.
                 */
                transport->stop();
            }
            else
            {
                log_info(
                    "TCP connection manager allowing (short term) connection "
                    "from " << transport->socket().remote_endpoint() << ", "
                    "limit reached."
                );
                
                /**
                 * Allocate the tcp_connection.
                 */
                auto connection = std::make_shared<tcp_connection> (
                    io_service_, stack_impl_, tcp_connection::direction_incoming,
                    transport
                );

                /**
                 * Retain the connection.
                 */
                m_tcp_connections[transport->socket().remote_endpoint()] =
                    connection
                ;
                
                /**
                 * Start the tcp_connection.
                 */
                connection->start();
                
                /**
                 * Stop the connection (after 8 seconds).
                 */
                connection->stop_after(8);
            }
        }
        else
        {
            log_debug(
                "TCP connection manager accepted new tcp connection from " <<
                transport->socket().remote_endpoint() << ", " <<
                m_tcp_connections.size() << " connected peers."
            );

            /**
             * Allocate the tcp_connection.
             */
            auto connection = std::make_shared<tcp_connection> (
                io_service_, stack_impl_, tcp_connection::direction_incoming,
                transport
            );

            /**
             * Retain the connection.
             */
            m_tcp_connections[transport->socket().remote_endpoint()] =
                connection
            ;
            
            /**
             * Start the tcp_connection.
             */
            connection->start();
        }
    }
}

void tcp_connection_manager::broadcast(
    const char * buf, const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto j = i.second.lock())
        {
            j->send(buf, len);
        }
    }
}

void tcp_connection_manager::broadcast_bip0037(
    const char * buf, const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto j = i.second.lock())
        {
            /**
             * Skip the bip0037 tcp_connection with relay = false.
             */
            if (j->protocol_version_relay() == false)
            {
                continue;
            }
            else
            {
                j->send(buf, len);
            }
        }
    }
}

std::map< boost::asio::ip::tcp::endpoint, std::weak_ptr<tcp_connection> > &
    tcp_connection_manager::tcp_connections()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    return m_tcp_connections;
}

std::size_t tcp_connection_manager::active_tcp_connections()
{
    std::size_t ret = 0;
    
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            if (connection->is_transport_valid())
            {
                if (auto t = connection->get_tcp_transport().lock())
                {
                    if (t->state() == tcp_transport::state_connected)
                    {
                        ++ret;
                    }
                }
            }
        }
    }
    
    return ret;
}

bool tcp_connection_manager::is_connected()
{
    std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
    
    auto tcp_connections = 0;
    
    for (auto & i : m_tcp_connections)
    {
        if (auto connection = i.second.lock())
        {
            if (auto t = connection->get_tcp_transport().lock())
            {
                if (t->state() == tcp_transport::state_connected)
                {
                    ++tcp_connections;
                }
            }
        }
    }
    
    return tcp_connections > 0;
}

std::size_t tcp_connection_manager::minimum_tcp_connections()
{
    /**
     * SPV clients download the headers from a single peer until the last
     * checkpoint is near at which point we increase the connection count
     * to 3 peers and switch to getblocks. When connected to three peers we
     * only download from one of them rotating as needed but accept blocks
     * from all connections that advertise them.
     */
    if (globals::instance().is_client_spv() == true)
    {
        if (
            globals::instance().spv_block_last() == 0 ||
            globals::instance().spv_use_getblocks() == false
            )
        {
            return 1;
        }
    
        return 3;
    }

    return utility::is_initial_block_download() ? 3 : 8;
}

const std::time_t & tcp_connection_manager::time_last_inbound() const
{
    return m_time_last_inbound;
}

bool tcp_connection_manager::connect(const boost::asio::ip::tcp::endpoint & ep)
{
    if (globals::instance().state() == globals::state_started)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
        
        if (network::instance().is_address_banned(ep.address().to_string()))
        {
            log_info(
                "TCP connection manager tried to connect to a banned "
                "address " << ep << "."
            );
            
            return false;
        }
        else if (is_ip_banned(ep.address().to_string()))
        {
            log_debug(
                "TCP connection manager tried to connect to a bad address " <<
                ep << "."
            );
            
            return false;
        }
        else if (m_tcp_connections.find(ep) == m_tcp_connections.end())
        {
            log_none("TCP connection manager is connecting to " << ep << ".");
            
            /**
             * Inform the address_manager.
             */
            stack_impl_.get_address_manager()->on_connection_attempt(
                protocol::network_address_t::from_endpoint(ep)
            );
            
            /**
             * Allocate tcp_transport.
             */
            auto transport = std::make_shared<tcp_transport>(
                io_service_, strand_
            );
            
            /**
             * Allocate the tcp_connection.
             */
            auto connection = std::make_shared<tcp_connection> (
                io_service_, stack_impl_, tcp_connection::direction_outgoing,
                transport
            );
            
            /**
             * Retain the connection.
             */
            m_tcp_connections[ep] = connection;
            
            /**
             * Start the tcp_connection.
             */
            connection->start(ep);
            
            return true;
        }
        else
        {
            log_none(
                "TCP connection manager attempted connection to existing "
                "endpoint = " << ep << "."
            );
        }
    }
    
    return false;
}

void tcp_connection_manager::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_tcp_connections_);
        
        auto tcp_connections = 0;
        auto outgoing_tcp_connections = 0;
        
        auto it = m_tcp_connections.begin();
        
        while (it != m_tcp_connections.end())
        {
            if (auto connection = it->second.lock())
            {
                if (connection->is_transport_valid())
                {
                    if (auto t = connection->get_tcp_transport().lock())
                    {
                        if (t->state() == tcp_transport::state_connected)
                        {
                            ++tcp_connections;
                            
                            if (
                                connection->direction() ==
                                tcp_connection::direction_outgoing
                                )
                            {
                                ++outgoing_tcp_connections;
                            }
                        }
                    }
                    
                    ++it;
                }
                else
                {    
                    connection->stop();
                    
                    it = m_tcp_connections.erase(it);
                }
            }
            else
            {
                it = m_tcp_connections.erase(it);
            }
        }
        
        /**
         * Get if we are in initial download.
         */
        auto is_initial_block_download =
            globals::instance().is_client_spv() ?
            utility::is_spv_initial_block_download() :
            utility::is_initial_block_download()
        ;

        if (is_initial_block_download == false)
        {
            /**
             * Enforce the minimum_tcp_connections (outgoing).
             */
            if (outgoing_tcp_connections > minimum_tcp_connections())
            {
                auto it = m_tcp_connections.begin();
                
                std::advance(it, std::rand() % m_tcp_connections.size());
                
                if (auto connection = it->second.lock())
                {
                    if (
                        connection->direction() ==
                        tcp_connection::direction_outgoing
                        )
                    {
                        m_tcp_connections.erase(it);
                    }
                }
            }
        }
        
        /**
         * Maintain at least minimum_tcp_connections tcp connections.
         */
        if (tcp_connections < minimum_tcp_connections())
        {
            for (
                auto i = 0; i < minimum_tcp_connections() -
                tcp_connections; i++
                )
            {
                /**
                 * Get a network address from the address_manager.
                 */
                auto addr = stack_impl_.get_address_manager()->select(
                    10 + std::min(m_tcp_connections.size(),
                    static_cast<std::size_t> (8)) * 10
                );
            
                /**
                 * Only connect to one peer per group.
                 */
                auto is_in_same_group = false;

                for (auto & i : m_tcp_connections)
                {
                    if (auto j = i.second.lock())
                    {
                        if (auto k = j->get_tcp_transport().lock())
                        {
                            try
                            {
                                auto addr_tmp =
                                    protocol::network_address_t::from_endpoint(
                                    k->socket().remote_endpoint()
                                );
                                
                                if (addr.group() == addr_tmp.group())
                                {
                                    is_in_same_group = true;
                                }
                            }
                            catch (std::exception & e)
                            {
                                // ...
                            }
                        }
                    }
                }

                if (
                    constants::test_net == false &&
                    (addr.is_valid() == false || addr.is_local() ||
                    is_in_same_group)
                    )
                {
                    // ...
                }
                else
                {
                    /**
                     * Do not retry connections to the same network address more
                     * often than every 60 seconds.
                     */
                    if (
                        constants::test_net == false &&
                        std::time(0) - addr.last_try < 60
                        )
                    {
                        log_info(
                            "TCP connection manager attempted to "
                            "connect to " << addr.ipv4_mapped_address() <<
                            ":" << addr.port << " too soon, last try = " <<
                            (time::instance().get_adjusted() - addr.last_try) <<
                            " seconds."
                        );
                    }
                    else
                    {
                        /**
                         * Connect to the endpoint.
                         */
                        if (connect(
                            boost::asio::ip::tcp::endpoint(
                            addr.ipv4_mapped_address(), addr.port))
                            )
                        {
                            log_info(
                                "TCP connection manager is connecting to " <<
                                addr.ipv4_mapped_address() << ":" <<
                                addr.port << ", last seen = " <<
                                (time::instance().get_adjusted() -
                                addr.timestamp) / 60 << " mins, " <<
                                tcp_connections << " connected peers."
                            );
                        }
                    }
                }
            }
            
            auto self(shared_from_this());
            
            timer_.expires_from_now(std::chrono::seconds(1));
            timer_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection_manager::tick, self,
                std::placeholders::_1))
            );
        }
        else
        {
            auto self(shared_from_this());
            
            timer_.expires_from_now(std::chrono::seconds(8));
            timer_.async_wait(globals::instance().strand().wrap(
                std::bind(&tcp_connection_manager::tick, self,
                std::placeholders::_1))
            );
        }

        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status message.
         */
        status["type"] = "network";
        
        /**
         * Set the value.
         */
        status["value"] = tcp_connections > 0 ? "Connected" : "Connecting";
        
        /**
         * Set the network.tcp.connections.
         */
        status["network.tcp.connections"] = std::to_string(
            tcp_connections
        );
        
        /**
         * Callback status.
         */
        stack_impl_.get_status_manager()->insert(status);
    }
}

void tcp_connection_manager::do_resolve(
    const std::vector<boost::asio::ip::tcp::resolver::query> & queries
    )
{
    /**
     * Sanity check.
     */
    assert(queries.size() <= 100);
    
    /**
     * Resolve the first entry.
     */
    resolver_.async_resolve(queries.front(),
        strand_.wrap([this, queries](
            const boost::system::error_code & ec,
            const boost::asio::ip::tcp::resolver::iterator & it
            )
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    log_debug(
                        "TCP connection manager resolved " << it->endpoint() <<
                        "."
                    );
                    
                    /**
                     * Create the network address.
                     */
                    protocol::network_address_t addr =
                        protocol::network_address_t::from_endpoint(
                        it->endpoint()
                    );
                    
                    /**
                     * Add to the address manager.
                     */
                    stack_impl_.get_address_manager()->add(
                        addr, protocol::network_address_t::from_endpoint(
                        boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address::from_string("127.0.0.1"), 0))
                    );
                }
                
                if (queries.size() > 0)
                {
                    auto tmp = queries;
                    
                    /**
                     * Remove the first entry.
                     */
                    tmp.erase(tmp.begin());
                    
                    if (tmp.size() > 0)
                    {
                        /**
                         * Keep resolving as long as we have entries.
                         */
                        do_resolve(tmp);
                    }
                }
            }
        )
    );
}

bool tcp_connection_manager::is_ip_banned(const std::string & val)
{
    /**
     * Amazon EC2 IP's.
     */
    if (
        (val[0] == '5' && val[1] == '4') ||
        (val[0] == '5' && val[1] == '0') ||
        (val[0] == '2' && val[1] == '1' && val[2] == '1') ||
        (val[0] == '2' && val[1] == '1' && val[2] == '9')
        )
    {
        return true;
    }
    
    /**
     * Known attack IP's.
     */
    static const std::map<std::string, std::int32_t> g_known_attack_ips =
    {
        /**
         * ??? - Opens TCP connections to all network nodes.
         */
        {"113.97.218.52", -1}
    };
    
    if (g_known_attack_ips.count(val) > 0)
    {
        return true;
    }
    
    /**
     * ToR exit IP's.
     */
    static const std::map<std::string, std::int32_t> g_tor_exit_ips =
    {
        {"101.178.229.25", -1},
        {"103.10.197.50", -1},
        {"103.240.91.7", -1},
        {"104.128.51.66", -1},
        {"104.130.169.121", -1},
        {"104.131.114.43", -1},
        {"104.131.206.23", -1},
        {"104.131.51.150", -1},
        {"104.153.222.251", -1},
        {"104.156.232.247", -1},
        {"104.156.233.124", -1},
        {"104.167.103.52", -1},
        {"104.167.111.208", -1},
        {"104.167.113.138", -1},
        {"104.167.117.21", -1},
        {"104.232.3.33", -1},
        {"104.236.100.82", -1},
        {"104.236.190.127", -1},
        {"104.236.225.239", -1},
        {"104.237.152.195", -1},
        {"104.237.156.214", -1},
        {"104.245.233.128", -1},
        {"104.255.64.26", -1},
        {"104.40.1.143", -1},
        {"105.103.58.32", -1},
        {"106.185.28.25", -1},
        {"106.185.29.93", -1},
        {"106.185.38.151", -1},
        {"106.185.49.137", -1},
        {"106.186.16.115", -1},
        {"106.186.21.31", -1},
        {"106.186.28.33", -1},
        {"106.187.90.158", -1},
        {"106.187.99.148", -1},
        {"107.141.170.82", -1},
        {"107.150.29.17", -1},
        {"107.150.29.25", -1},
        {"107.181.174.84", -1},
        {"108.166.161.186", -1},
        {"108.166.168.158", -1},
        {"108.166.168.158", -1},
        {"108.61.212.102", -1},
        {"109.120.148.60", -1},
        {"109.120.173.48", -1},
        {"109.120.180.245", -1},
        {"109.122.5.22", -1},
        {"109.163.234.2", -1},
        {"109.163.234.4", -1},
        {"109.163.234.5", -1},
        {"109.163.234.7", -1},
        {"109.163.234.8", -1},
        {"109.163.234.9", -1},
        {"109.163.235.228", -1},
        {"109.169.0.29", -1},
        {"109.169.23.202", -1},
        {"109.169.33.163", -1},
        {"109.173.57.19", -1},
        {"109.173.60.177", -1},
        {"109.190.200.97", -1},
        {"109.194.103.70", -1},
        {"109.200.130.62", -1},
        {"109.201.154.183", -1},
        {"109.222.219.87", -1},
        {"109.230.251.238", -1},
        {"109.236.142.65", -1},
        {"109.237.211.128", -1},
        {"109.252.74.16", -1},
        {"109.252.74.56", -1},
        {"109.74.151.149", -1},
        {"110.174.43.136", -1},
        {"110.93.23.170", -1},
        {"111.69.165.196", -1},
        {"113.20.142.188", -1},
        {"116.83.31.147", -1},
        {"117.18.75.235", -1},
        {"119.17.42.190", -1},
        {"120.29.217.51", -1},
        {"120.56.162.1", -1},
        {"120.57.172.96", -1},
        {"120.59.165.113", -1},
        {"120.59.36.49", -1},
        {"121.127.250.156", -1},
        {"121.54.175.50", -1},
        {"123.108.224.70", -1},
        {"128.199.114.114", -1},
        {"128.199.127.170", -1},
        {"128.199.165.212", -1},
        {"128.199.52.7", -1},
        {"128.199.87.155", -1},
        {"128.204.203.78", -1},
        {"128.52.128.105", -1},
        {"128.79.53.244", -1},
        {"129.123.7.6", -1},
        {"129.123.7.6", -1},
        {"129.123.7.7", -1},
        {"129.123.7.7", -1},
        {"129.127.254.213", -1},
        {"129.174.117.10", -1},
        {"129.41.159.22", -1},
        {"133.130.50.97", -1},
        {"139.162.8.154", -1},
        {"14.202.230.49", -1},
        {"141.105.68.12", -1},
        {"141.138.141.208", -1},
        {"141.239.152.53", -1},
        {"141.239.243.208", -1},
        {"141.255.165.138", -1},
        {"141.255.167.101", -1},
        {"141.255.189.161", -1},
        {"142.4.208.167", -1},
        {"142.4.213.25", -1},
        {"144.76.16.66", -1},
        {"145.236.19.240", -1},
        {"146.0.72.180", -1},
        {"146.0.77.237", -1},
        {"146.185.143.144", -1},
        {"146.185.150.219", -1},
        {"146.185.177.103", -1},
        {"149.172.250.11", -1},
        {"149.202.98.160", -1},
        {"149.202.98.161", -1},
        {"149.210.171.69", -1},
        {"149.210.171.70", -1},
        {"149.91.82.139", -1},
        {"149.91.83.223", -1},
        {"150.140.5.34", -1},
        {"150.145.1.88", -1},
        {"151.226.42.207", -1},
        {"151.80.204.14", -1},
        {"154.58.80.243", -1},
        {"158.181.96.227", -1},
        {"158.69.51.97", -1},
        {"162.218.208.132", -1},
        {"162.219.2.177", -1},
        {"162.221.184.64", -1},
        {"162.221.201.57", -1},
        {"162.222.193.69", -1},
        {"162.243.100.225", -1},
        {"162.244.25.186", -1},
        {"162.244.25.249", -1},
        {"162.247.72.199", -1},
        {"162.247.72.200", -1},
        {"162.247.72.201", -1},
        {"162.247.72.212", -1},
        {"162.247.72.213", -1},
        {"162.247.72.216", -1},
        {"162.247.72.217", -1},
        {"162.247.72.7", -1},
        {"162.247.73.204", -1},
        {"162.247.73.206", -1},
        {"162.247.73.74", -1},
        {"162.247.91.74", -1},
        {"162.248.11.176", -1},
        {"162.248.160.151", -1},
        {"162.248.9.229", -1},
        {"166.70.15.14", -1},
        {"166.70.181.109", -1},
        {"166.70.207.2", -1},
        {"166.70.207.2", -1},
        {"167.114.114.136", -1},
        {"167.114.114.246", -1},
        {"167.114.92.58", -1},
        {"167.88.42.54", -1},
        {"171.25.193.20", -1},
        {"171.25.193.235", -1},
        {"171.25.193.77", -1},
        {"171.25.193.78", -1},
        {"173.11.1.241", -1},
        {"173.208.196.215", -1},
        {"173.243.112.148", -1},
        {"173.243.112.148", -1},
        {"173.244.207.14", -1},
        {"173.246.103.8", -1},
        {"173.254.216.66", -1},
        {"173.254.216.67", -1},
        {"173.254.216.68", -1},
        {"173.254.216.69", -1},
        {"173.255.196.30", -1},
        {"173.255.202.40", -1},
        {"173.255.226.142", -1},
        {"173.255.232.192", -1},
        {"173.255.250.240", -1},
        {"174.136.111.250", -1},
        {"176.10.104.240", -1},
        {"176.10.104.240", -1},
        {"176.10.104.240", -1},
        {"176.10.104.240", -1},
        {"176.10.104.243", -1},
        {"176.10.104.243", -1},
        {"176.10.104.243", -1},
        {"176.10.104.243", -1},
        {"176.10.99.200", -1},
        {"176.10.99.200", -1},
        {"176.10.99.201", -1},
        {"176.10.99.201", -1},
        {"176.10.99.202", -1},
        {"176.10.99.202", -1},
        {"176.10.99.203", -1},
        {"176.10.99.203", -1},
        {"176.10.99.204", -1},
        {"176.10.99.204", -1},
        {"176.10.99.205", -1},
        {"176.10.99.205", -1},
        {"176.10.99.206", -1},
        {"176.10.99.206", -1},
        {"176.10.99.207", -1},
        {"176.10.99.207", -1},
        {"176.10.99.208", -1},
        {"176.10.99.208", -1},
        {"176.10.99.209", -1},
        {"176.10.99.209", -1},
        {"176.116.104.49", -1},
        {"176.126.252.11", -1},
        {"176.126.252.12", -1},
        {"176.26.49.159", -1},
        {"176.31.152.159", -1},
        {"176.31.165.31", -1},
        {"176.31.191.26", -1},
        {"176.37.40.213", -1},
        {"176.58.100.98", -1},
        {"176.58.106.89", -1},
        {"176.62.101.85", -1},
        {"176.77.58.80", -1},
        {"176.9.145.194", -1},
        {"176.9.16.81", -1},
        {"176.9.39.218", -1},
        {"176.9.99.134", -1},
        {"177.19.78.103", -1},
        {"177.204.177.197", -1},
        {"177.45.136.5", -1},
        {"178.10.97.143", -1},
        {"178.140.98.147", -1},
        {"178.140.98.147", -1},
        {"178.140.98.58", -1},
        {"178.140.98.58", -1},
        {"178.140.98.93", -1},
        {"178.140.98.93", -1},
        {"178.140.98.93", -1},
        {"178.16.208.56", -1},
        {"178.16.208.57", -1},
        {"178.17.170.19", -1},
        {"178.170.111.194", -1},
        {"178.175.128.50", -1},
        {"178.175.131.194", -1},
        {"178.18.17.204", -1},
        {"178.18.83.215", -1},
        {"178.20.55.16", -1},
        {"178.20.55.18", -1},
        {"178.201.70.98", -1},
        {"178.209.50.151", -1},
        {"178.219.245.214", -1},
        {"178.238.223.67", -1},
        {"178.238.232.110", -1},
        {"178.238.237.44", -1},
        {"178.250.210.95", -1},
        {"178.254.8.50", -1},
        {"178.33.36.84", -1},
        {"178.62.217.233", -1},
        {"178.62.80.124", -1},
        {"178.63.97.34", -1},
        {"178.74.65.255", -1},
        {"178.79.139.46", -1},
        {"178.89.2.110", -1},
        {"179.0.194.199", -1},
        {"18.125.1.222", -1},
        {"18.238.2.85", -1},
        {"180.210.203.249", -1},
        {"181.41.219.117", -1},
        {"184.105.220.24", -1},
        {"185.10.71.80", -1},
        {"185.100.84.82", -1},
        {"185.104.120.2", -1},
        {"185.104.120.4", -1},
        {"185.12.12.133", -1},
        {"185.13.37.45", -1},
        {"185.14.29.221", -1},
        {"185.16.200.176", -1},
        {"185.17.184.228", -1},
        {"185.27.238.123", -1},
        {"185.29.232.82", -1},
        {"185.31.100.75", -1},
        {"185.31.136.244", -1},
        {"185.34.33.2", -1},
        {"185.36.100.145", -1},
        {"185.4.227.34", -1},
        {"185.44.130.20", -1},
        {"185.45.193.240", -1},
        {"185.47.200.121", -1},
        {"185.61.148.187", -1},
        {"185.61.148.189", -1},
        {"185.61.148.228", -1},
        {"185.61.149.176", -1},
        {"185.61.149.193", -1},
        {"185.61.149.242", -1},
        {"185.61.149.62", -1},
        {"185.62.189.44", -1},
        {"185.62.189.44", -1},
        {"185.62.190.231", -1},
        {"185.65.200.93", -1},
        {"185.72.177.105", -1},
        {"185.73.44.54", -1},
        {"185.73.44.58", -1},
        {"185.77.129.88", -1},
        {"185.77.129.88", -1},
        {"185.77.131.102", -1},
        {"185.77.131.102", -1},
        {"185.77.131.144", -1},
        {"185.77.131.144", -1},
        {"185.77.131.185", -1},
        {"185.77.131.185", -1},
        {"185.77.131.207", -1},
        {"185.77.131.207", -1},
        {"185.86.107.134", -1},
        {"185.86.151.13", -1},
        {"186.7.68.255", -1},
        {"186.78.167.56", -1},
        {"187.131.230.146", -1},
        {"188.113.114.120", -1},
        {"188.120.253.39", -1},
        {"188.126.74.72", -1},
        {"188.126.93.81", -1},
        {"188.138.1.229", -1},
        {"188.138.1.229", -1},
        {"188.138.1.229", -1},
        {"188.138.1.229", -1},
        {"188.138.17.15", -1},
        {"188.138.17.15", -1},
        {"188.138.9.49", -1},
        {"188.138.9.49", -1},
        {"188.165.59.43", -1},
        {"188.166.124.79", -1},
        {"188.166.18.80", -1},
        {"188.209.49.65", -1},
        {"188.209.52.158", -1},
        {"188.209.52.193", -1},
        {"188.226.131.21", -1},
        {"188.226.192.48", -1},
        {"188.226.254.89", -1},
        {"188.255.112.224", -1},
        {"188.26.87.113", -1},
        {"188.78.218.9", -1},
        {"188.96.201.79", -1},
        {"189.172.121.90", -1},
        {"189.178.168.63", -1},
        {"190.104.217.195", -1},
        {"191.101.13.20", -1},
        {"192.121.82.222", -1},
        {"192.121.82.66", -1},
        {"192.151.154.142", -1},
        {"192.155.95.222", -1},
        {"192.163.250.219", -1},
        {"192.241.192.47", -1},
        {"192.241.199.208", -1},
        {"192.241.222.240", -1},
        {"192.3.172.236", -1},
        {"192.3.177.167", -1},
        {"192.3.203.97", -1},
        {"192.3.24.227", -1},
        {"192.3.24.227", -1},
        {"192.42.113.102", -1},
        {"192.42.113.102", -1},
        {"192.42.115.101", -1},
        {"192.42.115.102", -1},
        {"192.42.116.16", -1},
        {"192.81.249.31", -1},
        {"192.87.28.28", -1},
        {"192.87.28.82", -1},
        {"192.99.154.24", -1},
        {"192.99.168.39", -1},
        {"192.99.2.137", -1},
        {"192.99.2.137", -1},
        {"192.99.246.164", -1},
        {"192.99.98.185", -1},
        {"193.107.19.30", -1},
        {"193.107.85.56", -1},
        {"193.107.85.57", -1},
        {"193.107.85.61", -1},
        {"193.107.85.62", -1},
        {"193.11.137.126", -1},
        {"193.110.157.151", -1},
        {"193.111.136.162", -1},
        {"193.138.216.101", -1},
        {"193.24.209.148", -1},
        {"193.33.216.23", -1},
        {"193.37.152.241", -1},
        {"193.90.12.86", -1},
        {"193.90.12.87", -1},
        {"193.90.12.88", -1},
        {"193.90.12.89", -1},
        {"193.90.12.90", -1},
        {"194.104.0.100", -1},
        {"194.135.85.95", -1},
        {"194.150.168.79", -1},
        {"194.150.168.95", -1},
        {"194.218.3.79", -1},
        {"194.63.141.120", -1},
        {"194.63.142.220", -1},
        {"194.74.181.78", -1},
        {"195.144.222.36", -1},
        {"195.154.15.227", -1},
        {"195.154.9.55", -1},
        {"195.160.172.180", -1},
        {"195.169.125.226", -1},
        {"195.180.11.196", -1},
        {"195.19.194.108", -1},
        {"195.228.45.176", -1},
        {"195.228.45.176", -1},
        {"195.248.168.222", -1},
        {"195.40.181.35", -1},
        {"197.231.221.211", -1},
        {"198.100.144.75", -1},
        {"198.108.63.107", -1},
        {"198.211.122.191", -1},
        {"198.23.202.71", -1},
        {"198.24.179.164", -1},
        {"198.255.2.3", -1},
        {"198.255.2.4", -1},
        {"198.255.2.6", -1},
        {"198.48.129.198", -1},
        {"198.50.128.236", -1},
        {"198.50.145.72", -1},
        {"198.50.191.95", -1},
        {"198.50.200.135", -1},
        {"198.50.200.143", -1},
        {"198.50.200.143", -1},
        {"198.51.75.165", -1},
        {"198.58.107.53", -1},
        {"198.58.115.210", -1},
        {"198.73.50.71", -1},
        {"198.96.155.3", -1},
        {"198.98.49.3", -1},
        {"199.127.226.150", -1},
        {"199.254.238.44", -1},
        {"199.68.196.124", -1},
        {"199.87.154.251", -1},
        {"199.87.154.255", -1},
        {"2.110.136.110", -1},
        {"2.111.64.26", -1},
        {"200.223.212.210", -1},
        {"200.63.47.10", -1},
        {"200.9.255.32", -1},
        {"201.81.200.195", -1},
        {"203.161.103.17", -1},
        {"203.217.173.146", -1},
        {"204.11.50.131", -1},
        {"204.124.83.130", -1},
        {"204.124.83.130", -1},
        {"204.124.83.134", -1},
        {"204.124.83.134", -1},
        {"204.17.56.42", -1},
        {"204.17.56.42", -1},
        {"204.194.29.4", -1},
        {"204.8.156.142", -1},
        {"204.85.191.30", -1},
        {"205.168.84.133", -1},
        {"207.192.69.165", -1},
        {"207.201.223.197", -1},
        {"208.111.34.48", -1},
        {"208.111.35.80", -1},
        {"209.126.110.112", -1},
        {"209.126.110.112", -1},
        {"209.126.110.112", -1},
        {"209.126.110.112", -1},
        {"209.126.110.112", -1},
        {"209.126.110.112", -1},
        {"209.159.138.19", -1},
        {"209.222.8.196", -1},
        {"209.234.102.238", -1},
        {"209.249.157.69", -1},
        {"209.249.180.198", -1},
        {"209.33.19.50", -1},
        {"210.211.122.204", -1},
        {"212.109.216.220", -1},
        {"212.117.143.74", -1},
        {"212.159.143.81", -1},
        {"212.16.104.33", -1},
        {"212.18.232.123", -1},
        {"212.192.74.100", -1},
        {"212.192.74.101", -1},
        {"212.21.66.6", -1},
        {"212.24.144.188", -1},
        {"212.47.245.34", -1},
        {"212.7.194.71", -1},
        {"212.71.238.203", -1},
        {"212.83.40.238", -1},
        {"212.83.40.239", -1},
        {"212.92.219.15", -1},
        {"213.108.105.71", -1},
        {"213.113.244.241", -1},
        {"213.136.71.21", -1},
        {"213.136.75.42", -1},
        {"213.136.76.37", -1},
        {"213.146.54.28", -1},
        {"213.152.162.79", -1},
        {"213.186.7.232", -1},
        {"213.208.188.203", -1},
        {"213.21.123.232", -1},
        {"213.248.45.46", -1},
        {"213.252.140.118", -1},
        {"213.61.149.100", -1},
        {"213.61.149.100", -1},
        {"213.64.226.230", -1},
        {"213.9.93.174", -1},
        {"213.95.21.54", -1},
        {"213.95.21.59", -1},
        {"216.115.3.26", -1},
        {"216.119.149.174", -1},
        {"216.17.110.252", -1},
        {"216.218.134.12", -1},
        {"217.115.10.131", -1},
        {"217.115.10.133", -1},
        {"217.115.10.134", -1},
        {"217.12.204.104", -1},
        {"217.13.197.5", -1},
        {"217.172.190.19", -1},
        {"217.172.190.19", -1},
        {"217.197.204.212", -1},
        {"217.23.7.229", -1},
        {"217.23.7.229", -1},
        {"217.23.7.232", -1},
        {"217.23.7.232", -1},
        {"217.23.7.236", -1},
        {"217.23.7.236", -1},
        {"217.251.82.253", -1},
        {"217.70.191.13", -1},
        {"223.18.109.216", -1},
        {"23.239.18.57", -1},
        {"23.240.213.3", -1},
        {"23.80.226.2", -1},
        {"23.80.226.4", -1},
        {"23.92.18.98", -1},
        {"23.95.38.135", -1},
        {"23.95.43.72", -1},
        {"23.95.43.73", -1},
        {"23.95.43.75", -1},
        {"24.233.74.111", -1},
        {"24.26.241.22", -1},
        {"24.90.197.246", -1},
        {"31.172.30.2", -1},
        {"31.185.27.1", -1},
        {"31.19.176.18", -1},
        {"31.192.105.21", -1},
        {"31.192.228.185", -1},
        {"31.214.133.30", -1},
        {"31.220.45.6", -1},
        {"31.31.78.19", -1},
        {"31.52.20.48", -1},
        {"35.0.127.52", -1},
        {"35.0.127.52", -1},
        {"36.230.202.58", -1},
        {"37.1.194.182", -1},
        {"37.110.130.56", -1},
        {"37.120.5.57", -1},
        {"37.130.227.133", -1},
        {"37.130.227.133", -1},
        {"37.139.3.171", -1},
        {"37.143.9.74", -1},
        {"37.15.11.205", -1},
        {"37.157.195.178", -1},
        {"37.157.195.196", -1},
        {"37.187.114.36", -1},
        {"37.187.129.166", -1},
        {"37.187.129.166", -1},
        {"37.187.176.64", -1},
        {"37.187.239.8", -1},
        {"37.187.38.147", -1},
        {"37.187.7.74", -1},
        {"37.220.31.113", -1},
        {"37.220.31.113", -1},
        {"37.220.31.115", -1},
        {"37.220.31.115", -1},
        {"37.220.31.38", -1},
        {"37.220.31.38", -1},
        {"37.220.35.144", -1},
        {"37.220.35.61", -1},
        {"37.221.160.234", -1},
        {"37.221.161.37", -1},
        {"37.221.162.226", -1},
        {"37.221.162.226", -1},
        {"37.229.219.172", -1},
        {"37.48.115.224", -1},
        {"37.48.120.196", -1},
        {"37.48.65.122", -1},
        {"37.48.78.159", -1},
        {"37.59.112.7", -1},
        {"37.59.14.201", -1},
        {"37.59.97.134", -1},
        {"39.48.129.182", -1},
        {"4.31.64.70", -1},
        {"41.142.9.114", -1},
        {"41.223.53.141", -1},
        {"41.223.55.4", -1},
        {"43.252.36.12", -1},
        {"45.33.45.207", -1},
        {"45.33.48.204", -1},
        {"45.63.120.177", -1},
        {"45.63.4.186", -1},
        {"45.79.207.176", -1},
        {"45.79.65.104", -1},
        {"46.0.135.55", -1},
        {"46.10.111.77", -1},
        {"46.10.205.252", -1},
        {"46.148.18.74", -1},
        {"46.16.234.131", -1},
        {"46.165.221.166", -1},
        {"46.165.221.166", -1},
        {"46.165.223.217", -1},
        {"46.167.245.172", -1},
        {"46.167.245.51", -1},
        {"46.182.106.190", -1},
        {"46.182.18.111", -1},
        {"46.183.218.141", -1},
        {"46.183.219.196", -1},
        {"46.183.219.70", -1},
        {"46.183.220.132", -1},
        {"46.19.137.132", -1},
        {"46.20.246.117", -1},
        {"46.21.107.230", -1},
        {"46.211.35.240", -1},
        {"46.226.108.26", -1},
        {"46.226.110.185", -1},
        {"46.227.69.242", -1},
        {"46.233.0.70", -1},
        {"46.233.38.132", -1},
        {"46.235.227.70", -1},
        {"46.246.40.192", -1},
        {"46.249.37.143", -1},
        {"46.252.151.120", -1},
        {"46.252.152.192", -1},
        {"46.28.109.163", -1},
        {"46.28.110.136", -1},
        {"46.28.68.158", -1},
        {"46.29.248.238", -1},
        {"46.30.43.39", -1},
        {"46.32.232.238", -1},
        {"46.38.50.228", -1},
        {"46.38.63.7", -1},
        {"46.39.102.2", -1},
        {"46.4.55.177", -1},
        {"46.41.132.84", -1},
        {"46.45.137.71", -1},
        {"49.212.194.113", -1},
        {"46.100.118.166", -1},
        {"46.101.101.233", -1},
        {"46.101.105.32", -1},
        {"46.135.152.208", -1},
        {"46.135.158.101", -1},
        {"46.135.183.137", -1},
        {"46.135.209.86", -1},
        {"46.135.85.23", -1},
        {"46.149.248.85", -1},
        {"46.157.82.219", -1},
        {"46.165.77.25", -1},
        {"46.175.194.69", -1},
        {"46.189.130.149", -1},
        {"46.189.146.133", -1},
        {"46.196.1.129", -1},
        {"46.196.14.234", -1},
        {"46.199.130.188", -1},
        {"46.199.142.195", -1},
        {"46.2.128.74", -1},
        {"46.2.138.119", -1},
        {"46.255.93.96", -1},
        {"46.28.62.85", -1},
        {"46.39.86.206", -1},
        {"46.39.94.152", -1},
        {"46.44.107.23", -1},
        {"46.56.133.19", -1},
        {"46.61.34.63", -1},
        {"46.79.68.161", -1},
        {"46.79.68.161", -1},
        {"46.9.110.133", -1},
        {"46.9.146.203", -1},
        {"46.9.158.75", -1},
        {"50.129.135.213", -1},
        {"50.137.174.39", -1},
        {"50.155.222.171", -1},
        {"50.190.206.111", -1},
        {"50.199.1.178", -1},
        {"50.245.124.131", -1},
        {"50.247.195.124", -1},
        {"50.7.138.125", -1},
        {"50.7.139.243", -1},
        {"50.7.143.20", -1},
        {"50.7.143.60", -1},
        {"50.7.159.178", -1},
        {"50.7.159.195", -1},
        {"50.7.159.196", -1},
        {"50.7.205.156", -1},
        {"50.7.227.27", -1},
        {"50.7.71.173", -1},
        {"52.0.4.72", -1},
        {"52.17.9.94", -1},
        {"52.68.145.235", -1},
        {"52.68.54.232", -1},
        {"52.68.75.110", -1},
        {"52.68.94.105", -1},
        {"52.68.94.115", -1},
        {"52.8.59.206", -1},
        {"52.8.59.233", -1},
        {"52.8.62.128", -1},
        {"52.8.62.153", -1},
        {"52.8.62.161", -1},
        {"54.153.66.33", -1},
        {"54.153.68.101", -1},
        {"54.153.68.88", -1},
        {"54.153.69.139", -1},
        {"54.153.73.44", -1},
        {"54.153.73.60", -1},
        {"54.153.74.162", -1},
        {"54.153.74.18", -1},
        {"54.153.74.246", -1},
        {"54.153.74.49", -1},
        {"54.153.74.83", -1},
        {"54.153.75.229", -1},
        {"54.153.75.48", -1},
        {"54.153.8.220", -1},
        {"54.171.94.249", -1},
        {"54.64.35.244", -1},
        {"54.65.172.254", -1},
        {"54.65.206.23", -1},
        {"54.65.206.44", -1},
        {"54.65.206.52", -1},
        {"54.65.206.57", -1},
        {"54.65.206.60", -1},
        {"54.65.206.67", -1},
        {"54.65.206.74", -1},
        {"54.65.206.79", -1},
        {"54.68.29.170", -1},
        {"54.94.137.164", -1},
        {"54.94.238.181", -1},
        {"54.94.240.151", -1},
        {"54.94.240.5", -1},
        {"54.94.241.0", -1},
        {"54.94.241.162", -1},
        {"54.94.241.168", -1},
        {"54.94.241.171", -1},
        {"54.94.241.181", -1},
        {"54.94.241.184", -1},
        {"58.7.188.135", -1},
        {"59.127.163.155", -1},
        {"59.179.17.195", -1},
        {"61.230.170.202", -1},
        {"62.133.130.105", -1},
        {"62.141.45.12", -1},
        {"62.149.12.153", -1},
        {"62.210.105.116", -1},
        {"62.210.37.82", -1},
        {"62.212.84.229", -1},
        {"62.212.89.117", -1},
        {"62.218.77.122", -1},
        {"62.221.95.48", -1},
        {"62.49.92.150", -1},
        {"62.57.160.237", -1},
        {"62.75.216.154", -1},
        {"63.163.64.154", -1},
        {"64.113.32.29", -1},
        {"64.113.44.206", -1},
        {"65.181.112.128", -1},
        {"65.181.113.136", -1},
        {"65.181.118.10", -1},
        {"65.181.123.254", -1},
        {"66.132.174.142", -1},
        {"66.171.179.194", -1},
        {"66.180.193.219", -1},
        {"66.31.208.246", -1},
        {"66.56.207.102", -1},
        {"66.85.131.72", -1},
        {"67.1.231.17", -1},
        {"67.215.255.140", -1},
        {"68.112.156.227", -1},
        {"68.233.235.217", -1},
        {"68.71.46.138", -1},
        {"69.162.139.9", -1},
        {"69.164.207.234", -1},
        {"69.164.214.250", -1},
        {"69.172.229.199", -1},
        {"69.5.113.57", -1},
        {"70.114.19.115", -1},
        {"70.164.255.174", -1},
        {"70.85.31.202", -1},
        {"71.135.39.238", -1},
        {"71.230.253.68", -1},
        {"72.14.176.172", -1},
        {"72.14.179.10", -1},
        {"72.249.185.100", -1},
        {"72.253.92.44", -1},
        {"72.52.75.27", -1},
        {"72.52.91.19", -1},
        {"72.52.91.30", -1},
        {"72.52.91.30", -1},
        {"73.172.157.202", -1},
        {"73.201.114.57", -1},
        {"74.142.74.157", -1},
        {"74.207.248.110", -1},
        {"74.208.220.222", -1},
        {"74.3.165.39", -1},
        {"76.22.122.48", -1},
        {"76.85.207.212", -1},
        {"77.109.139.87", -1},
        {"77.109.141.138", -1},
        {"77.109.141.138", -1},
        {"77.109.141.138", -1},
        {"77.173.141.34", -1},
        {"77.222.138.14", -1},
        {"77.244.254.227", -1},
        {"77.244.254.228", -1},
        {"77.244.254.229", -1},
        {"77.244.254.230", -1},
        {"77.247.181.162", -1},
        {"77.247.181.162", -1},
        {"77.247.181.162", -1},
        {"77.247.181.163", -1},
        {"77.247.181.165", -1},
        {"77.247.181.165", -1},
        {"77.41.43.4", -1},
        {"77.51.62.237", -1},
        {"77.81.240.41", -1},
        {"78.108.63.46", -1},
        {"78.111.78.140", -1},
        {"78.192.154.198", -1},
        {"78.193.103.77", -1},
        {"78.193.86.3", -1},
        {"78.208.60.125", -1},
        {"78.247.15.126", -1},
        {"78.41.115.145", -1},
        {"78.46.51.124", -1},
        {"78.46.51.124", -1},
        {"78.60.179.10", -1},
        {"78.61.12.99", -1},
        {"78.70.166.85", -1},
        {"78.9.141.182", -1},
        {"78.92.97.43", -1},
        {"79.120.10.98", -1},
        {"79.120.211.108", -1},
        {"79.134.234.247", -1},
        {"79.136.42.226", -1},
        {"79.143.185.10", -1},
        {"79.143.87.204", -1},
        {"79.143.87.204", -1},
        {"79.172.193.32", -1},
        {"79.197.209.38", -1},
        {"79.210.195.159", -1},
        {"79.219.220.41", -1},
        {"79.98.107.90", -1},
        {"80.220.230.107", -1},
        {"80.248.208.131", -1},
        {"80.68.95.180", -1},
        {"80.73.242.130", -1},
        {"80.78.242.81", -1},
        {"80.78.246.86", -1},
        {"80.79.23.7", -1},
        {"80.98.80.130", -1},
        {"81.176.228.54", -1},
        {"81.193.138.85", -1},
        {"81.220.163.26", -1},
        {"81.220.185.142", -1},
        {"81.245.209.221", -1},
        {"81.7.11.70", -1},
        {"81.7.15.115", -1},
        {"81.89.96.88", -1},
        {"81.89.96.89", -1},
        {"82.116.120.3", -1},
        {"82.135.112.218", -1},
        {"82.161.210.87", -1},
        {"82.211.19.143", -1},
        {"82.211.31.134", -1},
        {"82.228.252.20", -1},
        {"82.248.119.208", -1},
        {"82.94.251.227", -1},
        {"83.102.63.92", -1},
        {"83.149.126.29", -1},
        {"83.166.232.27", -1},
        {"83.236.208.78", -1},
        {"83.49.84.247", -1},
        {"84.103.74.120", -1},
        {"84.105.49.66", -1},
        {"84.115.64.67", -1},
        {"84.130.146.217", -1},
        {"84.19.179.229", -1},
        {"84.193.75.243", -1},
        {"84.200.249.40", -1},
        {"84.200.55.32", -1},
        {"84.232.201.15", -1},
        {"84.25.7.205", -1},
        {"84.255.239.131", -1},
        {"84.3.0.53", -1},
        {"84.45.76.10", -1},
        {"84.45.76.11", -1},
        {"84.45.76.12", -1},
        {"84.45.76.13", -1},
        {"84.48.61.141", -1},
        {"84.74.11.222", -1},
        {"84.92.24.214", -1},
        {"85.0.252.124", -1},
        {"85.10.211.53", -1},
        {"85.114.140.43", -1},
        {"85.140.202.61", -1},
        {"85.150.210.68", -1},
        {"85.159.113.228", -1},
        {"85.166.130.189", -1},
        {"85.17.132.245", -1},
        {"85.17.132.246", -1},
        {"85.17.172.161", -1},
        {"85.17.177.73", -1},
        {"85.17.24.95", -1},
        {"85.214.11.209", -1},
        {"85.214.146.66", -1},
        {"85.23.243.147", -1},
        {"85.24.215.117", -1},
        {"85.25.103.119", -1},
        {"85.93.218.204", -1},
        {"86.146.208.38", -1},
        {"86.146.208.38", -1},
        {"86.192.65.196", -1},
        {"87.118.84.181", -1},
        {"87.118.91.140", -1},
        {"87.119.186.79", -1},
        {"87.236.195.185", -1},
        {"87.252.5.163", -1},
        {"87.98.178.61", -1},
        {"87.98.250.222", -1},
        {"88.127.96.38", -1},
        {"88.161.203.46", -1},
        {"88.166.192.181", -1},
        {"88.190.118.95", -1},
        {"88.195.207.117", -1},
        {"88.198.14.171", -1},
        {"88.198.175.76", -1},
        {"88.198.56.140", -1},
        {"88.204.113.189", -1},
        {"88.67.162.178", -1},
        {"88.76.24.243", -1},
        {"89.100.15.158", -1},
        {"89.105.194.68", -1},
        {"89.105.194.70", -1},
        {"89.105.194.71", -1},
        {"89.105.194.72", -1},
        {"89.105.194.73", -1},
        {"89.105.194.74", -1},
        {"89.105.194.75", -1},
        {"89.105.194.76", -1},
        {"89.105.194.77", -1},
        {"89.105.194.78", -1},
        {"89.105.194.79", -1},
        {"89.105.194.80", -1},
        {"89.105.194.81", -1},
        {"89.105.194.82", -1},
        {"89.105.194.83", -1},
        {"89.105.194.84", -1},
        {"89.105.194.85", -1},
        {"89.105.194.86", -1},
        {"89.105.194.87", -1},
        {"89.105.194.88", -1},
        {"89.105.194.89", -1},
        {"89.105.194.90", -1},
        {"89.105.194.91", -1},
        {"89.132.10.166", -1},
        {"89.187.142.208", -1},
        {"89.218.16.7", -1},
        {"89.234.157.254", -1},
        {"89.234.157.254", -1},
        {"89.238.77.4", -1},
        {"89.248.164.56", -1},
        {"89.252.2.140", -1},
        {"89.46.100.13", -1},
        {"89.46.100.182", -1},
        {"89.73.177.236", -1},
        {"90.146.29.56", -1},
        {"90.182.235.46", -1},
        {"90.231.152.159", -1},
        {"91.106.158.157", -1},
        {"91.109.247.173", -1},
        {"91.121.100.200", -1},
        {"91.121.159.196", -1},
        {"91.121.21.224", -1},
        {"91.146.121.3", -1},
        {"91.178.175.229", -1},
        {"91.196.50.121", -1},
        {"91.199.197.76", -1},
        {"91.200.85.68", -1},
        {"91.213.8.235", -1},
        {"91.213.8.235", -1},
        {"91.213.8.236", -1},
        {"91.213.8.43", -1},
        {"91.213.8.84", -1},
        {"91.214.168.240", -1},
        {"91.214.168.253", -1},
        {"91.219.236.218", -1},
        {"91.219.236.222", -1},
        {"91.219.236.232", -1},
        {"91.219.237.229", -1},
        {"91.220.163.65", -1},
        {"91.220.220.5", -1},
        {"91.228.151.52", -1},
        {"91.229.77.64", -1},
        {"91.234.22.48", -1},
        {"91.234.226.35", -1},
        {"91.238.21.8", -1},
        {"91.240.202.138", -1},
        {"91.240.67.4", -1},
        {"91.44.206.216", -1},
        {"91.51.85.226", -1},
        {"91.67.73.182", -1},
        {"91.82.237.127", -1},
        {"92.195.30.208", -1},
        {"92.22.47.62", -1},
        {"92.220.210.218", -1},
        {"92.222.22.113", -1},
        {"92.222.38.67", -1},
        {"92.222.65.128", -1},
        {"92.222.69.188", -1},
        {"92.243.69.105", -1},
        {"92.53.36.215", -1},
        {"92.7.159.178", -1},
        {"93.103.61.81", -1},
        {"93.11.115.31", -1},
        {"93.115.241.2", -1},
        {"93.126.101.223", -1},
        {"93.129.31.168", -1},
        {"93.174.90.30", -1},
        {"93.184.66.227", -1},
        {"93.186.200.163", -1},
        {"93.190.46.154", -1},
        {"93.31.155.175", -1},
        {"93.64.207.55", -1},
        {"93.72.101.14", -1},
        {"94.102.53.177", -1},
        {"94.103.175.86", -1},
        {"94.139.36.35", -1},
        {"94.142.241.240", -1},
        {"94.142.245.231", -1},
        {"94.194.162.113", -1},
        {"94.198.100.17", -1},
        {"94.199.51.101", -1},
        {"94.21.202.207", -1},
        {"94.210.0.28", -1},
        {"94.222.104.181", -1},
        {"94.23.247.86", -1},
        {"94.23.252.31", -1},
        {"94.23.30.53", -1},
        {"94.23.6.131", -1},
        {"94.242.198.164", -1},
        {"94.242.246.23", -1},
        {"94.242.246.24", -1},
        {"94.242.254.101", -1},
        {"94.242.254.101", -1},
        {"94.242.57.38", -1},
        {"94.45.59.240", -1},
        {"94.76.206.194", -1},
        {"95.128.43.164", -1},
        {"95.130.11.147", -1},
        {"95.130.11.170", -1},
        {"95.130.12.64", -1},
        {"95.130.12.91", -1},
        {"95.131.135.179", -1},
        {"95.140.42.183", -1},
        {"95.142.161.63", -1},
        {"95.154.88.252", -1},
        {"95.157.8.60", -1},
        {"95.21.235.166", -1},
        {"95.211.169.35", -1},
        {"95.211.229.158", -1},
        {"95.215.44.194", -1},
        {"95.215.44.30", -1},
        {"95.215.46.36", -1},
        {"95.215.46.49", -1},
        {"95.215.46.72", -1},
        {"95.84.129.186", -1},
        {"95.85.10.71", -1},
        {"96.35.130.131", -1},
        {"96.43.142.28", -1},
        {"96.43.142.28", -1},
        {"96.44.189.100", -1},
        {"96.44.189.101", -1},
        {"96.44.189.102", -1},
        {"96.47.226.20", -1},
        {"96.47.226.21", -1},
        {"96.47.226.22", -1},
        {"98.142.47.54", -1},
        {"98.158.100.102", -1},
        {"98.158.108.58", -1},
        {"98.158.109.184", -1},
        {"98.158.109.184", -1},
    };
    
    if (g_tor_exit_ips.count(val) > 0)
    {
        return true;
    }
    
    return false;
}

