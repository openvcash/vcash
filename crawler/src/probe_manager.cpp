/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#include <sstream>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <crawler/database_stack.hpp>
#include <crawler/http_transport.hpp>
#include <crawler/logger.hpp>
#include <crawler/probe_manager.hpp>
#include <crawler/stack_impl.hpp>

using namespace crawler;

probe_manager::probe_manager(stack_impl & owner)
    : stack_impl_(owner)
    , timer_(owner.io_service())
    , timer_post_(owner.io_service())
    , timer_probe_(owner.io_service())
{
    // ...
}

void probe_manager::start()
{
    auto self(shared_from_this());
    
    /**
     * Start the timer.
     */
    timer_.expires_from_now(std::chrono::seconds(8));
    timer_.async_wait(stack_impl_.strand().wrap(
        std::bind(&probe_manager::tick, self,
        std::placeholders::_1))
    );
    
    /**
     * Start the timer.
     */
    timer_post_.expires_from_now(std::chrono::seconds(30));
    timer_post_.async_wait(stack_impl_.strand().wrap(
        std::bind(&probe_manager::tick_post, self,
        std::placeholders::_1))
    );
    
    /**
     * Start the timer.
     */
    timer_probe_.expires_from_now(std::chrono::seconds(16));
    timer_probe_.async_wait(stack_impl_.strand().wrap(
        std::bind(&probe_manager::tick_probe, self,
        std::placeholders::_1))
    );
}

void probe_manager::stop()
{
    timer_.cancel();
    timer_post_.cancel();
    timer_probe_.cancel();
}

void probe_manager::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        auto snodes =
            stack_impl_.get_database_stack()->storage_nodes()
        ;
        
        log_info(
            "Probe manager has " << snodes.size() << " snodes."
        );
        
        for (auto & i : snodes)
        {
            if (i.count("endpoint") > 0)
            {
                auto uptime = std::atoll(i["uptime"].c_str());
                auto last_update = std::atoll(i["last_update"].c_str());
                auto endpoint = i["endpoint"];
                auto rtt = std::atoi(i["rtt"].c_str());
                auto stats_udp_bps_inbound =
                    std::atoi(i["stats_udp_bps_inbound"].c_str())
                ;
                auto stats_udp_bps_outbound =
                    std::atoi(i["stats_udp_bps_outbound"].c_str())
                ;

                std::vector<std::string> parts;
                
                boost::split(parts, endpoint, boost::is_any_of(":"));
                
                if (parts.size() != 2)
                {
                    continue;
                }

                auto address = parts[0];
                auto port = std::atoi(parts[1].c_str());
                
                std::lock_guard<std::mutex> l1(mutex_peers_);
                
                if (m_peers.count(endpoint) > 0)
                {
                    boost::asio::ip::udp::endpoint ep(
                        boost::asio::ip::address::from_string(address),
                        port
                    );
                    
                    peer p(
                        ep, uptime, last_update, rtt, stats_udp_bps_inbound,
                        stats_udp_bps_outbound
                    );
                    
                    p.set_version(m_peers[endpoint].version());
                    p.set_protocol(m_peers[endpoint].protocol());
                    p.set_useragent(m_peers[endpoint].useragent());
                    p.set_height(m_peers[endpoint].height());
                    p.set_time_last_seen(std::time(0));
                    p.set_is_tcp_open(m_peers[endpoint].is_tcp_open());
                    p.set_last_probed(m_peers[endpoint].last_probed());
                    
                    m_peers[endpoint] = p;
                }
                else
                {
                    boost::asio::ip::udp::endpoint ep(
                        boost::asio::ip::address::from_string(address),
                        port
                    );
                    
                    peer p(
                        ep, uptime, last_update, rtt, stats_udp_bps_inbound,
                        stats_udp_bps_outbound
                    );
                    
                    m_peers[endpoint] = p;
                }
            }
        }
        
        /**
         * Expire old peers.
         */
        auto it = m_peers.begin();
        
        while (it != m_peers.end())
        {
            /**
             * If we have not seen a peer in 1 hours delete it.
             */
            if (std::time(0) - it->second.time_last_seen() > 1 * 60 * 60)
            {
                it = m_peers.erase(it);
            }
            else
            {
                ++it;
            }
        }

        /**
         * Start the timer.
         */
        timer_.expires_from_now(std::chrono::seconds(8));
        timer_.async_wait(stack_impl_.strand().wrap(
            std::bind(&probe_manager::tick, self,
            std::placeholders::_1))
        );
    }
}
        
void probe_manager::tick_post(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        boost::property_tree::ptree pt;
        
        boost::property_tree::ptree pt_children;
        
        std::lock_guard<std::mutex> l1(mutex_peers_);
        
        /**
         * Encode the peers into JSON format.
         */
        for (auto & i : m_peers)
        {
            boost::property_tree::ptree pt_child;
            
            const auto & p = i.second;
           
            boost::asio::ip::udp::endpoint m_udp_endpoint;

            pt_child.put("endpoint", p.udp_endpoint());
            pt_child.put("version", p.version());
            pt_child.put("protocol", p.protocol());
            pt_child.put("useragent", p.useragent());
            pt_child.put("height", p.height());
            pt_child.put("uptime", std::time(0) - p.uptime());
            pt_child.put("last_update", p.last_update());
            pt_child.put(
                "last_probed",
                p.last_probed() == 0 ? - 1 : std::time(0) - p.last_probed()
            );
            pt_child.put("rtt", p.rtt());
            pt_child.put("udp_bps_inbound", p.udp_bps_inbound());
            pt_child.put("udp_bps_outbound", p.udp_bps_outbound());
            pt_child.put("tcp_open", p.is_tcp_open());
            pt_child.put(
                "super_peer",
                p.is_tcp_open() == true ? "true" : "false"
            );
        
            pt_children.push_back(std::make_pair("", pt_child));
        }
        
        pt.add_child("peers", pt_children);
        
        /**
         * The std::stringstream.
         */
        std::stringstream ss;
        
        /**
         * Write property tree to json file.
         */
        write_json(ss, pt, false);
        
#if 0
        auto url =
            "http://v.cash/network/post.php?token="
            "1234567891011121314151617181920"
        ;
        
        std::shared_ptr<http_transport> t =
            std::make_shared<http_transport>(stack_impl_.io_service(), url)
        ;

        /**
         * Set the content-length.
         */
        t->headers()["content-length"] = ss.str().size();
        
        t->set_request_body(ss.str());
        
        t->start(
            [this](
            boost::system::error_code ec, std::shared_ptr<http_transport> t)
        {
            if (ec)
            {
                // ...
            }
            else
            {
                // ...
            }
        }, 80);
#else
        /**
         * Open the output file stream.
         */
        std::ofstream ofs("peers.json");
        
        /**
         * Write the json.
         */
        ofs << ss.str();
        
        /**
         * Flush to disk.
         */
        ofs.flush();
#endif

        /**
         * Start the timer.
         */
        timer_post_.expires_from_now(std::chrono::seconds(60));
        timer_post_.async_wait(stack_impl_.strand().wrap(
            std::bind(&probe_manager::tick_post, self,
            std::placeholders::_1))
        );
    }
}

void probe_manager::tick_probe(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());

        std::lock_guard<std::mutex> l1(mutex_peers_);
        
        auto index = 0;
        
        /**
         * Encode the peers into JSON format.
         */
        for (auto & i : m_peers)
        {
            if (std::time(0) - i.second.last_probed() > 300)
            {
                auto url =
                    "https://" + i.first.substr(0, i.first.find(":")) + "/"
                ;

                std::shared_ptr<http_transport> t =
                    std::make_shared<http_transport>(
                    stack_impl_.io_service(), url)
                ;

                auto ep = i.second.udp_endpoint();
                
                t->start(
                    [this, i](
                    boost::system::error_code ec,
                    std::shared_ptr<http_transport> t)
                {
                    auto key = i.first;

                    if (ec)
                    {
                        /**
                         * Since we are not checking the error we do not know
                         * if it is the remote peer's fault, therefore we wait
                         * up to 20 minutes before setting them to TCP closed.
                         */
                        if (std::time(0) - i.second.last_probed() > 1200)
                        {
                            /**
                             * Update firewall status.
                             */
                            m_peers[key].set_is_tcp_open(false);
                        }
                    }
                    else
                    {
                        /**
                         * Set the last probed.
                         */
                        m_peers[key].set_last_probed(std::time(0));
                
                        try
                        {
                            boost::property_tree::ptree pt;
                            
                            std::stringstream ss;
                        
                            ss << t->response_body();
                            
                            read_json(ss, pt);
                            
                            try
                            {
                                /**
                                 * Get the version.
                                 */
                                auto version =
                                    pt.get_child("version").get<
                                    std::string> ("")
                                ;
                                
                                m_peers[key].set_version(version);
                            }
                            catch (...)
                            {
                                // ...
                            }
                            
                            try
                            {
                                /**
                                 * Get the protocol.
                                 */
                                auto protocol =
                                    pt.get_child("protocol").get<
                                    std::string> ("")
                                ;
                                
                                m_peers[key].set_protocol(std::stoi(protocol));
                            }
                            catch (...)
                            {
                                // ...
                            }
                            
                            try
                            {
                                /**
                                 * Get the useragent.
                                 */
                                auto useragent =
                                    pt.get_child("useragent").get<
                                    std::string> ("")
                                ;
                                
                                m_peers[key].set_useragent(useragent);
                            }
                            catch (...)
                            {
                                // ...
                            }
                            
                            try
                            {
                                /**
                                 * Get the height.
                                 */
                                auto height =
                                    pt.get_child("height").get<std::string> ("")
                                ;

                                m_peers[key].set_height(std::stoi(height));
                            }
                            catch (...)
                            {
                                // ...
                            }
                        }
                        catch (std::exception & e)
                        {
                            // ...
                        }

                        /**
                         * Update firewall status.
                         */
                        m_peers[key].set_is_tcp_open(true);
                    }
                }, ep.port());
                
                if (++index >= 24)
                {
                    break;
                }
            }
        }

        /**
         * Start the timer.
         */
        timer_probe_.expires_from_now(std::chrono::seconds(8));
        timer_probe_.async_wait(stack_impl_.strand().wrap(
            std::bind(&probe_manager::tick_probe, self,
            std::placeholders::_1))
        );
    }
}
