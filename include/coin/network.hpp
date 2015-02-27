/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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

#ifndef COIN_NETWORK_HPP
#define COIN_NETWORK_HPP

#include <clocale>
#include <ctime>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include <coin/logger.hpp>

namespace coin {

    /**
     * Implements network related functionality.
     */
    class network
    {
        public:
        
            /**
             * Constructor
             */
            network()
            {
                /**
                 * Insert the "always" allowed RPC IP addresses.
                 */
                m_allowed_addresses_rpc.insert("127.0.0.1");
            }
        
            /**
             * The singleton accessor.
             */
            static network & instance()
            {
                static network g_network;
                
                return g_network;
            }
        
            /**
             * The minimum number of inbound TCP connections.
             */
            enum { tcp_inbound_minimum = 8 };
        
            /**
             * The maximum number of inbound TCP connections.
             */
            enum { tcp_inbound_maximum = 36 };
    
            /**
             * rfc1123 time.
             */
            std::string rfc1123_time()
            {
                char buf[64];
                
                std::time_t now;
                
                std::time(&now);
                
                struct tm * now_gmt = std::gmtime(&now);
                
                std::string locale(setlocale(LC_TIME, 0));
                
                std::setlocale(LC_TIME, "C");
                
                std::strftime(
                    buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", now_gmt
                );
                
                std::setlocale(LC_TIME, locale.c_str());
                
                return std::string(buf);
            }
        
            /**
             * The allowed addresses.
             */
            std::set<std::string> & allowed_addresses_rpc()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_allowed_addresses_rpc;
            }
        
            /**
             * The banned addresses.
             */
            std::map<std::string, std::time_t> & banned_addresses()
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                return m_banned_addresses;
            }
        
            /**
             * Bans an address for 24 hours.
             * @param addr The address.
             */
            void ban_address(const std::string & addr)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                log_info("Network is banning address " << addr << ".");
                
                m_banned_addresses[addr] = std::time(0) + 24 * 60 * 60;
            }
        
            /**
             * If true the address is banned.
             * @param addr The address.
             */
            bool is_address_banned(const std::string & addr)
            {
                std::lock_guard<std::mutex> l1(mutex_);
                
                auto it = m_banned_addresses.find(addr);
                
                if (it != m_banned_addresses.end())
                {
                    if (std::time(0) < it->second)
                    {
                        return true;
                    }
                    else
                    {
                        /**
                         * The address is no longer banned, erase it.
                         */
                        m_banned_addresses.erase(it);
                        
                        return false;
                    }
                }
                
                return false;
            }
        
            /**
             * If true the address is allowed.
             * @param addr The address.
             */
            bool is_address_rpc_allowed(const std::string & addr)
            {
                return
                    m_allowed_addresses_rpc.find(addr) !=
                    m_allowed_addresses_rpc.end()
                ;
            }
        
        private:
        
            /**
             * The allowed addresses.
             */
            std::set<std::string> m_allowed_addresses_rpc;
        
            /**
             * The banned addresses.
             */
            std::map<std::string, std::time_t> m_banned_addresses;
        
        protected:
        
            /**
             * The std::mutex.
             */
            std::mutex mutex_;
    };
}

#endif // COIN_NETWORK_HPP
