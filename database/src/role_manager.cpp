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

#include <thread>

#include <database/cpu.hpp>
#include <database/firewall_manager.hpp>
#include <database/logger.hpp>
#include <database/network.hpp>
#include <database/node_impl.hpp>
#include <database/role_manager.hpp>
#include <database/stack.hpp>

using namespace database;

role_manager::role_manager(
    boost::asio::io_service & ios, std::shared_ptr<node_impl> owner
    )
    : io_service_(ios)
    , strand_(ios)
    , node_impl_(owner)
    , delayed_start_timer_(ios)
{
    // ...
}

void role_manager::start()
{
    auto timeout = std::chrono::seconds(
        network::address_is_private(network::local_address()) ? 3600 : 300
    );
    
    delayed_start_timer_.expires_from_now(timeout);
    delayed_start_timer_.async_wait(
        strand_.wrap(std::bind(&role_manager::do_start, shared_from_this(),
        std::placeholders::_1))
    );
}

void role_manager::stop()
{
    delayed_start_timer_.cancel();
}

void role_manager::do_start(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        if (auto n = node_impl_.lock())
        {
            /**
             * If we are an interface node check to see if we can be promoted.
             */
            if (
                n->config().operation_mode() ==
                stack::configuration::operation_mode_interface
                )
            {
                if (n->firewall_manager_)
                {
                    float firewall_score =
                        (n->firewall_manager_->tcp_score() +
                        n->firewall_manager_->udp_score()) / 2.0f
                    ;
                    
                    log_debug(
                        "Role manager firewall score = " << firewall_score << "."
                    );

                    if (firewall_score == 100.0f)
                    {
                        log_debug(
                            "Role manager determined firewall score is good "
                            "enough to act as storage node."
                        );
                        
                        /**
                         * Get the cpu frequency.
                         */
                        std::size_t cpu_frequency = cpu::frequency();
                        
                        /**
                         * Get the number of cpu cores.
                         */
                        std::size_t cpu_cores = std::thread::hardware_concurrency();
                        
                        log_debug(
                            "Role manager detected CPU frequency = " <<
                            cpu_frequency << " Mhz, cores = " << cpu_cores << "."
                        );
                        
                        if ((cpu_frequency * cpu_cores) >= 20800)
                        {
                            log_debug(
                                "Role manager has determined cpu is good enough "
                                "to act as storage node."
                            );
                            
                            /**
                             * Set the operation mode to operation_mode_storage.
                             */
                            n->config().set_operation_mode(
                                stack::configuration::operation_mode_storage
                            );
                            
                            log_info(
                                "Role manager says node is now acting "
                                "as a storage node."
                            );
                        }
                    }
                }
            }
        }
    
        auto timeout = std::chrono::seconds(
            network::address_is_private(network::local_address()) == false ?
            60 : 60
        );
        
        delayed_start_timer_.expires_from_now(timeout);
        delayed_start_timer_.async_wait(
            strand_.wrap(std::bind(&role_manager::do_start, shared_from_this(),
            std::placeholders::_1))
        );
    }
}

