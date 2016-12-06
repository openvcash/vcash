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

#include <stdexcept>
#include <vector>

#include <crawler/database_stack.hpp>
#include <crawler/logger.hpp>
#include <crawler/stack_impl.hpp>

using namespace crawler;

database_stack::database_stack(
    boost::asio::io_service & ios, boost::asio::strand & s,
    stack_impl & owner
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , timer_(ios)
{
    // ...
}

void database_stack::start(const std::uint16_t & port, const bool & is_client)
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    database::stack::configuration stack_config;
    
    /**
     * The bootstrap contacts.
     */
    std::vector< std::pair<std::string, std::uint16_t> > contacts;
    
    /**
     * Add the hard-coded bootstrap contacts.
     */
    contacts.push_back(std::make_pair("p01.vcash.info", 35784));
    contacts.push_back(std::make_pair("p02.vcash.info", 48376));
    contacts.push_back(std::make_pair("p03.vcash.info", 35533));
    contacts.push_back(std::make_pair("p04.vcash.info", 51985));
    contacts.push_back(std::make_pair("p05.vcash.info", 47547));
    
    /**
     * Set the port.
     */
    stack_config.set_port(port);
    
    /**
     * Set the operation mode.
     */
    stack_config.set_operation_mode(
        is_client ? database::stack::configuration::operation_mode_interface :
        database::stack::configuration::operation_mode_storage
    );
    
    /**
     * Start the database::stack.
     */
    database::stack::start(stack_config);
    
    /**
     * Join the database::stack.
     */
    database::stack::join(contacts);
#endif // USE_DATABASE_STACK

    auto self(shared_from_this());
    
    /**
     * Start the timer.
     */
    timer_.expires_from_now(std::chrono::seconds(8));
    timer_.async_wait(strand_.wrap(
        std::bind(&database_stack::tick, self,
        std::placeholders::_1))
    );
}

void database_stack::stop()
{
    /**
     * Cancel the timer.
     */
    timer_.cancel();

#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    database::stack::stop();
#endif // USE_DATABASE_STACK
}

std::uint16_t database_stack::broadcast(const std::vector<std::uint8_t> & val)
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    return database::stack::broadcast(val);
#else
    return 0;
#endif // USE_DATABASE_STACK
}

std::list< std::pair<std::string, std::uint16_t> > database_stack::endpoints()
{
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
    return database::stack::endpoints();
#else
    return std::list< std::pair<std::string, std::uint16_t> > ();
#endif // USE_DATABASE_STACK
}

void database_stack::on_find(
    const std::uint16_t & transaction_id,
    const std::string & query
    )
{
    // ...
}

void database_stack::on_udp_receive(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    // ...
}

void database_stack::on_broadcast(
    const char * addr, const std::uint16_t & port,
    const char * buf, const std::size_t & len
    )
{
    // ...
}

void database_stack::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        auto self(shared_from_this());
        
        /**
         * Get the number of udp endpoints in the routing table.
         */
#if (defined USE_DATABASE_STACK && USE_DATABASE_STACK)
        auto udp_connections = endpoints().size();
#else
        auto udp_connections = 0;
#endif // USE_DATABASE_STACK
        
        log_info(
            "Database stack has " << udp_connections << " UDP connections."
        );

        /**
         * Start the timer.
         */
        timer_.expires_from_now(std::chrono::seconds(60));
        timer_.async_wait(strand_.wrap(
            std::bind(&database_stack::tick, self,
            std::placeholders::_1))
        );
    }
}
