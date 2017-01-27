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
 
#if (defined _MSC_VER)
#include <Objbase.h>
#endif // _MSC_VER

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>

#include <database/compression.hpp>
#include <database/ecdhe.hpp>
#include <database/hc256.hpp>
#include <database/protocol.hpp>
#include <database/routing_table.hpp>
#include <database/slot.hpp>
#include <database/stack.hpp>
#include <database/storage.hpp>

using namespace database;

void usage()
{
    std::cout << "Commands are boot.\n";
}

class my_database_stack : public database::stack
{
    public:
    
        /**
         * Called when a search result is received.
         * @param transaction_id The transaction id.
         * @param query The query.
         */
        virtual void on_find(
            const std::uint16_t & transaction_id, const std::string & query
            )
        {
            std::cerr << query << std::endl;
        }
    
    private:
    
        // ...
    
    protected:
    
        // ...
};

#include <database/ecdhe.h>

int main(int argc, const char * argv[])
{
    std:srand(std::clock());

#if (defined _MSC_VER)
    CoInitialize(0);
#endif // _MSC_VER

    my_database_stack s;
    
    stack::configuration config;
 
    std::vector< std::pair<std::string, unsigned short> > contacts;
    
    if (argc == 1)
    {
        config.set_port(0);
        
        config.set_operation_mode(stack::configuration::operation_mode_storage);

        contacts.push_back(std::make_pair("127.0.0.1", 40334));
        contacts.push_back(std::make_pair("192.168.1.133", 40334));
        contacts.push_back(std::make_pair("162.219.176.251", 40334));
    }
    else if (argc > 1)
    {
        config.set_port(std::stoi(argv[1]));
    }
    else
    {
        usage();
            
        return 0;
    }

    s.start(config);
    
    s.join(contacts);

    /**
     * Wait for termination.
     */
    boost::asio::io_service ios;
    boost::asio::signal_set signals(ios, SIGINT, SIGTERM);
    signals.async_wait(std::bind(&boost::asio::io_service::stop, &ios));
    ios.run();

    s.stop();
    
#if (defined _MSC_VER)
    CoUninitialize();
#endif // _MSC_VER
    
    return 0;
}
