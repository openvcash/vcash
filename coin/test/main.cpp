/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
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

#include <iostream>

#include <boost/asio.hpp>

#pragma comment(lib, "Shell32.lib")
#if (defined _DEBUG)
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\libeay32MTd.lib")
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\ssleay32MTd.lib")
// build with project file in build_windows
#pragma comment(lib, "..\\deps\\platforms\\windows\\db\\build_windows\\Win32\\Debug_static\\libdb48sd.lib")
#else
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\libeay32MT.lib")
#pragma comment(lib, "C:\\OpenSSL-Win32\\lib\\VC\\static\\ssleay32MT.lib")
// build with project file in build_windows
#pragma comment(lib, "..\\deps\\platforms\\windows\\db\\build_windows\\Win32\\Release_static\\libdb48s.lib")
#endif

#include <coin/stack.hpp>

int main(int argc, const char * argv[])
{
    int ret = 0;

    /**
     * Allocate the stack.
     */
    coin::stack s;
    
    std::map<std::string, std::string> args;
    
    for (auto i = 0; i < argc; i++)
    {
        if (argv[i][0] == '-' && argv[i][1] == '-')
        {
            std::string arg = std::string(argv[i]).substr(2, strlen(argv[i]));
            
            std::string key, value;
            
            auto i = arg.find("=");

            if (i != std::string::npos)
            {
                key = arg.substr(0, i);
                
                i = arg.find("=");
                
                if (i != std::string::npos)
                {
                    value = arg.substr(i + 1, arg.length());
                    
                    args[key] = value;
                }
            }
        }
    }
    
    /**
     * Start the stack.
     */
    s.start(args);

    /**
     * Wait for termination.
     */
    boost::asio::io_service ios;
    boost::asio::signal_set signals(ios, SIGINT, SIGTERM);
    signals.async_wait(std::bind(&boost::asio::io_service::stop, &ios));
    ios.run();

    /**
     * Stop the stack.
     */
    s.stop();

    return ret;
}

