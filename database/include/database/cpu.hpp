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

#ifndef DATABASE_CPU_HPP
#define DATABASE_CPU_HPP

#if (defined _MSC_VER)
#include <boost/asio.hpp>
#elif (defined __APPLE__)
#include <sys/types.h>
#include <sys/sysctl.h>
#else
#include <cstring>
#endif

#include <string>

#include <database/logger.hpp>

namespace database {

    /**
     * Implements CPU utility functions.
     */
    class cpu
    {
        public:
        
            /**
             * The frequency.
             */
            static std::size_t frequency()
            {
                std::size_t ret = -1;
#if (defined _MSC_VER)
                HKEY key;
                DWORD size = 4;
            
                if (
                    RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                    L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0,
                    KEY_READ, &key) != ERROR_SUCCESS
                    )
                {
                    return -1;
                }
            
                if (
                    RegQueryValueEx(key, L"~MHz", NULL, NULL, (LPBYTE)&ret,
                    (LPDWORD)&size) != ERROR_SUCCESS
                    )
                {
                    RegCloseKey(key);
                    return -1;
                }
                RegCloseKey(key);
#elif (defined __APPLE__)
                std::uint64_t freq;
                std::size_t size = sizeof(freq);
                
                if (sysctlbyname("hw.cpufrequency", &freq, &size, NULL, 0))
                {
                    // ...
                }
                else
                {
                    ret = freq / 1000000;
                }
#else
                float freq;
                FILE * f;
                char line[1024], * s;

                f = fopen("/proc/cpuinfo", "rt");
                
                if (!f)
                {
                    return -1;
                }
                
                while (fgets(line, sizeof(line), f))
                {
                    if (!strncmp(line, "cpu MHz", 7))
                    {
                        s = strchr(line, ':');
                        
                        if (s && 1 == sscanf(s, ":%f.", &freq))
                        {
                            ret = freq;
                            
                            break;
                        }
                    }
                }
                
                fclose(f);
#endif
                return ret;
            }
        
            /**
             * Runs test case.
             */
            static int run_test()
            {
                log_info("CPU frequency = " << frequency() << ".");
            }
        
        private:
        
            // ...
            
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_CPU_HPP
