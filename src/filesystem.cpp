/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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
#include <cstdlib>

#include <boost/asio.hpp>
#include <boost/format.hpp>

#include <coin/constants.hpp>
#include <coin/filesystem.hpp>
#include <coin/logger.hpp>

using namespace coin;

#if (defined _MSC_VER)
#include "Shlobj.h"
#define ERRNO GetLastError()
static int _mkdir(const char * path)
{
    std::wstring directory(path, path + strlen(path));

    return SHCreateDirectoryEx(NULL, directory.c_str(), NULL );
}
#define CREATE_DIRECTORY(P) _mkdir(P)
#else
#include <sys/stat.h>
#define ERRNO errno
#define ERROR_ALREADY_EXISTS EEXIST
static int _mkdir(const char * dir)
{
    char tmp[256];
    char * p = NULL;
    size_t len;
 
    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    
    if (tmp[len - 1] == '/')
    {
        tmp[len - 1] = 0;
    }
    
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = 0;

            mkdir(tmp, S_IRWXU);

            *p = '/';
        }
    }
    
    return mkdir(tmp, S_IRWXU);
}
#define CREATE_DIRECTORY(P) _mkdir(P)
#endif

int filesystem::error_already_exists = ERROR_ALREADY_EXISTS;

int filesystem::create_path(const std::string & path)
{
    if (CREATE_DIRECTORY(path.c_str()) == 0)
    {
        return 0;
    }
    
    return ERRNO;
}

bool filesystem::copy_file(const std::string & src, const std::string & dest)
{
    enum { buffer_length = 32768 };
    
    std::vector<char> buf(buffer_length);
    
    auto infile =- 1, outfile =- 1;

    if ((infile = ::open(src.c_str(), O_RDONLY)) < 0)
    {
        return false;
    }

    struct stat from_stat;
    
    if (::stat(src.c_str(), &from_stat)!= 0)
    { 
        ::close(infile);
      
        return false;
    }

    int oflag = O_CREAT | O_WRONLY | O_TRUNC;

    if ((outfile = ::open(dest.c_str(), oflag, from_stat.st_mode)) < 0)
    {
        int open_errno = errno;
        
        assert(infile >= 0);
        
        ::close(infile);
        
        errno = open_errno;
        
        return false;
    }

    ssize_t sz, read = 1, write;
    
    while (
        read > 0 && (read = ::read(infile, &buf[0], buffer_length)) > 0
        )
    {
        write = 0;
        
        do
        {
            if (
                (sz = ::write(outfile, &buf[0] + write, read - write)) < 0
                )
            {
                read = sz;

                break;
            }
            
            write += sz;
            
        } while (write < read);
    }

    if (::close(infile) < 0)
    {
        read = -1;
    }
    
    if (::close(outfile) < 0)
    {
        read = -1;
    }

    return read >= 0;
}

std::string filesystem::data_path()
{
    static const std::string bundle_id = constants::client_name;
    std::string ret;
#if (defined _MSC_VER)
    ret += getenv("APPDATA");
    ret += "\\" + bundle_id + "\\";
#elif (defined __APPLE__)
    ret = home_path();
    ret += "Library/";
    ret += "Application Support/";
    ret += bundle_id + "/";
#elif (defined __ANDROID__)
    ret = home_path() + bundle_id + "/";
#else
    ret = home_path();
    ret += "." + bundle_id + "/data/";
#endif
    return ret;
}

std::string filesystem::home_path()
{
    std::string ret;
#if (defined __ANDROID__)
    static const std::string android_package = constants::client_name;
    ret = "/data/data/" + android_package;
#else
    if (std::getenv("HOME"))
    {
        ret = std::getenv("HOME");
    }
    else if (std::getenv("USERPOFILE"))
    {
        ret = std::getenv("USERPOFILE");
    }
    else if (std::getenv("HOMEDRIVE") && std::getenv("HOMEPATH"))
    {
        ret = (
            boost::format("%1%%2%") % std::getenv("HOMEDRIVE") %
            std::getenv("HOMEPATH")
        ).str();
    }
    else
    {
        ret = ".";
    }
#endif // __ANDROID__
#if (defined _MSC_VER)
    return ret + "\\";
#else
    return ret + "/";
#endif
}
