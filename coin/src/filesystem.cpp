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
#include <cstdio>
#include <fstream>

#include <boost/asio.hpp>
#include <boost/format.hpp>

#include <coin/constants.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/logger.hpp>

using namespace coin;

#if (defined _MSC_VER)
#include <io.h>
#include "Shlobj.h"
#define ERRNO GetLastError()
static int _mkdir(const char * path)
{
    DWORD len = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
    std::unique_ptr<wchar_t> w_path(new wchar_t[len]);
    MultiByteToWideChar(CP_ACP, 0, path, -1, w_path.get(), len);
    return SHCreateDirectoryEx(0, w_path.get(), 0);
}
#define CREATE_DIRECTORY(P) _mkdir(P)

typedef ptrdiff_t handle_type;

struct dirent
{
    char * d_name;
};

struct DIR
{
    handle_type handle;
    struct _finddata_t info;
    struct dirent result;
    char * name;
};

DIR * opendir(const char *name)
{
    DIR * dir = 0;

    if (name && name[0])
    {
        auto base_length = strlen(name);
        
        const auto * all = strchr("/\\", name[base_length - 1]) ? "*" : "/*";

        if (
            (dir = (DIR *)malloc(sizeof *dir)) != 0 &&
            (dir->name = (char *)malloc(base_length + strlen(all) + 1)) != 0
            )
        {
            strcat(strcpy(dir->name, name), all);

            if (
                (dir->handle =
                (handle_type)_findfirst(dir->name, &dir->info)) != -1
                )
            {
                dir->result.d_name = 0;
            }
            else
            {
                free(dir->name);
                free(dir), dir = 0;
            }
        }
        else
        {
            free(dir), dir = 0;
            
            errno = ENOMEM;
        }
    }
    else
    {
        errno = EINVAL;
    }

    return dir;
}

int closedir(DIR * dir)
{
    auto ret = -1;

    if (dir)
    {
        if (dir->handle != -1)
        {
            ret = _findclose(dir->handle);
        }

        free(dir->name);
        free(dir);
    }

    if (ret == -1)
    {
        errno = EBADF;
    }

    return ret;
}

struct dirent * readdir(DIR * dir)
{
    struct dirent * ret = 0;

    if (dir && dir->handle != -1)
    {
        if (!dir->result.d_name || _findnext(dir->handle, &dir->info) != -1)
        {
            ret = &dir->result;
            
            ret->d_name = dir->info.name;
        }
    }
    else
    {
        errno = EBADF;
    }

    return ret;
}

#else
#include <dirent.h>
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
    try
    {
        std::ifstream ifs(src, std::ios::binary);
        
        std::ofstream ofs(dest, std::ios::binary);

        if (ifs.is_open() && ofs.is_open())
        {
            ofs << ifs.rdbuf();

            ifs.close();

            ofs.close();
        }
        else
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }
    
    return true;
}

std::vector<std::string> filesystem::path_contents(const std::string & path)
{
    std::vector<std::string> ret;

    DIR * dir = 0;
    
    struct dirent * ent;
    
    if ((dir = opendir(path.c_str())) != 0)
    {
        while ((ent = readdir(dir)) != 0)
        {
            ret.push_back(ent->d_name);
        }
        
        closedir(dir);
    }

    return ret;
}

std::string filesystem::data_path()
{
    auto bundle_id = constants::client_name;
    
    if (constants::test_net == true)
    {
        bundle_id += "TestNet";
    }
    
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
    ret = home_path() + "data/";
#else
    ret = home_path();
    ret += "." + bundle_id + "/data/";
#endif

    if (globals::instance().is_client_spv() == true)
    {
        ret += "client/";
    }

    return ret;
}

#if (defined _MSC_VER)
std::wstring filesystem::w_data_path()
{
    std::string bundle_id = constants::client_name;
    std::wstring w_bundle_id(bundle_id.begin(), bundle_id.end());

    if (constants::test_net == true)
    {
        w_bundle_id += L"TestNet";
    }

    std::wstring ret;
    ret += _wgetenv(L"APPDATA");
    ret += L"\\" + w_bundle_id + L"\\";
    if (globals::instance().is_client_spv() == true)
    {
        ret += L"client/";
    }
    return ret;
}
#endif

std::string filesystem::home_path()
{
    std::string ret;
#if (defined __ANDROID__)
    std::string bundle_id = "net.vcash.vcash";
    ret = "/data/data/" + bundle_id;
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
    return ret + "/";
}
