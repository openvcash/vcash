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
#include <io.h>
#include <windows.h>
#else
#include <stdio.h>
#include <unistd.h>
#endif // _MSC_VER

#include <stdexcept>

#include <coin/file.hpp>

using namespace coin;

file::file()
    : m_file(0)
{
    // ...
}

file::~file()
{
    close();
}

bool file::open(const char * path, const char * mode)
{
    m_file = fopen(path, mode);
    
    return m_file != 0;
}

void file::close()
{
    if (m_file)
    {
        if (m_file != stdin && m_file != stdout && m_file != stderr)
        {
            fclose(m_file);
        }
        
        m_file = 0;
    }
}

bool file::read(char * buf, const std::size_t & len)
{
    if (m_file)
    {
        if (fread(buf, 1, len, m_file) != len)
        {
            return false;
        }
        
        return true;
    }
    else
    {
        // ...
    }
    
    return false;
}

bool file::read(char * buf, std::size_t & len)
{
    if (m_file)
    {
        len = fread(buf, 1, len, m_file);
        
        return true;
    }
    else
    {
        // ...
    }
    
    return false;
}

void file::write(const char * buf, const std::size_t & len)
{
    if (m_file)
    {
        if (fwrite(buf, 1, len, m_file) != len)
        {
            throw std::runtime_error("file write failed");
        }
    }
    else
    {
        // ...
    }
}


bool file::remove(const std::string & path)
{
#if (defined _MSC_VER)
    return ::DeleteFileW(
        std::wstring(path.begin(), path.end()).c_str()
    ) != 0;
#else
    return ::unlink(path.c_str())== 0;
#endif
}

long file::size()
{
    long ret = -1;
    
    if (m_file)
    {
        auto position = ::ftell(m_file);
        
        if (fseek(m_file, 0, SEEK_END) == 0)
        {
            ret = ::ftell(m_file);
        }
        
        fseek(m_file, position, SEEK_SET);
    }
    
    return ret;
}

int file::seek_set(long offset)
{
    return ::fseek(m_file, offset, SEEK_SET);
}

bool file::seek_end()
{
    return ::fseek(m_file, 0, SEEK_END) == 0;
}

long file::ftell()
{
    return ::ftell(m_file);
}

int file::fflush()
{
    return ::fflush(m_file);
}

int file::fsync()
{
#if (defined _MSC_VER)
    return ::_commit(_fileno(m_file));
#else
    return ::fsync(fileno(m_file));
#endif // _MSC_VER
}

FILE * file::get_FILE()
{
    return m_file;
}
