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

#include <coin/big_number.hpp>
#include <coin/data_buffer.hpp>

using namespace coin;

big_number::big_number()
{
    BN_init(this);
}

big_number::big_number(const big_number & b)
{
    BN_init(this);
    
    if (!BN_copy(this, &b))
    {
        BN_clear_free(this);
        
        throw std::runtime_error("BN_copy failed");
    }
}

big_number::big_number(std::int8_t n)
{
    BN_init(this);
    
    if (n >= 0)
    {
        set_ulong(n);
    }
    else
    {
        set_int64(n);
    }
}

big_number::big_number(std::int16_t n)
{
    BN_init(this);
    
    if (n >= 0)
    {
        set_ulong(n);
    }
    else
    {
        set_int64(n);
    }
}

big_number::big_number(std::int32_t n)
{
    BN_init(this);
    
    if (n >= 0)
    {
        set_ulong(n);
    }
    else
    {
        set_int64(n);
    }
}

big_number::big_number(std::int64_t n)
{
    BN_init(this);
    
    set_int64(n);
}

big_number::big_number(std::uint8_t n)
{
    BN_init(this);
    
    set_ulong(n);
}

big_number::big_number(std::uint16_t n)
{
    BN_init(this);
    
    set_ulong(n);
}

big_number::big_number(std::uint32_t n)
{
    BN_init(this);
    
    set_ulong(n);
}

big_number::big_number(std::uint64_t n)
{
    BN_init(this);
    
    set_uint64(n);
}

big_number::big_number(sha256 n)
{
    BN_init(this);
    
    set_sha256(n);
}

big_number::big_number(const std::vector<std::uint8_t> & vch)
{
    BN_init(this);
    
    set_vector(vch);
}

big_number::~big_number()
{
    BN_clear_free(this);
}

void big_number::encode(data_buffer & buffer)
{
    auto bytes = get_vector();
    
    buffer.write_var_int(bytes.size());
    
    buffer.write_bytes(
        reinterpret_cast<const char *>(&bytes[0]), bytes.size()
    );
}

void big_number::decode(data_buffer & buffer)
{
    std::vector<std::uint8_t> bytes;
    
    bytes.resize(buffer.read_var_int());
    
    buffer.read_bytes(
        reinterpret_cast<char *>(&bytes[0]), bytes.size()
    );
}

void big_number::set_ulong(unsigned long n)
{
    auto err = BN_set_word(this, n);
    
    if (!err)
    {
        throw std::runtime_error("BN_set_word failed " + std::to_string(err));
    }
}

unsigned long big_number::get_ulong() const
{
    return BN_get_word(this);
}

unsigned int big_number::get_uint() const
{
    return static_cast<unsigned int> (BN_get_word(this));
}

int big_number::get_int() const
{
    unsigned long n = BN_get_word(this);
    
    if (!BN_is_negative(this))
    {
        return
            (n > std::numeric_limits<int>::max() ?
            std::numeric_limits<int>::max() : static_cast<int> (n))
        ;
    }
    
    return
        (n > (unsigned long)std::numeric_limits<int>::max() ?
        std::numeric_limits<int>::min() : -(int)n)
    ;
}

void big_number::set_int64(std::int64_t val)
{
    std::uint8_t pch[sizeof(val) + 6];
    
    std::uint8_t * p = pch + 4;
    
    bool is_negative;
    
    std::uint64_t n;

    if (val < (std::int64_t)0)
    {
        n = -(val + 1);
        ++n;
        is_negative = true;
    }
    else
    {
        n = val;
        is_negative = false;
    }

    bool has_leading_zeroes = true;
    
    for (auto i = 0; i < 8; i++)
    {
        std::uint8_t c = (n >> 56) & 0xff;
        
        n <<= 8;
        
        if (has_leading_zeroes)
        {
            if (c == 0)
            {
                continue;
            }
            
            if (c & 0x80)
            {
                *p++ = (is_negative ? 0x80 : 0);
            }
            else if (is_negative)
            {
                c |= 0x80;
            }
            
            has_leading_zeroes = false;
        }
        
        *p++ = c;
    }
    
    auto size = p - (pch + 4);
    
    pch[0] = (size >> 24) & 0xff;
    pch[1] = (size >> 16) & 0xff;
    pch[2] = (size >> 8) & 0xff;
    pch[3] = (size) & 0xff;
    
    BN_mpi2bn(pch, static_cast<int> (p - pch), this);
}

std::uint64_t big_number::get_uint64()
{
    unsigned int size = BN_bn2mpi(this, NULL);
    
    if (size < 4)
    {
        return 0;
    }
    
    std::vector<std::uint8_t> vch(size);
    
    BN_bn2mpi(this, &vch[0]);
    
    if (vch.size() > 4)
    {
        vch[4] &= 0x7f;
    }
    
    std::uint64_t n = 0;
    
    for (
        unsigned long i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--
        )
    {
        ((std::uint8_t*)&n)[i] = vch[j];
    }
    
    return n;
}

void big_number::set_uint64(std::uint64_t n)
{
    std::uint8_t pch[sizeof(n) + 6];
    std::uint8_t * p = pch + 4;
    bool has_leading_zeroes = true;
    for (int i = 0; i < 8; i++)
    {
        std::uint8_t c = (n >> 56) & 0xff;
        
        n <<= 8;
        
        if (has_leading_zeroes)
        {
            if (c == 0)
            {
                continue;
            }
            
            if (c & 0x80)
            {
                *p++ = 0;
            }
            
            has_leading_zeroes = false;
        }
        
        *p++ = c;
    }
    
    auto size = p - (pch + 4);
    
    pch[0] = (size >> 24) & 0xff;
    pch[1] = (size >> 16) & 0xff;
    pch[2] = (size >> 8) & 0xff;
    pch[3] = (size) & 0xff;
    
    BN_mpi2bn(pch, static_cast<int> (p - pch), this);
}

void big_number::set_sha256(sha256 val)
{
    std::uint8_t pch[1024];
    std::uint8_t * p = pch + 4;
    
    bool has_leading_zeroes = true;
    
    std::uint8_t * pbegin = val.digest();
    std::uint8_t * psrc = pbegin + sha256::digest_length;
    
    while (psrc != pbegin)
    {
        std::uint8_t c = *(--psrc);
        
        if (has_leading_zeroes)
        {
            if (c == 0)
            {
                continue;
            }
            
            if (c & 0x80)
            {
                *p++ = 0;
            }
            
            has_leading_zeroes = false;
        }
        *p++ = c;
    }
    
    auto size = p - (pch + 4);
    
    pch[0] = (size >> 24) & 0xff;
    pch[1] = (size >> 16) & 0xff;
    pch[2] = (size >> 8) & 0xff;
    pch[3] = (size >> 0) & 0xff;
    
    BN_mpi2bn(pch, static_cast<int> (p - pch), this);
}

sha256 big_number::get_sha256()
{
    unsigned int size = BN_bn2mpi(this, 0);
    
    if (size < 4)
    {
        return sha256();
    }

    std::vector<std::uint8_t> vch(size);
    
    BN_bn2mpi(this, &vch[0]);
    
    if (vch.size() > 4)
    {
        vch[4] &= 0x7f;
    }
    
    sha256 n;
    
    for (
        unsigned long i = 0, j = vch.size() - 1; i <
        sha256::digest_length && j >= 4;
        i++, j--
        )
    {
        n.digest()[i] = vch[j];
    }
    
    return n;
}


void big_number::set_vector(const std::vector<std::uint8_t> & val)
{
    std::vector<std::uint8_t> val2(val.size() + 4);
    
    auto size = val.size();

    val2[0] = (size >> 24) & 0xff;
    val2[1] = (size >> 16) & 0xff;
    val2[2] = (size >> 8) & 0xff;
    val2[3] = (size >> 0) & 0xff;

    std::reverse_copy(val.begin(), val.end(), val2.begin() + 4);
    
    BN_mpi2bn(&val2[0], static_cast<int> (val2.size()), this);
}

std::vector<std::uint8_t> big_number::get_vector() const
{
    unsigned int size = BN_bn2mpi(this, 0);
    
    if (size <= 4)
    {
        return std::vector<std::uint8_t>();
    }
    
    std::vector<std::uint8_t> vch(size);
    
    BN_bn2mpi(this, &vch[0]);
    
    vch.erase(vch.begin(), vch.begin() + 4);
    
    std::reverse(vch.begin(), vch.end());
    
    return vch;
}

big_number & big_number::set_compact(unsigned int val)
{
    unsigned int size = val >> 24;
    
    std::vector<std::uint8_t> vch(4 + size);
    
    vch[3] = size;
    
    if (size >= 1) vch[4] = (val >> 16) & 0xff;
    if (size >= 2) vch[5] = (val >> 8) & 0xff;
    if (size >= 3) vch[6] = (val >> 0) & 0xff;
    
    BN_mpi2bn(&vch[0], static_cast<int> (vch.size()), this);
    
    return *this;
}

unsigned int big_number::get_compact() const
{
    unsigned int size = BN_bn2mpi(this, 0);
    
    std::vector<std::uint8_t> vch(size);
    
    size -= 4;
    
    BN_bn2mpi(this, &vch[0]);
    
    unsigned int val = size << 24;
    
    if (size >= 1) val |= (vch[4] << 16);
    if (size >= 2) val |= (vch[5] << 8);
    if (size >= 3) val |= (vch[6] << 0);
    
    return val;
}

void big_number::set_hex(const std::string& str)
{
    const char * psz = str.c_str();
    
    while (isspace(*psz))
    {
        psz++;
    }
    
    bool is_negative = false;
    
    if (*psz == '-')
    {
        is_negative = true;
        psz++;
    }
    
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
    {
        psz += 2;
    }
    
    while (isspace(*psz))
    {
        psz++;
    }
    
    static const signed char phexdigit[256] =
    {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,
        0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0
    };
    
    *this = 0;
    
    while (isxdigit(*psz))
    {
        *this <<= 4;
        int n = phexdigit[(std::uint8_t)*psz++];
        *this += n;
    }
   
    if (is_negative)
    {
        *this = 0 - *this;
    }
}

std::string big_number::to_string(int base) const
{
    context pctx;
    big_number bbase = base;
    big_number bn0 = 0;
    std::string str;
    big_number bn = *this;
    BN_set_negative(&bn, false);
    big_number dv;
    big_number rem;
    
    if (BN_cmp(&bn, &bn0) == 0)
    {
        return "0";
    }
    
    while (BN_cmp(&bn, &bn0) > 0)
    {
        if (!BN_div(&dv, &rem, &bn, &bbase, pctx))
        {
            throw std::runtime_error("BN_div failed");
        }
        
        bn = dv;
        
        auto c = rem.get_ulong();
        
        str += "0123456789abcdef"[c];
    }
    
    if (BN_is_negative(this))
    {
        str += "-";
    }
    
    std::reverse(str.begin(), str.end());
    
    return str;
}

std::string big_number::get_hex() const
{
    return to_string(16);
}
