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

#include <coin/key_pool.hpp>
#include <coin/key_reserved.hpp>
#include <coin/logger.hpp>
#include <coin/wallet.hpp>

using namespace coin;

key_reserved::key_reserved(wallet & w)
    : wallet_(w)
    , index_(-1)
{
    // ...
}

key_reserved::~key_reserved()
{
    if (globals::instance().state() < globals::state_stopping)
    {
        return_key();
    }
}

void key_reserved::return_key()
{
    if (index_ != -1)
    {
        wallet_.return_key(index_);
    }
    
    index_ = -1;
    
    public_key_ = key_public();
}

key_public key_reserved::get_reserved_key()
{
    if (index_ == -1)
    {
        key_pool pool;
        
        wallet_.reserve_key_from_key_pool(index_, pool);
        
        if (index_ != -1)
        {
            public_key_ = pool.get_key_public();
        }
        else
        {
            log_warn(
                "Key reserved, get reserved key is using default key "
                "instead of new key, key pool needs topped off."
            );
            
            public_key_ = wallet_.key_public_default();
        }
    }
    
    assert(public_key_.is_valid());
    
    return public_key_;
}

void key_reserved::keep_key()
{
    if (index_ != -1)
    {
        wallet_.keep_key(index_);
    }
    
    index_ = -1;
    
    public_key_ = key_public();
}
