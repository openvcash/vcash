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
#include <memory>

#include <coin/address.hpp>

using namespace coin;

address::address()
{
    // ...
}

address::address(const destination::tx_t & dest)
{
    set_destination_tx(dest);
}

address::address(const std::string & val)
{
    set_string(val);
}

bool address::set_id_key(const types::id_key_t & value)
{
    set_data(
        constants::test_net ? type_pubkey_test : type_pubkey,
        reinterpret_cast<const char *> (&value.digest()[0]),
        types::id_key_t::digest_length
    );
    
    return true;
}

bool address::set_id_script(const types::id_script_t & value)
{
    set_data(
        constants::test_net ? type_script_test : type_script,
        reinterpret_cast<const char *> (&value.digest()[0]),
        types::id_key_t::digest_length
    );
    
    return true;
}

bool address::set_destination_tx(const destination::tx_t & value)
{
    return boost::apply_visitor(visitor(*this), value);
}

bool address::is_valid()
{
    auto expected_size = types::id_key_t::digest_length;
    
    bool expect_test_net = false;
    
    switch(version())
    {
        case type_pubkey:
        {
            expected_size = types::id_key_t::digest_length;
            
            expect_test_net = false;
        }
        break;
        case type_script:
        {
            expected_size = types::id_key_t::digest_length;
            
            expect_test_net = false;
        }
        break;
        case type_pubkey_test:
        {
            expected_size = types::id_key_t::digest_length;
            
            expect_test_net = true;
        }
        break;
        case type_script_test:
        {
            expected_size = types::id_key_t::digest_length;
            
            expect_test_net = true;
        }
        break;
        default:
        {
            return false;
        }
        break;
    }
    
    return
        expect_test_net == constants::test_net &&
        data().size() == expected_size
    ;
}

destination::tx_t address::get()
{
    if (is_valid())
    {
        switch (version())
        {
            case type_pubkey:
            case type_pubkey_test:
            {
                ripemd160 id;
                
                std::memcpy(
                    &id.digest()[0], &data()[0], ripemd160::digest_length
                );
                
                return types::id_key_t(id);
            }
            break;
            case type_script:
            case type_script_test:
            {
                ripemd160 id;
                
                std::memcpy(
                    &id.digest()[0], &data()[0], ripemd160::digest_length
                );
                
                return types::id_script_t(id);
            }
            break;
            default:
            break;
        }
    }
    
    return destination::none();
}

bool address::get_id_key(types::id_key_t & id_key)
{
    if (is_valid())
    {
        switch (version())
        {
            case type_pubkey:
            case type_pubkey_test:
            {
                ripemd160 id;
                
                std::memcpy(
                    &id.digest()[0], &data()[0], ripemd160::digest_length
                );
                
                id_key = types::id_key_t(id);
                
                return true;
            }
            break;
            default:
            break;
        }
    }
    
    return false;
}

bool address::is_script()
{
    if (is_valid())
    {
        switch (version())
        {
            case type_script:
            case type_script_test:
            {
                return true;
            }
            break;
            default:
            break;
        }
    }

    return false;
}
