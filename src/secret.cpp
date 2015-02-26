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

#include <coin/secret.hpp>

using namespace coin;

secret::secret()
{
    // ...
}

secret::secret(const key::secret_t & bytes, const bool & compressed)
{
    set_secret(bytes, compressed);
}

void secret::set_secret(const key::secret_t & bytes, const bool & compressed)
{
    assert(bytes.size() == 32);
    
    set_data(
        128 + (constants::test_net ? address::type_pubkey_test :
        address::type_pubkey),
        reinterpret_cast<const char *> (&bytes[0]), bytes.size()
    );

    if (compressed)
    {
        data().push_back(1);
    }
}

key::secret_t secret::get_secret(bool & compressed)
{
    key::secret_t bytes(32);
    
    std::memcpy(&bytes[0], &data()[0], 32);
    
    compressed = data().size() == 33;
    
    return bytes;
}

bool secret::is_valid()
{
    bool expect_test_net = false;

    switch(version())
    {
        case (128 + address::type_pubkey):
        {
            // ...
        }
        break;
        case (128 + address::type_pubkey_test):
        {
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
        (data().size() == 32 || (data().size() == 33 &&
        data()[32] == 1))
    ;
}

bool secret::set_string(const std::string & value)
{
    bool ret = base58::set_string(value);
    
    if (ret)
    {
        ret = is_valid();
    }
    
    return ret;
}
