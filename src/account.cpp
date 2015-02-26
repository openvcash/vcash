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

#include <coin/account.hpp>
#include <coin/constants.hpp>
#include <coin/logger.hpp>

using namespace coin;

void account::encode()
{
    encode(*this);
}

void account::encode(data_buffer & buffer, const bool & encode_version)
{
    if (encode_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(constants::version_client);
    }
    
    /**
     * Encode the public key.
     */
    m_key_public.encode(buffer);
}

void account::decode()
{
    decode(*this);
}

void account::decode(data_buffer & buffer, const bool & decode_version)
{
    if (decode_version)
    {
        /**
         * Read the version.
         */
        buffer.read_uint32();
    }
    
    /**
     * Decode the public key.
     */
    if (m_key_public.decode(buffer))
    {
        // ...
    }
    else
    {
        log_error("Account failed to decode public key.");
    }
}

key_public & account::get_key_public()
{
    return m_key_public;
}
