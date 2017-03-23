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

#include <coin/incentive_collaterals.hpp>

using namespace coin;

incentive_collaterals::incentive_collaterals()
    : m_version(current_version)
{
    set_null();
}

incentive_collaterals::incentive_collaterals(
    const std::set<address_manager::recent_endpoint_t> & collaterals
    )
    : m_version(current_version)
    , m_collaterals(collaterals)
{
    // ...
}

void incentive_collaterals::encode()
{
    encode(*this);
}

void incentive_collaterals::encode(data_buffer & buffer)
{
    /**
     * Encode the version.
     */
    buffer.write_uint32(m_version);
    
    /**
     * Write the number of collateral entries.
     */
    buffer.write_var_int(m_collaterals.size());
    
    /**
     * Write the collateral entries.
     */
     for (auto & i : m_collaterals)
     {
        /**
         * Write the address.
         */
        buffer.write_network_address(i.addr, false);
        
        /**
         * Write the size of the wallet address.
         */
        buffer.write_var_int(i.wallet_address.size());
        
        /**
         * Write the wallet address.
         */
        buffer.write_bytes(i.wallet_address.data(), i.wallet_address.size());
        
        auto public_key = i.public_key;
        
        /**
         * Write the public key.
         */
        public_key.encode(buffer);
        
        /**
         * Write the transaction_in.
         */
        i.tx_in.encode(buffer);
        
        /**
         * Write the time.
         */
        buffer.write_uint64(i.time);
        
        /**
         * Write the protocol version.
         */
        buffer.write_uint32(i.protocol_version);
        
        /**
         * Write the protocol user agent.
         */
        buffer.write_var_int(i.protocol_version_user_agent.size());
        
        /**
         * Write the protocol version user agent.
         */
        buffer.write_bytes(
            i.protocol_version_user_agent.data(),
            i.protocol_version_user_agent.size()
        );
        
        /**
         * Write the protocol version services.
         */
        buffer.write_uint64(i.protocol_version_services);
        
        /**
         * Write the protocol version start height.
         */
        buffer.write_int32(i.protocol_version_start_height);
     }
}

bool incentive_collaterals::decode()
{
    return decode(*this);
}

bool incentive_collaterals::decode(data_buffer & buffer)
{
    /**
     * Decode the version.
     */
    m_version = buffer.read_uint32();
    
    assert(m_version == current_version);
    
    /**
     * Read the number of collateral entries.
     */
    auto count = buffer.read_var_int();
    
    /**
     * Read each collateral entry.
     */
    for (auto i = 0; i < count; i++)
    {
        address_manager::recent_endpoint_t collateral;
        
        /**
         * Read the address.
         */
        collateral.addr = buffer.read_network_address(false, true);
        
        auto len = buffer.read_var_int();
        
        collateral.wallet_address.resize(len);
        
        /**
         * Read the wallet address.
         */
        buffer.read_bytes(
            const_cast<char *> (collateral.wallet_address.data()),
            collateral.wallet_address.size()
        );
        
        /**
         * Read the public key.
         */
        collateral.public_key.decode(buffer);
        
        /**
         * Read the transaction_in.
         */
        collateral.tx_in.decode(buffer);
        
        /**
         * Read the time.
         */
        collateral.time = buffer.read_uint64();
        
        /**
         * Read the protocol version.
         */
        collateral.protocol_version = buffer.read_uint32();
        
        /**
         * Read the protocol version user agent length.
         */
        len = buffer.read_var_int();
        
        collateral.protocol_version_user_agent.resize(len);
        
        /**
         * Read the protocol version user agent.
         */
        buffer.read_bytes(
            const_cast<char *> (collateral.protocol_version_user_agent.data()),
            collateral.protocol_version_user_agent.size()
        );
        
        /**
         * Read the protocol version services.
         */
        collateral.protocol_version_services = buffer.read_uint64();
        
        /**
         * Read the protocol version start height.
         */
        collateral.protocol_version_start_height = buffer.read_int32();
        
        m_collaterals.insert(collateral);
    }
    
    return true;
}

void incentive_collaterals::set_null()
{
    m_version = current_version;
    m_collaterals.clear();
}

std::set<address_manager::recent_endpoint_t> &
    incentive_collaterals::collaterals()
{
    return m_collaterals;
}
