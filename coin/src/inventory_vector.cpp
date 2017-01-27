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

#include <coin/data_buffer.hpp>
#include <coin/db_tx.hpp>
#include <coin/globals.hpp>
#include <coin/incentive.hpp>
#include <coin/inventory_vector.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

inventory_vector::inventory_vector()
    : m_type(type_error)
    , m_hash(0)
{
    // ...
}

inventory_vector::inventory_vector(const type_t & type, const sha256 & hash)
    : m_type(type)
    , m_hash(hash)
{
    // ...
}

inventory_vector::inventory_vector(
    const std::string & type, const sha256 & hash
    )
    : m_hash(hash)
{
    auto i  = 1;
    
    for (
        ; i < sizeof(protocol::inventory_type_names) /
        sizeof(protocol::inventory_type_names[0]); i++
        )
    {
        if (type == protocol::inventory_type_names[i])
        {
            m_type = static_cast<type_t> (i);
            
            break;
        }
    }
    
    if (
        i == sizeof(protocol::inventory_type_names) /
        sizeof(protocol::inventory_type_names[0])
        )
    {
        throw std::runtime_error(
            "unkown type (" + type + ")"
        );
    }
}

bool inventory_vector::encode(data_buffer & buffer)
{
    buffer.write_uint32(m_type);
    buffer.write_sha256(m_hash);
    
    return true;
}

bool inventory_vector::decode(data_buffer & buffer)
{
    m_type = static_cast<type_t> (buffer.read_uint32());
    m_hash = buffer.read_sha256();
    
    return true;
}

void inventory_vector::set_type(const type_t & val)
{
    m_type = val;
}

const inventory_vector::type_t & inventory_vector::type() const
{
    return m_type;
}

const sha256 & inventory_vector::hash() const
{
    return m_hash;
}

bool inventory_vector::is_know_type() const
{
    return
        m_type > type_error && m_type <
        static_cast<type_t> (sizeof(protocol::inventory_type_names) /
        sizeof(protocol::inventory_type_names[0]))
    ;
}

const std::string inventory_vector::command() const
{
    if (is_know_type() == false)
    {
        throw std::runtime_error(
            "unkown type (" + std::to_string(m_type) + ")"
        );
    }
    
    return protocol::inventory_type_names[m_type];
}

const std::string inventory_vector::to_string() const
{
    return
        command() + " " + m_hash.to_string().substr(0, 20)
    ;
}

bool inventory_vector::already_have(
    db_tx & tx_db, const inventory_vector & inv
    )
{
    switch (inv.type())
    {
        case type_error:
        {
            // ...
        }
        break;
        case type_msg_tx:
        {
            auto tx_in_map = transaction_pool::instance().exists(inv.hash());
            
            return
                tx_in_map ||
                globals::instance().orphan_transactions().count(inv.hash()) ||
                tx_db.contains_transaction(inv.hash()
            );
        }
        break;
        case type_msg_block:
        {
            return
                globals::instance().block_indexes().count(inv.hash()) ||
                globals::instance().orphan_blocks().count(inv.hash())
            ;
        }
        break;
        case type_msg_ztlock:
        {
            return zerotime::instance().locks().count(inv.hash()) > 0;
        }
        break;
        case type_msg_ztvote:
        {
            return zerotime::instance().votes().count(inv.hash()) > 0;
        }
        break;
        case type_msg_ivote:
        {
            return incentive::instance().votes().count(inv.hash()) > 0;
        }
        break;
        default:
        break;
    }
    
    return true;
}

bool inventory_vector::spv_already_have(const inventory_vector & inv)
{
    switch (inv.type())
    {
        case type_error:
        {
            // ...
        }
        break;
        case type_msg_tx:
        {
            auto tx_in_map = transaction_pool::instance().exists(inv.hash());
            
            return
                tx_in_map ||
                globals::instance().orphan_transactions().count(inv.hash()) > 0
            ;
        }
        break;
        case type_msg_block:
        case type_msg_filtered_block_nonstandard:
        {
            /**
             * We exclude orphans here because of the way they are handled
             * differently. Adding them here using the current design would
             * stall the initial synchronisation
             */
            return
                globals::instance().spv_block_merkles().count(inv.hash())
            ;
        }
        break;
        case type_msg_ztlock:
        {
            return zerotime::instance().locks().count(inv.hash()) > 0;
        }
        break;
        case type_msg_ztvote:
        {
            return zerotime::instance().votes().count(inv.hash()) > 0;
        }
        break;
        case type_msg_ivote:
        {
            return incentive::instance().votes().count(inv.hash()) > 0;
        }
        break;
        default:
        break;
    }
    
    return true;
}
