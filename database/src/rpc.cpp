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

#include <database/rpc.hpp>

using namespace database;

rpc::rpc(
    boost::asio::io_service & ios, const std::uint16_t & tid,
    const boost::asio::ip::udp::endpoint & ep
    )
    : m_transaction_id(tid)
    , m_endpoint(ep)
    , io_service_(ios)
    , strand_(ios)
    , timeout_timer_(ios)
{
    // ..
}

void rpc::start()
{
    /**
     * Start the timeout timer.
     */
    timeout_timer_.expires_from_now(
        std::chrono::seconds(timeout_interval)
    );
    timeout_timer_.async_wait(
        strand_.wrap(std::bind(&rpc::timeout_tick, shared_from_this(),
        std::placeholders::_1))
    );
}

void rpc::stop()
{
    /**
     * Cancel the refresh timer.
     */
    timeout_timer_.cancel();
}

void rpc::set_on_timeout(const std::function<void (const std::uint16_t &)> & f)
{
    m_on_timeout = f;
}

const std::uint16_t & rpc::transaction_id() const
{
    return m_transaction_id;
}

const boost::asio::ip::udp::endpoint & rpc::endpoint() const
{
    return m_endpoint;
}

void rpc::timeout_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        if (m_on_timeout)
        {
            m_on_timeout(m_transaction_id);
        }
    }
}
