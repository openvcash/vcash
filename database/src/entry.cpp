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

#include <iostream>

#include <boost/algorithm/string.hpp>

#include <database/entry.hpp>
#include <database/logger.hpp>
#include <database/query.hpp>
#include <database/storage.hpp>
#include <database/utility.hpp>

using namespace database;

entry::entry(
    boost::asio::io_service & ios, const std::shared_ptr<storage> & s,
    const std::string & query_string
    )
    : m_query_string(query_string)
    , m_lifetime(0)
    , m_allocation_time(std::time(0))
    , m_timestamp(std::time(0))
    , m_expired(false)
    , strand_(ios)
    , storage_(s)
    , expire_timer_(ios)
{
    /**
     * Allocate the query.
     */
    query q(query_string);
    
    /**
     * Get the lifetime.
     */
    for (auto & i : q.pairs())
    {
        if (boost::iequals("_l", i.first))
        {
            m_lifetime = utility::to_int(i.second);
        }
    }
    
    if (m_lifetime > max_lifetime)
    {
        m_lifetime = max_lifetime;
    }
    
    if (m_lifetime < min_lifetime)
    {
        m_lifetime = min_lifetime;
    }
}

entry::~entry()
{
    // ...
}

void entry::start()
{
    /**
     * Start the expire timer.
     */
    expire_timer_.expires_from_now(std::chrono::seconds(m_lifetime));
    expire_timer_.async_wait(
        strand_.wrap(std::bind(&entry::expire_tick, shared_from_this(),
        std::placeholders::_1))
    );
}

void entry::stop()
{
    expire_timer_.cancel();
}

const std::string & entry::query_string() const
{
    return m_query_string;
}

const std::uint32_t & entry::lifetime() const
{
    return m_lifetime;
}

void entry::set_timestamp(const std::time_t & val)
{
    m_timestamp = val;
}

const std::time_t & entry::timestamp() const
{
    return m_timestamp;
}

std::map<std::string, std::string> & entry::pairs()
{
    return m_pairs;
}

const std::uint32_t entry::expires() const
{
    return m_lifetime - (std::time(0) - m_allocation_time);
}

void entry::expire_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        log_debug("Entry " << m_query_string << " expired.");
        
        /**
         * Set the entry to expired.
         */
        m_expired = true;
    }
}

const bool & entry::expired() const
{
    return m_expired;
}
            