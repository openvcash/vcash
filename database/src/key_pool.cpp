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

#include <database/key_pool.hpp>
#include <database/logger.hpp>

using namespace database;

key_pool::key_pool(boost::asio::io_service & ios)
    : io_service_(ios)
    , strand_(ios)
    , cleanup_timer_(ios)
{
    // ...
}

void key_pool::start()
{
    /*
     * Start the cleanup timer.
     */
    cleanup_timer_.expires_from_now(std::chrono::seconds(3600));
    cleanup_timer_.async_wait(
        strand_.wrap(std::bind(&key_pool::cleanup_tick, this,
        std::placeholders::_1))
    );
}

void key_pool::stop()
{
    cleanup_timer_.cancel();
    
    std::lock_guard<std::mutex> l1(mutex_shared_secrets_);
    
    m_shared_secrets.clear();
}

std::string key_pool::find(const boost::asio::ip::udp::endpoint & ep)
{
    std::string ret;
    
    std::lock_guard<std::mutex> l1(mutex_shared_secrets_);
    
    auto it = m_shared_secrets.find(ep);
    
    if (it != m_shared_secrets.end())
    {
        ret = it->second.first;
    }
    
    return ret;
}

void key_pool::insert(
    const boost::asio::ip::udp::endpoint & ep, const std::string & shared_secret
    )
{
    std::lock_guard<std::mutex> l1(mutex_shared_secrets_);

    if (m_shared_secrets.size() < max_shared_secrets)
    {
        m_shared_secrets[ep] = std::make_pair(shared_secret, std::time(0));
    }
    else
    {
        log_error("Key pool failed to insert shared secret, limit exceeded.");
    }
}

void key_pool::erase_expired_shared_secrets()
{
    std::lock_guard<std::mutex> l1(mutex_shared_secrets_);
    
    auto count = m_shared_secrets.size();
    
    auto it = m_shared_secrets.begin();
    
    while (it != m_shared_secrets.end())
    {
        if (
            std::time(0) - it->second.second >= max_shared_secret_lifetime
            )
        {
            it = m_shared_secrets.erase(it);
        }
        else
        {
            ++it;
        }
    }
    
    count = count - m_shared_secrets.size();
    
    log_info("Key pool erased " << count << " expired shared secrets.");
}

void key_pool::cleanup_tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        /**
         * Erase expired shared secrets.
         */
        erase_expired_shared_secrets();
        
        /**
         * Start the cleanup timer.
         */
        cleanup_timer_.expires_from_now(std::chrono::seconds(3600));
        cleanup_timer_.async_wait(
            strand_.wrap(std::bind(&key_pool::cleanup_tick, this,
            std::placeholders::_1))
        );
    }
}
