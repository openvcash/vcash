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

storage::storage(boost::asio::io_service & ios)
    : io_service_(ios)
    , strand_(ios)
    , timer_(ios)
{
    // ...
}

void storage::start()
{
    /**
     * Start the expire timer.
     */
    timer_.expires_from_now(std::chrono::seconds(5));
    timer_.async_wait(
        strand_.wrap(std::bind(&storage::tick, this, std::placeholders::_1))
    );
}

void storage::stop()
{
    /**
     * Cancel the timer.
     */
    timer_.cancel();
    
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    auto it = m_entries.begin();
    
    while (it != m_entries.end())
    {
        if (*it)
        {
            (*it)->stop();
        }
        else
        {
            // ...
        }
        
        it = m_entries.erase(it);
    }
}

void storage::store(const std::shared_ptr<entry> e)
{
    /**
     * Allocate the query.
     */
    query q(e->query_string());
    
    for (auto & i : q.pairs())
    {
        if (utility::string::starts_with(i.first, "_"))
        {
            continue;
        }
        
        e->pairs().insert(std::make_pair(i.first, i.second));
    }
    
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    auto it = m_entries.begin();

    for (; it != m_entries.end();)
    {
        auto index1 = 0, index2 = 0;
        
        std::string qs1, qs2;
    
        auto it1 = e->pairs().begin();
        
        for (; it1 != e->pairs().end(); ++it1)
        {
            if (utility::string::starts_with(it1->first, "_"))
            {
                index1++;
                
                continue;
            }
            
            qs1 += it1->first + "=" + it1->second;

            if (index1++ < (e->pairs().size() - 1))
            {
                qs1.append("&", strlen("&"));
            }
        }
        
        auto it2 = (*it)->pairs().begin();
        
        for (; it2 != (*it)->pairs().end(); ++it2)
        {
            if (utility::string::starts_with(it2->first, "_"))
            {
                index2++;
                
                continue;
            }
            
            qs2 += it2->first + "=" + it2->second;
            
            if (index2++ < ((*it)->pairs().size() - 1))
            {
                qs2.append("&", strlen("&"));
            }
        }
    
        if (boost::iequals(qs1, qs2))
        {
            /**
             * Copy the timestamp from the older entry.
             */
            e->set_timestamp((*it)->timestamp());
            
            /**
             * Stop the older entry.
             */
            (*it)->stop();
            
            /**
             * Erase the older entry.
             */
            it = m_entries.erase(it);
            
            /**
             * Because of this logic there shouldn't be any more matches.
             */
            break;
        }
        else
        {
            ++it;
        }
    }

    /**
     * Insert the entry.
     */
    m_entries.push_back(e);
    
    /**
     * Start the entry.
     */
    e->start();
}

const std::vector< std::shared_ptr<entry> > storage::find(
    const std::string & query_string
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);

    std::vector< std::shared_ptr<entry> > ret;

    /**
     * Allocate the query.
     */
    query q(query_string);

    for (auto & i : m_entries)
    {
        bool matches = true;
        
        for (auto & j : q.pairs())
        {
            if (utility::string::starts_with(j.first, "_"))
            {
                continue;
            }
            
            /**
             * Make sure the each key from the query is found in the entry, 
             * otherwise it is a record mismatch.
             */
            bool found = false;
            
            for (auto & k : i->pairs())
            {
                if (boost::iequals(j.first, k.first))
                {
                    found = true;
                    break;
                }
            }
            
            if (!found)
            {
                matches = false;
                break;
            }
            
            for (auto & k : i->pairs())
            {
                if (utility::string::starts_with(k.first, "_"))
                {
                    continue;
                }

                if (boost::iequals(j.first, k.first))
                {
                    log_debug(j.second << ":" << k.second);
                    
                    if (boost::iequals(j.second, k.second))
                    {
                        // ...
                    }
                    else
                    {
                        matches = false;
                    }
                    
                    log_debug("matches = " << matches);
                }
                
                if (!matches)
                {
                    break;
                }
            }
        }
        
        if (matches)
        {
            log_debug("Insert result = " << i->query_string());
            
            ret.push_back(i);
        }
    }

    return ret;
}

void storage::tick(const boost::system::error_code & ec)
{
    if (ec)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l(mutex_);

        auto it = m_entries.begin();
        
        while (it != m_entries.end())
        {
            if (*it && (*it)->expired())
            {
                log_debug("Entry " << (*it)->query_string() << " expired.");
                
                (*it)->stop();
                
                it = m_entries.erase(it);
            }
            else if (*it)
            {
                ++it;
            }
            else
            {
                it = m_entries.erase(it);
            }
        }
    
        /**
         * Start the expire timer.
         */
        timer_.expires_from_now(std::chrono::seconds(5));
        timer_.async_wait(
            strand_.wrap(std::bind(&storage::tick, this,
            std::placeholders::_1))
        );
    }
}

const std::vector< std::shared_ptr<entry> > & storage::entries() const
{
    return m_entries;
}

int storage::run_test()
{
    std::vector<std::string> pairs1;
    boost::split(pairs1, "username=john&age=36", boost::is_any_of("&"));

    std::cerr << pairs1.size() << std::endl;
    
    assert(pairs1.size() == 2);
    
    std::map<std::string, std::string> pairs3;
    
    for (auto & i : pairs1)
    {
        std::vector<std::string> pairs2;
        
        boost::split(pairs2, i, boost::is_any_of("="));
        
        pairs3[pairs2[0]] = pairs2[1];
    }
    
    std::cerr << pairs3.size() << std::endl;
    
    assert(pairs3.size() == 2);
  
    for (auto & i : pairs3)
    {
        std::cerr << i.first << std::endl;
        std::cerr << i.second << std::endl;
    }

    return 0;
}
