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
 
#include <set>
#include <thread>

#include <boost/algorithm/string.hpp>

#include <database/logger.hpp>
#include <database/node.hpp>
#include <database/stack.hpp>
#include <database/stack_impl.hpp>
#include <database/utility.hpp>

using namespace database;

stack_impl::stack_impl(stack & owner)
    : stack_(owner)
    , strand_(m_io_service)
    , udp_resolver_(m_io_service)
{
    // ...
}
            
void stack_impl::start(const stack::configuration & config)
{
    /**
     * Allocate the node.
     */
    m_node.reset(new node(m_io_service, *this));
    
    /**
     * Start the node.
     */
    m_node->start(config);
    
    /**
     * Calculate the number of threads.
     */
    std::size_t threads = 1;
    
    log_info(
        "Stack is starting with " << threads << " concurrent threads."
    );
    
    for (auto i = 0; i < threads; i++)
    {
        threads_.push_back(
            std::make_shared<std::thread>(&stack_impl::run, this)
        );
    }
}

void stack_impl::stop()
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    /**
     * Stop the node.
     */
    m_node->stop();
    
    /**
     * Stop the boost::asio::io_service.
     */
    m_io_service.stop();
    
    try
    {
        for (auto & i : threads_)
        {
            if (i)
            {
                i->join();
            }
        }
    }
    catch (std::exception & e)
    {
        // ...
    }
}

void stack_impl::run()
{
    m_io_service.run();
}

void stack_impl::join(
    const std::vector< std::pair<std::string, unsigned short> > & contacts
    )
{
    m_io_service.post(strand_.wrap(
        std::bind(&stack_impl::do_join, this, contacts))
    );
}

void stack_impl::leave()
{
    m_io_service.post(strand_.wrap(
        std::bind(&stack_impl::do_leave, this))
    );
}

void stack_impl::do_join(
    const std::vector< std::pair<std::string, unsigned short> > & contacts
    )
{
    /**
     * Randomize the bootstrap nodes.
     */
    std::vector< std::pair<std::string, unsigned short> > randomized;
    randomized.insert(randomized.begin(), contacts.begin(), contacts.end());
    std::random_shuffle(randomized.begin(), randomized.end());
    
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    for (auto & i : randomized)
    {
        try
        {
            boost::asio::ip::udp::endpoint ep(
                boost::asio::ip::address::from_string(i.first.c_str()), i.second
            );
            
            /**
             * Add the bootstrap contact.
             */
            m_node->bootstrap_contacts().push_back(ep);

            /**
             * Queue the endpoint to be pinged.
             */
            m_node->queue_ping(ep);
        }
        catch (std::exception & e)
        {
            boost::asio::ip::udp::resolver::query query(
                i.first, utility::to_string(i.second)
            );
            
            udp_resolver_.async_resolve(query, strand_.wrap(
                std::bind(&stack_impl::handle_udp_resolve, this,
                std::placeholders::_1, std::placeholders::_2))
            );
        }
    }
}

void stack_impl::do_leave()
{
    // ...
}

std::uint16_t stack_impl::store(const std::string & query_string)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    if (m_node.get())
    {
        return m_node->store(query_string);
    }
    
    return 0;
}

std::uint16_t stack_impl::find(
    const std::string & query_string, const std::size_t & max_results
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    if (m_node.get())
    {
        return m_node->find(query_string, max_results);
    }
    
    return 0;
}

std::uint16_t stack_impl::broadcast(const std::vector<std::uint8_t> & buffer)
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    if (m_node.get())
    {
        return m_node->broadcast(buffer);
    }
    
    return 0;
}

std::vector< std::map<std::string, std::string> > stack_impl::storage_nodes()
{
    if (m_node.get())
    {
        return m_node->storage_nodes();
    }
    
    return std::vector< std::map<std::string, std::string> > ();
}

std::list< std::pair<std::string, std::uint16_t> > stack_impl::endpoints()
{
    if (m_node.get())
    {
        return m_node->endpoints();
    }
    
    return std::list< std::pair<std::string, std::uint16_t> > ();
}

void stack_impl::on_find(
    const std::uint16_t & transaction_id, const std::string & query_string
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    stack_.on_find(transaction_id, query_string);
}

void stack_impl::on_udp_receive(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);

    stack_.on_udp_receive(addr, port, buf, len);
}

void stack_impl::on_broadcast(
    const char * addr, const std::uint16_t & port,
    const char * buf, const std::size_t & len
    )
{
    std::lock_guard<std::recursive_mutex> l(mutex_);
    
    stack_.on_broadcast(addr, port, buf, len);
}

void stack_impl::handle_udp_resolve(
    const boost::system::error_code & ec,
    boost::asio::ip::udp::resolver::iterator it
    )
{
    if (ec)
    {
        // ...
    }
    else
    {
        for (; it != boost::asio::ip::udp::resolver::iterator(); ++it)
        {
            std::lock_guard<std::recursive_mutex> l(mutex_);
            
            if (m_node.get())
            {
                /**
                 * Add the bootstrap contact.
                 */
                m_node->bootstrap_contacts().push_back(it->endpoint());

                /**
                 * Queue the endpoint to be pinged.
                 */
                m_node->queue_ping(it->endpoint());
            }
        }
    }
}

boost::asio::io_service & stack_impl::io_service()
{
    return m_io_service;
}
