/*
 * Copyright (c) 2013-2016 John Connor
 * Copyright (c) 2016-2017 The Vcash Developers
 *
 * This file is part of Vcash.
 *
 * Vcash is free software: you can redistribute it and/or modify
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

#include <boost/algorithm/string.hpp>

#include <crawler/database_stack.hpp>
#include <crawler/probe_manager.hpp>
#include <crawler/stack.hpp>
#include <crawler/stack_impl.hpp>

using namespace crawler;

stack_impl::stack_impl(crawler::stack & owner)
    : m_strand(m_io_service)
    , stack_(owner)
{
    // ...
}

void stack_impl::start(const std::map<std::string, std::string> & args)
{
    /**
     * Parse the command line arguments.
     */
    parse_command_line_args(args);
    
    /**
     * Reset the boost::asio::io_service.
     */
    m_io_service.reset();
    
    /**
     * Allocate the boost::asio::io_service::work.
     */
    work_.reset(new boost::asio::io_service::work(m_io_service));

    /**
     * Allocate the thread.
     */
    auto thread = std::make_shared<std::thread> (
        std::bind(&stack_impl::loop, this)
    );
    
    /**
     * Retain the thread.
     */
    threads_.push_back(thread);
    
    /**
     * Allocate the database_stack.
     */
    m_database_stack = std::make_shared<database_stack>(
        m_io_service, m_strand, *this
    );

    /**
     * Start the database_stack.
     */
    m_database_stack->start(0, false);
    
    /**
     * Allocate the probe_manager.
     */
    m_probe_manager = std::make_shared<probe_manager>(*this);
    
    /**
     * Start the probe_manager.
     */
    m_probe_manager->start();
}

void stack_impl::stop()
{
    if (m_database_stack)
    {
        m_database_stack->stop();
    }
    
    if (m_probe_manager)
    {
        m_probe_manager->stop();
    }
    
    /**
     * Reset the work.
     */
    work_.reset();

    /**
     * Stop the boost::asio::io_service.
     */
    m_io_service.stop();
    
    /**
     * Join the threads.
     */
    for (auto & i : threads_)
    {
        try
        {
            if (i->joinable())
            {
                i->join();
            }
        }
        catch (std::exception & e)
        {
            // ...
        }
    }
    
    /**
     * Clear the threads.
     */
    threads_.clear();
    
    m_probe_manager.reset();
}

void stack_impl::parse_command_line_args(
    const std::map<std::string, std::string> & args
    )
{
    for (auto & i : args)
    {
        // ...
    }
}

void stack_impl::loop()
{
    while (work_)
    {
        try
        {
            m_io_service.run();
            
            if (work_ == 0)
            {
                break;
            }
        }
        catch (std::exception & e)
        {
            // ...
        }
    }
}

boost::asio::io_service & stack_impl::io_service()
{
    return m_io_service;
}

boost::asio::strand & stack_impl::strand()
{
    return m_strand;
}

std::shared_ptr<database_stack> & stack_impl::get_database_stack()
{
    return m_database_stack;
}

std::shared_ptr<probe_manager> & stack_impl::get_probe_manager()
{
    return m_probe_manager;
}
