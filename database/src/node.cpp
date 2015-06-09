//
//  node.cpp
//  database
//
//  Created by John Connor on 7/30/12.
//  Copyright (c) 2012 John Connor. All rights reserved.
//

#include <stdexcept>

#include <database/logger.hpp>
#include <database/node.hpp>
#include <database/node_impl.hpp>
#include <database/stack_impl.hpp>

using namespace database;

node::node(boost::asio::io_service & ios, stack_impl & owner)
    : stack_impl_(owner)
    , node_impl_(new node_impl(ios, *this))
{
    // ...
}

void node::start(const stack::configuration & config)
{
    try
    {
        node_impl_->start(config);
    }
    catch (std::exception & e)
    {
        log_error("Failed to start node_impl, what = " << e.what() << ".");
        
        /**
         * Stop
         */
        stop();
    }
}

void node::stop()
{
    if (node_impl_)
    {
        node_impl_->stop();
    }
}

void node::queue_ping(const boost::asio::ip::udp::endpoint & ep)
{
    if (node_impl_)
    {
        node_impl_->queue_ping(ep);
    }
}

std::uint16_t node::store(const std::string & query_string)
{
    if (node_impl_)
    {
        return node_impl_->store(query_string);
    }
    
    return 0;
}

std::uint16_t node::find(
    const std::string & query_string, const std::size_t & max_results
    )
{
    if (node_impl_)
    {
        return node_impl_->find(query_string, max_results);
    }
    
    return 0;
}

std::list< std::pair<std::string, std::uint16_t> > node::endpoints()
{
    if (node_impl_)
    {
        return node_impl_->endpoints();
    }
    
    return std::list< std::pair<std::string, std::uint16_t> > ();
}

void node::on_connected(const boost::asio::ip::tcp::endpoint & ep)
{
    stack_impl_.on_connected(ep);
}

void node::on_disconnected(const boost::asio::ip::tcp::endpoint & ep)
{
    stack_impl_.on_disconnected(ep);
}

void node::on_find(
    const std::uint16_t & transaction_id, const std::string & query_string
    )
{
    stack_impl_.on_find(transaction_id, query_string);
}

void node::on_udp_receive(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    stack_impl_.on_udp_receive(addr, port, buf, len);
}

void node::set_bootstrap_contacts(
    const std::list<boost::asio::ip::udp::endpoint> & val
    )
{
    node_impl_->set_bootstrap_contacts(val);
}

std::list<boost::asio::ip::udp::endpoint> & node::bootstrap_contacts()
{
    return node_impl_->bootstrap_contacts();
}

const std::string & node::id() const
{
    static std::string ret;
    
    if (node_impl_)
    {
        return node_impl_->id();
    }
    
    return ret;
}
