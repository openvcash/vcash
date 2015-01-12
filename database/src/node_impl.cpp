/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#include <random>

#include <database/block.hpp>
#include <database/constants.hpp>
#include <database/entry.hpp>
#include <database/find_operation.hpp>
#include <database/firewall_manager.hpp>
#include <database/logger.hpp>
#include <database/message.hpp>
#include <database/network.hpp>
#include <database/node.hpp>
#include <database/node_impl.hpp>
#include <database/operation_queue.hpp>
#include <database/ping_operation.hpp>
#include <database/protocol.hpp>
#include <database/role_manager.hpp>
#include <database/routing_table.hpp>
#include <database/slot.hpp>
#include <database/storage.hpp>
#include <database/store_operation.hpp>
#include <database/tcp_acceptor.hpp>
#include <database/tcp_connector.hpp>
#include <database/tcp_transport.hpp>
#include <database/udp_handler.hpp>
#include <database/udp_multiplexor.hpp>
#include <database/utility.hpp>

#if (defined _MSC_VER)
#undef min
#undef max
#endif

#define USE_TCP_CONNECTOR 0

using namespace database;

node_impl::node_impl(boost::asio::io_service & ios, node & owner)
    : node_(owner)
    , io_service_(ios)
    , strand_(ios)
{
    // ...
}

void node_impl::start(const stack::configuration & config)
{
    std::srand(std::clock());
    
    /**
     * Assign the configuration.
     */
    m_config = config;
    
    /**
     * Generate the local id from the host name.
     */
    m_id = boost::asio::ip::host_name();
    
    /**
     * Allocate the firewall_manager.
     */
    firewall_manager_.reset(
        new firewall_manager(io_service_, shared_from_this())
    );

    /**
     * Allocate the udp_multiplexor.
     */
    udp_multiplexor_.reset(new udp_multiplexor(io_service_));
    
    /**
     * Allocate the tcp_acceptor.
     */
    tcp_acceptor_.reset(new tcp_acceptor(io_service_, shared_from_this()));
    
    /**
     * Allocate the udp_handler.
     */
    udp_handler_.reset(
        new udp_handler(io_service_, shared_from_this(), udp_multiplexor_)
    );
    
    /**
     * Set the on_async_receive_from handler.
     */
    udp_multiplexor_->set_on_async_receive_from(
        strand_.wrap(std::bind(&udp_handler::on_async_receive_from,
        udp_handler_, std::placeholders::_1, std::placeholders::_2,
        std::placeholders::_3))
    );
    
    /**
     * Allocate the storage.
     */
    storage_.reset(new storage(io_service_));

    /**
     * Allocate the role_manager.
     */
    role_manager_.reset(new role_manager(io_service_, shared_from_this()));

    /**
     * Allocate the routing_table.
     */
    routing_table_.reset(new routing_table(io_service_, shared_from_this()));
    
    /**
     * Allocate the operation_queue.
     */
    operation_queue_.reset(new operation_queue(io_service_));
    
    /**
     * Start the firewall_manager.
     */
    if (firewall_manager_)
    {
        firewall_manager_->start();
    }
    
    /**
     * Start the storage.
     */
    storage_->start();
    
    /**
     * Start the routing table.
     */
    routing_table_->start();

    if (role_manager_)
    {
        /**
         * Start the role_manager.
         */
        role_manager_->start();
    }
    
    /**
     * Start the operation_queue.
     */
    operation_queue_->start();
    
    /**
     * Make sure the tcp and udp ports are the same.
     */
    std::uint16_t tcp_port = m_config.port(), udp_port = m_config.port();
    
    if (m_config.port() == 0)
    {
        /**
         * Open the tcp_acceptor.
         */
        tcp_acceptor_->open(m_config.port());
        
        tcp_port = tcp_acceptor_->local_endpoint().port();
        
        udp_port = tcp_port;
        
        /**
         * Open the udp_multiplexor.
         */
        udp_multiplexor_->open(udp_port);    
    }
    else
    {
        /**
         * Open the tcp_acceptor.
         */
        tcp_acceptor_->open(m_config.port());
        
        /**
         * Open the udp_multiplexor.
         */
        udp_multiplexor_->open(m_config.port());
    }

    /**
     * Set the udp port to the port chosen by the subsystem.
     */
    m_config.set_port(udp_port);
    
    log_debug("tcp_port = " << tcp_port << ", udp_port = " << udp_port);
    
    assert(tcp_port == udp_port);

#if 0 // // C++14
    std::unique_lock<std::shared_mutex> l(
        public_endpoint_mutex_, std::defer_lock
    );
#else
    std::lock_guard<std::recursive_mutex> l(public_endpoint_mutex_);
#endif

    /**
     * Set the public endpoint.
     */
    m_public_endpoint = boost::asio::ip::udp::endpoint(
        network::local_address(), udp_port
    );
    
    log_debug("Node public endpoint = " << m_public_endpoint << ".");
    
#if (defined USE_TCP_CONNECTOR && USE_TCP_CONNECTOR)
    /**
     * Allocate the tcp_connector.
     */
    tcp_connector_.reset(new tcp_connector(io_service_, shared_from_this(),
        [this](const boost::asio::ip::tcp::endpoint & ep)
    {
        log_debug("Node has connected to parent node " << ep << ".");
        
        /**
         * If we've just connected and the routing table has no storage nodes
         * perform a bootstrap. This could happen if a node starts up without
         * an internet connection and later it becomes available.
         */
        if (routing_table_->storage_nodes().size() == 0)
        {
            for (auto & i : m_bootstrap_contacts)
            {
                ping(i);
            }
        }

        node_.on_connected(ep);
    }, 
        [this](const boost::asio::ip::tcp::endpoint & ep)
    {
        log_debug("Node has disconnected from parent node " << ep << ".");
        
        node_.on_disconnected(ep);
    },
        [this](const boost::asio::ip::tcp::endpoint & ep, message & msg)
    {
        log_debug(
            "Node got message from " << ep << ", code = " <<
            msg.header_code() << "."
        );
        
        switch (msg.header_code())
        {
            case protocol::message_code_ack:
            case protocol::message_code_nack:
            {
                for (auto & i : msg.string_attributes())
                {
                    if (i.type == message::attribute_type_proxy_payload)
                    {
                        log_debug(
                            "***** Node got attribute_type_proxy_payload, "
                            "empty = " << i.value.empty() << "."
                        );
                        
                        node_.on_proxy(msg.header_transaction_id(), ep, i.value);
                    }
                }
            }
            break;
            default:
            break;
        }
    }));
    
    /**
     * Start the tcp_connector.
     */
    tcp_connector_->start();
#endif // USE_TCP_CONNECTOR
}

void node_impl::stop()
{
    /**
     * Stop the firewall_manager.
     */
    if (firewall_manager_)
    {
        firewall_manager_->stop();
    }
    
    /**
     * Stop the operation_queue.
     */
    if (operation_queue_)
    {
        operation_queue_->stop();
    }
    
    /**
     * Stop the routing table.
     */
    if (routing_table_)
    {
        routing_table_->stop();
    }
    
    /**
     * Stop the role manager.
     */
    if (role_manager_)
    {
        role_manager_->stop();
    }
    
    /**
     * Stop the storage.
     */
    if (storage_)
    {
        storage_->stop();
    }
    
    /**
     * Stop the tcp_connector.
     */
    if (tcp_connector_)
    {
        tcp_connector_->stop();
    }
    
    /**
     * Close the tcp_acceptor.
     */
    if (tcp_acceptor_)
    {
        tcp_acceptor_->close();
    }
    
    /**
     * Close the udp_multiplexor.
     */
    if (udp_multiplexor_)
    {
        udp_multiplexor_->close();
    }
    
    /**
     * Stop the udp_handler.
     */
    if (udp_handler_)
    {
        udp_handler_->stop();
    }
}

std::uint16_t node_impl::ping(
    const boost::asio::ip::udp::endpoint & ep, std::vector<storage_node> snodes
    )
{
    std::uint16_t ret = operation::next_transaction_id();
    
    /**
     * Allocate the ping_operation.
     */
    std::shared_ptr<ping_operation> op(
        new ping_operation(io_service_, ret, operation_queue_,
        shared_from_this(), ep, snodes)
    );
    
    /**
     * Insert the find_operation into the operation_queue.
     */
    operation_queue_->insert(op);
    
    return ret;
}

void node_impl::queue_ping(const boost::asio::ip::udp::endpoint & ep)
{
    if (routing_table_)
    {
        routing_table_->queue_ping(ep);
    }
}

std::uint16_t node_impl::store(const std::string & query_string)
{
    std::uint16_t ret = operation::next_transaction_id();
    
    io_service_.post(strand_.wrap(std::bind(
        [this, ret, query_string]
        {
            /**
             * Get the slot id's responsible for the query.
             */
            auto slot_ids = routing_table_->slot_ids_for_query(query_string);
            
            /**
             * Get the endpoints responsible for the query.
             */
            auto snodes = routing_table_->storage_nodes_for_query(
                query_string, constants::snodes_per_keyword
            );
            
            /**
             * We didn't find any storage nodes in the slot or block, use
             * whatever we have.
             */
            if (snodes.empty())
            {
                snodes = routing_table_->storage_nodes(
                    constants::snodes_per_keyword
                );
            }
            
            if (snodes.empty())
            {
                log_error(
                    "Node attempted store operation but no endpoints were found, "
                    "query_string = " << query_string << "."
                );
            }
            else
            {
                log_debug(
                    "Node is performing store operation, query = " <<
                    query_string << "."
                );
                
                /**
                 * Allocate the store_operation.
                 */
                std::shared_ptr<store_operation> op(
                    new store_operation(io_service_, ret, operation_queue_,
                    shared_from_this(), query_string, slot_ids, snodes)
                );
                
                /**
                 * Insert the find_operation into the operation_queue.
                 */
                operation_queue_->insert(op);
            }
        }
    )));
    
    return ret;
}

std::uint16_t node_impl::find(
    const std::string & query_string, const std::size_t & max_results
    )
{
    std::uint16_t ret = operation::next_transaction_id();
    
    io_service_.post(strand_.wrap(std::bind(
        [this, ret, query_string, max_results]
        {
            /**
             * Get the slot id's responsible for the query.
             */
            auto slot_ids = routing_table_->slot_ids_for_query(query_string);
            
            /**
             * Get the endpoints responsible for the query.
             */
            auto snodes = routing_table_->storage_nodes_for_query(
                query_string, constants::snodes_per_keyword
            );
            
            /**
             * We didn't find any storage nodes in the slot or block, use
             * whatever we have.
             */
            if (snodes.empty())
            {
                snodes = routing_table_->storage_nodes(
                    constants::snodes_per_keyword
                );
            }

            if (snodes.empty())
            {
                log_error(
                    "Node attempted find operation but no endpoints were found, "
                    "query_string = " << query_string << "."
                );
            }
            else
            {
                /**
                 * Allocate the find_operation.
                 */
                std::shared_ptr<find_operation> op(
                    new find_operation(io_service_, ret, operation_queue_,
                    shared_from_this(), query_string, slot_ids, snodes,
                    max_results)
                );
                
                /**
                 * Insert the find_operation into the operation_queue.
                 */
                operation_queue_->insert(op);
            }
        }
    )));
    
    return ret;
}

std::uint16_t node_impl::proxy(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    std::uint16_t ret = 0;

    /**
     * Allocate the proxy message.
     */
    std::shared_ptr<message> msg(
        new message(protocol::message_code_proxy)
    );

    message::attribute_endpoint attr1;
    
    attr1.type = message::attribute_type_endpoint;
    attr1.length = 0;
    attr1.value = boost::asio::ip::udp::endpoint(
        boost::asio::ip::address::from_string(addr), port
    );
    
    msg->endpoint_attributes().push_back(attr1);
    
    message::attribute_string attr2;
    
    attr2.type = message::attribute_type_proxy_payload;
    attr2.length = len;
    attr2.value = std::string(buf, len);
    
    msg->string_attributes().push_back(attr2);
    
    ret = msg->header_transaction_id();
    
    /**
     * Encode the message.
     */
    msg->encode();

    /**
     * Send the message.
     */
    if (!tcp_connector_->send(msg->data(), msg->size()))
    {
        log_error("Proxy send failed, not connected.");
    }

    return ret;
}

std::list< std::pair<std::string, std::uint16_t> > node_impl::endpoints()
{
    std::list< std::pair<std::string, std::uint16_t> > ret;
    
    if (routing_table_)
    {
        const auto & snodes = routing_table_->storage_nodes();
        
        for (auto & i : snodes)
        {
            ret.push_back(std::make_pair(i.address().to_string(), i.port()));
        }
        
        return ret;
    }
    
    return ret;
}

stack::configuration & node_impl::config()
{
    return m_config;
}

boost::asio::ip::udp::endpoint & node_impl::public_endpoint()
{
#if 0 // // C++14
    std::shared_lock<std::shared_mutex> l(public_endpoint_mutex_, std::defer_lock);
#else
    std::lock_guard<std::recursive_mutex> l(public_endpoint_mutex_);
#endif
    return m_public_endpoint;
}

void node_impl::set_bootstrap_contacts(
    const std::list<boost::asio::ip::udp::endpoint> & val
    )
{
    m_bootstrap_contacts = val;
}

std::list<boost::asio::ip::udp::endpoint> & node_impl::bootstrap_contacts()
{
    return m_bootstrap_contacts;
}

const std::string & node_impl::id() const
{
    return m_id;
}

void node_impl::send_message(
    const boost::asio::ip::udp::endpoint & ep, std::shared_ptr<message> msg
    )
{
    if (udp_handler_)
    {
        udp_handler_->send_message(ep, msg);
    }
}

void node_impl::handle_message(
    const boost::asio::ip::tcp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    /**
     * Allocate the message.
     */
    message msg(buf, len);
    
    try
    {
        /**
         * Decode the message.
         */
        if (msg.decode())
        {
            switch (msg.header_code())
            {
                case protocol::message_code_ack:
                {
                    handle_ack_message(ep, msg);
                }
                break;
                default:
                {
                    log_none(
                        "Node got invalid (tcp) header code = " <<
                        msg.header_code() << "."
                    );
                }
                break;
            }
        }
        else
        {
            log_error("Node failed to decode (tcp) message from " << ep << ".");
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "Node failed to decode (tcp) message from " << ep << ", what = " <<
            e.what() << "."
        );
    }
}

void node_impl::handle_message(
    const boost::asio::ip::udp::endpoint & ep, const char * buf,
    const std::size_t & len
    )
{
    /**
     * Allocate the message.
     */
    message msg(buf, len);
    
    /**
     * Set the source endpoint.
     */
    msg.set_source_endpoint(ep);
    
    try
    {
        /**
         * Decode the message.
         */
        if (msg.decode())
        {
            /**
             * Inform the tcp_connector.
             */
            if (tcp_connector_)
            {
                tcp_connector_->handle_message(ep, msg);
            }
    
            switch (msg.header_code())
            {
                case protocol::message_code_ack:
                {
                    handle_ack_message(ep, msg);
                }
                break;
                case protocol::message_code_nack:
                {
                    handle_nack_message(ep, msg);
                }
                break;
                case protocol::message_code_ping:
                {
                    handle_ping_message(ep, msg);
                }
                break;
                case protocol::message_code_store:
                {
                    handle_store_message(ep, msg);
                }
                break;
                case protocol::message_code_find:
                {
                    handle_find_message(ep, msg);
                }
                break;
                case protocol::message_code_firewall:
                {
                    handle_firewall_message(ep, msg);
                }
                break;
                case protocol::message_code_probe:
                {
                    handle_probe_message(ep, msg);
                }
                break;
                case protocol::message_code_error:
                {
                    handle_error_message(ep, msg);
                }
                break;
                default:
                {
                    log_debug(
                        "Node got invalid header code = " <<
                        msg.header_code() << "."
                    );
                }
                break;
            }
        }
        else
        {
            log_error("Node failed to decode message from " << ep << ".");
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "Node failed to decode message from " << ep << ", what = " <<
            e.what() << "."
        );
    }
}

void node_impl::handle_rpc_response(
    const std::uint16_t & operation_id,
    const std::uint16_t & transaction_id,
    const boost::asio::ip::udp::endpoint & ep
    )
{
    if (routing_table_)
    {
        routing_table_->handle_rpc_response(operation_id, transaction_id, ep);
    }
}

void node_impl::handle_rpc_timeout(
    const std::uint16_t & transaction_id,
    const boost::asio::ip::udp::endpoint & ep
    )
{
    if (routing_table_)
    {
        routing_table_->handle_rpc_timeout(ep);
    }
}

void node_impl::on_app_udp_receive(
    const char * addr, const std::uint16_t & port, const char * buf,
    const std::size_t & len
    )
{
    node_.on_udp_receive(addr, port, buf, len);
}

void node_impl::handle_ack_message(
    const boost::asio::ip::tcp::endpoint & ep, message & msg
    )
{
    if (firewall_manager_ && firewall_manager_->handle_message(ep, msg))
    {
        // ...
    }
    else
    {
        // ...
    }
}

void node_impl::handle_ack_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
    }
    
    if (firewall_manager_ && firewall_manager_->handle_message(ep, msg))
    {
        // ...
    }
    else
    {    
        /**
         * Find the operation.
         */
        const std::shared_ptr<operation> op = operation_queue_->find(
            msg.header_transaction_id()
        );

        if (op)
        {
            /**
             * Inform the operation.
             */
            op->on_response(msg);

            /**
             * Results are piggy backed onto ack messages. Check if there is at
             * least one result, tuples of query and lifetime.
             */
            if (msg.string_attributes().size() >= 1)
            {
                /**
                 * Get the queries.
                 */
                std::vector<std::string> queries;
                    
                for (auto & i : msg.string_attributes())
                {
                    if (i.type == message::attribute_type_storage_query)
                    {
                        queries.push_back(i.value);
                    }
                }

                /**
                 * Callback on each query result.
                 */
                for (std::size_t i = 0; i < queries.size(); i++)
                {
                    log_none(
                        "Node got query = " << queries[i] <<
                        ", tid = " << msg.header_transaction_id() << "."
                    );

                    /**
                     * API Callback
                     */
                    node_.on_find(
                        op ? op->transaction_id() : 0, queries[i]
                    );
                }
            }
        }
    }
    
    /**
     * Iterate the uint32 attributes.
     */
    for (auto & i : msg.uint32_attributes())
    {
        /**
         * Look for statistics attributes.
         */
        if (
            i.type == message::attribute_type_stats_tcp_inbound ||
            i.type == message::attribute_type_stats_udp_bps_inbound ||
            i.type == message::attribute_type_stats_udp_bps_outbound
            )
        {
            routing_table_->update_statistics(ep, i);
        }
    }
    
    /**
     * Iterate the endpoint attributes.
     */
    for (auto & i : msg.endpoint_attributes())
    {
        queue_ping(i.value);
    }
}

void node_impl::handle_nack_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
    }
    
    /**
     * Find the operation.
     */
    const std::shared_ptr<operation> op = operation_queue_->find(
        msg.header_transaction_id()
    );
    
    if (op)
    {
        /**
         * Inform the operation.
         */
        op->on_response(msg);
    }
}

void node_impl::handle_ping_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    auto response = std::make_shared<message>(
        protocol::message_code_ack, msg.header_transaction_id()
    );
    
    /**
     * Generate a random number of storage nodes to piggy back.
     */
    auto snodes_length =
        std::rand() % 2 == 1 ? std::rand() % block::slot_length : 0
    ;
    
    if (
        m_config.operation_mode() ==
        stack::configuration::operation_mode_interface
        )
    {
        // ...
    }
    else
    {
        if (snodes_length > 0)
        {
            /**
             * Get some of the storage nodes.
             */
            const auto & snodes = routing_table_->storage_nodes(snodes_length);
            
            /**
             * Piggyback storage nodes.
             */
            for (auto & i : snodes)
            {
                message::attribute_endpoint attr1;
                
                attr1.type = message::attribute_type_endpoint;
                attr1.length = 0;
                attr1.value = i;
                
                response->endpoint_attributes().push_back(attr1);
            }
            
            /**
             * Randomly piggyback statistics.
             */
            auto piggyback = std::rand() % 2 == 1;
    
            if (tcp_acceptor_ && piggyback)
            {
                enum { listen_sockets = 2 };
                
                /**
                 * Add the attribute_type_stats_tcp_inbound.
                 */
                if (tcp_acceptor_->tcp_transports().size() > listen_sockets)
                {
                    message::attribute_uint32 attr1;
                    
                    attr1.type = message::attribute_type_stats_tcp_inbound;
                    attr1.length = sizeof(attr1.value);
                    attr1.value =
                        tcp_acceptor_->tcp_transports().size() - listen_sockets
                    ;
                    
                    response->uint32_attributes().push_back(attr1);
                }

                /**
                 * Add the attribute_type_stats_udp_bps_inbound.
                 */
                message::attribute_uint32 attr1;
                
                attr1.type = message::attribute_type_stats_udp_bps_inbound;
                attr1.length = sizeof(attr1.value);
                attr1.value = udp_multiplexor_->bps_received();
                
                response->uint32_attributes().push_back(attr1);
                
                /**
                 * Add the attribute_type_stats_udp_bps_outbound.
                 */
                message::attribute_uint32 attr2;
                
                attr2.type = message::attribute_type_stats_udp_bps_outbound;
                attr2.length = sizeof(attr2.value);
                attr2.value = udp_multiplexor_->bps_sent();
                
                response->uint32_attributes().push_back(attr2);
            }
        }
    }
    
    /**
     * Send the ack message.
     */
    send_message(ep, response);
    
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
        
        /**
         * Iterate the uint32 attributes.
         */
        for (auto & i : msg.uint32_attributes())
        {
            /**
             * Look for statistics attributes.
             */
            if (
                i.type == message::attribute_type_stats_tcp_inbound ||
                i.type == message::attribute_type_stats_udp_bps_inbound ||
                i.type == message::attribute_type_stats_udp_bps_outbound
                )
            {
                routing_table_->update_statistics(ep, i);
            }
        }
        
        /**
         * Iterate the endpoint attributes.
         */
        for (auto & i : msg.endpoint_attributes())
        {
            queue_ping(i.value);
        }
    }

    /**
     * Find the operation.
     */
    const std::shared_ptr<operation> op = operation_queue_->find(
        msg.header_transaction_id()
    );
    
    if (op)
    {
        /**
         * Inform the operation.
         */
        op->on_response(msg);
    }
}

void node_impl::handle_store_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
    }
    
    std::set<std::uint16_t> slots;

    for (auto & i : msg.uint32_attributes())
    {
        if (i.type == message::attribute_type_slot)
        {
            slots.insert(i.value);
        }
    }
    
    std::string query;
    
    for (auto & i : msg.string_attributes())
    {
        if (i.type == message::attribute_type_storage_query)
        {
            query = i.value;
        }
    }
    
    if (slots.size() > 0 && query.empty())
    {
        std::shared_ptr<message> response(
            new message(protocol::message_code_nack, msg.header_transaction_id())
        );
        
        for (auto & i : slots)
        {
            /**
             * Get some storage nodes that belong to the responsible slot.
             */
            auto i1 = routing_table_->slots_for_id(i);
            
            /**
             * Piggy back some storage nodes that are responsible for the query.
             */
            if (i1.size() > 0)
            {
                for (auto & i2 : i1)
                {
                    for (auto & i3 : i2->storage_nodes())
                    {
                        message::attribute_endpoint attr;
                        
                        attr.type = message::attribute_type_endpoint;
                        attr.length = 0;
                        attr.value = i3.endpoint;
                        
                        response->endpoint_attributes().push_back(attr);
                    }
                }
            }
        }
        
        /**
         * Send the nack message.
         */
        send_message(ep, response);
    }
    else if (query.size() > 0)
    {
        log_debug("Got store message, query = " << query << ".");
        
        if (
            m_config.operation_mode() ==
            stack::configuration::operation_mode_interface
            )
        {
            std::shared_ptr<message> response(
                new message(protocol::message_code_nack,
                msg.header_transaction_id())
            );
            
            /**
             * Send the nack message.
             */
            send_message(ep, response);
        }
        else
        {
            std::shared_ptr<message> response(
                new message(protocol::message_code_ack,
                msg.header_transaction_id())
            );
            
            if (slots.size() > 0)
            {
                for (auto & i : slots)
                {
                    /**
                     * Get some storage nodes that belong to the responsible
                     * slot.
                     */
                    auto i1 = routing_table_->slots_for_id(i);
                    
                    /**
                     * Piggy back some storage nodes that are responsible for
                     * the query.
                     */
                    if (i1.size() > 0)
                    {
                        for (auto & i2 : i1)
                        {
                            for (auto & i3 : i2->storage_nodes())
                            {
                                message::attribute_endpoint attr;
                                
                                attr.type = message::attribute_type_endpoint;
                                attr.length = 0;
                                attr.value = i3.endpoint;
                                
                                response->endpoint_attributes().push_back(attr);
                            }
                        }
                    }
                }
            }
            else
            {
                // :TODO: remove this one day. clients now send slot requests
                // with their store messages.
                /**
                 * Get some storage nodes that belong to the responsible slot.
                 */
                auto i1 = routing_table_->storage_nodes_for_query(
                    query, block::slot_length
                );
                
                /**
                 * Piggy back some storage nodes that are responsible for the query.
                 */
                if (i1.size() > 0)
                {
                    for (auto & i3 : i1)
                    {
                        message::attribute_endpoint attr;
                        
                        attr.type = message::attribute_type_endpoint;
                        attr.length = 0;
                        attr.value = i3;
                        
                        response->endpoint_attributes().push_back(attr);
                    }
                }
            }
            
            /**
             * Send the ack message.
             */
            send_message(ep, response);
            
            /**
             * Allocate the entry.
             */
            std::shared_ptr<entry> e(new entry(io_service_, storage_, query));
            
            /**
             * Store the entry.
             */
            storage_->store(e);
        }
    }
    else
    {
        log_error("Node got invalid store message, sending error.");
        
        /**
         * Allocate the error message.
         */
        std::shared_ptr<message> response(
            new message(protocol::message_code_error,
            msg.header_transaction_id())
        );
        
        /**
         * Send the error message.
         */
        send_message(ep, response);
    }
    
    /**
     * Find the operation.
     */
    const std::shared_ptr<operation> op = operation_queue_->find(
        msg.header_transaction_id()
    );
    
    if (op)
    {
        /**
         * Inform the operation.
         */
        op->on_response(msg);
    }
}

void node_impl::handle_find_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
    }
    
    std::set<std::uint16_t> slots;

    for (auto & i : msg.uint32_attributes())
    {
        if (i.type == message::attribute_type_slot)
        {
            slots.insert(i.value);
        }
    }
    
    std::string query;
    
    for (auto & i : msg.string_attributes())
    {
        if (i.type == message::attribute_type_storage_query)
        {
            query = i.value;
            
            break;
        }
    }
    
    if (slots.size() > 0)
    {
        std::shared_ptr<message> response(
            new message(protocol::message_code_nack, msg.header_transaction_id())
        );
        
        for (auto & i : slots)
        {
            /**
             * Get some storage nodes that belong to the responsible slot.
             */
            auto i1 = routing_table_->slots_for_id(i);
            
            /**
             * Piggy back some storage nodes that are responsible for the query.
             */
            if (i1.size() > 0)
            {
                for (auto & i2 : i1)
                {
                    for (auto & i3 : i2->storage_nodes())
                    {
                        message::attribute_endpoint attr;
                        
                        attr.type = message::attribute_type_endpoint;
                        attr.length = 0;
                        attr.value = i3.endpoint;
                        
                        response->endpoint_attributes().push_back(attr);
                    }
                }
            }
        }
        
        /**
         * Send the nack message.
         */
        send_message(ep, response);
    }
    else if (query.size() > 0)
    {
        if (
            m_config.operation_mode() ==
            stack::configuration::operation_mode_interface
            )
        {
            std::shared_ptr<message> response(
                new message(protocol::message_code_nack,
                msg.header_transaction_id())
            );
            
            /**
             * Send the nack message.
             */
            send_message(ep, response);
        }
        else
        {
            auto i = storage_->find(query);
            
            if (query.empty())
            {
                /**
                 * Allocate the error message.
                 */
                std::shared_ptr<message> response(
                    new message(protocol::message_code_error,
                    msg.header_transaction_id())
                );
                
                /**
                 * Send the error message.
                 */
                send_message(ep, response);
            }
            else if (i.size() > 0)
            {
#if 1
                if (i.size() > 8)
                {
                    std::random_device rd;
                    std::mt19937 g(rd());
        
                    /**
                     * Shuffle the results.
                     */
                    std::shuffle(i.begin(), i.end(), g);
                }
                
                enum { max_query_results = 200 };
                
                /**
                 * Do not send back more than max_query_results.
                 */
                if (i.size() > max_query_results)
                {
                    i.resize(max_query_results);
                }
                
                std::vector<message::attribute_string> attrs;
                
                /**
                 * Loop sending 8 query results per response message.
                 */
                for (auto i2 = 0; i2 < i.size(); i2++)
                {
                    auto & result = i[i2];
                    
                    message::attribute_string attr1;
                    
                    attr1.type = message::attribute_type_storage_query;
                    
                    /**
                     * Formulate the query appending useful information.
                     */
                    std::string query = result->query_string();
                    
                    /**
                     * Append the expires.
                     */
                    query += "&_e=" + utility::to_string(result->expires());
                    
                    /**
                     * Append the timestamp.
                     */
                    query += "&_t=" + utility::to_string(result->timestamp());

                    /**
                     * Set the length.
                     */
                    attr1.length = query.size();
                    
                    /**
                     * Set the value.
                     */
                    attr1.value = query;

                    /**
                     * Add the attribute.
                     */
                    attrs.push_back(attr1);
                    
                    /**
                     * If we have 8 attributes send a response and continue
                     * processing the rest of the query results.
                     */
                    if (attrs.size() == 8)
                    {
                        std::shared_ptr<message> response(
                            new message(protocol::message_code_ack,
                            msg.header_transaction_id())
                        );
                        
                        /**
                         * Add the attribute.
                         */
                        response->string_attributes().insert(
                            response->string_attributes().begin(),
                            attrs.begin(), attrs.end()
                        );
                        
                        /**
                         * Send the ack message.
                         */
                        send_message(ep, response);
                        
                        /**
                         * Clear the attributes.
                         */
                        attrs.clear();
                    }
                }
                
                /**
                 * Send the remaining query results.
                 */
                if (attrs.size() > 0)
                {
                   std::shared_ptr<message> response(
                        new message(protocol::message_code_ack,
                        msg.header_transaction_id())
                    );
                    
                    /**
                     * Add the attribute.
                     */
                    response->string_attributes().insert(
                        response->string_attributes().begin(),
                        attrs.begin(), attrs.end()
                    );
                    
                    /**
                     * Send the ack message.
                     */
                    send_message(ep, response);
                }
#else
                for (auto & i2 : i)
                {
                    std::shared_ptr<message> response(
                        new message(protocol::message_code_ack,
                        msg.header_transaction_id())
                    );
                
                    message::attribute_string attr1;
                    
                    attr1.type = message::attribute_type_storage_query;
                    
                    /**
                     * Formulate the query appending useful information.
                     */
                    std::string query = i2->query_string();
                    
                    /**
                     * Append the expires.
                     */
                    query += "&_e=" + utility::to_string(i2->expires());
                    
                    /**
                     * Append the timestamp.
                     */
                    query += "&_t=" + utility::to_string(i2->timestamp());

                    /**
                     * Set the length.
                     */
                    attr1.length = query.size();
                    
                    /**
                     * Set the value.
                     */
                    attr1.value = query;

                    /**
                     * Add the attribute.
                     */
                    response->string_attributes().push_back(attr1);
                    
                    /**
                     * Send the ack message.
                     */
                    send_message(ep, response);
                } 
#endif
            }
            else
            {
                /**
                 * Get some storage nodes that belong to the responsible slot.
                 */
                auto i1 = routing_table_->storage_nodes_for_query(
                    query, block::slot_length
                );
                
                if (i1.empty())
                {
                    send_message(
                        ep, std::make_shared<message>(
                        protocol::message_code_nack,
                        msg.header_transaction_id())
                    );
                }
                else
                {
                    std::shared_ptr<message> response(
                        new message(protocol::message_code_nack,
                        msg.header_transaction_id())
                    );
                    
                    for (auto & i2 : i1)
                    {
                        message::attribute_endpoint attr;
                        
                        attr.type = message::attribute_type_endpoint;
                        attr.length = 0;
                        attr.value = i2;
                        
                        response->endpoint_attributes().push_back(attr);
                        
                        if (
                            response->endpoint_attributes().size() >=
                            block::slot_length
                            )
                        {
                            break;
                        }
                        
                        if (
                            response->endpoint_attributes().size() >=
                            block::slot_length
                            )
                        {
                            break;
                        }
                    }
                    
                    send_message(ep, response);
                }
            }
        }
    }
    
    /**
     * Find the operation.
     */
    const std::shared_ptr<operation> op = operation_queue_->find(
        msg.header_transaction_id()
    );
    
    if (op)
    {
        /**
         * Inform the operation.
         */
        op->on_response(msg);
    }
}

void node_impl::handle_firewall_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    log_debug("Node got firewall messsage from " << ep << ".");
    
    if (!msg.endpoint_attributes().empty())
    {
        /**
         * Send the response back to the endpoint address as seen by us but use
         * the provided port number.    
         */
        boost::asio::ip::udp::endpoint wirewall_ep(
            ep.address(), msg.endpoint_attributes().front().value.port()
        );
        
        /**
         * Allocate the messsage.
         */
        std::shared_ptr<message> response(
            new message(protocol::message_code_ack)
        );
        
        /**
         * Copy the transaction id.
         */
        response->set_header_transaction_id(msg.header_transaction_id());
        
        /**
         * If we are operating in interface mode we must set the message
         * header flag DONTROUTE so that other nodes do not add us to
         * their routing table.
         */
        if (
            m_config.operation_mode() ==
            stack::configuration::operation_mode_interface
            )
        {
            response->set_header_flags(
                static_cast<protocol::message_flag_t> (
                response->header_flags() | protocol::message_flag_dontroute)
            );
        }
        
        /**
         * Encode the message.
         */
        if (response->encode())
        {
            log_debug(
                "Node sending firewall (udp ack) message to " <<
                wirewall_ep << "."
            );
            
            /**
             * Send this message directly to the firewall endpoint.
             */
            udp_multiplexor_->send_to(
                wirewall_ep, response->data(), response->size()
            );
        }
        else
        {
            log_error("Node message encoding failed.");
        }
        
        /**
         * Form a tcp connection to the firewall endpoint.
         */
        auto t = std::make_shared<tcp_transport>(io_service_);
        
        /**
         * Set the write timeout.
         */
        t->set_write_timeout(5);
        
        /**
         * Close the connection after the message is written.
         */
        t->set_close_after_writes(true);
        
        /**
         * Connect to the firewall endpoint.
         */
        t->start(wirewall_ep.address().to_string(), wirewall_ep.port(), 
            [this, msg, wirewall_ep](boost::system::error_code ec,
            std::shared_ptr<tcp_transport> t)
        {
            if (ec)
            {
                log_error(
                    "Firewall check tcp_transport connect failed, message = " <<
                    ec.message() << "."
                );
            }
            else
            {
                /**
                 * Allocate the messsage.
                 */
                std::shared_ptr<message> response(
                    new message(protocol::message_code_ack)
                );
                
                /**
                 * Copy the transaction id.
                 */
                response->set_header_transaction_id(msg.header_transaction_id());
                
                /**
                 * If we are operating in interface mode we must set the message
                 * header flag DONTROUTE so that other nodes do not add us to
                 * their routing table.
                 */
                if (
                    m_config.operation_mode() ==
                    stack::configuration::operation_mode_interface
                    )
                {
                    response->set_header_flags(
                        static_cast<protocol::message_flag_t> (
                        response->header_flags() |
                        protocol::message_flag_dontroute)
                    );
                }
                
                /**
                 * Encode the message.
                 */
                if (response->encode())
                {
                    log_debug(
                        "Node sending firewall (tcp ack) message to " <<
                        wirewall_ep << "."
                    );
                    
                    /**
                     * Send the response.
                     */
                    t->write(response->data(), response->size());
                }
                else
                {
                    log_error("Node message encoding failed.");
                }
            }
        });
    }
    else
    {
        log_error("Node got firewall message without an endpoint attribute.");
    }
}

void node_impl::handle_probe_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    log_debug("Node got probe messsage from " << ep << ".");

    bool has_client_connection = false;
    
    for (auto & i : msg.uint32_attributes())
    {
        if (i.type == message::attribute_type_client_connection)
        {
            has_client_connection = true;
            
            break;
        }
    }
    
    if (has_client_connection)
    {
        std::uint32_t connections = 0;
        
        if (tcp_acceptor_)
        {
            connections = tcp_acceptor_->tcp_transports().size();
        }
    
        if (connections < tcp_acceptor::max_tcp_connections)
        {
            /**
             * Allocate the messsage.
             */
            std::shared_ptr<message> response(
                new message(protocol::message_code_ack,
                msg.header_transaction_id())
            );
            
            message::attribute_uint32 attr;
            
            attr.type = message::attribute_type_client_connection;
            attr.length = sizeof(attr.value);
            attr.value = 0;
        
            response->uint32_attributes().push_back(attr);
            
            /**
             * Send the response.
             */
            send_message(ep, response);
        }
        else
        {
            /**
             * Allocate the messsage.
             */
            std::shared_ptr<message> response(
                new message(protocol::message_code_nack,
                msg.header_transaction_id())
            );
            
            /**
             * Get some storage nodes that belong to a random slot.
             */
            auto i1 = routing_table_->slots_for_id(
                std::rand() % (slot::length - 1)
            );
            
            /**
             * Piggy back some storage nodes that are responsible for the query.
             */
            if (i1.size() > 0)
            {
                for (auto & i2 : i1)
                {
                    for (auto & i3 : i2->storage_nodes())
                    {
                        message::attribute_endpoint attr;
                        
                        attr.type = message::attribute_type_endpoint;
                        attr.length = 0;
                        attr.value = i3.endpoint;
                        
                        response->endpoint_attributes().push_back(attr);
                    }
                }
            }
            
            /**
             * Send the response.
             */
            send_message(ep, response);
        }
    }
    else
    {
        /**
         * Allocate the messsage.
         */
        std::shared_ptr<message> response(
            new message(protocol::message_code_ack,
            msg.header_transaction_id())
        );
        
        /**
         * Send the response.
         */
        send_message(ep, response);
    }
}

void node_impl::handle_error_message(
    const boost::asio::ip::udp::endpoint & ep, message & msg
    )
{
    if (msg.header_flags() & protocol::message_flag_dontroute)
    {
        // ...
    }
    else
    {
        /**
         * Update the routing table.
         */
        routing_table_->update(ep, msg.header_transaction_id());
    }
    
    if (msg.string_attributes().size() > 0)
    {
        auto message = msg.string_attributes().front().value;
    
        log_debug(
            "Node got error messsage from " << ep << ", message = " <<
            message << "."
        );
        
        if (message == "418 I'm a teapot")
        {
            if (msg.endpoint_attributes().size() > 0)
            {
                auto ep = msg.endpoint_attributes().front();

                if (
                    network::address_is_private(ep.value.address()) == false &&
                    network::address_is_loopback(ep.value.address()) == false &&
                    network::address_is_any(ep.value.address()) == false
                    )
                {
#if 0 // C++14
                    std::unique_lock<std::shared_mutex> l(
                        public_endpoint_mutex_, std::defer_lock
                    );
#else
                    std::lock_guard<std::recursive_mutex> l(
                        public_endpoint_mutex_
                    );
#endif
                    /**
                     * Set our public endpoint.
                     */
                    m_public_endpoint = ep.value;
                    
                    log_debug(
                        "Node discovered public endpoint = " <<
                        m_public_endpoint << "."
                    );
                }
            }
        }
        else
        {
            // ...
        }
    }
    else
    {
        log_debug("Node got error messsage from " << ep << ".");
    }
}
