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

#ifndef DATABASE_NODE_IMPL_HPP
#define DATABASE_NODE_IMPL_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <boost/asio.hpp>

#include <database/stack.hpp>
#include <database/storage_node.hpp>

namespace database {

    class firewall_manager;
    class message;
    class node;
    class operation_queue;
    class role_manager;
    class routing_table;
    class storage;
    class tcp_acceptor;
    class tcp_connector;
    class udp_handler;
    class udp_multiplexor;
    
    /**
     * The node implementation.
     */
    class node_impl : public std::enable_shared_from_this<node_impl>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param owner The node.
             */
            node_impl(boost::asio::io_service &, node &);
            
            /**
             * Starts the node implementation.
             * @param config The stack::configuration.
             */
            void start(const stack::configuration &);
            
            /**
             * Stops the node implementation.
             */
            void stop();
        
            /**
             * Performs a ping operation.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param snodes The storage_node's.
             */
            std::uint16_t ping(
                const boost::asio::ip::udp::endpoint &,
                std::vector<storage_node> snodes = std::vector<storage_node>()
            );
        
            /**
             * Queues a ping operation in the routing table.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param snodes The storage_node's.
             */
            void queue_ping(
                const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * Performs a store operation.
             * @param query The query.
             */
            std::uint16_t store(const std::string &);
        
            /**
             * Performs a lookup on the query.
             * @param query The query.
             * @param max_results The maximum number of results.
             */
            std::uint16_t find(const std::string &, const std::size_t &);
        
            /**
             * Performs a (tcp) proxy operation given endpoint and buffer.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            std::uint16_t proxy(
                const char * addr, const std::uint16_t & port,
                const char * buf, const std::size_t & len
            );
        
            /**
             * Returns all of the endpoints in the routing table.
             */
            std::list< std::pair<std::string, std::uint16_t> > endpoints();
        
            /**
             * The stack::configuration.
             */
            stack::configuration & config();
        
            /**
             * The public boost::asio::ip::udp::endpoint.
             */
            boost::asio::ip::udp::endpoint & public_endpoint();
        
            /**
             * Sets the bootstrap contacts.
             * @param val The value.
             */
            void set_bootstrap_contacts(
                const std::list<boost::asio::ip::udp::endpoint> &
            );
        
            /**
             * The bootstrap contacts.
             */
            std::list<boost::asio::ip::udp::endpoint> & bootstrap_contacts();
        
            /**
             * The id.
             */
            const std::string & id() const;

            /**
             * Sends the given message to the boost::asio::ip::udp::endpoint.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void send_message(
                const boost::asio::ip::udp::endpoint &,
                std::shared_ptr<message>
            );
        
            /**
             * Handles a message.
             * @param ep The boost::asio::ip::tcp::endpoint.
             * @param buf The buffer.
             * @param len The length
             */
            void handle_message(
                const boost::asio::ip::tcp::endpoint &, const char *,
                const std::size_t &
            );
        
            /**
             * Handles a message.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param buf The buffer.
             * @param len The length
             */
            void handle_message(
                const boost::asio::ip::udp::endpoint &, const char *,
                const std::size_t &
            );
        
            /**
             * Called when an rpc receives a response.
             * @param oid The operation identifier.
             * @param tid The transaction identifier.
             * @param ep The boost::asio::ip::udp::endpoint.
             */
            void handle_rpc_response(
                const std::uint16_t &, const std::uint16_t &,
                const boost::asio::ip::udp::endpoint &
            );
            
            /**
             * Called when an rpc times out.
             * @param tid The transaction identifier.
             * @param node_id The node id.
             */
            void handle_rpc_timeout(
                const std::uint16_t &, const boost::asio::ip::udp::endpoint &
            );
        
            /**
             * Called when a udp packet doesn't match the protocol fingerprint.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_app_udp_receive(
                const char * addr, const std::uint16_t & port, const char * buf,
                const std::size_t & len
            );
        
        private:

            /**
             *
             * @param ep The boost::asio::ip::tcp::endpoint.
             * @param msg The message.
             */
            void handle_ack_message(
                const boost::asio::ip::tcp::endpoint & ep, message & msg
            );
        
            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_ack_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );

            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_nack_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );

            /**
             * Handles a ping message.
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_ping_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );

            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_store_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );

            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_find_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );

            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_firewall_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );
        
            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_probe_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );
        
            /**
             *
             * @param ep The boost::asio::ip::udp::endpoint.
             * @param msg The message.
             */
            void handle_error_message(
                const boost::asio::ip::udp::endpoint & ep, message & msg
            );
        
            /**
             * The stack::configuration.
             */
            stack::configuration m_config;
        
            /**
             * The id.
             */
            std::string m_id;
        
            /**
             * The public boost::asio::ip::udp::endpoint.
             */
            boost::asio::ip::udp::endpoint m_public_endpoint;
        
            /**
             * The bootstrap contacts.
             */
            std::list<boost::asio::ip::udp::endpoint> m_bootstrap_contacts;
        
            /**
             * The on find handler.
             */
            std::function<
                void (const std::uint16_t &, const std::string &,
                const std::string &, const std::uint32_t &)
            > m_on_find;
        
        protected:
        
            friend class firewall_manager;
            friend class ping_operation;
            friend class role_manager;
            friend class slot;
            friend class tcp_acceptor;
            friend class tcp_connector;
        
            /**
             * The node.
             */
            node & node_;
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
            
            /**
             * The boost::asio::io_service::stand.
             */
            boost::asio::io_service::strand strand_;
        
            /**
             * The public endpoint mutex.
             */
#if 0 // C++14
            std::shared_mutex public_endpoint_mutex_;
#else
            std::recursive_mutex public_endpoint_mutex_;
#endif
            /**
             * The firewall_manager.
             */
            std::shared_ptr<firewall_manager> firewall_manager_;
        
            /**
             * The tcp_acceptor.
             */
            std::shared_ptr<tcp_acceptor> tcp_acceptor_;
        
            /**
             * The tcp_connector.
             */
            std::shared_ptr<tcp_connector> tcp_connector_;
        
            /**
             * The udp_multiplexor.
             */
            std::shared_ptr<udp_multiplexor> udp_multiplexor_;
            
            /**
             * The udp_handler.
             */
            std::shared_ptr<udp_handler> udp_handler_;
        
            /**
             * The routing_table.
             */
            std::shared_ptr<routing_table> routing_table_;
        
            /**
             * The operation_queue.
             */
            std::shared_ptr<operation_queue> operation_queue_;
        
            /**
             * The role_manager.
             */
            std::shared_ptr<role_manager> role_manager_;
        
            /**
             * The storage.
             */
            std::shared_ptr<storage> storage_;
    };
    
} // namespace database

#endif // DATABASE_NODE_IMPL_HPP
