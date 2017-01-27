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
 
#ifndef DATABASE_STACK_HPP
#define DATABASE_STACK_HPP

#include <cstdint>
#include <list>
#include <map>
#include <string>
#include <vector>

namespace database {

    class stack_impl;
    
    /**
     * The stack.
     */
    class stack
    {
        public:
        
            /**
             * The configuration.
             * @param port The listen port.
             */
            class configuration
            {
                public:
                
                    /**
                     * The operation modes.
                     */
                    typedef enum operation_modes
                    {
                        operation_mode_interface,
                        operation_mode_storage,
                    } operation_mode_t;
                
                    /**
                     * Constructor
                     */
                    configuration()
                        : m_port(0)
                        , m_operation_mode(operation_mode_storage)
                    {
                        // ...
                    }
                
                    /**
                     * Sets the port.
                     * @param val The value.
                     */
                    void set_port(const std::uint16_t & val)
                    {
                        m_port = val;
                    }
                
                    /**
                     * The port.
                     */
                    const std::uint16_t & port() const
                    {
                        return m_port;
                    }
                
                    /**
                     * Sets the operation mode.
                     * @param val The value.
                     */
                    void set_operation_mode(const operation_mode_t & val)
                    {
                        m_operation_mode = val;
                    }
                
                    /**
                     * The operation mode.
                     */
                    const operation_mode_t & operation_mode() const
                    {
                        return m_operation_mode;
                    }
                
                private:
                
                    /**
                     * The port.
                     */
                    std::uint16_t m_port;
                
                    /**
                     * The operation mode.
                     */
                    operation_mode_t m_operation_mode;
                    
                protected:
                
                    // ...
            };
            
            /**
             * Constructor
             */
            stack();
            
            /**
             * Starts the stack.
             * @param config The configuration.
             */
            void start(const configuration &);
            
            /**
             * Stops the stack.
             */
            void stop();
            
            /**
             * Joins the overlay.
			 * @param contacts The bootstrap contacts.
             */
            void join(
                const std::vector< std::pair<std::string, unsigned short> > &
            );
            
			/**
			 * Leaves the overlay.
			 */
			void leave();
        
            /**
             * Performs a store operation.
             * @param query The query.
             */
            std::uint16_t store(const std::string &);
        
            /**
             * Performs a find operation.
             * @param query The query.
             * @param max_results The maximum number of results.
             */
            std::uint16_t find(const std::string &, const std::size_t &);
        
            /**
             * Performs a broadcast operation.
             * @param buffer The buffer.
             */
            std::uint16_t broadcast(const std::vector<std::uint8_t> &);
        
            /**
             * Returns all of the storage nodes in the routing table.
             */
            std::vector< std::map<std::string, std::string> > storage_nodes();
        
            /**
             * Returns all of the endpoints in the routing table.
             */
            std::list< std::pair<std::string, std::uint16_t> > endpoints();
        
            /**
             * Called when a search result is received.
             * @param transaction_id The transaction id.
             * @param query The query.
             */
            virtual void on_find(
                const std::uint16_t & transaction_id,
                const std::string & query
            );
        
            /**
             * Called when a udp packet doesn't match the protocol fingerprint.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            virtual void on_udp_receive(
                const char * addr, const std::uint16_t & port, const char * buf,
                const std::size_t & len
            );

            /**
             * Called when a broadcast message is received.
             * @param addr The address.
             * @param port The port.
             * @param buf The buffer.
             * @param len The length.
             */
            virtual void on_broadcast(
                const char * addr, const std::uint16_t & port,
                const char * buf, const std::size_t & len
            );
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The stack implementation.
             */
            stack_impl * stack_impl_;
    };

} // namespace database

#endif // DATABASE_STACK_HPP
