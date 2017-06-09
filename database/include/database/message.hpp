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

#ifndef DATABASE_MESSAGE_HPP
#define DATABASE_MESSAGE_HPP

#include <vector>

#include <boost/asio.hpp>

#include <database/byte_buffer.hpp>
#include <database/protocol.hpp>

namespace database {
    
    /**
     * The message.
     */
    class message
    {
        public:
        
            /**
             * The version.
             */
            enum { version = 10005 };
        
            /**
             * The minimum version.
             */
            enum { version_minimum = 10004 };
        
            /**
             * The attribute types.
             */
            enum attribute_types
            {
                attribute_type_none = 0,
                attribute_type_slot = 8,
                attribute_type_endpoint = 16,
                attribute_type_public_key = 18,
                attribute_type_storage_query = 32,
                attribute_type_broadcast_buffer = 36,
                attribute_type_version = 128,
                attribute_type_stats_udp_bps_outbound = 132,
                attribute_type_stats_udp_bps_inbound = 133,
                attribute_type_stats_storage_entries = 134,
                attribute_type_error = 0xfe,
            };
        
            /**
             * Implements an attribute.
             */
            template <typename T>
            class attribute
            {
                public:
                    std::uint16_t type;
                    std::uint16_t length;
                    T value;
            };
        
            /**
             * Implements a binary attribute.
             */
            typedef attribute< std::vector<std::uint8_t> > attribute_binary;
        
            /**
             * Implements a string attribute.
             */
            typedef attribute<std::string> attribute_string;
        
            /**
             * Implements a uint32 attribute.
             */
            typedef attribute<std::uint32_t> attribute_uint32;
        
            /**
             * Implements a endpoint attribute.
             */
            typedef attribute<boost::asio::ip::udp::endpoint> attribute_endpoint;
        
            /**
             * Constructor
             * @param code The message code.
             */
            message(const protocol::message_code_t &);
            
            /**
             * Constructor
             * @param code The message code.
             * @param tid The transaction identifier.
             */
            message(const protocol::message_code_t &, const std::uint16_t &);
            
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            message(const char *, const std::size_t &);
        
            /**
             * Sets the header flags.
             * @param flags The flags.
             */
            void set_header_flags(const protocol::message_flag_t &);
        
            /**
             * The message header flags.
             */
            const protocol::message_flag_t header_flags() const;
        
            /**
             * The message header code.
             */
            const protocol::message_code_t header_code() const;
        
            /**
             * Sets the header transaction id.
             * @param val The value.
             */
            void set_header_transaction_id(const std::uint16_t &);
        
            /**
             * The transaction identifier.
             */
            const std::uint16_t & header_transaction_id() const;

            /**
             * Set the sourceboost::asio::ip::udp::endpoint.
             * @param val Theboost::asio::ip::udp::endpoint.
             */
            void set_source_endpoint(const boost::asio::ip::udp::endpoint &);
            
            /**
             * The sourceboost::asio::ip::udp::endpoint.
             */
            const boost::asio::ip::udp::endpoint & source_endpoint() const;
        
            /**
             * The binary attributes.
             */
            std::vector<attribute_binary> & binary_attributes();
        
            /**
             * The string attributes.
             */
            std::vector<attribute_string> & string_attributes();
        
            /**
             * The uint32 attributes.
             */
            std::vector<attribute_uint32> & uint32_attributes();
        
            /**
             * The endpoint attributes.
             */
            std::vector<attribute_endpoint> & endpoint_attributes();
        
            /**
             * Encodes the message.
             */
            virtual bool encode();
            
            /**
             * Decodes the message.
             */
            virtual bool decode();
            
            /**
             * Encodes the message body.
             * @param attributes The database::byte_buffer.
             */
            bool encode(const database::byte_buffer &);
            
            /**
             * Encodes a string.
             * @param body The database::byte_buffer.
             * @param val The string.
             */
            void encode_string(database::byte_buffer &, const std::string &);
            
            /**
             * Decodes a string.
             * @param body The database::byte_buffer.
             * @param val The string.
             * @param attribute_length The attribute length.
             */
            void decode_string(
                database::byte_buffer &, std::string &, const std::uint16_t &
            );
            
            /**
             * Encodes aboost::asio::ip::udp::endpoint.
             * @param body The database::byte_buffer.
             * @param ep Theboost::asio::ip::udp::endpoint.
             */
            void encode_endpoint(
                database::byte_buffer &, const boost::asio::ip::udp::endpoint &
            );
            
            /**
             * Decodes a boost::asio::ip::udp::endpoint.
             * @param body The database::byte_buffer.
             */
            boost::asio::ip::udp::endpoint decode_endpoint(
                database::byte_buffer &
            );
        
            /**
             * Encrypt
             * @param key The key.
             */
            bool encrypt(const std::string & key);
        
            /**
             * Decrypt
             * @param key The key.
             */
            bool decrypt(const std::string & key);
        
            /**
             * The data.
             */
            const char * data() const;
            
            /**
             * The size.
             */
            const std::size_t & size() const;
    
            /**
             * Runs test case.
             */
            static int run_test();
        
        private:
        
            /**
             * The header.
             */
            protocol::header_t m_header;
            
            /**
             * The sourceboost::asio::ip::udp::endpoint.
             */
            boost::asio::ip::udp::endpoint m_source_endpoint;
        
            /**
             * The binary attributes.
             */
            std::vector<attribute_binary> m_binary_attributes;
        
            /**
             * The string attributes.
             */
            std::vector<attribute_string> m_string_attributes;
        
            /**
             * The uint32 attributes.
             */
            std::vector<attribute_uint32> m_uint32_attributes;
        
            /**
             * The endpoint attributes.
             */
            std::vector<attribute_endpoint> m_endpoint_attributes;
        
        protected:
        
            /**
             * The database::byte_buffer.
             */
            database::byte_buffer byte_buffer_;
    };
    
} // namespace database

#endif // DATABASE_MESSAGE_HPP
