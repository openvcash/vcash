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

#ifndef COIN_MESSAGE_HPP
#define COIN_MESSAGE_HPP

#include <cstdint>
#include <string>

#include <coin/data_buffer.hpp>
#include <coin/protocol.hpp>

namespace coin {

    /**
     * Implements a message.
     */
    class message : public data_buffer
    {
        public:
        
            /**
             * The header magic length.
             */
            enum { header_magic_length = 4 };
        
            /**
             * Constructor
             * @param buf The buffer.
             * @param len The length.
             */
            message(const char * buf, const std::size_t & len);
        
            /**
             * Constructor
             * @param command The command.
             */
            message(const std::string & command);
        
            /**
             * Constructor
             * @param command The command.
             * @param payload The payload.
             */
            message(
                const std::string & command, const data_buffer & payload
            );
        
            /**
             * Encodes the message.
             */
            void encode();
        
            /**
             * Decodes the message.
             */
            void decode();
        
            /**
             * Verifies the header magic.
             */
            bool verify_header_magic();

            /**
             * The header magic.
             */
            static std::vector<std::uint8_t> header_magic_bytes();
        
            /**
             * The header magic number.
             */
            static const std::uint32_t header_magic();
        
            /**
             * The header length.
             */
            enum { header_length = 24 };
        
            /**
             * The header.
             * @param magic A value indicating message origin network, and to
             * seek to next message when the tcp stream state is unknown.
             * @param command A null-terminated ASCII string identifying the
             * packet. This field MUST be 12 bytes in length.
             * @param length The lenth of the payload.
             * @param checksum The checksum of the payload calculated by
             * sha256(sha256(payload)).
             */
            typedef struct
            {
                std::uint32_t magic;
                std::string command;
                std::uint32_t length;
                std::uint32_t checksum;
            } header_t;

            /**
             * The header.
             */
            header_t & header();
        
            /**
             * The protocol version.
             */
            protocol::version_t & protocol_version();
        
            /**
             * The protocol addr structure.
             */
            protocol::addr_t & protocol_addr();
        
            /**
             * The protocol ping structure.
             */
            protocol::ping_t & protocol_ping();
        
            /**
             * The protocol pong structure.
             */
            protocol::pong_t & protocol_pong();
        
            /**
             * The protocol inv structure.
             */
            protocol::inv_t & protocol_inv();
        
            /**
             * The protocol getdata structure.
             */
            protocol::getdata_t & protocol_getdata();
        
            /**
             * The protocol getblocks structure.
             */
            protocol::getblocks_t & protocol_getblocks();
        
            /**
             * The protocol block structure.
             */
            protocol::block_t & protocol_block();
        
            /**
             * The protocol getheaders structure.
             */
            protocol::getheaders_t & protocol_getheaders();
        
            /**
             * The protocol headers structure.
             */
            protocol::headers_t & protocol_headers();
        
            /**
             * The protocol checkpoint structure.
             */
            protocol::checkpoint_t & protocol_checkpoint();
        
            /**
             * The protocol checkpoint structure.
             */
            protocol::tx_t & protocol_tx();
        
            /**
             * The protocol alert structure.
             */
            protocol::alert_t & protocol_alert();
        
            /**
             * The protocol filterload.
             */
            protocol::filterload_t & protocol_filterload();
        
            /**
             * The protocol filteradd.
             */
            protocol::filteradd_t & protocol_filteradd();
        
            /**
             * The protocol merkleblock.
             */
            protocol::merkleblock_t & protocol_merkleblock();
        
            /**
             * The protocol ztlock structure.
             */
            protocol::ztlock_t & protocol_ztlock();
        
            /**
             * The protocol ztquestion structure.
             */
            protocol::ztquestion_t & protocol_ztquestion();
        
            /**
             * The protocol ztanswer structure.
             */
            protocol::ztanswer_t & protocol_ztanswer();
        
            /**
             * The protocol ztvote structure.
             */
            protocol::ztvote_t & protocol_ztvote();
        
            /**
             * The protocol ianswer structure.
             */
            protocol::ianswer_t & protocol_ianswer();
        
            /**
             * The protocol iquestion structure.
             */
            protocol::iquestion_t & protocol_iquestion();
        
            /**
             * The protocol ivote structure.
             */
            protocol::ivote_t & protocol_ivote();
        
            /**
             * The protocol isync structure.
             */
            protocol::isync_t & protocol_isync();

            /**
             * The protocol icols structure.
             */
            protocol::icols_t & protocol_icols();
        
            /**
             * The protocol cbbroadcast structure.
             */
            protocol::cbbroadcast_t & protocol_cbbroadcast();
        
            /**
             * The protocol cbjoin structure.
             */
            protocol::cbjoin_t & protocol_cbjoin();
        
            /**
             * The protocol cbleave structure.
             */
            protocol::cbleave_t & protocol_cbleave();
        
            /**
             * The protocol cbstatus structure.
             */
            protocol::cbstatus_t & protocol_cbstatus();
        
        private:
        
            /**
             * The header.
             */
            header_t m_header;
        
            /**
             * The payload.
             */
            data_buffer m_payload;
    
            /**
             * The protocol version structure.
             */
            protocol::version_t m_protocol_version;
        
            /**
             * The protocol addr structure.
             */
            protocol::addr_t m_protocol_addr;
        
            /**
             * The protocol ping structure.
             */
            protocol::ping_t m_protocol_ping;
        
            /**
             * The protocol pong structure.
             */
            protocol::pong_t m_protocol_pong;
        
            /**
             * The protocol inv structure.
             */
            protocol::inv_t m_protocol_inv;
        
            /**
             * The protocol getdata structure.
             */
            protocol::getdata_t m_protocol_getdata;
        
            /**
             * The protocol getblocks structure.
             */
            protocol::getblocks_t m_protocol_getblocks;
        
            /**
             * The protocol block structure.
             */
            protocol::block_t m_protocol_block;
        
            /**
             * The protocol getheaders structure.
             */
            protocol::getheaders_t m_protocol_getheaders;
        
            /**
             * The protocol headers structure.
             */
            protocol::headers_t m_protocol_headers;
        
            /**
             * The protocol checkpoint structure.
             */
            protocol::checkpoint_t m_protocol_checkpoint;
        
            /**
             * The protocol checkpoint structure.
             */
            protocol::tx_t m_protocol_tx;
        
            /**
             * The protocol alert structure.
             */
            protocol::alert_t m_protocol_alert;
        
            /**
             * The protocol filterload.
             */
            protocol::filterload_t m_protocol_filterload;
        
            /**
             * The protocol filteradd.
             */
            protocol::filteradd_t m_protocol_filteradd;
        
            /**
             * The protocol merkleblock.
             */
            protocol::merkleblock_t m_protocol_merkleblock;
        
            /**
             * The protocol ztlock structure.
             */
            protocol::ztlock_t m_protocol_ztlock;
        
            /**
             * The protocol ztquestion structure.
             */
            protocol::ztquestion_t m_protocol_ztquestion;
        
            /**
             * The protocol ztanswer structure.
             */
            protocol::ztanswer_t m_protocol_ztanswer;
        
            /**
             * The protocol ztvote structure.
             */
            protocol::ztvote_t m_protocol_ztvote;
        
            /**
             * The protocol ianswer structure.
             */
            protocol::ianswer_t m_protocol_ianswer;
        
            /**
             * The protocol iquestion structure.
             */
            protocol::iquestion_t m_protocol_iquestion;
        
            /**
             * The protocol ivote structure.
             */
            protocol::ivote_t m_protocol_ivote;
        
            /**
             * The protocol isync structure.
             */
            protocol::isync_t m_protocol_isync;

            /**
             * The protocol icols structure.
             */
            protocol::icols_t m_protocol_icols;
        
            /**
             * The protocol cbbroadcast structure.
             */
            protocol::cbbroadcast_t m_protocol_cbbroadcast;
        
            /**
             * The protocol cbjoin structure.
             */
            protocol::cbjoin_t m_protocol_cbjoin;
        
            /**
             * The protocol cbleave structure.
             */
            protocol::cbleave_t m_protocol_cbleave;
        
            /**
             * The protocol cbstatus structure.
             */
            protocol::cbstatus_t m_protocol_cbstatus;
        
        protected:
        
            /**
             * Creates a version.
             */
            data_buffer create_version();
        
            /**
             * Creates an addr.
             */
            data_buffer create_addr();
        
            /**
             * Creates a ping.
             */
            data_buffer create_ping();
        
            /**
             * Creates a pong.
             */
            data_buffer create_pong();
        
            /**
             * Creates an inv.
             */
            data_buffer create_inv();
        
            /**
             * Creates a getdata.
             */
            data_buffer create_getdata();
        
            /**
             * Creates a getblocks.
             */
            data_buffer create_getblocks();
        
            /**
             * Creates getheaders.
             */
            data_buffer create_getheaders();
        
            /**
             * Creates headers.
             */
            data_buffer create_headers();
        
            /**
             * Creates a checkpoint.
             */
            data_buffer create_checkpoint();
        
            /**
             * Creates a block.
             */
            data_buffer create_block();
 
            /**
             * Creates a filterload.
             */
            data_buffer create_filterload();
        
            /**
             * Creates a filteradd.
             */
            data_buffer create_filteradd();
        
            /**
             * Creates a filterclear.
             */
            data_buffer create_filterclear();
  
            /**
             * Creates a merkleblock.
             */
            data_buffer create_merkleblock();
        
            /**
             * Creates a tx.
             */
            data_buffer create_tx();
        
            /**
             * Creates an alert.
             */
            data_buffer create_alert();
        
            /**
             * Creates an ztlock.
             */
            data_buffer create_ztlock();
        
            /**
             * Creates an ztquestion.
             */
            data_buffer create_ztquestion();
        
            /**
             * Creates an ztanswer.
             */
            data_buffer create_ztanswer();
        
            /**
             * Creates an ztvote.
             */
            data_buffer create_ztvote();
        
            /**
             * Creates an ianswer.
             */
            data_buffer create_ianswer();
        
            /**
             * Creates an iquestion.
             */
            data_buffer create_iquestion();
        
            /**
             * Creates an ivote.
             */
            data_buffer create_ivote();
        
            /**
             * Creates an isync.
             */
            data_buffer create_isync();
        
            /**
             * Creates an icols.
             */
            data_buffer create_icols();
        
            /**
             * Creates an cbbroadcast.
             */
            data_buffer create_cbbroadcast();
        
            /**
             * Creates an cbjoin.
             */
            data_buffer create_cbjoin();
        
            /**
             * Creates an cbleave.
             */
            data_buffer create_cbleave();
        
            /**
             * Creates an cbstatus.
             */
            data_buffer create_cbstatus();
    };
    
} // namespace coin

#endif // COIN_MESSAGE_HPP
