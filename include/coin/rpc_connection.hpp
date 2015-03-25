/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * vanillacoin is free software: you can redistribute it and/or modify
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

#ifndef COIN_RPC_CONNECTION_HPP
#define COIN_RPC_CONNECTION_HPP

#include <cstdint>
#include <map>
#include <string>

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/variant/static_visitor.hpp>

#include <coin/address.hpp>
#include <coin/destination.hpp>
#include <coin/globals.hpp>
#include <coin/key_public.hpp>
#include <coin/rpc_json_parser.hpp>
#include <coin/types.hpp>
#include <coin/utility.hpp>
#include <coin/wallet.hpp>

namespace coin {

    class stack_impl;
    class rpc_transport;
    
    /**
     * Implements an RPC connection.
     */
    class rpc_connection : public std::enable_shared_from_this<rpc_connection>
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param s The boost::asio::strand .
             * @param owner The stack_impl.
             * @param transport The rpc_transport.
             */
            explicit rpc_connection(
                boost::asio::io_service & ios, boost::asio::strand & s,
                stack_impl & owner, std::shared_ptr<rpc_transport> transport
            );
        
            /**
             * Destructor
             */
            ~rpc_connection();
        
            /**
             * Starts direction_incoming.
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
    
            /**
             * If true the transport is valid (usable).
             */
            bool is_transport_valid();
        
        private:
        
            /**
             * A JSON-RPC request.
             */
            typedef struct
            {
                std::string method;
                boost::property_tree::ptree params;
                std::string id;
            } json_rpc_request_t;
        
            /**
             * A JSON-RPC response.
             */
            typedef struct
            {
                boost::property_tree::ptree result;
                boost::property_tree::ptree error;
                std::string id;
            } json_rpc_response_t;
        
            /**
             * The on read handler.
             * @param buf The buffer.
             * @param len The length.
             */
            void on_read(const char * buf, const std::size_t & len);
        
            /**
             * Parses an incoming request.
             * @param buf The buffer.
             * @param len The length.
             * @param headers_out The headers (out).
             * @param body_out The body (out).
             */
            bool parse(
                const char * buf, const std::size_t & len,
                std::map<std::string, std::string> & headers_out,
                std::string & body_out
            );
        
            /**
             * Parses the status line.
             * @param buffer The buffer.
             */
            std::size_t parse_status(std::string & buffer);
        
            /**
             * Parses the header.
             * @param buffer The buffer.
             * @param headers_out the headers.
             */
            std::size_t parse_header(
                const std::string & buffer,
                std::map<std::string, std::string> & headers_out
            );
        
            /**
             * Parses a header line.
             * @param buffer The buffer.
             * @param headers_out The headers (out).
             */
            void parse_header_line(
                std::string & buffer,
                std::map<std::string, std::string> & headers_out
            );
        
            /**
             * Parses a JSON-RPC request.
             * @param request_in The request (in).
             * @Param request_out The request (out).
             */
            bool parse_json_rpc_request(
                const std::string & request_in, json_rpc_request_t & request_out
            );
        
        protected:
        
            /**
             * The error codes.
             */
            typedef enum error_code_s
            {
                error_code_invalid_request  = -32600,
                error_code_method_not_found = -32601,
                error_code_invalid_params = -32602,
                error_code_internal_error = -32603,
                error_code_parse_error = -32700,
                error_code_misc_error = -1,
                error_code_forbidden_by_safe_mode = -2,
                error_code_type_error = -3,
                error_code_invalid_address_or_key = -5,
                error_code_out_of_memory = -7,
                error_code_invalid_parameter = -8,
                error_code_database_error = -20,
                error_code_deserialization_error = -22,
                error_code_client_not_connected = -9,
                error_code_client_in_initial_download = -10,
                error_code_wallet_error = -4,
                error_code_wallet_insufficient_funds = -6,
                error_code_wallet_invalid_account_name = -11,
                error_code_wallet_keypool_ran_out = -12,
                error_code_wallet_unlock_needed = -13,
                error_code_wallet_passphrase_incorrect = -14,
                error_code_wallet_wrong_enc_state = -15,
                error_code_wallet_encryption_failed = -16,
                error_code_wallet_already_unlocked = -17,
                error_code_sign_block_failed = -100,
                error_code_amount_too_small = -101,
            } error_code_t;
        
            /**
             * A static visitor that describes an address.
             */
            class describe_address_visitor
                : public boost::static_visitor<boost::property_tree::ptree>
            {
                public:

                    boost::property_tree::ptree operator()(
                        const destination::none & dest
                        ) const
                    {
                        return boost::property_tree::ptree();
                    }

                    boost::property_tree::ptree operator()(
                        const types::id_key_t & key_id
                        ) const
                    {
                        boost::property_tree::ptree pt;
                        
                        key_public pub_key;
                        
                        globals::instance().wallet_main()->get_pub_key(
                            key_id, pub_key
                        );
                        
                        pt.put("isscript", false);
                        pt.put(
                            "pubkey", utility::hex_string(pub_key.bytes()),
                            rpc_json_parser::translator<std::string> ()
                        );
                        pt.put("iscompressed", pub_key.is_compressed());
                        
                        return pt;
                    }

                    boost::property_tree::ptree operator()(
                        const types::id_script_t & script_id
                        ) const
                    {
                        boost::property_tree::ptree pt;
                        
                        pt.put("isscript", true);
                        
                        script subscript;
                        
                        globals::instance().wallet_main()->get_c_script(
                            script_id, subscript
                        );
                        
                        std::vector<destination::tx_t> addresses;
                        
                        types::tx_out_t which_type;
                        
                        std::int32_t required;
                        
                        script::extract_destinations(
                            subscript, which_type, addresses, required
                        );

                        pt.put(
                            "script", script::get_txn_output_type(which_type),
                            rpc_json_parser::translator<std::string> ()
                        );
                        
                        boost::property_tree::ptree pt_addresses;
                        
                        for (auto & i : addresses)
                        {
                            boost::property_tree::ptree pt_child;
                            
                            pt_child.put(
                                "", address(i).to_string(),
                                rpc_json_parser::translator<std::string> ()
                            );
                            
                            pt_addresses.push_back(std::make_pair("", pt_child));
                        }
                        
                        pt.put_child("addresses", pt_addresses);
                        
                        if (which_type == types::tx_out_multisig)
                        {
                            pt.put("sigsrequired", required);
                        }

                        return pt;
                    }
                
                private:
                
                    // ...
            
                protected:
                
                    // ...
            };
        
            /**
             * Handles a JSON-RPC request.
             * @param request The json_rpc_request_t.
             * @param response The json_rpc_response_t.
             */
            bool handle_json_rpc_request(
                const json_rpc_request_t & request,
                json_rpc_response_t & response
            );
        
            /**
             * Sends a JSON-RPC response.
             * @param response The json_rpc_response_t.
             */
            bool send_json_rpc_response(const json_rpc_response_t & response);
        
            /**
             * Sends an array of JSON-RPC responses.
             * @param responses The std::vector<json_rpc_response_t>.
             */
            bool send_json_rpc_responses(
                const std::vector<json_rpc_response_t> & responses
            );
        
            /**
             * Performs a backupwallet operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_backupwallet(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a checkwallet operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_checkwallet(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes dumpprivkey data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_dumpprivkey(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes encryptwallet data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_encryptwallet(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getaccount data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getaccount(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getaccountaddress data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getaccountaddress(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getbalance data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getbalance(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getdifficulty data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getdifficulty(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getblock data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getblock(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getblockcount data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getblockcount(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getblockhash data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getblockhash(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getblocktemplate data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getblocktemplate(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getinfo data into JSON format.
             */
            boost::property_tree::ptree json_getinfo();
        
            /**
             * Encodes getmininginfo data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getmininginfo(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getnetworkhashps data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getnetworkhashps(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getnewaddress data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getnewaddress(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getpeerinfo data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getpeerinfo(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes getrawtransaction data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_getrawtransaction(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes gettransaction data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_gettransaction(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes importprivkey data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_importprivkey(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes listblocksince data into JSON format.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_listsinceblock(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a listtransactions operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_listtransactions(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a listreceivedbyaddress operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_listreceivedbyaddress(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a listreceivedbyaccount operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_listreceivedbyaccount(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a repairwallet operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_repairwallet(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a sendmany operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_sendmany(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a sendtoaddress operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_sendtoaddress(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a submitblock operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_submitblock(
                const json_rpc_request_t & request
            );
        
            /**
             * Performs a validateaddress operation.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_validateaddress(
                const json_rpc_request_t & request
            );
        
            /**
             * Unlocks the wallet.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_walletpassphrase(
                const json_rpc_request_t & request
            );

            /**
             * Locks the wallet.
             * @param request The json_rpc_request_t.
             */
            json_rpc_response_t json_walletlock(
                const json_rpc_request_t & request
            );
        
            /**
             * Encodes a transaction_wallet into a boost::property_tree::ptree.
             * @param wtx The transaction_wallet.
             */
            boost::property_tree::ptree transaction_wallet_to_ptree(
                const transaction_wallet & wtx
            );

            /**
             * Encodes a transaction into a boost::property_tree::ptree.
             * @param wtx The transaction_wallet.
             * @param hash_block The hash of the block.
             */
            boost::property_tree::ptree transaction_to_ptree(
                const transaction & tx, const sha256 & hash_block
            );
    
            /**
             * Encodes transactions in the given account and at the minimum
             * depth into a boost::property_tree::ptree.
             * @param wtx The transaction_wallet.
             * @param account The account.
             * @param minimim_depth The minimum depth in the main chain.
             * @param include_transactions It true transactions will be
             * included.
             */
            boost::property_tree::ptree transactions_to_ptree(
                const transaction_wallet & wtx, const std::string & account,
                const std::uint32_t & minimim_depth,
                const bool & include_transactions
            );

            /**
             * Encodes a list of received addresses/accounts.
             * @param minimim_depth The minimum depth in the main chain.
             * @param include_empty If true includes empty.
             * @param by_accounts If true list is by accounts.
             */
            boost::property_tree::ptree received_to_ptree(
                const std::int32_t & minimim_depth, const bool & include_empty,
                const bool & by_accounts
            );
        
            /**
             * Creates a JSON-RPC 2.0 error object.
             * @param code The error_code_t.
             * @param message The message.
             */
            boost::property_tree::ptree create_error_object(
                const error_code_t & code, const std::string & message
            );
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand & strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;
        
            /**
             * The rpc_transport.
             */
            std::weak_ptr<rpc_transport> rpc_transport_;
        
            /**
             * The buffer.
             */
            std::string buffer_;
    };
    
} // namespace coin

#endif // COIN_RPC_CONNECTION_HPP
