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

#include <future>
#include <sstream>
#include <vector>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <coin/big_number.hpp>
#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/block_locator.hpp>
#include <coin/db_tx.hpp>
#include <coin/key_reserved.hpp>
#include <coin/logger.hpp>
#include <coin/mining_manager.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/rpc_connection.hpp>
#include <coin/rpc_transport.hpp>
#include <coin/script.hpp>
#include <coin/secret.hpp>
#include <coin/stack_impl.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/tcp_transport.hpp>
#include <coin/transaction_in.hpp>
#include <coin/transaction_index.hpp>
#include <coin/transaction_out.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/utility.hpp>

using namespace coin;

rpc_connection::rpc_connection(
    boost::asio::io_service & ios, boost::asio::strand & s,
    stack_impl & owner, std::shared_ptr<rpc_transport> transport
    )
    : io_service_(ios)
    , strand_(s)
    , stack_impl_(owner)
    , rpc_transport_(transport)
{
    // ...
}

rpc_connection::~rpc_connection()
{
    // ...
}

void rpc_connection::start()
{
    if (auto transport = rpc_transport_.lock())
    {
        auto self(shared_from_this());
        
        /**
         * Set the transport on read handler.
         */
        transport->set_on_read(
            [this, self](std::shared_ptr<rpc_transport> t,
            const char * buf, const std::size_t & len)
        {
            on_read(buf, len);
        });

        /**
         * Start the transport accepting the connection.
         */
        transport->start();
    }
}

void rpc_connection::stop()
{
    if (auto t = rpc_transport_.lock())
    {
        t->stop();
    }
}

bool rpc_connection::is_transport_valid()
{
    if (auto transport = rpc_transport_.lock())
    {
        return true;
    }
    
    return false;
}

void rpc_connection::on_read(const char * buf, const std::size_t & len)
{
    if (buffer_.size() > 0)
    {
        buffer_ += std::string(buf, len);
    }
    else
    {
        buffer_ = std::string(buf, len);
    }
    
    std::map<std::string, std::string> headers_out;
    
    std::string body_out;
    
    if (auto transport = rpc_transport_.lock())
    {
        if (parse(0, 0, headers_out, body_out))
        {
            /**
             * Check if it is an array (6 Batch).
             */
            bool is_array = body_out.size() > 0 && body_out[0] == '[';
            
            if (is_array)
            {
                std::stringstream ss;

                ss << body_out;

                boost::property_tree::ptree pt;
                
                try
                {
                    read_json(ss, pt);
                    
                    /**
                     * The responses.
                     */
                    std::vector<json_rpc_response_t> responses;
                    
                    for (auto & i : pt)
                    {
                        /**
                         * Allocate the request.
                         */
                        json_rpc_request_t request;
                        
                        for (auto & j : i.second)
                        {
                            if (j.first == "method")
                            {
                                request.method = j.second.get<std::string> ("");
                            }
                            else if (j.first == "params")
                            {
                                request.params = j.second;
                            }
                            else if (j.first == "id")
                            {
                                request.id = j.second.get<std::string> ("");
                            }
                        }
                        
                        /**
                         * Allocate the response.
                         */
                        json_rpc_response_t response;
                        
                        if (handle_json_rpc_request(request, response))
                        {
                            responses.push_back(response);
                        }
                        else
                        {
                            log_error(
                                "RPC connection failed to handle "
                                "JSON-RPC message, request = " <<
                                request.id << "."
                            );
                        }
                    }
                    
                    /**
                     * Send the JSON-RPC responses.
                     */
                    send_json_rpc_responses(responses);
                }
                catch (std::exception & e)
                {
                    log_error(
                        "RPC connection failed to parse JSON-RPC body, "
                        "what = " << e.what() << "."
                    );
                }
            }
            else
            {
                /**
                 * Allocate the request.
                 */
                json_rpc_request_t request;

                if (parse_json_rpc_request(body_out, request))
                {
                    /**
                     * Allocate the response.
                     */
                    json_rpc_response_t response;
                    
                    if (handle_json_rpc_request(request, response))
                    {
                        /**
                         * Send the JSON-RPC response.
                         */
                        send_json_rpc_response(response);
                    }
                    else
                    {
                        log_error(
                            "RPC connection failed to handle JSON-RPC message, "
                            "request = " << body_out << "."
                        );
                    }
                }
                else
                {
                    log_error(
                        "RPC connection failed to parse JSON-RPC message, "
                        "request = " << body_out << "."
                    );
                    
                    /**
                     * Stop
                     */
                    stop();
                }
            }
        }
        else
        {
            /**
             * Keep parsing the stream.
             */
        }
    }
}

bool rpc_connection::parse(
    const char * buf, const std::size_t & len,
    std::map<std::string, std::string> & headers_out, std::string & body_out
    )
{
    auto status_length = parse_status(buffer_);

    if (status_length > 0)
    {
        auto buffer = buffer_.substr(status_length, buffer_.size());
        
        /**
         * Parse the header.
         */
        auto header_length = parse_header(buffer, headers_out);
        
        auto it = headers_out.find("content-length");
        
        if (it != headers_out.end())
        {
            auto content_length = std::stoi(it->second);
        
            if (
                buffer_.size() -
                (status_length + header_length) != content_length
                )
            {
                return false;
            }
            else
            {
                body_out = std::string(
                    buffer_.data() + status_length + header_length,
                    content_length
                );
                    
                log_debug("RPC connection got http body = " << body_out);
            }
        }
    }
    else
    {
        /**
         * Stop
         */
        stop();
    }
    
    buffer_.clear();

    return true;
}

std::size_t rpc_connection::parse_status(std::string & buffer)
{
    std::istringstream stream(buffer);
    
    std::string status;
    
    std::getline(stream, status);

    std::vector<std::string> parts;
    
    boost::split(parts, status, boost::is_any_of(" "));
    
    if (parts.size() < 2)
    {
        log_error("RPC connection got bad status line = " << status << ".");
    
        return false;
    }
    
    log_none("RPC connection got status line = " << status << ".");
    
    return status.size();
}

std::size_t rpc_connection::parse_header(
    const std::string & buffer,
    std::map<std::string, std::string> & headers_out
    )
{
    std::size_t ret = 0;
    
    ret = buffer.find("\n");
    
    if (ret != std::string::npos)
    {
        std::istringstream stream(buffer.substr(ret));
        
        std::string line;
        
        /**
         * Read the \n.
         */
        std::getline(stream, line);

        while (std::getline(stream, line) && line != "\r")
        {
            try
            {
                parse_header_line(line, headers_out);
            }
            catch (std::exception & e)
            {
                log_error(
                    "RPC connection failed to parse header, what = " <<
                    e.what() << "."
                );
            }
        }
        
        ret = buffer.find("\r\n\r\n");
        
        if (ret != std::string::npos)
        {
            ret += 4;
        }
    }
    
    return ret;
}

void rpc_connection::parse_header_line(
    std::string & buffer, std::map<std::string, std::string> & headers_out
    )
{
    std::string t;
    
    std::string::size_type i;

    while ((i = buffer.find("\r")) != std::string::npos)
    {
        t = buffer.substr(0, i);
        
        buffer.erase(0, i + 1);
        
        if (t == "")
        {
            break;
        }
        
        i = t.find(": ");
        
        if (i == std::string::npos)
        {
            throw std::runtime_error(
                "RPC connection message got bad header line " + t + "."
            );
        }
        else
        {
            /**
             * Find the key.
             */
            std::string key = t.substr(0, i);
            
            /**
             * Find the value.
             */
            std::string value = t.substr(i + 2);

            /**
             * Trim whitespace.
             */
            boost::algorithm::trim(key);
            
            /**
             * Normalize
             */
            boost::to_lower(key);
            
            /**
             * Trim whitespace.
             */
            boost::algorithm::trim(value);
            
            /**
             * Normalize
             */
            boost::to_lower(value);
                
            /**
             * Insert the header field.
             */
            headers_out.insert(std::make_pair(key, value));
        }
    }
}

bool rpc_connection::parse_json_rpc_request(
    const std::string & request_in, json_rpc_request_t & request_out
    )
{
    /**
     * Example: {"id":"2","method":"login","params":["first","second"]}
     */
    if (request_in.size() > 0)
    {
        std::stringstream ss;

        ss << request_in;

        boost::property_tree::ptree pt;
        
        std::map<std::string, std::string> result;
        
        try
        {
            read_json(ss, pt);

            auto & method = pt.get_child("method");
            
            request_out.method = method.get<std::string> ("");
            
            auto & params = pt.get_child("params");
            
            request_out.params = params;
            
            auto & id = pt.get_child("id");
            
            request_out.id = id.get<std::string> ("");
        }
        catch (std::exception & e)
        {
            log_error(
                "RPC connection failed to parse JSON-RPC request, what = " <<
                e.what() << "."
            );
        }
    }
    else
    {
        return false;
    }

    return true;
}

bool rpc_connection::handle_json_rpc_request(
    const json_rpc_request_t & request, json_rpc_response_t & response
    )
{
    log_debug(
        "RPC connection got JSON-RPC request, id = " << request.id <<
        ", method = " << request.method
    );

    if (request.method == "checkwallet")
    {
        response = json_checkwallet(request);
    }
    else if (request.method == "dumpprivkey")
    {
        response = json_dumpprivkey(request);
    }
    else if (request.method == "encryptwallet")
    {
        response = json_encryptwallet(request);
    }
    else if (request.method == "getaccount")
    {
        response = json_getaccount(request);
    }
    else if (request.method == "getaccountaddress")
    {
        response = json_getaccountaddress(request);
    }
    else if (request.method == "backupwallet")
    {
        response = json_backupwallet(request);
    }
    else if (request.method == "getbalance")
    {
        response = json_getbalance(request);
    }
    else if (request.method == "getblock")
    {
        response = json_getblock(request);
    }
    else if (request.method == "getblockcount")
    {
        response = json_getblockcount(request);
    }
    else if (request.method == "getblockhash")
    {
        response = json_getblockhash(request);
    }
    else if (request.method == "getblocktemplate")
    {
        response = json_getblocktemplate(request);
    }
    else if (request.method == "getdifficulty")
    {
        response = json_getdifficulty(request);
    }
    else if (request.method == "getinfo")
    {
        response.result = json_getinfo();
    }
    else if (request.method == "listsinceblock")
    {
        response = json_listsinceblock(request);
    }
    else if (request.method == "getmininginfo")
    {
        response = json_getmininginfo(request);
    }
    else if (request.method == "getnetworkhashps")
    {
        response = json_getnetworkhashps(request);
    }
    else if (request.method == "getnewaddress")
    {
        response = json_getnewaddress(request);
    }
    else if (request.method == "getpeerinfo")
    {
        response = json_getpeerinfo(request);
    }
    else if (request.method == "getrawtransaction")
    {
        response = json_getrawtransaction(request);
    }
    else if (request.method == "gettransaction")
    {
        response = json_gettransaction(request);
    }
    else if (request.method == "importprivkey")
    {
        response = json_importprivkey(request);
    }
    else if (request.method == "listtransactions")
    {
        response = json_listtransactions(request);
    }
    else if (request.method == "listreceivedbyaddress")
    {
        response = json_listreceivedbyaddress(request);
    }
    else if (request.method == "listreceivedbyaccount")
    {
        response = json_listreceivedbyaccount(request);
    }
    else if (request.method == "repairwallet")
    {
        response = json_repairwallet(request);
    }
    else if (request.method == "submitblock")
    {
        response = json_submitblock(request);
    }
    else if (request.method == "sendmany")
    {
        response = json_sendmany(request);
    }
    else if (request.method == "sendtoaddress")
    {
        response = json_sendtoaddress(request);
    }
    else if (request.method == "walletpassphrase")
    {
        response = json_walletpassphrase(request);
    }
    else if (request.method == "walletlock")
    {
        response = json_walletlock(request);
    }
    else if (request.method == "validateaddress")
    {
        response = json_validateaddress(request);
    }
    else
    {
        response.error = create_error_object(
            error_code_method_not_found, "method not found"
        );
    }
    
    /**
     * Set the id from the request.
     */
    response.id = request.id;
    
    return true;
}

bool rpc_connection::send_json_rpc_response(
    const json_rpc_response_t & response
    )
{
    if (auto transport = rpc_transport_.lock())
    {
        /**
         * Allocate the response.
         */
        std::string http_response;
        
        /**
         * Formulate the response.
         */
        http_response += "HTTP/1.1 200 OK\r\n";
        http_response +=
            "Date: " + network::instance().rfc1123_time() + "\r\n"
        ;
        http_response += "Connection: close\r\n";
        http_response += "Content-Type: application/json\r\n";
        
        /**
         * Allocate the body.
         */
        std::string body;

        try
        {
            boost::property_tree::ptree pt;

            if (response.error.size() > 0)
            {
                /**
                 * Put error into property tree.
                 */
                pt.put_child("error", response.error);
            }
            else
            {
                /**
                 * Put the result into property tree.
                 */
                pt.put_child("result", response.result);
            }

            /**
             * Put id into property tree.
             */
            pt.put(
                "id", response.id, rpc_json_parser::translator<std::string> ()
            );
            
            /**
             * The std::stringstream.
             */
            std::stringstream ss;
            
            /**
             * Write property tree to json file.
             */
            rpc_json_parser::write_json(ss, pt, false);
            
            /**
             * Set the body.
             */
            body = ss.str();
        }
        catch (std::exception & e)
        {
            log_error(
                "RPC Connection failed to create response, what = " <<
                e.what() << "."
            );
            
            return false;
        }
        
        http_response += "Content-Length: " +
            std::to_string(body.size()) + "\r\n"
        ;
        http_response += "Server: VanillaCoin JSON-RPC 2.0\r\n";
        http_response += "\r\n";
        
        http_response += body;

        /**
         * Write the response.
         */
        if (transport)
        {
            /**
             * Set that the transport should close after it writes all of it's
             * queued buffers.
             */
            transport->set_close_after_writes(true);
            
            /**
             * Write the response.
             */
            transport->write(http_response.data(), http_response.size());
        }
        
        return true;
    }

    return false;
}

bool rpc_connection::send_json_rpc_responses(
    const std::vector<json_rpc_response_t> & responses
    )
{
    if (auto transport = rpc_transport_.lock())
    {
        /**
         * Allocate the response.
         */
        std::string http_response;
        
        /**
         * Formulate the response.
         */
        http_response += "HTTP/1.1 200 OK\r\n";
        http_response +=
            "Date: " + network::instance().rfc1123_time() + "\r\n"
        ;
        http_response += "Connection: close\r\n";
        http_response += "Content-Type: application/json\r\n";
        
        /**
         * Allocate the body.
         */
        std::string body;
        
        try
        {
            boost::property_tree::ptree pt;
            
            for (auto & i : responses)
            {
                boost::property_tree::ptree pt_child;
                
                if (i.id.size() == 0)
                {
                    continue;
                }
                
                if (i.error.size() > 0)
                {
                    /**
                     * Put error into property tree.
                     */
                    pt_child.put_child("error", i.error);
                }
                else
                {
                    /**
                     * Put the result into property tree.
                     */
                    pt_child.put_child("result", i.result);
                }

                /**
                 * Put id into property tree.
                 */
                pt_child.put(
                    "id", i.id, rpc_json_parser::translator<std::string> ()
                );

                
                pt.push_back(std::make_pair("", pt_child));
            }
            
            /**
             * The std::stringstream.
             */
            std::stringstream ss;
            
            /**
             * Write property tree to json file.
             */
            rpc_json_parser::write_json(ss, pt, false);
            
            /**
             * Set the body.
             */
            body = ss.str();
        }
        catch (std::exception & e)
        {
            log_error(
                "RPC Connection failed to create response, what = " <<
                e.what() << "."
            );
            
            return false;
        }
        
        http_response += "Content-Length: " +
            std::to_string(body.size()) + "\r\n"
        ;
        http_response += "Server: VanillaCoin JSON-RPC 2.0\r\n";
        http_response += "\r\n";
        
        http_response += body;
        
        /**
         * Write the response.
         */
        if (transport)
        {
            transport->write(http_response.data(), http_response.size());
        }
        
        return true;
    }

    return false;
}

rpc_connection::json_rpc_response_t rpc_connection::json_backupwallet(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        if (request.params.size() == 1)
        {
            auto path = request.params.front().second.get<std::string> ("");
            
            if (
                db_wallet::backup(*globals::instance().wallet_main(),
                path) == true
                )
            {
                ret.result.put("", "null");
            }
            else
            {
                auto pt_error = create_error_object(
                    error_code_wallet_error, "backup failed"
                );
                
                /**
                 * error_code_wallet_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            if (db_wallet::backup(*globals::instance().wallet_main()) == true)
            {
                ret.result.put("", "null");
            }
            else
            {
                auto pt_error = create_error_object(
                    error_code_wallet_error, "backup failed"
                );
                
                /**
                 * error_code_wallet_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_backupwallet, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_checkwallet(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        /**
         * The mismatch spent coins.
         */
        std::int32_t mismatch_spent = 0;
        
        /**
         * The balance in question.
         */
        std::int64_t balance_in_question = 0;
        
        bool check_only = true;
        
        /**
         * If there coins marked spent that should not be then check and
         * repair them.
         */
        globals::instance().wallet_main()->fix_spent_coins(
            mismatch_spent, balance_in_question, check_only
        );
        
        if (mismatch_spent == 0)
        {
            ret.result.put("wallet check passed", true);
        }
        else
        {
            ret.result.put("mismatched spent coins", mismatch_spent);
            ret.result.put(
                "amount affected by repair",
                balance_in_question / constants::coin
            );
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_checkwallet, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_encryptwallet(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 1)
        {
            if (globals::instance().wallet_main()->is_crypted())
            {
                auto pt_error = create_error_object(
                    error_code_wallet_wrong_enc_state, "crypted"
                );
                
                /**
                 * error_code_wallet_wrong_enc_state
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            /**
             * Get the passphrase parameter.
             */
            auto param_passphrase =
                request.params.front().second.get<std::string> ("")
            ;
            
            if (globals::instance().wallet_main()->encrypt(param_passphrase))
            {
                ret.result.put(
                    "", "wallet encrypted, restart process",
                    rpc_json_parser::translator<std::string> ()
                );
            }
            else
            {
                auto pt_error = create_error_object(
                    error_code_wallet_encryption_failed,
                    "encryption failed"
                );
                
                /**
                 * error_code_wallet_encryption_failed
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            // ...
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_misc_error, e.what()
        );
        
        /**
         * error_code_misc_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_dumpprivkey(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 1)
        {
            /**
             * Get the address parameter.
             */
            auto param_address =
                request.params.front().second.get<std::string> ("")
            ;

            address addr;
            
            if (addr.set_string(param_address) == false)
            {
                auto pt_error = create_error_object(
                    error_code_invalid_address_or_key, "invalid address"
                );
                
                /**
                 * error_code_invalid_address_or_key
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            if (globals::instance().wallet_unlocked_mint_only())
            {
                auto pt_error = create_error_object(
                    error_code_wallet_unlock_needed,
                    "wallet is unlocked for minting only"
                );
                
                /**
                 * error_code_wallet_unlock_needed
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            types::id_key_t key_id;
            
            if (addr.get_id_key(key_id) == false)
            {
                auto pt_error = create_error_object(
                    error_code_type_error, "failed to get key id"
                );
                
                /**
                 * error_code_type_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            key::secret_t s;
            
            bool compressed = false;
            
            if (
                globals::instance().wallet_main()->get_secret(
                key_id, s, compressed) == false
                )
            {
                auto pt_error = create_error_object(
                    error_code_wallet_error, "failed to get secret"
                );
                
                /**
                 * error_code_wallet_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            ret.result.put(
                "", secret(s, compressed).to_string(),
                rpc_json_parser::translator<std::string> ()
            );
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getaccount(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 1)
        {
            try
            {
                /**
                 * Get the account parameter.
                 */
                auto account =
                    request.params.front().second.get<std::string> ("")
                ;
                
                address addr(account);
                
                if (addr.is_valid() == false)
                {
                    auto pt_error = create_error_object(
                        error_code_invalid_address_or_key, "invalid address"
                    );
                    
                    /**
                     * error_code_invalid_address_or_key
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
                else
                {
                    auto address_book =
                        globals::instance().wallet_main()->address_book()
                    ;
                    
                    auto it = address_book.find(addr.get());
                    
                    if (it != address_book.end())
                    {
                        ret.result.put(
                            "", it->second,
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                }
            }
            catch (std::exception & e)
            {
                auto pt_error = create_error_object(
                    error_code_internal_error, e.what()
                );
                
                /**
                 * error_code_internal_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getaccountaddress(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 1)
        {
            auto acct = request.params.front().second.get<std::string> ("");
            
            if (acct == "*")
            {
                auto pt_error = create_error_object(
                    error_code_wallet_invalid_account_name,
                    "invalid account name"
                );
                
                /**
                 * error_code_wallet_invalid_account_name
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            else
            {
                address addr_out;
                
                auto result = wallet::get_account_address(
                    *globals::instance().wallet_main(), acct, addr_out
                );
                
                if (result.first)
                {
                    ret.result.put(
                        "", addr_out.to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_keypool_ran_out, result.second
                    );
                    
                    /**
                     * error_code_wallet_keypool_ran_out
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getbalance(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 0)
        {
            ret.result.put(
                "", static_cast<double> (
                globals::instance().wallet_main()->get_balance()) /
                constants::coin
            );
            
            return ret;
        }
        else if (request.params.size() > 0)
        {
            std::string account;
            
            auto minimum_depth_in_main_chain = 1;
        
            auto index = 0;
            
            for (auto & i : request.params)
            {
                if (index == 0)
                {
                    account = i.second.get<std::string> ("");
                }
                else if (index == 1)
                {
                    minimum_depth_in_main_chain =
                        i.second.get<std::int32_t> ("")
                    ;
                }
            
                index++;
            }

            if (account == "*")
            {
                std::int64_t balance = 0;
                
                auto transactions =
                    globals::instance().wallet_main()->transactions()
                ;
                
                for (auto & i : transactions)
                {
                    const auto & wtx = i.second;
                    
                    if (wtx.is_final() == false)
                    {
                        continue;
                    }
                    
                    std::int64_t
                        all_generated_immature, all_generated_mature, all_fee
                    ;
                    
                    all_generated_immature = all_generated_mature = all_fee = 0;

                    std::string send_account;
                    
                    std::list< std::pair<destination::tx_t, std::int64_t> > r;
                    std::list< std::pair<destination::tx_t, std::int64_t> > s;
                    
                    wtx.get_amounts(
                        all_generated_immature, all_generated_mature, r, s,
                        all_fee, send_account
                    );
                    
                    if (
                        wtx.get_depth_in_main_chain() >=
                        minimum_depth_in_main_chain
                        )
                    {
                        for (auto & j : r)
                        {
                            balance += j.second;
                        }
                    }
                    
                    for (auto & j : s)
                    {
                        balance -= j.second;
                    }
                    
                    balance -= all_fee;
                    balance += all_generated_mature;
                }
                
                ret.result.put(
                    "", static_cast<double> (balance) / constants::coin
                );
                
                return ret;
            }
            else
            {
                auto balance = wallet::get_account_balance(
                    account, minimum_depth_in_main_chain
                );

                ret.result.put(
                    "", static_cast<double> (balance) / constants::coin
                );
                
                return ret;
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getdifficulty(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 0)
        {
            /**
             * Put proof-of-work into property tree.
             */
            ret.result.put("proof-of-work", stack_impl_.difficulty());
            
            /**
             * Put proof-of-stake into property tree.
             */
            ret.result.put(
                "proof-of-stake",
                stack_impl_.difficulty(utility::get_last_block_index(
                stack_impl::get_block_index_best(), true))
            );
            
            /**
             * Put search-interval into property tree.
             */
            ret.result.put(
                "search-interval",
                globals::instance().last_coin_stake_search_interval()
            );
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getblock(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;

    try
    {
        if (request.params.size() >= 1 && request.params.size() <= 2)
        {
            sha256 hash_block(
                request.params.front().second.get<std::string> ("")
            );
            
            if (globals::instance().block_indexes().count(hash_block) == 0)
            {
                auto pt_error = create_error_object(
                    error_code_invalid_address_or_key, "block not found"
                );
                
                /**
                 * error_code_invalid_address_or_key
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            else
            {
                block blk;
                
                auto index = globals::instance().block_indexes()[hash_block];
                
                blk.read_from_disk(index, true);
                
                ret.result.put(
                    "hash", blk.get_hash().to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                
                transaction_merkle tx(blk.transactions()[0]);
                
                tx.set_merkle_branch(&blk);
                
                ret.result.put("confirmations", tx.get_depth_in_main_chain());
                ret.result.put("size", blk.size());
                ret.result.put("height", index->height());
                ret.result.put("version", blk.header().version);
                ret.result.put(
                    "merkleroot", blk.header().hash_merkle_root.to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                ret.result.put("mint", index->mint() / constants::coin);
                ret.result.put("time", blk.header().timestamp);
                ret.result.put("nonce", blk.header().nonce);
                ret.result.put(
                    "bits", utility::hex_string_from_bits(blk.header().bits),
                    rpc_json_parser::translator<std::string> ()
                );
                ret.result.put("difficulty", stack_impl_.difficulty(index));
                
                if (index->block_index_previous())
                {
                    ret.result.put(
                        "previousblockhash",
                        index->block_index_previous(
                        )->get_block_hash().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
                
                if (index->block_index_next())
                {
                    ret.result.put(
                        "nextblockhash",
                        index->block_index_next()->get_block_hash().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
                
                ret.result.put(
                    "flags",
                    std::string(index->is_proof_of_stake()? "proof-of-stake" :
                    "proof-of-work") +
                    std::string(index->generated_stake_modifier() ?
                    " stake-modifier": ""),
                    rpc_json_parser::translator<std::string> ()
                );
                
                ret.result.put(
                    "proofhash",
                    (index->is_proof_of_stake() ?
                    index->hash_proof_of_stake().to_string() :
                    index->get_block_hash().to_string()),
                    rpc_json_parser::translator<std::string> ()
                );
                
                ret.result.put(
                    "entropybit", index->get_stake_entropy_bit()
                );

                /**
                 * :TODO: %016
                 */
                ret.result.put(
                    "modifier", index->stake_modifier()
                );
                
                /**
                 * :TODO: %08x
                 */
                ret.result.put(
                    "modifierchecksum", index->stake_modifier_checksum()
                );

                boost::property_tree::ptree pt_txinfo;
                
                boost::property_tree::ptree pt_txinfo_children;
                
                for (auto & i : blk.transactions())
                {
                    pt_txinfo.put(
                        "", i.get_hash().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    
                    pt_txinfo_children.push_back(
                        std::make_pair("", pt_txinfo)
                    );
                }

                ret.result.put_child("tx", pt_txinfo_children);
                
                /**
                 * Get the block signature.
                 */
                const auto & signature = blk.signature();

                ret.result.put(
                    "signature",
                    utility::hex_string(signature.begin(), signature.end()),
                    rpc_json_parser::translator<std::string> ()
                );
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getblockcount(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 0)
        {
            ret.result.put("", globals::instance().best_block_height());
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getblockhash(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;

    try
    {
        if (request.params.size() == 1)
        {
            auto height = std::stoi(
                request.params.front().second.get<std::string> ("")
            );
            
            if (height <= -1 || height > globals::instance().best_block_height())
            {
                auto pt_error = create_error_object(
                    error_code_invalid_params, "invalid height"
                );
                
                /**
                 * error_code_invalid_params
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            else
            {
                auto index = utility::find_block_index_by_height(height);
                
                if (index)
                {
                    ret.result.put(
                        "", index->get_block_hash().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getblocktemplate(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
 
    /**
     * BIP-0022: https://en.bitcoin.it/wiki/BIP_0022
     */
    try
    {
        std::string mode = "template";

        if (request.params.size() > 0)
        {
            auto it = request.params.find("mode");
            
            if (it != request.params.not_found())
            {
                if (it->second.get<std::string> ("").size() > 0)
                {
                    mode = it->second.get<std::string> ("");
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_invalid_parameter, "invalid parameter"
                    );
                    
                    /**
                     * error_code_invalid_parameter
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
        }

        if (mode != "template")
        {
            auto pt_error = create_error_object(
                error_code_invalid_parameter, "invalid parameter"
            );
            
            /**
             * error_code_invalid_parameter
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }

        if (
            stack_impl_.get_tcp_connection_manager(
            )->tcp_connections().size() == 0
            )
        {
            auto pt_error = create_error_object(
                error_code_client_not_connected, "client not connected"
            );
            
            /**
             * error_code_client_not_connected
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }

        if (utility::is_initial_block_download())
        {
            auto pt_error = create_error_object(
                error_code_client_in_initial_download, "in initial download"
            );
            
            /**
             * error_code_client_in_initial_download
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }

        /**
         * Update the block.
         */
        static std::uint32_t transactions_updated_last;
        static std::shared_ptr<block_index> index_previous;
        static std::time_t start;
        static std::shared_ptr<block> blk;
        
        static key_reserved reserved_key(*globals::instance().wallet_main());

        if (
            index_previous != stack_impl::get_block_index_best() ||
            (globals::instance().transactions_updated() !=
            transactions_updated_last && std::time(0) - start > 5)
            )
        {
            index_previous = 0;

            transactions_updated_last =
                globals::instance().transactions_updated()
            ;
            
            auto index_previous_new = stack_impl::get_block_index_best();
            
            start = std::time(0);

            /**
             * Create a new block.
             */
            if (blk)
            {
                blk.reset();
            }
            
            blk = block::create_new(
                globals::instance().wallet_main(), false
            );
            
            if (blk == 0)
            {
                auto pt_error = create_error_object(
                    error_code_out_of_memory, "out of memory"
                );
                
                /**
                 * error_code_out_of_memory
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            /**
             * Update
             */
            index_previous = index_previous_new;
        }
        
        /**
         * Update the time.
         */
        blk->update_time(*index_previous);
        blk->header().nonce = 0;

        boost::property_tree::ptree transactions;
        
        std::map<sha256, std::int64_t> transaction_indexes;
        
        auto index = 0;
        
        db_tx tx_db("r");

        for (auto & tx : blk->transactions())
        {
            auto hash_tx = tx.get_hash();
            
            transaction_indexes[hash_tx] = index++;

            if (tx.is_coin_base())
            {
                continue;
            }
            
            if (tx.is_coin_stake())
            {
                continue;
            }

            boost::property_tree::ptree entry;

            data_buffer buffer;
            
            tx.encode(buffer);
            
            entry.put(
                "data", utility::hex_string(buffer.data(),
                buffer.data() + buffer.size()),
                rpc_json_parser::translator<std::string> ()
            );

            entry.put(
                "hash", hash_tx.to_string(),
                rpc_json_parser::translator<std::string> ()
            );

            std::map<
                sha256, std::pair<transaction_index, transaction>
            > inputs;
            
            std::map<sha256, transaction_index> unused;
            
            bool invalid = false;

            if (
                tx.fetch_inputs(tx_db, unused, false, false, inputs, invalid)
                )
            {
                entry.put(
                    "fee",
                    static_cast<std::int64_t> (tx.get_value_in(inputs) -
                    tx.get_value_out())
                );

                boost::property_tree::ptree pt_deps;
                
                for (auto & i : inputs)
                {
                    if (transaction_indexes.count(i.first) > 0)
                    {
                        auto index = transaction_indexes[i.first];
                        
                        boost::property_tree::ptree pt_child;
                        
                        pt_child.put("", index);
                        
                        pt_deps.push_back(std::make_pair("", pt_child));
                    }
                }
                
                if (pt_deps.size() > 0)
                {
                    entry.put_child("depends", pt_deps);
                }
                else
                {
                    boost::property_tree::ptree pt_empty;
                    
                    pt_empty.push_back(
                        std::make_pair("", boost::property_tree::ptree())
                    );
                    
                    entry.put_child("depends", pt_empty);
                }
                
                std::int64_t sigops = tx.get_legacy_sig_op_count();
                
                sigops += tx.get_p2sh_sig_op_count(inputs);
                
                entry.put("sigops", sigops);
            }
            
            transactions.push_back(std::make_pair("", entry));
        }

        boost::property_tree::ptree aux;
        
        aux.put(
            "flags",
            utility::hex_string(
            globals::instance().coinbase_flags().begin(),
            globals::instance().coinbase_flags().end()),
            rpc_json_parser::translator<std::string> ()
        );

        auto hashTarget = big_number().set_compact(
            blk->header().bits
        ).get_sha256();
        
        boost::property_tree::ptree pt_mutable;
        boost::property_tree::ptree pt_child1, pt_child2, pt_child3;

        pt_child1.put(
            "", "time", rpc_json_parser::translator<std::string> ()
        );
        pt_child2.put(
            "", "transactions", rpc_json_parser::translator<std::string> ()
        );
        pt_child3.put(
            "", "prevblock", rpc_json_parser::translator<std::string> ()
        );

        pt_mutable.push_back(std::make_pair("", pt_child1));
        pt_mutable.push_back(std::make_pair("", pt_child2));
        pt_mutable.push_back(std::make_pair("", pt_child3));
        
        /**
         * Put version into property tree.
         */
        ret.result.put("version", blk->header().version);
        
        /**
         * Put previousblockhash into property tree.
         */
        ret.result.put(
            "previousblockhash",
            blk->header().hash_previous_block.to_string(),
            rpc_json_parser::translator<std::string> ()
        );

        if (transactions.size() == 0)
        {
            boost::property_tree::ptree pt_empty;
            
            pt_empty.push_back(
                std::make_pair("", boost::property_tree::ptree())
            );
            
            /**
             * Put transactions into property tree.
             */
            ret.result.put_child("transactions", pt_empty);
        }
        else
        {
            /**
             * Put transactions into property tree.
             */
            ret.result.put_child("transactions", transactions);
        }
        
        /**
         * Put coinbaseaux into property tree.
         */
        ret.result.put_child("coinbaseaux", aux);
        
        /**
         * Put coinbasevalue into property tree.
         */
        ret.result.put(
            "coinbasevalue",
            blk->transactions()[0].transactions_out()[0].value()
        );
        
        /**
         * Put target into property tree.
         */
        ret.result.put(
            "target", hashTarget.to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        
        /**
         * Put mintime into property tree.
         */
        ret.result.put("mintime", index_previous->get_median_time_past() + 1);
        
        /**
         * Put mutable into property tree.
         */
        ret.result.put_child("mutable", pt_mutable);
        
        /**
         * Put noncerange into property tree.
         */
        ret.result.put(
            "noncerange", "00000000ffffffff",
            rpc_json_parser::translator<std::string> ()
        );
        
        /**
         * Put sigoplimit into property tree.
         */
        ret.result.put("sigoplimit", constants::max_block_sig_ops);
        
        /**
         * Put sizelimit into property tree.
         */
        ret.result.put("sizelimit", constants::max_block_size);
        
        /**
         * Put curtime into property tree.
         */
        ret.result.put("curtime", blk->header().timestamp);
        
        /**
         * Put bits into property tree.
         */
        ret.result.put(
            "bits", utility::hex_string_from_bits(blk->header().bits),
            rpc_json_parser::translator<std::string> ()
        );
        
        /**
         * Put height into property tree.
         */
        ret.result.put("height", index_previous->height() + 1);
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

boost::property_tree::ptree rpc_connection::json_getinfo()
{
    boost::property_tree::ptree ret;

    try
    {
        ret.put(
            "version",
            constants::client_name + ":" + constants::version_string,
            rpc_json_parser::translator<std::string> ()
        );
        ret.put("protocolversion", protocol::version);
        ret.put(
            "walletversion", globals::instance().wallet_main()->get_version()
        );
        ret.put(
            "balance", static_cast<double> (
            globals::instance().wallet_main()->get_balance()) / constants::coin
        );
        ret.put(
            "newmint",
            static_cast<double> (
            globals::instance().wallet_main()->get_new_mint()) /
            constants::coin
        );
        ret.put(
            "stake",
            static_cast<double> (
            globals::instance().wallet_main()->get_stake()) /
            constants::coin
        );
        ret.put("blocks", globals::instance().best_block_height());
        ret.put(
            "moneysupply",
            static_cast<double> (
            globals::instance().money_supply()) / constants::coin
        );
        ret.put(
            "connections",
            stack_impl_.get_tcp_connection_manager()->tcp_connections().size()
        );
        ret.put(
            "ip", globals::instance().address_public().to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        ret.put("difficulty", stack_impl_.difficulty());
        ret.put(
            "keypoolsize", transaction_pool::instance().size()
        );
        ret.put(
            "paytxfee",
            static_cast<double> (constants::min_tx_fee) / constants::coin
        );
        
        /**
         * The std::stringstream.
         */
        std::stringstream ss;
        
        /**
         * Write property tree to json file.
         */
        rpc_json_parser::write_json(ss, ret, false);
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_getinfo, what = " <<
            e.what() << "."
        );
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getmininginfo(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        if (request.params.size() == 0)
        {
            ret.result.put("blocks", globals::instance().best_block_height());
            ret.result.put(
                "currentblocksize", globals::instance().last_block_size()
            );
            ret.result.put(
                "currentblocktx", globals::instance().last_block_transactions()
            );
            ret.result.put("difficulty", stack_impl_.difficulty());
            ret.result.put(
                "errors", "", rpc_json_parser::translator<std::string> ()
            );
            ret.result.put("generate", false);
            ret.result.put("genproclimit", 0);
            ret.result.put(
                "hashespersec",
                stack_impl_.get_mining_manager()->hashes_per_second()
            );
            ret.result.put(
                "networkhashps", stack_impl_.network_hash_per_second()
            );
            ret.result.put("pooledtx", transaction_pool().instance().size());
            ret.result.put("testnet", constants::test_net);
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getnetworkhashps(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        ret.result.put("", stack_impl_.network_hash_per_second());
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getnewaddress(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        std::string acct;
        
        if (request.params.size() == 1)
        {
            acct = request.params.front().second.get<std::string> ("");
            
            if (acct == "*")
            {
                auto pt_error = create_error_object(
                    error_code_wallet_invalid_account_name,
                    "invalid account name"
                );
                
                /**
                 * error_code_wallet_invalid_account_name
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        
        /**
         * Allocate the public key.
         */
        key_public pub_key;
        
        if (
            globals::instance().wallet_main()->get_key_from_pool(
            pub_key, false) == false
            )
        {
            auto pt_error = create_error_object(
                error_code_wallet_keypool_ran_out, "keypool ran out"
            );
            
            /**
             * error_code_wallet_keypool_ran_out
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
        else
        {
            const auto & key_id = pub_key.get_id();
            
            globals::instance().wallet_main()->set_address_book_name(
                key_id, acct
            );
            
            ret.result.put(
                "", address(key_id).to_string(),
                rpc_json_parser::translator<std::string> ()
            );
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getpeerinfo(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    /**
     * Set the id from the request.
     */
    ret.id = request.id;
    
    try
    {
        auto tcp_connections =
            stack_impl_.get_tcp_connection_manager()->tcp_connections()
        ;
        
        for (auto & i : tcp_connections)
        {
            if (auto j = i.second.lock())
            {
                if (auto k = j->get_tcp_transport().lock())
                {
                    try
                    {
                        boost::property_tree::ptree pt_child;
                        
                        pt_child.put(
                            "addr", k->socket().remote_endpoint().address(
                            ).to_string() + ":" + std::to_string(
                            j->protocol_version_addr_src().port),
                            rpc_json_parser::translator<std::string> ()
                        );
                        pt_child.put(
                            "services", j->protocol_version_services()
                        );
                        pt_child.put("lastsend", k->time_last_write());
                        pt_child.put("lastrecv", k->time_last_read());
                        pt_child.put(
                            "conntime", j->protocol_version_timestamp()
                        );
                        pt_child.put("version", j->protocol_version());
                        pt_child.put(
                            "subver", j->protocol_version_user_agent(),
                            rpc_json_parser::translator<std::string> ()
                        );
                        pt_child.put(
                            "inbound",
                            j->direction() == tcp_connection::direction_incoming
                        );
                        pt_child.put("releasetime", -1);
                        pt_child.put(
                            "startingheight", j->protocol_version_start_height()
                        );
                        pt_child.put("banscore", j->dos_score());

                        ret.result.push_back(std::make_pair("", pt_child));
                    }
                    catch (...)
                    {
                        // ...
                    }
                }
            }
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_getrawtransaction(
    const json_rpc_request_t & request
    )
{
    rpc_connection::json_rpc_response_t ret;

    try
    {
        if (request.params.size() >= 1 && request.params.size() <= 2)
        {
            std::string transaction_id;

            bool verbose = false;
            
            auto index = 0;
            
            for (auto & i : request.params)
            {
                if (index == 0)
                {
                    transaction_id = i.second.get<std::string> ("");
                }
                else if (index == 1)
                {
                    verbose = i.second.get<std::uint8_t> ("") == 1;
                }
            
                index++;
            }
            
            sha256 hash_tx(transaction_id);

            transaction tx;
            
            sha256 hash_block;
            
            if (utility::get_transaction(hash_tx, tx, hash_block) == false)
            {
                auto pt_error = create_error_object(
                    error_code_invalid_address_or_key,
                    "invalid key or address"
                );
                
                /**
                 * error_code_invalid_address_or_key
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error,
                    request.id
                };
            }

            data_buffer buffer;
            
            tx.encode(buffer);
            
            auto hex = utility::hex_string(
                buffer.data(), buffer.data() + buffer.size()
            );
            
            if (verbose)
            {
                ret.result.put(
                    "hex", hex, rpc_json_parser::translator<std::string> ()
                );
                
                ret.result.put(
                    "txid", tx.get_hash().to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                ret.result.put("version", tx.version());
                ret.result.put("time", tx.time());
                ret.result.put("locktime", tx.time_lock());

                boost::property_tree::ptree pt_vin;
                
                for (auto & i : tx.transactions_in())
                {
                    boost::property_tree::ptree pt_in;
                    
                    if (tx.is_coin_base())
                    {
                        pt_in.put(
                            "coinbase",
                            utility::hex_string(i.script_signature().begin(),
                            i.script_signature().end()),
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                    else
                    {
                        pt_in.put(
                            "txid", i.previous_out().get_hash().to_string(),
                            rpc_json_parser::translator<std::string> ()
                        );
                        pt_in.put(
                            "vout", i.previous_out().n()
                        );

                        boost::property_tree::ptree pt_o;
                        
                        pt_o.put(
                            "asm", i.script_signature().to_string(),
                            rpc_json_parser::translator<std::string> ()
                        );
                        pt_o.put(
                            "hex", utility::hex_string(
                            i.script_signature().begin(),
                            i.script_signature().end()),
                            rpc_json_parser::translator<std::string> ()
                        );
                        
                        pt_in.put_child("scriptSig", pt_o);
                    }
                    
                    pt_in.put("sequence", i.sequence());
                    
                    pt_vin.push_back(std::make_pair("", pt_in));
                }
                
                ret.result.put_child("vin", pt_vin);

                boost::property_tree::ptree pt_outs;
                
                for (auto i = 0; i < tx.transactions_out().size(); i++)
                {
                    const auto & tx_out = tx.transactions_out()[i];
                    
                    boost::property_tree::ptree pt_out;
                    
                    pt_out.put(
                        "value",
                        static_cast<double> (tx_out.value()) / constants::coin
                    );
                    pt_out.put("n", i);
                    
                    boost::property_tree::ptree pt_o;
                    
                    types::tx_out_t type;
                    
                    std::vector<destination::tx_t> addresses;
                    
                    std::int32_t required;

                    pt_o.put(
                        "asm", tx_out.script_public_key().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    pt_o.put(
                        "hex", utility::hex_string(
                        tx_out.script_public_key().begin(),
                        tx_out.script_public_key().end()),
                        rpc_json_parser::translator<std::string> ()
                    );

                    if (
                        script::extract_destinations(tx_out.script_public_key(),
                        type, addresses, required) == false
                        )
                    {
                        pt_o.put(
                            "type",
                            script::get_txn_output_type(
                            types::tx_out_nonstandard),
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                    else
                    {
                        pt_o.put("reqSigs", required);
                        pt_o.put(
                            "type", script::get_txn_output_type(type),
                            rpc_json_parser::translator<std::string> ()
                        );

                        boost::property_tree::ptree pt_a;
                        
                        for (auto & i : addresses)
                        {
                            boost::property_tree::ptree pt_tmp;
                            
                            pt_tmp.put(
                                "", address(i).to_string(),
                                rpc_json_parser::translator<std::string> ()
                            );
            
                            pt_a.push_back(std::make_pair("", pt_tmp));
                        }
                        
                        pt_o.put_child("addresses", pt_a);
                    }
                    
                    if (pt_o.size() > 0)
                    {
                        pt_out.put_child("scriptPubKey", pt_o);
                    }
                    else
                    {
                        pt_out.put_child(
                            "scriptPubKey", boost::property_tree::ptree()
                        );
                    }
                    
                    pt_outs.push_back(std::make_pair("", pt_out));
                }
                
                ret.result.put_child("vout", pt_outs);

                if (hash_block != 0)
                {
                    ret.result.put(
                        "blockhash", hash_block.to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    
                    auto block_indexes = globals::instance().block_indexes();
                    
                    auto it = block_indexes.find(hash_block);
                    
                    if (it != block_indexes.end() && it->second)
                    {
                        auto index = it->second;
                        
                        if (index->is_in_main_chain())
                        {
                            ret.result.put(
                                "confirmations",
                                1 + stack_impl::get_block_index_best(
                                )->height() - index->height()
                            );
                            ret.result.put("time", index->time());
                            ret.result.put("blocktime", index->time());
                        }
                        else
                        {
                            ret.result.put("confirmations", 0);
                        }
                    }
                }
            }
            else
            {
                ret.result.put(
                    "", hex, rpc_json_parser::translator<std::string> ()
                );
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_gettransaction(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        if (request.params.size() == 1)
        {
            /**
             * Get the txid parameter.
             */
            auto param_txid =
                request.params.front().second.get<std::string> ("")
            ;
            
            sha256 hash_txid(param_txid);
            
            const auto & transactions =
                globals::instance().wallet_main()->transactions()
            ;
            
            auto it = transactions.find(hash_txid);
            
            if (it != transactions.end())
            {
                const auto & wtx = it->second;

                auto transactions = transaction_to_ptree(wtx, 0);
                
                for (auto & i : transactions)
                {
                    ret.result.push_back(std::make_pair(i.first, i.second));
                }
                
                std::int64_t credit = wtx.get_credit();
                std::int64_t debit = wtx.get_debit();
                std::int64_t net = credit - debit;
                std::int64_t fee =
                    (wtx.is_from_me() ? wtx.get_value_out() - debit : 0)
                ;

                ret.result.put(
                    "amount", static_cast<double> (net - fee) /
                    constants::coin
                );
                
                if (wtx.is_from_me())
                {
                    ret.result.put(
                        "fee", static_cast<double> (fee) / constants::coin
                    );
                }
                
                auto pt = transaction_wallet_to_ptree(wtx);
                
                for (auto & i : pt)
                {
                    ret.result.push_back(std::make_pair(i.first, i.second));
                }

                auto pt_details =
                    transactions_to_ptree(
                    globals::instance().wallet_main()->transactions()
                    [hash_txid], "*", 0, false
                );
                
                if (pt_details.size() > 0)
                {
                    ret.result.put_child("details", pt_details);
                }
            }
            else
            {
                transaction tx;
                
                sha256 hash_block = 0;
                
                if (utility::get_transaction(hash_txid, tx, hash_block))
                {
                    ret.result.put(
                        "txid", hash_txid.to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    
                    auto transactions = transaction_to_ptree(tx, 0);
                    
                    for (auto & i : transactions)
                    {
                        ret.result.push_back(
                            std::make_pair(i.first, i.second)
                        );
                    }

                    if (hash_block == 0)
                    {
                        ret.result.put("confirmations", 0);
                    }
                    else
                    {
                        ret.result.put(
                            "blockhash", hash_block.to_string(),
                            rpc_json_parser::translator<std::string> ()
                        );
                        
                        auto it = globals::instance().block_indexes().find(
                            hash_block
                        );
                        
                        if (it != globals::instance().block_indexes().end())
                        {
                            const auto & index = it->second;
                            
                            if (index && index->is_in_main_chain())
                            {
                                ret.result.put(
                                    "confirmations",
                                    1 +
                                    stack_impl::get_block_index_best()->height()
                                    - index->height()
                                );
                                ret.result.put("txntime", tx.time());
                                ret.result.put("time", index->time());
                            }
                            else
                            {
                                ret.result.put("confirmations", 0);
                            }
                        }
                    }
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_invalid_address_or_key,
                        "error_code_invalid_address_or_key"
                    );
                    
                    /**
                     * error_code_invalid_address_or_key
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_gettransaction, what = " <<
            e.what() << "."
        );
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_importprivkey(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        /**
         * The privaye key parameter.
         */
        std::string private_key;
        
        /**
         * The label parameter.
         */
        std::string label;
        
        auto index = 0;
        
        for (auto & i : request.params)
        {
            if (index == 0)
            {
                private_key = i.second.get<std::string> ("");
            }
            else if (index == 1)
            {
                label = i.second.get<std::int32_t> ("");
            }
        
            index++;
        }
        
        if (globals::instance().wallet_unlocked_mint_only() == true)
        {
            auto pt_error = create_error_object(
                error_code_wallet_unlock_needed, "wallet is locked"
            );
            
            /**
             * error_code_invalid_address_or_key
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
        
        /**
         * Allocate the secret.
         */
        secret s1;

        /**
         * Set the private key.
         */
        if (s1.set_string(private_key) == true)
        {
            /**
             * Create the key.
             */
            key k;
            
            bool is_compressed;
            
            auto s2 = s1.get_secret(is_compressed);
            
            k.set_secret(s2, is_compressed);
            
            auto addr = k.get_public_key().get_id();

            /**
             * Mark all transactions as dirty.
             */
            globals::instance().wallet_main()->mark_dirty();
            
            /**
             * Set the address book name.
             */
            globals::instance().wallet_main()->set_address_book_name(
                addr, label
            );

            if (globals::instance().wallet_main()->add_key(k) == false)
            {
                auto pt_error = create_error_object(
                    error_code_wallet_error, "failed to add key to wallet"
                );
                
                /**
                 * error_code_wallet_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            else
            {
                globals::instance().wallet_main()->scan_for_transactions(
                    stack_impl::get_block_index_genesis(), true
                );
                globals::instance().wallet_main(
                    )->reaccept_wallet_transactions()
                ;

                ret.result.put("", "null");
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_address_or_key, "invalid private key"
            );
            
            /**
             * error_code_invalid_address_or_key
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_importprivkey, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_listsinceblock(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        std::shared_ptr<block_index> index_block;
        
        auto target_confirms = 1;
    
        auto index = 0;
        
        for (auto & i : request.params)
        {
            if (index == 0)
            {
                auto hex = i.second.get<std::string> ("");

                index_block = block_locator(sha256(hex)).get_block_index();
            }
            else if (index == 1)
            {
                target_confirms = i.second.get<std::int32_t> ("");

                if (target_confirms < 1)
                {
                    auto pt_error = create_error_object(
                        error_code_invalid_parameter, "invalid parameter"
                    );
                    
                    /**
                     * error_code_invalid_parameter
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
        
            index++;
        }
        
        auto depth =
            index_block ?
            (1 + stack_impl::get_block_index_best()->height() -
            index_block->height()) : -1
        ;
        
        boost::property_tree::ptree pt_transactions;

        auto transactions =
            globals::instance().wallet_main()->transactions()
        ;
        
        for (auto & i : transactions)
        {
            if (depth == -1 || i.second.get_depth_in_main_chain() < depth)
            {
                auto pt = transactions_to_ptree(i.second, "*", 0, true);
                
                for (auto & j : pt)
                {
                    pt_transactions.push_back(
                        std::make_pair(j.first, j.second)
                    );
                }
            }
        }

        sha256 lastblock;

        if (target_confirms == 1)
        {
            lastblock = globals::instance().hash_best_chain();
        }
        else
        {
            auto target_height =
                stack_impl::get_block_index_best()->height() + 1 -
                target_confirms
            ;

            std::shared_ptr<block_index> tmp;
            
            for (
                tmp = stack_impl::get_block_index_best();
                tmp && tmp->height() > target_height;
                tmp = tmp->block_index_previous()
                 )
            {
                // ...
            }

            lastblock = tmp ? tmp->get_block_hash() : 0;
        }

        if (pt_transactions.size() > 0)
        {
            ret.result.put_child("transactions", pt_transactions);
        }
        else
        {
            boost::property_tree::ptree pt_empty;
            
            pt_empty.push_back(
                std::make_pair("", boost::property_tree::ptree())
            );
            
            ret.result.put_child("transactions", pt_empty);
        }
        
        ret.result.put(
            "lastblock", lastblock.to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_listblocksince, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_listtransactions(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        std::string account = "*";
        
        std::int32_t count = 10;
        
        std::int32_t from = 0;

        auto index = 0;
        
        for (auto & i : request.params)
        {
            if (index == 0)
            {
                account = i.second.get<std::string> ("");
            }
            else if (index == 1)
            {
                count = i.second.get<std::int32_t> ("");
            }
            else if (index == 2)
            {
                from = i.second.get<std::int32_t> ("");
            }
        
            index++;
        }
        
        log_debug(
            "account = " << account << ", count = " <<
            count << ", from = " << from
        );
        
        if (count < 0 || from < 0)
        {
            auto pt_error = create_error_object(
                error_code_invalid_parameter, "negative parameter"
            );
            
            /**
             * error_code_invalid_parameter
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
        
        std::list<accounting_entry> accounting_entries;
        
        /**
         * Get the ordered transaction items.
         */
        auto ordered_items = globals::instance().wallet_main(
            )->ordered_tx_items(accounting_entries
        );
        
        for (auto it = ordered_items.rbegin(); it != ordered_items.rend(); ++it)
        {
            const auto & i = *it;
            
            if (i.second.first)
            {
                const auto & wtx = *i.second.first;
            
                auto pt_transactions = transactions_to_ptree(
                    wtx, account, 0, true
                );
                
                for (auto & j : pt_transactions)
                {
                    ret.result.push_back(std::make_pair(j.first, j.second));
                }
            }
            
            if (i.second.second)
            {
                const auto & entry = *i.second.second;

                bool all_accounts = account == "*";
            
                if (all_accounts || entry.account() == account)
                {
                    ret.result.put(
                        "account", entry.account(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    ret.result.put(
                        "category", "move",
                        rpc_json_parser::translator<std::string> ()
                    );
                    ret.result.put("time", entry.time());
                    ret.result.put(
                        "amount",
                        static_cast<double> (entry.credit_debit()) /
                        constants::coin
                    );
                    ret.result.put(
                        "otheraccount", entry.other_account(),
                        rpc_json_parser::translator<std::string> ()
                    );
                    ret.result.put(
                        "comment", entry.comment(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
            }
            
            if (ret.result.size() >= count + from)
            {
                break;
            }
        }

        if (from > ret.result.size())
        {
            from = static_cast<std::int32_t> (ret.result.size());
        }
        
        if ((from + count) > ret.result.size())
        {
            count = static_cast<std::int32_t> (ret.result.size()) - from;
        }
        
        auto first = ret.result.begin();
        
        std::advance(first, from);
        
        auto last = ret.result.begin();
        
        std::advance(last, from + count);

        if (last != ret.result.end())
        {
            ret.result.erase(last, ret.result.end());
        }
        
        if (first != ret.result.begin())
        {
            ret.result.erase(ret.result.begin(), first);
        }
        
        ret.result.reverse();

        if (ret.result.size() == 0)
        {
            ret.result.push_back(
                std::make_pair("", boost::property_tree::ptree())
            );
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_listtransactions, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_listreceivedbyaddress(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        std::int32_t minconf = 1;
        
        bool includeempty = false;

        auto index = 0;
        
        for (auto & i : request.params)
        {
            if (index == 0)
            {
                minconf = i.second.get<std::int32_t> ("");
            }
            else if (index == 1)
            {
                includeempty = i.second.get<bool> ("");
            }
        
            index++;
        }
        
        ret.result = received_to_ptree(minconf, includeempty, false);
    
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_listreceivedbyaddress, "
            "what = " << e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_listreceivedbyaccount(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        std::int32_t minconf = 1;
        
        bool includeempty = false;

        auto index = 0;
        
        for (auto & i : request.params)
        {
            if (index == 0)
            {
                minconf = i.second.get<std::int32_t> ("");
            }
            else if (index == 1)
            {
                includeempty = i.second.get<bool> ("");
            }
        
            index++;
        }
        
        ret.result = received_to_ptree(minconf, includeempty, true);
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_listreceivedbyaccount, "
            "what = " << e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_repairwallet(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        /**
         * The mismatch spent coins.
         */
        std::int32_t mismatch_spent = 0;
        
        /**
         * The balance in question.
         */
        std::int64_t balance_in_question = 0;
        
        bool check_only = false;
        
        /**
         * If there coins marked spent that should not be then check and
         * repair them.
         */
        globals::instance().wallet_main()->fix_spent_coins(
            mismatch_spent, balance_in_question, check_only
        );
        
        if (mismatch_spent == 0)
        {
            ret.result.put("wallet check passed", true);
        }
        else
        {
            ret.result.put("mismatched spent coins", mismatch_spent);
            ret.result.put(
                "amount affected by repair",
                balance_in_question / constants::coin
            );
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_repairwallet, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_sendmany(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;

    try
    {
        if (request.params.size() >= 2)
        {
            try
            {
                std::string account;
                
                boost::property_tree::ptree pt_addresses_and_amounts;
                
                boost::property_tree::ptree pt_minconf;

                std::string comment;

                auto index = 0;
                
                for (auto & i : request.params)
                {
                    if (index == 0)
                    {
                        account = i.second.get<std::string> ("");
                    }
                    else if (index == 1)
                    {
                        pt_addresses_and_amounts = i.second;
                    }
                    else if (index == 2)
                    {
                        pt_minconf = i.second;
                    }
                    else if (index == 3)
                    {
                        comment = i.second.get<std::string> ("");
                    }
                
                    index++;
                }

                /**
                 * Get the minimum depth in the main chain.
                 */
                auto minimum_depth_in_main_chain =
                    pt_minconf.get<std::uint32_t> ("minconf", 1
                );
                
                /**
                 * Allocate the transaction_wallet.
                 */
                transaction_wallet wtx;
                
                /**
                 * Set the from account.
                 */
                wtx.set_from_account(account);

                if (comment.size() > 0)
                {
                    wtx.values()["comment"] = comment;
                }
                
                std::set<address> addresses;
                
                std::vector< std::pair<script, std::int64_t> > to_send;
                
                std::int64_t total_amount = 0;
                
                for (auto & i : pt_addresses_and_amounts)
                {
                    address addr(i.first);
                    
                    log_info(
                        "RPC connection sendmany address = " << i.first << "."
                    );
                    
                    if (addr.is_valid())
                    {
                        /**
                         * Do not allow duplicate addresses.
                         */
                        if (addresses.count(addr) > 0)
                        {
                            auto pt_error = create_error_object(
                                error_code_invalid_parameter,
                                "invalid parameter"
                            );
                            
                            /**
                             * error_code_invalid_parameter
                             */
                            return json_rpc_response_t{
                                boost::property_tree::ptree(), pt_error,
                                request.id
                            };
                        }
                        else
                        {
                            addresses.insert(addr);

                            script script_pub_key;
                            
                            /**
                             * Set the destination.
                             */
                            script_pub_key.set_destination(addr.get());

                            /**
                             * Get the double value.
                             */
                            double value = i.second.get<double> ("");
                            
                            /**
                             * Make sure the value is within limits.
                             */
                            if (
                                value < 0.0f ||
                                value > constants::max_money_supply
                                )
                            {
                                auto pt_error = create_error_object(
                                    error_code_type_error, "invalid amount"
                                );
                                
                                /**
                                 * error_code_type_error
                                 */
                                return json_rpc_response_t{
                                    boost::property_tree::ptree(), pt_error,
                                    request.id
                                };
                            }
                            
                            /**
                             * Round the amount.
                             */
                            auto amount = static_cast<std::int64_t> (
                                (value * constants::coin) > 0 ?
                                (value * constants::coin) + 0.5 :
                                (value * constants::coin) - 0.5
                            );
                            
                            /**
                             * Check that the amount is within the money range.
                             */
                            if (utility::money_range(amount) == false)
                            {
                                auto pt_error = create_error_object(
                                    error_code_type_error,
                                    "invalid amount"
                                );
                                
                                /**
                                 * error_code_type_error
                                 */
                                return json_rpc_response_t{
                                    boost::property_tree::ptree(), pt_error,
                                    request.id
                                };
                            }

                            /**
                             * Make sure the amount is not less than the
                             * minimum transaction fee.
                             */
                            if (amount < constants::min_tx_fee)
                            {
                                auto pt_error = create_error_object(
                                    error_code_amount_too_small,
                                    "amount too small"
                                );
                                
                                /**
                                 * error_code_amount_too_small
                                 */
                                return json_rpc_response_t{
                                    boost::property_tree::ptree(), pt_error,
                                    request.id
                                };
                            }
                            
                            total_amount += amount;

                            /**
                             * Append the transaction.
                             */
                            to_send.push_back(
                                std::make_pair(script_pub_key, amount)
                            );
                        }
                    }
                    else
                    {
                        auto pt_error = create_error_object(
                            error_code_invalid_address_or_key,
                            "error_code_invalid_address_or_key(" + i.first +
                            ")"
                        );
                        
                        /**
                         * error_code_invalid_address_or_key
                         */
                        return json_rpc_response_t{
                            boost::property_tree::ptree(), pt_error, request.id
                        };
                    }
                }
                
                /**
                 * Make sure the wallet is unlocked.
                 */
                if (globals::instance().wallet_main()->is_locked())
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_unlock_needed, "wallet is locked"
                    );
                    
                    /**
                     * error_code_wallet_unlock_needed
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
                
                /**
                 * Make sure the wallet is not unlocked for minting only.
                 */
                if (globals::instance().wallet_unlocked_mint_only())
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_unlock_needed,
                        "wallet is unlocked for minting only"
                    );
                    
                    /**
                     * error_code_wallet_unlock_needed
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }

                /**
                 * Get the account balance.
                 */
                std::int64_t balance = wallet::get_account_balance(
                    account, minimum_depth_in_main_chain
                );

                if (total_amount > balance)
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_insufficient_funds,
                        "insufficient funds"
                    );
                    
                    /**
                     * error_code_wallet_insufficient_funds
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }

                key_reserved k(*globals::instance().wallet_main());
                
                std::int64_t required_fee = 0;
                
                /**
                 * Create the transaction.
                 */
                bool success =
                    globals::instance().wallet_main()->create_transaction(
                    to_send, wtx, k, required_fee
                );
                
                if (success == false)
                {
                    if (
                        total_amount + required_fee >
                        globals::instance().wallet_main()->get_balance()
                        )
                    {
                        auto pt_error = create_error_object(
                            error_code_wallet_insufficient_funds,
                            "insufficient funds"
                        );
                        
                        /**
                         * error_code_wallet_insufficient_funds
                         */
                        return json_rpc_response_t{
                            boost::property_tree::ptree(), pt_error,
                            request.id
                        };
                    }
                }
                
                /**
                 * Commit the transaction.
                 */
                auto ret_pair =
                    globals::instance().wallet_main()->commit_transaction(
                    wtx, k)
                ;

                if (ret_pair.first == false)
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_error, ret_pair.second
                    );
                    
                    /**
                     * error_code_wallet_error
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error,
                        request.id
                    };
                }
                
                /**
                 * Put the hash of the wallet transaction.
                 */
                ret.result.put(
                    "", wtx.get_hash().to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
            }
            catch (...)
            {
                // ...
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_sendmany, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_sendtoaddress(
    const json_rpc_request_t & request
    )
{
    rpc_connection::json_rpc_response_t ret;

    try
    {
        if (request.params.size() >= 2 && request.params.size() <= 4)
        {
            std::string address_dest;
            std::int64_t amount = 0;
            std::string comment;
            std::string comment_to;
            
            auto index = 0;
            
            for (auto & i : request.params)
            {
                if (index == 0)
                {
                    address_dest = i.second.get<std::string> ("");
                }
                else if (index == 1)
                {
                    double value = i.second.get<double> ("");
                    
                    if (value <= 0.0 || value > constants::max_money_supply)
                    {
                        auto pt_error = create_error_object(
                            error_code_type_error, "invalid amount"
                        );
                        
                        /**
                         * error_code_type_error
                         */
                        return json_rpc_response_t{
                            boost::property_tree::ptree(), pt_error, request.id
                        };
                    }
                    
                    /**
                     * Round the amount.
                     */
                    amount = static_cast<std::int64_t> (
                        (value * constants::coin) > 0 ?
                        (value * constants::coin) + 0.5 :
                        (value * constants::coin) - 0.5
                    );
                    
                    if (utility::money_range(amount) == false)
                    {
                        auto pt_error = create_error_object(
                            error_code_type_error, "invalid amount"
                        );
                        
                        /**
                         * error_code_type_error
                         */
                        return json_rpc_response_t{
                            boost::property_tree::ptree(), pt_error, request.id
                        };
                    }
                }
                else if (index == 2)
                {
                    comment = i.second.get<std::string> ("");
                }
                else if (index == 3)
                {
                    comment_to = i.second.get<std::string> ("");
                }

                index++;
            }
            
            if (amount < constants::min_txout_amount)
            {
                auto pt_error = create_error_object(
                    error_code_amount_too_small, "amount too small"
                );
                
                /**
                 * error_code_amount_too_small
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            
            /**
             * Allocate the transaction.
             */
            transaction_wallet wtx;
            
            /**
             * Set the key/value pairs.
             */
            if (comment.size() > 0)
            {
                wtx.values()["comment"] = comment;
            }
            
            if (comment_to.size() > 0)
            {
                wtx.values()["to"] = comment_to;
            }
            
            if (globals::instance().wallet_main()->is_locked())
            {
                auto pt_error = create_error_object(
                    error_code_wallet_unlock_needed, "wallet is locked"
                );
                
                /**
                 * error_code_wallet_unlock_needed
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
            else
            {
                auto result =
                    globals::instance().wallet_main(
                    )->send_money_to_destination(
                    address(address_dest).get(), amount, wtx
                );
                
                if (result.first)
                {
                    ret.result.put(
                        "", wtx.get_hash().to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_error, result.second
                    );
                    
                    /**
                     * error_code_wallet_error
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_sendtoaddress, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }

    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_submitblock(
    const json_rpc_request_t & request
    )
{
    rpc_connection::json_rpc_response_t ret;

    try
    {
        if (request.params.size() > 0 && request.params.size() < 2)
        {
            /**
             * Decode the block data.
             */
            auto data(
                utility::from_hex(
                request.params.front().second.get<std::string> (""))
            );
            
            /**
             * Copy the decoded data into the buffer.
             */
            data_buffer buffer(
                reinterpret_cast<const char *>(&data[0]), data.size()
            );
            
            /**
             * Allocate the block.
             */
            block blk;
            
            /**
             * Try to decode the block.
             */
            if (blk.decode(buffer))
            {
                /**
                 * Try to sign the block.
                 */
                if (blk.sign(*globals::instance().wallet_main()))
                {
                    /**
                     * Try to accept the block.
                     */
                    if (
                        blk.accept_block(
                        stack_impl_.get_tcp_connection_manager())
                        )
                    {
                        log_info("RPC connection accepted block.");
                        
                        ret.result.put("", "null");
                    }
                    else
                    {
                        log_info("RPC connection rejected block.");
                        
                        ret.result.put(
                            "", "rejected",
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_sign_block_failed, "failed to sign block"
                    );
                    
                    /**
                     * error_code_sign_block_failed
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
            else
            {
                auto pt_error = create_error_object(
                    error_code_deserialization_error, "failed to decode block"
                );
                
                /**
                 * error_code_deserialization_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_misc_error, "invalid parameter count"
            );
            
            /**
             * error_code_misc_error
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_submitblock, what = " <<
            e.what() << "."
        );
    }
    
    return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_validateaddress(
    const json_rpc_request_t & request
    )
{
    rpc_connection::json_rpc_response_t ret;

    try
    {
        if (request.params.size() == 1)
        {
            try
            {
                /**
                 * Get the address parameter.
                 */
                auto param_addr =
                    request.params.front().second.get<std::string> ("")
                ;
        
                /**
                 * Allocate the address from the single parameter.
                 */
                address addr(param_addr);
                
                auto is_valid = addr.is_valid();
                
                ret.result.put("isvalid", is_valid);
                
                if (is_valid)
                {
                    auto dest = addr.get();
                    
                    auto current_addr = addr.to_string();
                    
                    ret.result.put(
                        "address", current_addr,
                        rpc_json_parser::translator<std::string> ()
                    );
                    
                    auto is_mine = script::is_mine(
                        *globals::instance().wallet_main(), dest
                    );
                    
                    ret.result.put("ismine", is_mine);
                    
                    if (is_mine)
                    {
                        auto pt_detail =
                            boost::apply_visitor(describe_address_visitor(),
                            dest)
                        ;
                        
                        ret.result.insert(
                            ret.result.begin(), pt_detail.begin(),
                            pt_detail.end()
                        );
                    }
                    
                    auto it =
                        globals::instance().wallet_main()->address_book(
                        ).find(dest)
                    ;
                    
                    if (
                        it != globals::instance().wallet_main(
                        )->address_book().end()
                        )
                    {
                        ret.result.put(
                            "account", it->second,
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                }
            }
            catch (std::exception & e)
            {
                log_error(
                    "RPC connection failed to json_validateaddress, what = " <<
                    e.what() << "."
                );
                
                auto pt_error = create_error_object(
                    error_code_internal_error, e.what()
                );
                
                /**
                 * error_code_internal_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter coiunt"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC Connection failed to create json_validateaddress, what = " <<
            e.what() << "."
        );
        
        auto pt_error = create_error_object(
            error_code_internal_error, e.what()
        );
        
        /**
         * error_code_internal_error
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    
    return ret;
}


rpc_connection::json_rpc_response_t rpc_connection::json_walletpassphrase(
    const json_rpc_request_t & request
    )
{
    json_rpc_response_t ret;
    
    if (globals::instance().wallet_main()->is_crypted() == false)
    {
        auto pt_error = create_error_object(
            error_code_wallet_wrong_enc_state, "wallet is not encrypted"
        );
        
        /**
         * error_code_wallet_wrong_enc_state
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    else if (globals::instance().wallet_main()->is_locked() == false)
    {
        auto pt_error = create_error_object(
            error_code_wallet_already_unlocked, "wallet is already unlocked"
        );
        
        /**
         * error_code_wallet_already_unlocked
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    else
    {
        if (request.params.size() > 0)
        {
            auto passphrase =
                request.params.front().second.get<std::string> ("")
            ;

            try
            {
                if (
                    passphrase.size() > 0 &&
                    globals::instance().wallet_main()->unlock(
                    passphrase) == true
                    )
                {
                    ret.result.put("", "null");
                }
                else
                {
                    auto pt_error = create_error_object(
                        error_code_wallet_passphrase_incorrect,
                        "passphrase incorrect"
                    );
                    
                    /**
                     * error_code_wallet_passphrase_incorrect
                     */
                    return json_rpc_response_t{
                        boost::property_tree::ptree(), pt_error, request.id
                    };
                }
            }
            catch (std::exception & e)
            {
                auto pt_error = create_error_object(
                    error_code_misc_error, e.what()
                );
                
                /**
                 * error_code_internal_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        else
        {
            auto pt_error = create_error_object(
                error_code_invalid_params, "invalid parameter count"
            );
            
            /**
             * error_code_invalid_params
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    
	return ret;
}

rpc_connection::json_rpc_response_t rpc_connection::json_walletlock(
    const json_rpc_request_t & request
    )
{
	json_rpc_response_t ret;
    
    if (globals::instance().wallet_main()->is_crypted() == false)
    {
        auto pt_error = create_error_object(
            error_code_wallet_wrong_enc_state, "wallet is not encrypted"
        );
        
        /**
         * error_code_wallet_wrong_enc_state
         */
        return json_rpc_response_t{
            boost::property_tree::ptree(), pt_error, request.id
        };
    }
    else
    {
        try
        {
            if (globals::instance().wallet_main()->lock() == true)
            {
                ret.result.put("", "null");
            }
            else
            {
                auto pt_error = create_error_object(
                    error_code_misc_error, "failed to lock wallet"
                );

                /**
                 * error_code_misc_error
                 */
                return json_rpc_response_t{
                    boost::property_tree::ptree(), pt_error, request.id
                };
            }
        }
        catch (std::exception & e)
        {
            auto pt_error = create_error_object(
                error_code_internal_error, e.what()
            );

            /**
             * error_code_internal_error
             */
            return json_rpc_response_t{
                boost::property_tree::ptree(), pt_error, request.id
            };
        }
    }
    return ret;
}

boost::property_tree::ptree rpc_connection::transaction_wallet_to_ptree(
    const transaction_wallet & wtx
    )
{
    boost::property_tree::ptree ret;
    
    auto depth = wtx.get_depth_in_main_chain();
    
    ret.put("confirmations", depth);
    
    if (wtx.is_coin_base() || wtx.is_coin_stake())
    {
        ret.put("generated", true);
    }
    
    if (depth > 0)
    {
        ret.put(
            "blockhash", wtx.block_hash().to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        ret.put("blockindex", wtx.index());
        ret.put(
            "blocktime",
            globals::instance().block_indexes()[
            wtx.block_hash()]->time()
        );
    }
    
    ret.put(
        "txid", wtx.get_hash().to_string(),
        rpc_json_parser::translator<std::string> ()
    );
    ret.put("time", wtx.time());
    ret.put("timereceived", wtx.time_received());
    
    for (auto & i : wtx.values())
    {
        ret.put(
            i.first, i.second, rpc_json_parser::translator<std::string> ()
        );
    }
    
    return ret;
}

boost::property_tree::ptree rpc_connection::transaction_to_ptree(
    const transaction & tx, const sha256 & hash_block
    )
{
    boost::property_tree::ptree ret;

    try
    {
        ret.put(
            "txid", tx.get_hash().to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        ret.put("version", tx.version());
        ret.put("time", tx.time());
        ret.put("locktime", tx.time_lock());

        boost::property_tree::ptree pt_vin;
        
        for (auto & i : tx.transactions_in())
        {
            boost::property_tree::ptree pt_in;
            
            if (tx.is_coin_base())
            {
                pt_in.put(
                    "coinbase",
                    utility::hex_string(i.script_signature().begin(),
                    i.script_signature().end()),
                    rpc_json_parser::translator<std::string> ()
                );
            }
            else
            {
                pt_in.put(
                    "txid", i.previous_out().get_hash().to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                pt_in.put(
                    "vout", i.previous_out().n()
                );

                boost::property_tree::ptree pt_o;
                
                pt_o.put(
                    "asm", i.script_signature().to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                pt_o.put(
                    "hex", utility::hex_string(
                    i.script_signature().begin(),
                    i.script_signature().end()),
                    rpc_json_parser::translator<std::string> ()
                );
                
                pt_in.put_child("scriptSig", pt_o);
            }
            
            pt_in.put("sequence", i.sequence());
            
            pt_vin.push_back(std::make_pair("", pt_in));
        }
        
        ret.put_child("vin", pt_vin);

        boost::property_tree::ptree pt_outs;
        
        for (auto i = 0; i < tx.transactions_out().size(); i++)
        {
            const auto & tx_out = tx.transactions_out()[i];
            
            boost::property_tree::ptree pt_out;
            
            pt_out.put(
                "value", static_cast<double> (tx_out.value()) / constants::coin
            );
            pt_out.put("n", i);
            
            boost::property_tree::ptree pt_o;
            
            types::tx_out_t type;
            
            std::vector<destination::tx_t> addresses;
            
            int required;

            pt_o.put(
                "asm", tx_out.script_public_key().to_string(),
                rpc_json_parser::translator<std::string> ()
            );
            pt_o.put(
                "hex", utility::hex_string(
                tx_out.script_public_key().begin(),
                tx_out.script_public_key().end()),
                rpc_json_parser::translator<std::string> ()
            );

            if (
                script::extract_destinations(tx_out.script_public_key(),
                type, addresses, required) == false
                )
            {
                pt_o.put(
                    "type",
                    script::get_txn_output_type(
                    types::tx_out_nonstandard),
                    rpc_json_parser::translator<std::string> ()
                );
            }
            else
            {
                pt_o.put("reqSigs", required);
                pt_o.put(
                    "type", script::get_txn_output_type(type),
                    rpc_json_parser::translator<std::string> ()
                );

                boost::property_tree::ptree pt_a;
                
                for (auto & i : addresses)
                {
                    boost::property_tree::ptree pt_tmp;
                    
                    pt_tmp.put(
                        "", address(i).to_string(),
                        rpc_json_parser::translator<std::string> ()
                    );
    
                    pt_a.push_back(std::make_pair("", pt_tmp));
                }
                
                pt_o.put_child("addresses", pt_a);
            }
            
            if (pt_o.size() > 0)
            {
                pt_out.put_child("scriptPubKey", pt_o);
            }
            else
            {
                pt_out.put_child(
                    "scriptPubKey", boost::property_tree::ptree()
                );
            }
            
            pt_outs.push_back(std::make_pair("", pt_out));
        }
        
        ret.put_child("vout", pt_outs);

        if (hash_block != 0)
        {
            ret.put(
                "blockhash", hash_block.to_string(),
                rpc_json_parser::translator<std::string> ()
            );
            
            auto block_indexes = globals::instance().block_indexes();
            
            auto it = block_indexes.find(hash_block);
            
            if (it != block_indexes.end() && it->second)
            {
                auto index = it->second;
                
                if (index->is_in_main_chain())
                {
                    ret.put(
                        "confirmations",
                        1 + stack_impl::get_block_index_best(
                        )->height() - index->height()
                    );
                    ret.put("time", index->time());
                    ret.put("blocktime", index->time());
                }
                else
                {
                    ret.put("confirmations", 0);
                }
            }
        }
    }
    catch (std::exception & e)
    {
        log_error(
            "RPC connection failed to transaction to ptree, what = " <<
            e.what() << "."
        );
    }

    return ret;
}

boost::property_tree::ptree rpc_connection::transactions_to_ptree(
    const transaction_wallet & wtx, const std::string & account,
    const std::uint32_t & minimim_depth, const bool & include_transactions
    )
{
    boost::property_tree::ptree ret;
    
    std::int64_t generated_immature, generated_mature, fee;
    std::string account_sent;
    
    std::list< std::pair<destination::tx_t, std::int64_t> > received;
    std::list< std::pair<destination::tx_t, std::int64_t> > sent;

    wtx.get_amounts(
        generated_immature, generated_mature, received, sent, fee,
        account_sent
    );

    bool all_accounts = account == "*";

    /**
     * Generated
     */
    if (
        (generated_mature + generated_immature) != 0 &&
        (all_accounts || account == "")
        )
    {
        boost::property_tree::ptree pt_entry;
        
        pt_entry.put(
            "account", "", rpc_json_parser::translator<std::string> ()
        );
        
        pt_entry.put(
            "address",
            address(globals::instance().wallet_main(
            )->key_public_default().get_id()).to_string(),
            rpc_json_parser::translator<std::string> ()
        );
        
        if (generated_immature > 0)
        {
            pt_entry.put(
                "category",
                wtx.get_depth_in_main_chain() ? "immature" : "orphan",
                rpc_json_parser::translator<std::string> ()
            );
            pt_entry.put(
                "amount", static_cast<double> (generated_immature) /
                constants::coin
            );
        }
        else
        {
            pt_entry.put(
                "category", "generate",
                rpc_json_parser::translator<std::string> ()
            );
            pt_entry.put(
                "amount", static_cast<double> (generated_mature) /
                constants::coin
            );
        }
        
        if (include_transactions)
        {
            auto pt = transaction_wallet_to_ptree(wtx);
            
            for (auto & i : pt)
            {
                pt_entry.push_back(std::make_pair(i.first, i.second));
            }
        }
        
        ret.push_back(std::make_pair("", pt_entry));
    }
    
    /**
     * Sent
     */
    if (
        (sent.size() > 0 || fee != 0) &&
        (all_accounts || account == account_sent)
        )
    {
        for (auto & s : sent)
        {
            boost::property_tree::ptree pt_entry;
            
            pt_entry.put(
                "account", account_sent,
                rpc_json_parser::translator<std::string> ()
            );
            pt_entry.put(
                "address", address(s.first).to_string(),
                rpc_json_parser::translator<std::string> ()
            );
            pt_entry.put(
                "category", "send", rpc_json_parser::translator<std::string> ()
            );
            pt_entry.put(
                "amount", static_cast<double> (-s.second) / constants::coin
            );
            pt_entry.put(
                "fee", static_cast<double> (-fee) / constants::coin
            );
            
            if (include_transactions)
            {
                auto pt = transaction_wallet_to_ptree(wtx);
                
                for (auto & i : pt)
                {
                    pt_entry.push_back(std::make_pair(i.first, i.second));
                }
                
                ret.push_back(std::make_pair("", pt_entry));
            }
        }
    }

    /**
     * Received
     */
    if (
        received.size() > 0 &&
        wtx.get_depth_in_main_chain() >= minimim_depth
        )
    {
        for (auto & r : received)
        {
            std::string acct;
            
            const auto & address_book =
                globals::instance().wallet_main()->address_book()
            ;
            
            auto it = address_book.find(r.first);
            
            if (it != address_book.end())
            {
                acct = it->second;
            }
            
            if (all_accounts || acct == account)
            {
                boost::property_tree::ptree pt_entry;
                
                pt_entry.put(
                    "account", acct,
                    rpc_json_parser::translator<std::string> ()
                );
                pt_entry.put(
                    "address", address(r.first).to_string(),
                    rpc_json_parser::translator<std::string> ()
                );
                
                if (wtx.is_coin_base())
                {
                    if (wtx.get_depth_in_main_chain() < 1)
                    {
                        pt_entry.put(
                            "category", "orphan",
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                    else if (wtx.get_blocks_to_maturity() > 0)
                    {
                        pt_entry.put(
                            "category", "immature",
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                    else
                    {
                        pt_entry.put(
                            "category", "generate",
                            rpc_json_parser::translator<std::string> ()
                        );
                    }
                }
                else
                {
                    pt_entry.put(
                        "category", "receive",
                        rpc_json_parser::translator<std::string> ()
                    );
                }
                
                pt_entry.put(
                    "amount", static_cast<double> (r.second) / constants::coin
                );
            
                if (include_transactions)
                {
                    auto pt = transaction_wallet_to_ptree(wtx);
                    
                    for (auto & i : pt)
                    {
                        pt_entry.push_back(std::make_pair(i.first, i.second));
                    }
                }
                
                ret.push_back(std::make_pair("", pt_entry));
            }
        }
    }

    return ret;
}

boost::property_tree::ptree rpc_connection::received_to_ptree(
    const std::int32_t & minimim_depth, const bool & include_empty,
    const bool & by_accounts
    )
{
    boost::property_tree::ptree ret;

    /**
     * A tally item.
     */
    typedef std::pair<std::int64_t, std::int32_t> tally_item_t;

    /**
     * The tally.
     */
    std::map<destination::tx_t, tally_item_t> tally;
    
    /**
     * Get all of the transactions from the main wallet.
     */
    const auto & transactions =
        globals::instance().wallet_main()->transactions()
    ;
    
    for (auto & i : transactions)
    {
        const auto & wtx = i.second;

        if (
            wtx.is_coin_base() || wtx.is_coin_stake() ||
            wtx.is_final() == false
            )
        {
            continue;
        }
        
        auto depth = wtx.get_depth_in_main_chain();
        
        if (depth < minimim_depth)
        {
            continue;
        }
        
        for (auto & j : wtx.transactions_out())
        {
            destination::tx_t addr;
            
            if (
                script::extract_destination(
                j.script_public_key(), addr) == false ||
                script::is_mine(*globals::instance().wallet_main(),
                addr) == false
                )
            {
                continue;
            }
            
            auto & item = tally[addr];
            
            item.first += j.value();
            
            item.second = std::min(
                std::numeric_limits<std::int32_t>::max(), depth
            );
        }
    }

    /**
     * The account tally.
     */
    std::map<std::string, tally_item_t> account_tally;
    
    /**
     * Get the address book from the main wallet.
     */
    const auto & address_book =
        globals::instance().wallet_main()->address_book()
    ;
    
    for (auto & i : address_book)
    {
        const auto & addr = i.first;
        
        const auto & acct = i.second;
        
        auto it = tally.find(addr);
        
        if (it == tally.end() && include_empty == false)
        {
            continue;
        }
        
        std::int64_t amount = 0;
        
        auto conf = std::numeric_limits<std::int32_t>::max();
        
        if (it != tally.end())
        {
            amount = it->second.first;
            
            conf = it->second.second;
        }

        if (by_accounts)
        {
            auto & item = account_tally[acct];
            
            item.first += amount;
            
            item.second = std::min(
                std::numeric_limits<std::int32_t>::max(), conf
            );
        }
        else
        {
            boost::property_tree::ptree obj;
            
            obj.put(
                "address", address(addr).to_string(),
                rpc_json_parser::translator<std::string> ()
            );
            obj.put(
                "account", acct,
                rpc_json_parser::translator<std::string> ()
            );
            obj.put(
                "amount", static_cast<double> (amount) / constants::coin
            );
            obj.put(
                "confirmations",
                (conf == std::numeric_limits<std::int32_t>::max() ? 0 : conf)
            );
            
            ret.push_back(std::make_pair("", obj));
        }
    }

    if (by_accounts)
    {
        for (auto & i : account_tally)
        {
            auto amount = i.second.first;
            
            auto conf = i.second.second;
            
            boost::property_tree::ptree obj;
            
            obj.put(
                "account", i.first,
                rpc_json_parser::translator<std::string> ()
            );
            obj.put(
                "amount", static_cast<double> (amount) / constants::coin
            );
            obj.put(
                "confirmations",
                (conf == std::numeric_limits<std::int32_t>::max() ? 0 : conf)
            );
            
            ret.push_back(std::make_pair("", obj));
        }
    }
    
    return ret;
}

boost::property_tree::ptree rpc_connection::create_error_object(
    const error_code_t & code, const std::string & message
    )
{
    boost::property_tree::ptree ret;
    
    ret.put("code", code);
    ret.put(
        "message", message, rpc_json_parser::translator<std::string> ()
    );
    
    return ret;
}
