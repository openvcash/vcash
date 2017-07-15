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

#include <cassert>
#include <fstream>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/android.hpp>
#include <coin/configuration.hpp>
#include <coin/db_env.hpp>
#include <coin/filesystem.hpp>
#include <coin/logger.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/zerotime.hpp>
#include <coin/wallet.hpp>

using namespace coin;

configuration::configuration()
    : m_network_port_tcp(protocol::default_tcp_port)
    , m_network_tcp_inbound_maximum(network::tcp_inbound_maximum)
    , m_network_udp_enable(true)
    , m_rpc_port(protocol::default_rpc_port)
    , m_wallet_transaction_history_maximum(wallet::configuration_interval_history)
    , m_wallet_keypool_size(wallet::configuration_keypool_size)
    , m_zerotime_depth(zerotime::depth)
    , m_zerotime_answers_minimum(zerotime::answers_minimum)
    , m_wallet_rescan(false)
    , m_mining_proof_of_stake(true)
    , m_blockchain_pruning(false)
    , m_chainblender_debug_options(false)
    , m_chainblender_use_common_output_denominations(true)
    , m_database_cache_size(db_env::default_cache_size)
    , m_wallet_deterministic(true)
    , m_db_private(false)
{
    // ...
}

bool configuration::load()
{
    log_info("Configuration is loading from disk.");
    
    boost::property_tree::ptree pt;
    
    try
    {
        std::stringstream ss;
        
        /**
         * Read the json configuration from disk.
         */
        read_json(filesystem::data_path() + "config.dat", pt);
        
        /**
         * Get the version.
         */
        auto file_version = std::stoul(
            pt.get("version", std::to_string(version))
        );
        
        (void)file_version;
        
        log_debug("Configuration read version = " << file_version << ".");
        
        assert(file_version == version);

        /**
         * Get the network.tcp.port
         */
        m_network_port_tcp = std::stoul(
            pt.get("network.tcp.port",
            std::to_string(protocol::default_tcp_port))
        );
        
        log_debug(
            "Configuration read network.tcp.port = " <<
            m_network_port_tcp << "."
        );

        /**
         * Get the network.tcp.inbound.maximum.
         */
        m_network_tcp_inbound_maximum = std::stoul(pt.get(
            "network.tcp.inbound.maximum",
            std::to_string(network::tcp_inbound_maximum))
        );
        
        log_debug(
            "Configuration read network.tcp.inbound.maximum = " <<
            m_network_tcp_inbound_maximum << "."
        );
        
        /**
         * Enforce the minimum network.tcp.inbound.minimum.
         */
        if (m_network_tcp_inbound_maximum < network::tcp_inbound_minimum)
        {
            m_network_tcp_inbound_maximum = network::tcp_inbound_minimum;
        }
        
        /**
         * Get the network.udp.enable.
         */
        m_network_udp_enable = std::stoul(pt.get(
            "network.udp.enable", std::to_string(false))
        );
        
        log_debug(
            "Configuration read network.udp.enable = " <<
            m_network_udp_enable << "."
        );
        
        /**
         * Get the rpc.port
         */
        m_rpc_port = std::stoul(
            pt.get("rpc.port",
            std::to_string(protocol::default_rpc_port))
        );
        
        log_debug(
            "Configuration read rpc.port = " <<
            m_rpc_port << "."
        );

        /**
         * Get the wallet.transaction.history.maximum.
         */
        m_wallet_transaction_history_maximum = std::stoul(pt.get(
            "wallet.transaction.history.maximum",
            std::to_string(m_wallet_transaction_history_maximum))
        );
        
        log_debug(
            "Configuration read wallet.transaction.history.maximum = " <<
            m_wallet_transaction_history_maximum << "."
        );
        
        /**
         * Get the wallet.keypool.size.
         */
        m_wallet_keypool_size = std::stoi(pt.get(
            "wallet.keypool.size",
            std::to_string(m_wallet_keypool_size))
        );
        
        log_debug(
            "Configuration read wallet.keypool.size = " <<
            m_wallet_keypool_size << "."
        );

        /**
         * Get the zerotime.depth.
         */
        m_zerotime_depth = std::stoi(pt.get(
            "zerotime.depth",
            std::to_string(m_zerotime_depth))
        );
        
        log_debug(
            "Configuration read zerotime.depth = " <<
            static_cast<std::uint32_t> (m_zerotime_depth) << "."
        );
        
        /**
         * Get the zerotime.answers.minimum.
         */
        m_zerotime_answers_minimum = std::stoi(pt.get(
            "zerotime.answers.minimum",
            std::to_string(m_zerotime_answers_minimum))
        );
        
        /**
         * Enforce the minimum zerotime.answers.minimum.
         */
        if (m_zerotime_answers_minimum > zerotime::answers_maximum)
        {
            m_zerotime_answers_minimum = zerotime::answers_maximum;
        }
        
        log_debug(
            "Configuration read zerotime.answers.minimum = " <<
            static_cast<std::uint32_t> (m_zerotime_answers_minimum) << "."
        );

        /**
         * Get the wallet.rescan.
         */
        m_wallet_rescan = std::stoi(pt.get(
            "wallet.rescan",
            std::to_string(m_wallet_rescan))
        );
        
        log_debug(
            "Configuration read wallet.rescan = " <<
            m_wallet_rescan << "."
        );
        
        /**
         * Get the mining.proof-of-stake.
         */
        m_mining_proof_of_stake = std::stoi(pt.get(
            "mining.proof-of-stake",
            std::to_string(m_mining_proof_of_stake))
        );
        
        log_debug(
            "Configuration read mining.proof-of-stake = " <<
            m_mining_proof_of_stake << "."
        );

        /**
         * Get the chainblender.debug_options.
         */
        m_chainblender_debug_options = std::stoi(pt.get(
            "chainblender.debug_options",
            std::to_string(m_chainblender_debug_options))
        );
        
        log_debug(
            "Configuration read " << "chainblender.debug_options = " <<
            m_chainblender_debug_options << "."
        );
        
        /**
         * Get the chainblender.use_common_output_denominations.
         */
        m_chainblender_use_common_output_denominations = std::stoi(pt.get(
            "chainblender.use_common_output_denominations",
            std::to_string(m_chainblender_use_common_output_denominations))
        );
        
        log_debug(
            "Configuration read " <<
            "chainblender.use_common_output_denominations = " <<
            m_chainblender_use_common_output_denominations << "."
        );
        
        /**
         * Get the database.cache_size.
         */
        m_database_cache_size = std::stoi(pt.get(
            "database.cache_size",
            std::to_string(m_database_cache_size))
        );
        
        /**
         * Make sure the database.cache_size stays within a range.
         */
        if (m_database_cache_size < 1 || m_database_cache_size > 2048)
        {
            m_database_cache_size = db_env::default_cache_size;
        }
        
        log_debug(
            "Configuration read database.cache_size = " <<
            m_database_cache_size << "."
        );
        
        /**
         * Get the wallet.deterministic.
         */
        m_wallet_deterministic = std::stoi(pt.get(
            "wallet.deterministic",
            std::to_string(m_wallet_deterministic))
        );
        
        log_debug(
            "Configuration read wallet.deterministic = " <<
            m_wallet_deterministic << "."
        );
        
        /**
         * Get the database.private.
         */
        m_db_private = std::stoi(pt.get(
            "database.private", std::to_string(m_db_private))
        );
        
        log_debug(
            "Configuration read database.private = " << m_db_private << "."
        );
    }
    catch (std::exception & e)
    {
        log_error("Configuration failed to load, what = " << e.what() << ".");
    
        return false;
    }
#if 0
    if (m_args.size() > 0)
    {
        // :TODO: Iterate the args and override the variables. (if found).
        // :TODO: Restrict to Windows, macOS, and GNU/Linux.
    }
#endif
    return true;
}

bool configuration::save()
{
    log_info("Configuration is saving to disk.");
    
    try
    {
        boost::property_tree::ptree pt;
        
        /**
         * Put the version into property tree.
         */
        pt.put("version", std::to_string(version));
        
        /**
         * Put the network.tcp.port into property tree.
         */
        pt.put("network.tcp.port", std::to_string(m_network_port_tcp));
        
        /**
         * Put the network.tcp.inbound.maximum into property tree.
         */
        pt.put(
            "network.tcp.inbound.maximum",
            std::to_string(m_network_tcp_inbound_maximum)
        );
        
        /**
         * Put the network.udp.enable into property tree.
         */
        pt.put(
            "network.udp.enable", std::to_string(m_network_udp_enable)
        );

        /**
         * Put the rpc.port into property tree.
         */
        pt.put("rpc.port", std::to_string(m_rpc_port));

        /**
         * Put the wallet.transaction.history.maximum into property tree.
         */
        pt.put(
            "wallet.transaction.history.maximum",
            std::to_string(m_wallet_transaction_history_maximum)
        );
        
        /**
         * Put the wallet.keypool.size into property tree.
         */
        pt.put(
            "wallet.keypool.size", std::to_string(m_wallet_keypool_size)
        );
        
        /**
         * Put the zerotime.depth into property tree.
         */
        pt.put(
            "zerotime.depth", std::to_string(m_zerotime_depth)
        );
        
        /**
         * Put the zerotime.answers.minimum into property tree.
         */
        pt.put(
            "zerotime.answers.minimum",
            std::to_string(m_zerotime_answers_minimum)
        );
        
        /**
         * Put the wallet.rescan into property tree.
         */
        pt.put(
            "wallet.rescan", std::to_string(m_wallet_rescan)
        );
        
        /**
         * Put the mining.proof-of-stake into property tree.
         */
        pt.put(
            "mining.proof-of-stake", std::to_string(m_mining_proof_of_stake)
        );
        
        /**
         * Put the chainblender.debug_options into property tree.
         */
        pt.put(
            "chainblender.debug_options",
            std::to_string(m_chainblender_debug_options)
        );
        
        /**
         * Put the chainblender.use_common_output_denominations into property
         * tree.
         */
        pt.put(
            "chainblender.use_common_output_denominations",
            std::to_string(m_chainblender_use_common_output_denominations)
        );
        
        /**
         * Make sure the database.cache_size stays within a range.
         */
        if (m_database_cache_size < 1 || m_database_cache_size > 2048)
        {
            m_database_cache_size = db_env::default_cache_size;
        }
        
        /**
         * Put the database.cache_size into property tree.
         */
        pt.put(
            "database.cache_size", std::to_string(m_database_cache_size)
        );
        
        /**
         * Put the wallet.deterministic into property tree.
         */
        pt.put(
            "wallet.deterministic", std::to_string(m_wallet_deterministic)
        );
        
        /**
         * Put the database.private into property tree.
         */
        pt.put(
            "database.private", std::to_string(m_db_private)
        );
        
        /**
         * The std::stringstream.
         */
        std::stringstream ss;
        
        /**
         * Write property tree to json file.
         */
        write_json(ss, pt, true);
        
        /**
         * Open the output file stream.
         */
        std::ofstream ofs(
            filesystem::data_path() + "config.dat"
        );
        
        /**
         * Write the json.
         */
        ofs << ss.str();
        
        /**
         * Flush to disk.
         */
        ofs.flush();
    }
    catch (std::exception & e)
    {
        log_error("Configuration failed to save, what = " << e.what() << ".");
        
        return false;
    }
    
    return true;
}

void configuration::set_args(const std::map<std::string, std::string>  & val)
{
    m_args = val;
}

std::map<std::string, std::string> & configuration::args()
{
    return m_args;
}

void configuration::set_network_port_tcp(const std::uint16_t & val)
{
    m_network_port_tcp = val;
}

const std::uint16_t & configuration::network_port_tcp() const
{
    return m_network_port_tcp;
}

void configuration::set_network_tcp_inbound_maximum(const std::size_t & val)
{
    if (val < network::tcp_inbound_minimum)
    {
        m_network_tcp_inbound_maximum = network::tcp_inbound_minimum;
    }
    else
    {
        m_network_tcp_inbound_maximum = val;
    }
}

const std::size_t & configuration::network_tcp_inbound_maximum() const
{
    return m_network_tcp_inbound_maximum;
}

void configuration::set_network_udp_enable(const bool & val)
{
    m_network_udp_enable = val;
}

const bool & configuration::network_udp_enable() const
{
    return m_network_udp_enable;
}

void configuration::set_rpc_port(const std::uint16_t & val)
{
    m_rpc_port = val;
}

const std::uint16_t & configuration::rpc_port() const
{
    return m_rpc_port;
}

void configuration::set_chainblender_debug_options(const bool & val)
{
    m_chainblender_debug_options = val;
}

const bool & configuration::chainblender_debug_options() const
{
    return m_chainblender_debug_options;
}

void configuration::set_chainblender_use_common_output_denominations(
    const bool & val
    )
{
    m_chainblender_use_common_output_denominations = val;
}

const bool & configuration::chainblender_use_common_output_denominations() const
{
    return m_chainblender_use_common_output_denominations;
}

void configuration::set_database_cache_size(const std::uint32_t & val)
{
    m_database_cache_size = val;
}

const std::uint32_t & configuration::database_cache_size() const
{
    return m_database_cache_size;
}

void configuration::set_wallet_deterministic(const bool & val)
{
    m_wallet_deterministic = val;
}

const bool & configuration::wallet_deterministic() const
{
    return m_wallet_deterministic;
}

void configuration::set_db_private(const bool & val)
{
    m_db_private = val;
}

const bool & configuration::db_private() const
{
    return m_db_private;
}
