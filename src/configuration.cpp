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

#include <cassert>
#include <fstream>
#include <sstream>

#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/configuration.hpp>
#include <coin/filesystem.hpp>
#include <coin/logger.hpp>
#include <coin/network.hpp>
#include <coin/protocol.hpp>
#include <coin/wallet.hpp>

using namespace coin;

configuration::configuration()
    : m_network_port_tcp(protocol::default_tcp_port)
    , m_network_tcp_inbound_maximum(network::tcp_inbound_maximum)
    , m_wallet_transaction_history_maximum(wallet::configuration_interval_history)
    , m_wallet_keypool_size(wallet::configuration_keypool_size)
    , m_wallet_rescan(false)
    , m_mining_proof_of_stake(true)
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
         * Enforce the minimum network.tcp.inbound.maximum.
         */
        if (m_network_tcp_inbound_maximum < network::tcp_inbound_minimum)
        {
            m_network_tcp_inbound_maximum = network::tcp_inbound_minimum;
        }
        
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
    }
    catch (std::exception & e)
    {
        log_error("Configuration failed to load, what = " << e.what() << ".");
    
        return false;
    }
    
    if (m_args.size() > 0)
    {
#if (!defined _MSC_VER)
        #warning :TODO: Iterate the args and override the variables (if found).
#endif
    }
    
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
         * The std::stringstream.
         */
        std::stringstream ss;
        
        /**
         * Write property tree to json file.
         */
        write_json(ss, pt, false);
        
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
