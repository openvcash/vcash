/*
 * Copyright (c) 2013-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of vanillacoin.
 *
 * Vanillacoin is free software: you can redistribute it and/or modify
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

#include <fstream>
#include <iostream>
#include <random>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/address.hpp>
#include <coin/address_manager.hpp>
#include <coin/alert_manager.hpp>
#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/checkpoint_sync.hpp>
#include <coin/db_env.hpp>
#include <coin/db_tx.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/http_transport.hpp>
#include <coin/kernel.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/mining_manager.hpp>
#include <coin/nat_pmp_client.hpp>
#include <coin/protocol.hpp>
#include <coin/random.hpp>
#include <coin/rpc_manager.hpp>
#include <coin/stack.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/transaction.hpp>
#include <coin/upnp_client.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>

using namespace coin;

#error This file is intentionally left blank
