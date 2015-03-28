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

#include <coin/globals.hpp>
#include <coin/script.hpp>

using namespace coin;

globals::globals()
    : m_strand(m_io_service)
    , m_state(state_none)
#if (defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    , m_operation_mode(protocol::operation_mode_client)
#else
    , m_operation_mode(protocol::operation_mode_peer)
#endif // __IPHONE_OS_VERSION_MAX_ALLOWED
    , m_debug(true)
    , m_is_client(false)
    , m_version_nonce(0)
    , m_best_block_height(-1)
    , m_time_best_received(0)
    , m_transactions_updated(0)
    , m_peer_block_counts(5, 0)
    , m_transaction_fee(constants::min_tx_fee)
    , m_wallet_unlocked_mint_only(false)
    , m_last_coin_stake_search_interval(0)
    , m_option_rescan(false)
    , m_last_block_transactions(0)
    , m_last_block_size(0)
    , m_money_supply(0)
    , m_coinbase_flags(new script())
{
    /**
     * P2SH (BIP16 support) can be removed eventually.
     */
    auto p2sh = "/P2SH/";

    *m_coinbase_flags << std::vector<std::uint8_t>(p2sh, p2sh + strlen(p2sh));
}

void globals::set_operation_mode(const protocol::operation_mode_t & val)
{
    m_operation_mode = val;
}

protocol::operation_mode_t & globals::operation_mode()
{
    return m_operation_mode;
}

script & globals::coinbase_flags()
{
    return *m_coinbase_flags;
}