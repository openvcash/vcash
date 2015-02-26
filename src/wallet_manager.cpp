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

#include <coin/wallet_manager.hpp>

using namespace coin;

wallet_manager & wallet_manager::instance()
{
    static wallet_manager g_wallet_manager;
    
    return g_wallet_manager;
}

void wallet_manager::register_wallet(const std::shared_ptr<wallet> & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (val)
    {
        val->start();
        
        m_wallets.insert(val);
    }
}

void wallet_manager::unregister_wallet(const std::shared_ptr<wallet> & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (val)
    {
        val->stop();
        
        m_wallets.erase(val);
    }
}

bool wallet_manager::is_from_me(const transaction & tx) const
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        if (i->is_from_me(tx))
        {
            return true;
        }
    }
    
    return false;
}

void wallet_manager::erase_from_wallets(const sha256 & val) const
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        i->erase_from_wallet(val);
    }
}

void wallet_manager::sync_with_wallets(
    const transaction & tx, block * blk, const bool & update,
    const bool & connect
    )
{
    if (connect == false)
    {
        /**
         * Wallets need to refund inputs when disconnecting coinstake (ppcoin).
         */
        if (tx.is_coin_stake())
        {
            std::lock_guard<std::mutex> l1(mutex_);
            
            for (auto & i : m_wallets)
            {
                if (i->is_from_me(tx))
                {
                    i->disable_transaction(tx);
                }
            }
        }
    }
    else
    {
        std::lock_guard<std::mutex> l1(mutex_);
        
        for (auto & i : m_wallets)
        {
            i->add_to_wallet_if_involving_me(tx, blk, update);
        }
    }
}

bool wallet_manager::get_transaction(
    const sha256 & hash_tx, transaction_wallet & wtx_out
    )
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        if (i->get_transaction(hash_tx, wtx_out))
        {
            return true;
        }
    }
    
    return false;
}

void wallet_manager::set_best_chain(const block_locator val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        i->set_best_chain(val);
    }
}

void wallet_manager::on_transaction_updated(const sha256 & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        i->on_transaction_updated(val);
    }
}

void wallet_manager::on_inventory(const sha256 & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    for (auto & i : m_wallets)
    {
        i->on_inventory(val);
    }
}
