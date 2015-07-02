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

#include <coin/logger.hpp>
#include <coin/time.hpp>
#include <coin/transaction.hpp>
#include <coin/zerotime.hpp>

using namespace coin;

zerotime & zerotime::instance()
{
    static zerotime g_zerotime;
    
    std::lock_guard<std::mutex> l1(mutex_);
    
    return g_zerotime;
}

std::map<point_out, sha256> & zerotime::locked_inputs()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    return m_locked_inputs;
}

std::map<sha256, zerotime_lock> & zerotime::locks()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locks_);
    
    return m_locks;
}

bool zerotime::has_lock_conflict(const transaction & tx)
{
    for (auto & i : tx.transactions_in())
    {
        if (m_locked_inputs.count(i.previous_out()) > 0)
        {
            if (m_locked_inputs[i.previous_out()] != tx.get_hash())
            {
                return true;
            }
        }
    }

    return false;
}

void zerotime::clear_expired_input_locks()
{
    std::lock_guard<std::recursive_mutex> l1(recursive_mutex_locked_inputs_);
    
    std::lock_guard<std::recursive_mutex> l2(recursive_mutex_locks_);
    
    auto it = m_locks.begin();

    while (it != m_locks.end())
    {
        if (time::instance().get_adjusted() > it->second.expiration())
        {
            log_info(
                "ZeroTime is removing expired transaction lock " <<
                it->second.hash_tx().to_string() << "."
            );

            if (m_locks.count(it->second.hash_tx()))
            {
                auto & tx = m_locks[it->second.hash_tx()];

                for (auto & in : tx.transactions_in())
                {
                    m_locked_inputs.erase(in.previous_out());
                }
                
                m_locks.erase(it->second.hash_tx());
            }

            it = m_locks.erase(it);
        }
        else
        {
            it++;
        }
    }
}
