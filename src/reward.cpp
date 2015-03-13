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

#include <cmath>

#include <coin/constants.hpp>
#include <coin/logger.hpp>
#include <coin/reward.hpp>

using namespace coin;

std::int64_t reward::get_proof_of_work(
    const std::int32_t & height, const std::int64_t & fees,
    const sha256 & hash_previous
    )
{
    return get_proof_of_work_vanilla(height, fees, hash_previous);
}

std::int64_t reward::get_proof_of_stake(
    const std::int64_t & coin_age, const std::uint32_t & bits,
    const std::uint32_t & time, const std::int32_t & height
    )
{
    return get_proof_of_stake_vanilla(coin_age, bits, time, height);
}

std::int64_t reward::get_proof_of_stake_ppcoin(
    const std::int64_t & coin_age, const std::uint32_t & bits,
    const std::uint32_t & time, const std::int32_t & height
    )
{
    static std::int64_t coin_reward_year = constants::cent;
    
    std::int64_t subsidy = coin_age * 33 / (365 * 33 + 8) * coin_reward_year;
   
    log_debug(
        "Reward (ppcoin) create = " << subsidy << ", coin age = " << coin_age <<
        ", bits = " << bits << "."
    );
    
    return subsidy;
}

std::int64_t reward::get_proof_of_work_ppcoin(
    const std::int32_t & height, const std::int64_t & fees,
    const sha256 & hash_previous
    )
{
    // :TODO: get_proof_of_work_ppcoin
    
    return -1;
}

std::int64_t reward::get_proof_of_work_vanilla(
    const std::int32_t & height, const std::int64_t & fees,
    const sha256 & hash_previous
    )
{
    std::int64_t subsidy = 0;
    
    /**
     * The maximum coin supply is 30717658.00 over 13 years
     * Year 1: 15733333.00
     * Year 2: 23409756.00
     * Year 3: 27154646.00
     * Year 4: 28981324.00
     * Year 5: 29872224.00
     */
    subsidy = (1111.0 * (std::pow((height + 1.0), 2.0)));
    
    if (subsidy > 128)
    {
        subsidy = 128;
    }
    
    if (subsidy < 1)
    {
        subsidy = 1;
    }
    
    subsidy *= 1000000;

    for (auto i = 50000; i <= height; i += 50000)
    {
        subsidy -= subsidy / 6;
    }

    /**
     * If the subsidy is less than one cent the miner gets one cent
     * indefinitely.
     */
    if ((subsidy / 1000000.0f) <= 0.01f)
    {
        return 0.01f;
    }
    
    /**
     * Fees are destroyed to limit inflation.
     */
    return subsidy;
}

std::int64_t reward::get_proof_of_stake_vanilla(
    const std::int64_t & coin_age, const std::uint32_t & bits,
    const std::uint32_t & time, const std::int32_t & height
    )
{
    std::int64_t coin_reward_year = constants::max_mint_proof_of_stake;

    enum { yearly_block_count = 365 * 432};
    
    coin_reward_year = 1 * constants::max_mint_proof_of_stake;
    
    std::int64_t subsidy = coin_age * coin_reward_year / 365;
    
    log_debug(
        "Reward (vanilla) create = " << subsidy << ", coin age = " <<
        coin_age << ", bits = " << bits << "."
    );
    
    return subsidy;
}
