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
    return -1;
}

std::int64_t reward::get_proof_of_work_vanilla(
    const std::int32_t & height, const std::int64_t & fees,
    const sha256 & hash_previous
    )
{
    std::int64_t subsidy = 0;

    if (height >= 136400 && height <= 136400 + 1000)
    {
        subsidy = 1;
    }
    else
    {
        subsidy = 0;

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

        if (height < 325000)
        {
            for (auto i = 50000; i <= height; i += 50000)
            {
                subsidy -= subsidy / 6;
            }
        }
        else if (height < 385000)
        {
            for (auto i = 10000; i <= height; i += 10000)
            {
                subsidy -=
                    subsidy / 28 - ((double)(10000.0f / height) *
                    ((double)(10000.0f / height)))
                ;
                
                subsidy -= (subsidy / 28 * 4) / 28;
            }
        }
        else
        {
            for (auto i = 7000; i <= height; i += 7000)
            {
                subsidy -=
                    subsidy / 28 - ((double)(10000.0f / height) *
                    ((double)(10000.0f / height)))
                ;
                
                subsidy -= (subsidy / 28 * 4) / 28;
            }
        }
        
        if ((subsidy / 1000000.0f) < 1.0f)
        {
            subsidy = 1;
            
            subsidy *= 1000000;
        }
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
    
    coin_reward_year = 1 * constants::max_mint_proof_of_stake;
    
    std::int64_t subsidy = coin_age * coin_reward_year / 365;
    
    log_debug(
        "Reward (vanilla) create = " << subsidy << ", coin age = " <<
        coin_age << ", bits = " << bits << "."
    );
    
    return subsidy;
}
