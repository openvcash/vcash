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

#include <coin/chainblender.hpp>
#include <coin/constants.hpp>
#include <coin/globals.hpp>
#include <coin/utility.hpp>

using namespace coin;

std::mutex chainblender::mutex_;

chainblender::chainblender()
    : m_use_common_output_denominations(true)
    , m_denomination_mode(denomination_mode_auto)
{
    // ...
}

chainblender & chainblender::instance()
{
    static chainblender g_chainblender;
    
    std::lock_guard<std::mutex> l1(mutex_);
    
    return g_chainblender;
}

std::set<std::int64_t> chainblender::denominations()
{
    return
    {
        static_cast<std::int64_t> (500.0 * constants::coin) + 500000,
        static_cast<std::int64_t> (50.0 * constants::coin) + 50000,
        static_cast<std::int64_t> (5.0 * constants::coin) + 5000,
        /**
         * Enable 0.505 denomination when market price has risen from current
         * (Q1 2016) levels.
         */
#if 0
        static_cast<std::int64_t> (0.5 * constants::coin) + 500,
#endif
        static_cast<std::int64_t> (globals::instance().transaction_fee()) + 0,
    };
}

std::set<std::int64_t> chainblender::denominations_blended()
{
    /**
     * Cache the results.
     */
    static std::set<std::int64_t> ret;
    
    if (ret.size() == 0)
    {
        auto denoms = denominations();

        for (auto & i : denoms)
        {
            if (i == globals::instance().transaction_fee())
            {
                continue;
            }
            
            ret.insert(i + globals::instance().transaction_fee());
        }
    }
    
    return ret;
}

std::int16_t chainblender::calculate_score(
    const boost::asio::ip::tcp::endpoint & ep
    )
{
	std::int16_t ret = -1;

    auto index = utility::find_block_index_by_height(
        globals::instance().best_block_height()
    );
    
    if (index)
    {
        const auto & hash_block = index->get_block_hash();

        /**
         * Get the node endpoint.
         */
        auto node_ep =
            ep.address().to_string() + ":" + std::to_string(ep.port())
        ;
        
        /**
         * Hash the endpoint.
         */
        auto digest1 = hash::sha256d(
            reinterpret_cast<const std::uint8_t *>(node_ep.data()),
            node_ep.size()
        );
        
        /**
         * Hash the hash of the block.
         */
        auto digest2 = hash::sha256d(
            hash_block.digest(), sha256::digest_length
        );
        
        auto hash2 = sha256::from_digest(&digest2[0]);

        auto digest3 = hash::sha256d(
            &digest2[0], &digest2[0] + digest2.size(),
            &digest1[0], &digest1[0] + digest1.size()
        );
        
        auto hash3 = sha256::from_digest(&digest3[0]);
        
        if (hash3 > hash2)
        {
            ret =
                static_cast<std::int16_t> (
                (hash3 - hash2).to_uint64())
            ;
        }
        else
        {
            ret =
                static_cast<std::int16_t> (
                (hash2 - hash3).to_uint64())
            ;
        }
    }

    return ret;
}

std::map<sha256, chainblender::session_t> & chainblender::sessions()
{
    return m_sessions;
}

void chainblender::set_use_common_output_denominations(const bool & val)
{
    m_use_common_output_denominations = val;
}

const bool & chainblender::use_common_output_denominations() const
{
    return m_use_common_output_denominations;
}

const chainblender::denomination_mode_t &
    chainblender::denomination_mode() const
{
    return m_denomination_mode;
}
