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

#include <coin/chainblender.hpp>
#include <coin/constants.hpp>
#include <coin/globals.hpp>
#include <coin/utility.hpp>

using namespace coin;

std::mutex chainblender::mutex_;

chainblender::chainblender()
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
        static_cast<std::int64_t> (0.5 * constants::coin) + 500,
        static_cast<std::int64_t> (globals::instance().transaction_fee()) + 0,
    };
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
