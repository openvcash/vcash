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
#include <coin/incentive.hpp>
#include <coin/utility.hpp>

using namespace coin;

std::mutex incentive::mutex_;

incentive::incentive()
{
    // ...
}

incentive & incentive::instance()
{
    static incentive g_incentive;
    
    std::lock_guard<std::mutex> l1(mutex_);
    
    return g_incentive;
}

void incentive::set_key(const key & val)
{
    m_key = val;
}

key & incentive::get_key()
{
    return m_key;
}

std::map<sha256, incentive_vote> & incentive::votes()
{
    return m_votes;
}

std::map<std::uint32_t, std::string> & incentive::winners()
{
    return m_winners;
}

std::int16_t incentive::calculate_score(const incentive_vote & ivote)
{
	std::int16_t ret = -1;

	if (
        ivote.block_height() == 0 ||
        ivote.block_height() > globals::instance().best_block_height()
        )
	{
        // ...
	}
	else
	{
        auto index = utility::find_block_index_by_height(
            ivote.block_height()
        );
        
        if (index)
        {
            const auto & hash_block = index->get_block_hash();
            
            if (hash_block == ivote.hash_block())
            {
                if (ivote.public_key().is_valid())
                {
                    /**
                     * Hash the hash public key.
                     */
                    auto digest1 = hash::sha256d(
                        ivote.public_key().get_hash().digest(),
                        sha256::digest_length
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
            }
        }
    }

    return ret;
}

std::int16_t incentive::calculate_score(
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

bool incentive::sign(
    const sha256 & hash_value, std::vector<std::uint8_t> & signature
    )
{
    return m_key.sign(hash_value, signature);
}

bool incentive::verify(
    const key_public & public_key, const sha256 & hash_value,
    const std::vector<std::uint8_t> & signature
    )
{
    key k;

    return
        k.set_public_key(public_key) && k.verify(hash_value, signature)
    ;
}
