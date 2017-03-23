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

void incentive::set_transaction_in(const transaction_in & tx_in)
{
    m_transaction_in = tx_in;
}

const transaction_in & incentive::get_transaction_in() const
{
    return m_transaction_in;
}

std::map<sha256, incentive_vote> & incentive::votes()
{
    return m_votes;
}

std::map<std::uint32_t, std::pair<std::time_t, std::string> > &
    incentive::winners()
{
    return m_winners;
}

std::map<std::uint32_t, std::set<std::string> > & incentive::runners_up()
{
    return m_runners_up;
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

std::size_t incentive::get_collateral(const std::uint32_t & height)
{
    std::size_t ret = 0;

    std::size_t incentive_collaterlal = 0;

    std::uint32_t incentive_height = 0;

    if (constants::test_net == true)
    {
        incentive_collaterlal = 999;

        incentive_height = 600;
    }
    else
    {
        incentive_collaterlal = 9999;

        incentive_height = 220000;
    }
    
    if (height > incentive_height + (222 * 1) * 0)
    {
        ret = incentive_collaterlal;
    }
    else
    {
        ret = 0;
    }
    
    return ret;
}

std::size_t incentive::get_percentage(const std::uint32_t & height)
{
    std::size_t ret = 0;

    std::uint32_t incentive_height = 0;

    std::uint32_t incentive_height_start = 0;

    if (constants::test_net == true)
    {
        incentive_height = 600;

        incentive_height_start = 500;
    }
    else
    {
        incentive_height = 220000;

        incentive_height_start = 210000;
    }
    
    if (height > incentive_height + (222 * 38) * 38)
    {
        ret = 40;
    }
    else if (height > incentive_height + (222 * 37) * 37)
    {
        ret = 39;
    }
    else if (height > incentive_height + (222 * 36) * 36)
    {
        ret = 38;
    }
    else if (height > incentive_height + (222 * 35) * 35)
    {
        ret = 37;
    }
    else if (height > incentive_height + (222 * 34) * 34)
    {
        ret = 36;
    }
    else if (height > incentive_height + (222 * 33) * 33)
    {
        ret = 35;
    }
    else if (height > incentive_height + (222 * 32) * 32)
    {
        ret = 34;
    }
    else if (height > incentive_height + (222 * 31) * 31)
    {
        ret = 33;
    }
    else if (height > incentive_height + (222 * 30) * 30)
    {
        ret = 32;
    }
    else if (height > incentive_height + (222 * 29) * 29)
    {
        ret = 31;
    }
    else if (height > incentive_height + (222 * 28) * 28)
    {
        ret = 30;
    }
    else if (height > incentive_height + (222 * 27) * 27)
    {
        ret = 29;
    }
    else if (height > incentive_height + (222 * 26) * 26)
    {
        ret = 28;
    }
    else if (height > incentive_height + (222 * 25) * 25)
    {
        ret = 27;
    }
    else if (height > incentive_height + (222 * 24) * 24)
    {
        ret = 26;
    }
    else if (height > incentive_height + (222 * 23) * 23)
    {
        ret = 25;
    }
    else if (height > incentive_height + (222 * 22) * 22)
    {
        ret = 24;
    }
    else if (height > incentive_height + (222 * 21) * 21)
    {
        ret = 23;
    }
    else if (height > incentive_height + (222 * 20) * 20)
    {
        ret = 22;
    }
    else if (height > incentive_height + (222 * 19) * 19)
    {
        ret = 21;
    }
    else if (height > incentive_height + (222 * 18) * 18)
    {
        ret = 20;
    }
    else if (height > incentive_height + (222 * 17) * 17)
    {
        ret = 19;
    }
    else if (height > incentive_height + (222 * 16) * 16)
    {
        ret = 18;
    }
    else if (height > incentive_height + (222 * 15) * 15)
    {
        ret = 17;
    }
    else if (height > incentive_height + (222 * 14) * 14)
    {
        ret = 16;
    }
    else if (height > incentive_height + (222 * 13) * 13)
    {
        ret = 15;
    }
    else if (height > incentive_height + (222 * 12) * 12)
    {
        ret = 14;
    }
    else if (height > incentive_height + (222 * 11) * 11)
    {
        ret = 13;
    }
    else if (height > incentive_height + (222 * 10) * 10)
    {
        ret = 12;
    }
    else if (height > incentive_height + (222 * 9) * 9)
    {
        ret = 11;
    }
    else if (height > incentive_height + (222 * 8) * 8)
    {
        ret = 10;
    }
    else if (height > incentive_height + (222 * 7) * 7)
    {
        ret = 9;
    }
    else if (height > incentive_height + (222 * 6) * 6)
    {
        ret = 8;
    }
    else if (height > incentive_height + (222 * 5) * 5)
    {
        ret = 7;
    }
    else if (height > incentive_height + (222 * 4) * 4)
    {
        ret = 6;
    }
    else if (height > incentive_height + (222 * 3) * 3)
    {
        ret = 5;
    }
    else if (height > incentive_height + (222 * 2) * 2)
    {
        ret = 4;
    }
    else if (height > incentive_height + (222 * 1) * 1)
    {
        ret = 3;
    }
    else if (height > incentive_height + (222 * 1) * 0)
    {
        ret = 2;
    }
    else if (height > incentive_height_start)
    {
        ret = 1;
    }
    else
    {
        ret = 0;
    }
    
    /**
     * Sanity check.
     */
    if (ret > 50)
    {
        ret = 50;
    }
    
    return ret;
}