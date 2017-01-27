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

#ifndef COIN_REWARD_HPP
#define COIN_REWARD_HPP

#include <cstdint>

#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements various reward algorithms.
     */
    class reward
    {
        public:
        
            /**
             * Miner's coin base reward.
             * @param height The height.
             * @param fees The fees.
             * @param hash_previous The sha256.
             */
            static std::int64_t get_proof_of_work(
                const std::int32_t & height, const std::int64_t & fees,
                const sha256 & hash_previous
            );

            /**
             * Gets the reward for the proof of stake for the configured
             * algorithm.
             * @param coin_age The coin age.
             * @param bits The bits.
             * @param time The time.
             * @param height The height.
             */
            static std::int64_t get_proof_of_stake(
                const std::int64_t & coin_age, const std::uint32_t & bits,
                const std::uint32_t & time, const std::int32_t & height
            );
        
        private:
        
            /**
             * Miner's coin base reward for the ppcoin algorithm.
             * @param height The height.
             * @param fees The fees.
             * @param hash_previous The sha256.
             */
            static std::int64_t get_proof_of_work_ppcoin(
                const std::int32_t & height, const std::int64_t & fees,
                const sha256 & hash_previous
            );

            /**
             * Miner's coin base reward for the vanilla algorithm.
             * @param height The height.
             * @param fees The fees.
             * @param hash_previous The sha256.
             */
            static std::int64_t get_proof_of_work_vanilla(
                const std::int32_t & height, const std::int64_t & fees,
                const sha256 & hash_previous
            );
        
            /**
             * Gets the reward for the proof of stake for the ppcoin algorithm.
             * @param coin_age The coin age.
             * @param bits The bits.
             * @param time The time.
             * @param height The height.
             */
            static std::int64_t get_proof_of_stake_ppcoin(
                const std::int64_t & coin_age, const std::uint32_t & bits,
                const std::uint32_t & time, const std::int32_t & height
            );
        
            /**
             * Gets the reward for the proof of stake for the vanilla algorithm.
             * @param coin_age The coin age.
             * @param bits The bits.
             * @param time The time.
             * @param height The height.
             */
            static std::int64_t get_proof_of_stake_vanilla(
                const std::int64_t & coin_age, const std::uint32_t & bits,
                const std::uint32_t & time, const std::int32_t & height
            );
        
        protected:
    
            // ...
    };

} // namespace coin

#endif // COIN_REWARD_HPP
