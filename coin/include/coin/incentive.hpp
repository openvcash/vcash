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

#ifndef COIN_INCENTIVE_HPP
#define COIN_INCENTIVE_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <vector>

#include <coin/incentive_vote.hpp>
#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/sha256.hpp>
#include <coin/transaction_in.hpp>

#include <boost/asio.hpp>

namespace coin {

    /**
     * Implements an incentive mechanism.
     */
    class incentive
    {
        public:

            /**
             * Constructor
             */
            incentive();
            
            /**
             * The singleton accessor.
             */
            static incentive & instance();
        
            /**
             * Set the incentive key.
             * @param val The value.
             */
            void set_key(const key & val);
        
            /**
             * The incentive key.
             */
            key & get_key();
        
            /**
             * Sets the transaction_in.
             * @param tx_in The transaction_in.
             */
            void set_transaction_in(const transaction_in & tx_in);
        
            /**
             * The transaction_in.
             */
            const transaction_in & get_transaction_in() const;
        
            /**
             * The incentive_vote's.
             */
            std::map<sha256, incentive_vote> & votes();
        
            /**
             * The winners.
             */
            std::map<std::uint32_t, std::pair<std::time_t, std::string> > &
                winners()
            ;
        
            /**
             * The runners up.
             */
            std::map<std::uint32_t, std::set<std::string> > & runners_up();
        
            /**
             * Calculates the score of a incentive_vote's.
             * @param ivote The incentive_vote's.
             */
            std::int16_t calculate_score(const incentive_vote & ivote);
        
            /**
             * Calculates the score of a incentive_vote's.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            std::int16_t calculate_score(
                const boost::asio::ip::tcp::endpoint & ep
            );
        
            /**
             * Signs
             * @param hash_value The hash of the value.
             * @param signature The signature.
             */
            bool sign(
                const sha256 & hash_value,
                std::vector<std::uint8_t> & signature
            );

            /**
             * Verifies
             * @param public_key The public key.
             * @param hash_value The hash of the value.
             * @param signature The signature.
             */
            bool verify(
                const key_public & public_key,
                const sha256 & hash_value,
                const std::vector<std::uint8_t> & signature
            );
        
            /**
             * Calculates the collaeral based on block height.
             * @param height The height of the block.
             */
            std::size_t get_collateral(const std::uint32_t & height);
        
            /**
             * Calculates the percentage based on block height.
             * @param height The height of the block.
             */
            std::size_t get_percentage(const std::uint32_t & height);
       
        private:
        
            /**
             * The incentive key.
             */
            key m_key;
        
            /**
             * The transaction_in.
             */
            transaction_in m_transaction_in;
        
            /**
             * The incentive_vote's.
             */
            std::map<sha256, incentive_vote> m_votes;
        
            /**
             * The winners.
             */
            std::map<
                std::uint32_t, std::pair<std::time_t, std::string> > m_winners
            ;
        
            /**
             * The runners up.
             */
            std::map<std::uint32_t, std::set<std::string> > m_runners_up;
        
        protected:
        
            /**
             * The std::mutex.
             */
            static std::mutex mutex_;
    };
}

#endif // COIN_INCENTIVE_HPP
