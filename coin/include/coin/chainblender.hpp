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

#ifndef COIN_CHAINBLENDER_HPP
#define COIN_CHAINBLENDER_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <set>

#include <boost/asio.hpp>

#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements a chainblender mechanism.
     */
    class chainblender
    {
        public:
        
            /**
             * The denomination mode.
             */
            typedef enum denomination_mode_s
            {
                denomination_mode_auto,
                denomination_mode_low,
                denomination_mode_medium,
                denomination_mode_high,
            } denomination_mode_t;
        
            /**
             * A session.
             */
            typedef struct
            {
                sha256 hash_id;
                std::int64_t denomination;
                std::time_t time;
                std::uint8_t participants;
                bool is_active;
            } session_t;
        
            /**
             * k
             */
            enum { k = 8 };
        
            /**
             * n
             */
            enum { n = 2 };
        
            /**
             * Constructor
             */
            chainblender();
            
            /**
             * The singleton accessor.
             */
            static chainblender & instance();
        
            /**
             * The denominations.
             */
            std::set<std::int64_t> denominations();
        
            /**
             * The blended denominations.
             */
            std::set<std::int64_t> denominations_blended();
        
            /**
             * Calculates the score of a chainblender relay node.
             * @param ep The boost::asio::ip::tcp::endpoint.
             */
            std::int16_t calculate_score(
                const boost::asio::ip::tcp::endpoint & ep
            );
        
            /**
             * The sessions.
             */
            std::map<sha256, session_t> & sessions();
        
            /**
             * Set if we use common output denominations.
             * @param val The value.
             */
            void set_use_common_output_denominations(const bool & val);
        
            /**
             * If true common output denomindations will be used.
             */
            const bool & use_common_output_denominations() const;
        
            /**
             * The denomination mode.
             */
            const denomination_mode_t & denomination_mode() const;
        
        private:
        
            /**
             * The sessions.
             */
            std::map<sha256, session_t> m_sessions;
        
            /**
             * If true common output denomindations will be used.
             */
            bool m_use_common_output_denominations;
        
            /**
             * The denomination mode.
             */
            denomination_mode_t m_denomination_mode;
        
        protected:
        
            /**
             * The std::mutex.
             */
            static std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CHAINBLENDER_HPP
