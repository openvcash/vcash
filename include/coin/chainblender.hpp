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
             * Create the denominations.
             */
            std::set<std::int64_t> denominations();
        
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
        
        private:
        
            /**
             * The sessions.
             */
            std::map<sha256, session_t> m_sessions;
        
        protected:
        
            /**
             * The std::mutex.
             */
            static std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_CHAINBLENDER_HPP
