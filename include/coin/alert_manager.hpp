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

#ifndef COIN_ALERT_MANAGER_HPP
#define COIN_ALERT_MANAGER_HPP

#include <map>
#include <mutex>

#include <boost/asio.hpp>

#include <coin/alert.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class stack_impl;
    
    /**
     * Implements an alert manager.
     */
    class alert_manager
    {
        public:
        
            /**
             * Constructor
             * @param ios The boost::asio::io_service.
             * @param owner The stack_impl.
             */
            alert_manager(
                boost::asio::io_service & ios, stack_impl & owner
            );
        
            /**
             *
             * Processes an alert.
             * @param val The alert.
             */
            bool process(const alert & val);
    
            /**
             * Finds an alert by hash.
             */
            alert get(const sha256 & val);
    
            /**
             * The alerts.
             */
            const std::map<sha256, alert> & alerts() const;
        
        private:
        
            /**
             * The alerts.
             */
            std::map<sha256, alert> m_alerts;
        
        protected:
        
            /**
             * The boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;
        
            /**
             * The boost::asio::strand.
             */
            boost::asio::strand strand_;
        
            /**
             * The stack_impl.
             */
            stack_impl & stack_impl_;

            /**
             * The std::mutex
             */
            mutable std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_ALERT_MANAGER_HPP
