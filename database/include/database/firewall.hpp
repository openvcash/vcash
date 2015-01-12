/*
 * Copyright (c) 2008-2014 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of coinpp.
 *
 * coinpp is free software: you can redistribute it and/or modify
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

#ifndef DATABASE_FIREWALL_HPP
#define DATABASE_FIREWALL_HPP

namespace database {

    class firewall
    {
        public:
        
            /**
             * The implementation.
             */
            class impl
            {
                public:
                    virtual bool start() = 0;
                    virtual bool stop() = 0;
					virtual bool is_enabled() { return false; }
            };
        
            /**
             * Constructor
             */
            firewall();
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The implementation.
             */
            impl * impl_;
    };
}

#endif // DATABASE_FIREWALL_HPP
