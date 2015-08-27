/*
 * Copyright (c) 2013-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This file is part of Vanilacoin.
 *
 * Vanilacoin is free software: you can redistribute it and/or modify
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
 
#ifndef CRAWLER_STACK_HPP
#define CRAWLER_STACK_HPP

#include <map>
#include <string>

namespace crawler {

    class stack_impl;
    
    /**
     * The stack.
     */
    class stack
    {
        public:
        
            /**
             * Constructor
             */
            stack();
            
            /**
             * Starts the stack.
             * @param args The arguments.
             */
            void start(
                const std::map<std::string, std::string> & args =
                std::map<std::string, std::string> ()
            );
            
            /**
             * Stops the stack.
             */
            void stop();
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The stack implementation.
             */
            stack_impl * stack_impl_;
    };

} // namespace crawler

#endif // CRAWLER_STACK_HPP
