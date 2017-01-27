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

#ifndef DATABASE_QUERY_HPP
#define DATABASE_QUERY_HPP

#include <map>
#include <string>

namespace database {

    class query
    {
        public:
        
            /**
             * Constructor
             * @param val The value.
             */
            explicit query(const std::string & val);
        
            /**
             * The query string.
             */
            const std::string & str() const;

            /**
             * The kay/value pairs.
             */
            std::map<std::string, std::string> & pairs();
        
            /**
             * The public pairs.
             */
            std::map<std::string, std::string> & pairs_public();
        
        private:
        
            /**
             * URI decodes.
             * @param val The value.
             */
            static std::string uri_decode(const std::string &);
        
            /**
             * URI encodes.
             * @param val The value.
             */
            static std::string uri_encode(const std::string &);
        
            /**
             * The query string.
             */
            std::string m_str;
        
            /**
             * The key/value pairs.
             */
            std::map<std::string, std::string> m_pairs;
        
            /**
             * The public key/value pairs.
             */
            std::map<std::string, std::string> m_pairs_public;
        
        protected:
        
            // ...
    };
    
} // namespace database

#endif // DATABASE_QUERY_HPP
