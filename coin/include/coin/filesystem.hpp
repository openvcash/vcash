/*
 * Copyright (c) 2013-2016 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
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
 
#ifndef COIN_FILESYSTEM_HPP
#define COIN_FILESYSTEM_HPP

#include <string>
#include <vector>

namespace coin {

    class filesystem
    {
        public:
        
            /** 
             * File exists
             */
            static int error_already_exists;
        
            /**
             * Creates the last directory of the given path.
             * @param path The path.
             */
            static int create_path(const std::string & path);
        
            /**
             * Copies a file from source to destination.
             * @param src The source.
             * @param dest The destination.
             */
            static bool copy_file(
                const std::string & src, const std::string & dest
            );
        
            /**
             * Gets the directory contents at the specified path.
             * @param path The path.
             */
            static std::vector<std::string> path_contents(
                const std::string & path
            );
        
            /** 
             * The user data directory.
             */
            static std::string data_path();
        
            /** 
             * The (old) user data directory.
             */
            static std::string data_path_old();
        
        private:
        
            /** 
             * The user home directory.
             */
            static std::string home_path();
        
        protected:
        
            // ...
    };
    
} // coin

#endif // COIN_FILESYSTEM_HPP
