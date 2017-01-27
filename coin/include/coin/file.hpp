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

#ifndef coin_file_hpp
#define coin_file_hpp

#include <cstdio>
#include <string>

namespace coin {

    /**
     * Implements a FILE wrapper.
     */
    class file
    {
        public:
        
            /**
             * Constructor
             */
            file();
        
            /**
             * Destructor
             */
            ~file();
        
            /**
             * Opens the file at the given path with modes.
             * @param path The path.
             * @param mode The mode.
             */
            bool open(const char * path, const char * mode);
        
            /**
             * Closes the file.
             */
            void close();
        
            /**
             * Reads len bytes from the file.
             * @param buf The buffer.
             * @param len The length.
             */
            bool read(char * buf, const std::size_t & len);

            /**
             * Reads len bytes from the file.
             * @param buf The buffer.
             * @param len The length.
             */
            bool read(
                char * buf, std::size_t & len
            );
        
            /**
             * Writes len bytes of buf to the file.
             * @param buf The buffer.
             * @param len The length.
             */
            void write(const char * buf, const std::size_t & len);
    
            /**
             * Removes the file at path from disk.
             * @param path The abslute path.
             */
            static bool remove(const std::string & path);

            /**
             * The size.
             */
            long size();
        
            /**
             * Seeks to the offset from the start of the file.
             * @param offset The offset.
             */
            int seek_set(long offset);
        
            /**
             * Seeks to the end of the file.
             */
            bool seek_end();
        
            /**
             * Get current position in stream.
             */
            long ftell();
        
            /**
             * Flush to OS.
             */
            int fflush();
        
            /**
             * Flush to disk.
             */
            int fsync();

            /**
             * The FILE.
             */
            FILE * get_FILE();
        
        private:
        
            /**
             * The FILE.
             */
            FILE * m_file;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif
