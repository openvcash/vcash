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

#ifndef COIN_SIGNATURE_CACHE_HPP
#define COIN_SIGNATURE_CACHE_HPP

#include <cstdint>
#include <mutex>
#include <set>
#include <tuple>
#include <vector>

#include <coin/sha256.hpp>

namespace coin {

    /**
     * Implements a signature cache. It is ok for this to be a
     * singleton even in the presence of multiple instances in the same
     * memory space.
     */
    class signature_cache
    {
        public:
        
            /**
             * Signature data.
             */
            typedef std::tuple<
                sha256, std::vector<std::uint8_t>, std::vector<std::uint8_t>
            > signature_data_t;
        
            /**
             * The singleton accessor.
             */
            static signature_cache & instance();
        
            bool get(
                sha256 hash, const std::vector<std::uint8_t> & signature,
                const std::vector<std::uint8_t> & public_key
            );

            void set(
                sha256 hash, const std::vector<std::uint8_t>& signature,
                const std::vector<std::uint8_t>& public_key
            );
    
        private:
        
            /**
             * The maximum cache size. Limits the cache size to less than
             * 10MB (~200 bytes per cache entry times 50,000 entries). Since
             * there are a maximum of 20,000 signature operations per block
             * 50,000 is a reasonable default.
             */
            enum { max_cache_size = 50000};
        
            /**
             * The valid signatures.
             */
            std::set<signature_data_t> m_valid;
        
        protected:
        
            /**
             * The std::mutex.
             */
            std::mutex mutex_;
    };
    
} // namespace coin

#endif // COIN_SIGNATURE_CACHE_HPP
