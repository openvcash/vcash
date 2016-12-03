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

#ifndef COIN_SCRIPT_CHECKER_HPP
#define COIN_SCRIPT_CHECKER_HPP

#include <cstdint>

#include <coin/script.hpp>
#include <coin/transaction.hpp>

namespace coin {
    
    /**
     * Implements a RAII script checker.
     */
    class script_checker
    {
        public:
        
            /**
             * Constructor
             */
            script_checker();
        
            /**
             * Constructor
             * @param tx_from The transaction from.
             * @param tx_to The transaction to.
             * @param n The n.
             * @param strict_pay_to_script_hash If true use strict pay to
             * script hash.
             * @param hash_type The hash type.
             */
            script_checker(
                const transaction & tx_from, const transaction & tx_to,
                const std::uint32_t & n, const bool & strict_pay_to_script_hash,
                const std::int32_t & hash_type
            );
        
            /**
             * Returns true if the script passed validation.
             */
            bool check() const;
        
        private:
        
            /**
             * The script public key.
             */
            script m_script_public_key;
        
            /**
             * The transaction to.
             */
            transaction m_transaction_to;
        
            /**
             * The n.
             */
            std::uint32_t m_n;
        
            /**
             * If true use strict pay to script hash.
             */
            bool m_strict_pay_to_script_hash;
        
            /**
             * The hash type.
             */
            std::int32_t m_hash_type;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_SCRIPT_CHECKER_HPP
