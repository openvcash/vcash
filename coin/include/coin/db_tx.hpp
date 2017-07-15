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

#ifndef COIN_DB_TX_HPP
#define COIN_DB_TX_HPP

#define USE_LEVELDB 0

#if (defined USE_LEVELDB && USE_LEVELDB)
#include <coin/db_tx_ldb.hpp>
#else
#include <coin/db_tx_bdb.hpp>
#endif // USE_LEVELDB

namespace coin {

    // ...
    
} // namespace coin

#endif // COIN_DB_TX_HPP
