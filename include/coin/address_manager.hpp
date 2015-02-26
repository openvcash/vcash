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

#ifndef COIN_ADDRESS_MANAGER_HPP
#define COIN_ADDRESS_MANAGER_HPP

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <vector>

#include <boost/asio.hpp>

#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/protocol.hpp>
#include <coin/time.hpp>

namespace coin {

    /**
     * Implements an address manager.
     */
    class address_manager
    {
        public:
        
            /**
             * The address info structure.
             */
            typedef struct address_info_s
            {
                /**
                 * Initializes the strcuture with the given addresses.
                 */
                static address_info_s init(
                    const protocol::network_address_t & addr,
                    const protocol::network_address_t & addr_src
                    )
                {
                    address_info_s ret;
                    
                    ret.addr = addr;
                    ret.addr_src = addr_src.address;
                    ret.last_success = 0;
                    ret.last_attempts = 0;
                    ret.reference_count = 0;
                    ret.tried = false;
                    ret.random_position = 0;
                    
                    assert(ret.addr.is_valid());
                    
                    return ret;
                }
            
                /* Stored in Memory and on Disk */
                
                /**
                 * The address.
                 */
                protocol::network_address_t addr;
                
                /**
                 * Where knowledge of the address originated.
                 */
                std::array<std::uint8_t, 16> addr_src;
                
                /**
                 * The last successful connection by us.
                 */
                std::uint64_t last_success;
                
                /**
                 * The number of connection attempts since the last successful
                 * attempt.
                 */
                std::uint32_t last_attempts;
                
                /* Stored in Memory Only */
                
                /**
                 * Reference count in sets.
                 */
                std::uint32_t reference_count;
                
                /**
                 * If true the address is in a tried set.
                 */
                bool tried;
                
                /**
                 * The randomized position.
                 */
                std::uint32_t random_position;
                
                /**
                 * Calculates the tried bucket index.
                 * @param key The key.
                 */
                std::uint32_t calculate_tried_bucket(
                    const std::vector<std::uint8_t> & key
                    )
                {
                    std::vector<std::uint8_t> buf1, buf2;
                    
                    std::vector<std::uint8_t> addr_key = addr.key();
                    
                    buf1.insert(buf1.end(), key.begin(), key.end());
                    buf1.insert(buf1.end(), addr_key.begin(), addr_key.end());
   
                    auto h1 = hash::sha256d(&buf1[0], buf1.size());
                    
                    auto hash1 = hash::to_uint64(&h1[0]);

                    std::vector<std::uint8_t> group_key = addr.group();

                    buf2.insert(buf2.end(), key.begin(), key.end());
                    buf2.insert(
                        buf2.end(), group_key.begin(), group_key.end()
                    );
                    std::uint64_t hash1_m4 = (hash1 % 4);
                    buf2.insert(
                        buf2.end(), &hash1_m4, &hash1_m4 + sizeof(hash1_m4)
                    );
                    
                    auto h2 = hash::sha256d(&buf2[0], buf2.size());
                    
                    auto hash2 = hash::to_uint64(&h2[0]);

                    return hash2 % 64;
                }

                /**
                 * Calculates the new bucket index.
                 * @param key The key.
                 */
                std::uint32_t calculate_new_bucket(
                    const std::vector<std::uint8_t> & key,
                    const protocol::network_address_t & addr_src
                    )
                {
                    std::vector<std::uint8_t> buf1, buf2;
                    
                    std::vector<std::uint8_t> group_key = addr.group();
                    std::vector<std::uint8_t> group_key_src = addr_src.group();

                    buf1.insert(buf1.end(), key.begin(), key.end());
                    buf1.insert(
                        buf1.end(), group_key.begin(), group_key.end()
                    );
                    buf1.insert(
                        buf1.end(), group_key_src.begin(), group_key_src.end()
                    );
                    auto h1 = hash::sha256d(&buf1[0], buf1.size());
                    auto hash1 = hash::to_uint64(&h1[0]);

                    buf2.insert(buf2.end(), key.begin(), key.end());
                    buf2.insert(
                        buf2.end(), group_key_src.begin(), group_key_src.end()
                    );
                    std::uint64_t hash1_m32 = (hash1 % 32);
                    buf2.insert(
                        buf2.end(), &hash1_m32, &hash1_m32 + sizeof(hash1_m32)
                    );
                    
                    auto h2 = hash::sha256d(&buf2[0], buf2.size());
                    
                    auto hash2 = hash::to_uint64(&h2[0]);

                    return hash2 % 256;
                }
                
                /**
                 * If true the the address is terrible.
                 */
                bool is_terrible(
                    std::uint64_t now = time::instance().get_adjusted()
                    ) const
                {
                    /**
                     * Check if in the last minute.
                     */
                    if (addr.last_try && addr.last_try >= now - 60)
                    {
                        return false;
                    }

                    /**
                     * Check if back from the future.
                     */
                    if (addr.timestamp > now + 10 * 60)
                    {
                        return true;
                    }

                    /**
                     * Check if not seen in over a month.
                     */
                    if (
                        addr.timestamp == 0 || now - addr.timestamp > 30 * 86400
                        )
                    {
                        return true;
                    }

                    /**
                     * Check if tried three times without success.
                     */
                    if (last_success == 0 && last_attempts >= 3)
                    {
                        return true;
                    }

                    /**
                     * Check for 10 successive failures in the last week.
                     */
                    if (
                        now - last_success > 7 * 86400 && last_attempts >= 10
                        )
                    {
                        return true;
                    }

                    return false;
                }

                /**
                 * Calculate the relative chance this entry should be given
                 * when selecting nodes to connect to
                 */
                double get_chance(
                    std::uint64_t now = time::instance().get_adjusted()
                    ) const
                {
                    double ret = 1.0;

                    auto since_last_seen = now - addr.timestamp;
                    auto since_last_try = now - addr.last_try;

                    ret *= 600.0 / (600.0 + since_last_seen);

                    /**
                     * Deprioritize very recent attempts away.
                     */
                    if (since_last_try < 60 * 10)
                    {
                        ret *= 0.01;
                    }
                    
                    /**
                     * Deprioritize 50% after each failed attempt.
                     */
                    for (auto n = 0; n < last_attempts; n++)
                    {
                        ret /= 1.5;
                    }
                    
                    return ret;
                }
    

            } address_info_t;
        
            /**
             * Constructor
             */
            address_manager();
        
            /**
             * Starts
             */
            void start();
        
            /**
             * Stops
             */
            void stop();
        
            /**
             * Loads the file from disk.
             */
            bool load();
        
            /**
             * Saves the file to disk.
             */
            void save();
 
            /**
             * Finds address_info_t from a protocol::network_address_t.
             * @param addr The protocol::network_address_t.
             * @param ptr_id The ptr_id.
             */
            address_manager::address_info_t * find(
                const protocol::network_address_t & addr,
                std::uint32_t * ptr_id = 0
            );
    
            /**
             * Selects a protocol::network_address_t from a bucket.
             * @param unk_bias How much in percentage to favor new over tried
             * entries.
             */
            protocol::network_address_t select(
                const std::uint8_t & unk_bias = 50
            );
        
            /**
             * Called when a connection attempt to an address is made.
             * @param addr The protocol::network_address_t.
             * @param timestamp The timestamp.
             */
            void on_connection_attempt(
                const protocol::network_address_t & addr,
                const std::uint64_t & timestamp =
                time::instance().get_adjusted()
            );
        
            /**
             * Called when a connection to an address is established.
             * @param addr The protocol::network_address_t.
             * @param timestamp The timestamp.
             */
            void on_connected(
                const protocol::network_address_t & addr,
                const std::uint64_t & timestamp =
                time::instance().get_adjusted()
            );

            /**
             * Marks an entry as being good.
             * @param addr The protocol::network_address_t.
             * @param
             */
            void mark_good(
                const protocol::network_address_t & addr,
                const std::uint64_t &  timestamp =
                time::instance().get_adjusted()
            );
        
            /**
             * Moves an entry from the "new" table to the "tried" table.
             * @param info The address_info_t.
             * @param nid The nid.
             * @param bucket_index The bucket index.
             */
            void move_to_tried(
                address_info_t & info, const std::uint32_t & nid,
                const std::uint32_t & bucket_index
            );
        
            /**
             * Creates an address_info_t.
             * @param addr The address.
             * @param addr_src The source from where the address was learned.
             * @param ptr_id The ptr_id.
             */
            address_info_t & create(
                const protocol::network_address_t & addr,
                const protocol::network_address_t  & addr_src,
                std::uint32_t * ptr_id = 0
            );
        
            /**
             * Adds a protocol::network_address_t.
             * @param addr The protocol::network_address_t.
             * @param addr_src The protocol::network_address_t from which the
             * addr was learned.
             * @param time_penalty The time penalty if any.
             */
            bool add(
                const protocol::network_address_t & addr,
                const protocol::network_address_t & addr_src,
                const std::uint64_t & time_penalty = 0
            );
        
            /**
             * Gets up to the given number of addresses.
             * count The count.
             */
            std::vector<protocol::network_address_t> get_addr(
                const std::size_t & count = 2500
            );
        
            /**
             * The size.
             */
            const std::size_t size() const;
        
        private:

            /**
             * Returns the position in given bucket index to replace.
             * @param bucket_index The bucket index.
             */
            std::int32_t select_tried(const std::uint32_t & bucket_index);
        
            /**
             * Shrinks a new bucket at the given index.
             * @param index The index.
             */
            void shrink_bucket_new(const std::uint32_t & index);
        
            /**
             * Swaps random first and second in the random id's.
             * @param first The first.
             * @param second The second.
             */
            void swap_random(
                const std::uint32_t & first, const std::uint32_t & second
            );
        
        protected:
        
            /**
             * The key used to randomize bucket selection.
             */
            std::vector<std::uint8_t> key_;
    
            /**
             * The address_info_t map.
             */
            std::map<std::uint32_t, address_info_t> address_info_map_;

            /**
             * The protocol::network_address_t map.
             */
            std::map<protocol::network_address_t, std::uint32_t>
                network_address_map_
            ;
    
            /**
             * The randomly ordered id's.
             */
            std::vector<std::uint32_t> random_ids_;
        
            /**
             * The random_ids_ std::recursive_mutex.
             */
            mutable std::recursive_mutex mutex_random_ids_;

            /**
             * The last used id.
             */
            std::uint32_t id_count_;
            
            /**
             * The number of tried entries.
             */
            std::uint32_t number_tried_;

            /**
             * The number of new entries.
             */
            std::uint32_t number_new_;
    
            /**
             * The new buckets.
             */
            std::vector< std::set<std::uint32_t> > buckets_new_;
        
            /**
             * The buckets_new_ std::recursive_mutex.
             */
            std::recursive_mutex mutex_buckets_new_;
        
            /**
             * The tried buckets.
             */
            std::vector< std::vector<std::uint32_t> > buckets_tried_;
        
            /**
             * The buckets_tried_ std::recursive_mutex.
             */
            std::recursive_mutex mutex_buckets_tried_;
    };
    
} // namespace coin

#endif // COIN_ADDRESS_MANAGER_HPP
