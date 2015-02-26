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

#include <fstream>
#include <memory>
#include <stdexcept>

#include <boost/asio.hpp>

#include <openssl/rand.h>

#include <coin/address_manager.hpp>
#include <coin/data_buffer.hpp>
#include <coin/hash.hpp>
#include <coin/filesystem.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/random.hpp>

using namespace coin;

address_manager::address_manager()
    : id_count_(0)
    , number_tried_(0)
    , number_new_(0)
    , buckets_new_(std::vector< std::set<std::uint32_t> >(
        256, std::set<std::uint32_t>())
    )
    , buckets_tried_(std::vector< std::vector<std::uint32_t> >(
        64, std::vector<std::uint32_t>(0))
    )
{
    /**
     * Allocate the key.
     */
    key_.resize(32);
    
    /**
     * Randomize the key.
     */
    RAND_bytes(&key_[0], 32);
}

void address_manager::start()
{
    /**
     * Load the file from disk creating the structure in memory.
     */
    if (load() == false)
    {
        /**
         * We failed, save the empty database to disk.
         */
        save();
        
        /**
         * Try again, if thisfails something fatal has occured.
         */
        if (load() == false)
        {
            throw std::runtime_error("failed to write empty peers file");
        }
    }
}

void address_manager::stop()
{
    /**
     * Save the file.
     */
    save();
}

bool address_manager::load()
{
    std::string path = filesystem::data_path() + "peers.dat";
    
    log_info(
        "Address manager is reading peers file, path = " << path << "."
    );
    
    /**
     * Allocate the std::ifstream.
     */
    std::ifstream ifs(path, std::ifstream::in | std::ifstream::binary);
    
    if (ifs)
    {
        /**
         * Get the file length.
         */
        ifs.seekg(0, ifs.end);
        
        std::size_t len = ifs.tellg();
        
        ifs.seekg(0, ifs.beg);
        
        /**
         * Allocate the buffer.
         */
        std::unique_ptr<char> buf(new char[len]);
        
        /**
         * Read the file.
         */
        ifs.read(buf.get(), len);
        
        /**
         * Close the file.
         */
        ifs.close();
        
        /**
         * Calculate the sha256d hash of the data portion.
         */
        auto digest1 = hash::sha256d(
            reinterpret_cast<std::uint8_t *>(buf.get()),
            len - sha256::digest_length
        );
        
        /**
         * Allocate the temporary digest.
         */
        std::array<std::uint8_t, sha256::digest_length> digest2;
        
        /**
         * Copy the digest from the file.
         */
        std::memcpy(
            &digest2[0], buf.get() + (len - sha256::digest_length),
            sha256::digest_length
        );
        
        /**
         * Verify that the two digests match.
         */
        if (
            std::memcmp(&digest1[0], &digest2[0], sha256::digest_length) == 0
            )
        {
            /**
             * Parse the file.
             */
            data_buffer data(buf.get(), len - sha256::digest_length);
            
            /**
             * Decode the file magic from little endian.
             */
            auto magic = data.read_uint32();
            
            if (magic != message::header_magic())
            {
                throw std::runtime_error("invalid file header magic");
            }
            
            /**
             * Read the version byte.
             */
            auto version = data.read_uint8();
            
            (void)version;
            
            /**
             * Read the key length.
             */
            auto key_length = data.read_uint8();
            
            assert(key_length == sha256::digest_length);
        
            /**
             * Read the 32-byte key.
             */
            auto key_bytes = data.read_bytes(sha256::digest_length);
            
            /**
             * Set the key.
             */
            std::memcpy(&key_[0], &key_bytes[0], key_bytes.size());

            /**
             * The number of new peers.
             */
            number_new_ = data.read_uint32();

            /**
             * The number of tried peers.
             */
            number_tried_ = data.read_uint32();

            /**
             * The number of buckets.
             */
            auto number_buckets = data.read_uint32();
            
            log_none(
                "Address manager read version = " << (int)version <<
                ", key_length = " << (int)key_length << ", number_new = " <<
                number_new_ << ", number_tried = " <<
                number_tried_ << ", number_buckets = " << number_buckets << "."
            );
            
            assert(number_buckets == 256);
            
            /**
             * Set the id count.
             */
            id_count_ = 0;
            
            std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
            
            /**
             * Clear the maps.
             */
            address_info_map_.clear();
            network_address_map_.clear();
            random_ids_.clear();
            
            std::lock_guard<std::recursive_mutex> l2(mutex_buckets_new_);
            
            /**
             * Allocate the new buckets.
             */
            buckets_new_ = std::vector< std::set<std::uint32_t> >(
                256, std::set<std::uint32_t>()
            );
            
            std::lock_guard<std::recursive_mutex> l3(mutex_buckets_tried_);
            
            /**
             * Allocate the tried buckets.
             */
            buckets_tried_ = std::vector< std::vector<std::uint32_t> >(
                64, std::vector<std::uint32_t>(0)
            );

            for (auto i = 0; i < number_new_; i++)
            {
                /**
                 * Allocate the address info.
                 */
                address_info_t info;
                
                /**
                 * Zero
                 */
                std::memset(&info, 0, sizeof(info));
                
                /**
                 * Read the protocol::network_address_t.
                 */
                info.addr = data.read_network_address(
                    true, true
                );
                
                /**
                 * Read the ip address.
                 */
                auto ip = data.read_bytes(16);

                /**
                 * Copy
                 */
                std::memcpy(&info.addr_src[0], &ip[0], ip.size());
                
                /**
                 * Read the last success.
                 */
                info.last_success = data.read_uint64();
                
                /**
                 * Read the last attempts.
                 */
                info.last_attempts = data.read_uint32();
                
                log_none(
                    "NEW: version = " << (int)info.addr.version <<
                    ", ep = " << info.addr.ipv4_mapped_address() << ":" <<
                    info.addr.port << ", last_success = " << info.last_success <<
                    ", last_attempts = " << info.last_attempts << "."
                );

                address_info_map_[i] = info;
                network_address_map_[info.addr] = i;
                info.random_position = static_cast<std::uint32_t> (
                    random_ids_.size()
                );
                random_ids_.push_back(i);
                
                if (number_buckets == 256)
                {
                    // ...
                }
                else
                {
                    buckets_new_[info.calculate_tried_bucket(key_)].insert(i);
                    
                    info.reference_count++;
                }
            }
            
            id_count_ = number_new_;
            
            auto number_lost = 0;
            
            for (auto i = 0; i < number_tried_; i++)
            {
                /**
                 * Allocate the address info.
                 */
                address_info_t info;
                
                /**
                 * Zero
                 */
                std::memset(&info, 0, sizeof(info));
                
                /**
                 * Read the protocol::network_address_t.
                 */
                info.addr = data.read_network_address(
                    true, true
                );

                /**
                 * Read the ip address.
                 */
                auto ip = data.read_bytes(16);

                /**
                 * Copy
                 */
                std::memcpy(&info.addr_src[0], &ip[0], ip.size());
                
                /**
                 * Read the last success.
                 */
                info.last_success = data.read_uint64();
                
                /**
                 * Read the last attempts.
                 */
                info.last_attempts = data.read_uint32();
                
                log_none(
                    "TRIED: i = " << i << ", version = " <<
                    (int)info.addr.version << ", ep = " <<
                    info.addr.ipv4_mapped_address() << ":" << info.addr.port <<
                    ", last_success = " << info.last_success <<
                    ", last_attempts = " << info.last_attempts << "."
                );
                
                auto & tried = buckets_tried_[info.calculate_tried_bucket(key_)];
                
                if (tried.size() < 64)
                {
                    info.random_position = static_cast<std::uint32_t> (
                        random_ids_.size()
                    );
                    info.tried = true;
                    random_ids_.push_back(id_count_);
                    address_info_map_[id_count_] = info;
                    network_address_map_[info.addr] = id_count_;
                    tried.push_back(id_count_);
                    id_count_++;
                }
                else
                {
                    number_lost++;
                }
            }
            
            number_tried_ -= number_lost;
            
            for (auto i = 0; i < number_buckets; i++)
            {
                /**
                 * Get the new bucket.
                 */
                auto & bucket_new = buckets_new_[i];
                
                /**
                 * Read the size.
                 */
                auto size = data.read_uint32();

                for (auto j = 0; j < size; j++)
                {
                    /**
                     * Read the index.
                     */
                    auto index = data.read_uint32();
                    
                    auto & addr_info = address_info_map_[index];
                    
                    if (number_buckets == 256 && addr_info.reference_count < 4)
                    {
                        addr_info.reference_count++;
                        
                        bucket_new.insert(index);
                    }
                }
            }
        }
        else
        {
            throw std::runtime_error("invalid file checksum");
        }
    }
    else
    {
        log_error(
            "Address manager failed reading peers file, path = " << path <<
            " writing default file."
        );
        
        return false;
    }
    
    return true;
}

void address_manager::save()
{
    /**
     * Allocate the data_buffer.
     */
    data_buffer data;
    
    /**
     * Write the file magic.
     */
    data.write_uint32(message::header_magic());
    
    /**
     * Write the version byte.
     */
    data.write_uint8(0);
    
    /**
     * Write the key length.
     */
    data.write_uint8(sha256::digest_length);

    /**
     * Write the 32-byte key.
     */
    data.write_bytes(reinterpret_cast<const char *>(&key_[0]), key_.size());
    
    /**
     * Write the number of new peers.
     */
    data.write_uint32(number_new_);

    /**
     * Write the number of tried peers.
     */
    data.write_uint32(number_tried_);

    /**
     * Write the number of buckets.
     */
    data.write_uint32(256);
    
    auto nids = 0;
    
    std::map<std::uint32_t, std::uint32_t> unk_ids;
    
    /**
     * Write the new.
     */
    for (
        auto it = address_info_map_.begin(); it != address_info_map_.end(); ++it
        )
    {
        if (nids == number_new_)
        {
            break;
        }
    
        unk_ids[it->first] = nids;
    
        auto & info = it->second;
        
        if (info.reference_count > 0)
        {
            assert(info.addr.is_valid());
            
            /**
             * Write the network address.
             */
            data.write_network_address(info.addr, true, true);
            
            /**
             * Write the source ip address.
             */
            data.write_bytes(
                reinterpret_cast<const char *>(&info.addr_src[0]),
                info.addr_src.size()
            );

            /**
             * Write the last success.
             */
            data.write_uint64(info.last_success);

            /**
             * Read the last attempts.
             */
            data.write_uint32(info.last_attempts);
            
            nids++;
        }
    }
    
    nids = 0;
    
    /**
     * Write the tried.
     */
    for (
        auto it = address_info_map_.begin(); it != address_info_map_.end(); ++it
        )
    {
        if (nids == number_tried_)
        {
            break;
        }
        
        auto & info = it->second;

        if (info.tried)
        {
            assert(info.addr.is_valid());
            
            /**
             * Write the network address.
             */
            data.write_network_address(info.addr, true, true);
            
            /**
             * Write the source ip address.
             */
            data.write_bytes(
                reinterpret_cast<const char *>(&info.addr_src[0]),
                info.addr_src.size()
            );

            /**
             * Write the last success.
             */
            data.write_uint64(info.last_success);

            /**
             * Read the last attempts.
             */
            data.write_uint32(info.last_attempts);
            
            nids++;
        }
    }

    std::lock_guard<std::recursive_mutex> l1(mutex_buckets_new_);
    
    /**
     * Write the bucket's.
     */
    for (auto it1 = buckets_new_.begin(); it1 != buckets_new_.end(); ++it1)
    {
        const auto & bucket_new = *it1;

        std::uint32_t size = static_cast<std::uint32_t> (bucket_new.size());

        /**
         * Write the size.
         */
        data.write_uint32(size);
        
        for (auto it2 = bucket_new.begin(); it2 != bucket_new.end(); ++it2)
        {
            std::uint32_t index = unk_ids[*it2];

            /**
             * Write the index.
             */
            data.write_uint32(index);
        }
    }
    
    /**
     * Calculate the sha256d hash of the data portion.
     */
    auto digest1 = hash::sha256d(
        reinterpret_cast<std::uint8_t *>(data.data()),
        data.size()
    );
    
    /**
     * Write the checksum.
     */
    data.write_bytes(
        reinterpret_cast<const char *> (&digest1[0]), digest1.size()
    );
    
    std::string path = filesystem::data_path() + "peers.dat";
    
    log_info(
        "Address manager is writing peers file, path = " << path << "."
    );

    /**
     * Allocate the std::ofstream.
     */
    std::ofstream ofs(path, std::ifstream::out | std::ifstream::binary);
    
    /**
     * Write to disk.
     */
    ofs.write(data.data(), data.size());

    /**
     * Close the file.
     */
    ofs.close();
}

address_manager::address_info_t * address_manager::find(
    const protocol::network_address_t & addr, std::uint32_t * ptr_id
    )
{
    auto it1 = network_address_map_.find(addr);
    
    if (it1 != network_address_map_.end())
    {
        if (ptr_id)
        {
            *ptr_id = it1->second;
        }
        
        auto it2 = address_info_map_.find(it1->second);
        
        if (it2 != address_info_map_.end())
        {
            return &it2->second;
        }
    }
    
    return 0;
}

protocol::network_address_t address_manager::select(
    const std::uint8_t & unk_bias
    )
{
    assert(unk_bias <= 100);
    
    std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
    
    if (random_ids_.size() == 0)
    {
        // ...
    }
    else
    {
        double cor_tried = sqrt(number_tried_) * (100.0 - unk_bias);
        
        double cor_new = sqrt(number_new_) * unk_bias;
        
        if (
            (cor_tried + cor_new) *
            random::uint32(1 << 30) / (1 << 30) < cor_tried
            )
        {
            /**
             * Use an already tried peer.
             */
            double factor_chance = 1.0;
            
            std::lock_guard<std::recursive_mutex> l2(mutex_buckets_new_);
            std::lock_guard<std::recursive_mutex> l3(mutex_buckets_tried_);
            
            while (1)
            {
                auto bucket_index = random::uint32(
                    static_cast<std::uint32_t> (buckets_tried_.size())
                );
                
                auto & bucket_tried = buckets_tried_[bucket_index];
                
                if (bucket_tried.size() == 0)
                {
                    continue;
                }
                
                auto position = random::uint32(
                    static_cast<std::uint32_t> (bucket_tried.size())
                );

                assert(address_info_map_.count(bucket_tried[position]) == 1);
                
                auto & info = address_info_map_[bucket_tried[position]];
                
                if (
                    random::uint32(1 << 30) < factor_chance *
                    info.get_chance() * (1 << 30)
                    )
                {
                    return info.addr;
                }
                
                factor_chance *= 1.2;
            }
        }
        else
        {
            /**
             * Use a new peer.
             */
            double factor_chance = 1.0;
            
            while (1)
            {
                auto bucket_index = random::uint32(
                    static_cast<std::uint32_t> (buckets_new_.size())
                );
                
                auto & bucket_new = buckets_new_[bucket_index];
                
                if (bucket_new.size() == 0)
                {
                    continue;
                }
                
                auto position = random::uint32(
                    static_cast<std::uint32_t> (bucket_new.size())
                );
                
                auto it = bucket_new.begin();
                
                while (position--)
                {
                    it++;
                }
                
                assert(address_info_map_.count(*it) == 1);
                
                auto & info = address_info_map_[*it];
                
                if (
                    random::uint32(1 << 30) < factor_chance *
                    info.get_chance() * (1 << 30)
                    )
                {
                    return info.addr;
                }
                
                factor_chance *= 1.2;
            }
        }
    }
    
    return protocol::network_address_t();
}

void address_manager::on_connection_attempt(
    const protocol::network_address_t & addr, const std::uint64_t & timestamp
    )
{
    if (auto * ptr_info = find(addr))
    {
        auto & info = *ptr_info;

        /**
         * Make sure the address and port match.
         */
        if (info.addr == addr && info.addr.port == addr.port)
        {
            info.addr.last_try = timestamp;
            info.last_attempts++;
        }
    }
}

void address_manager::mark_good(
    const protocol::network_address_t & addr, const std::uint64_t &  timestamp
    )
{
    log_none(
        "Address manager is marking " <<
        addr.ipv4_mapped_address() << ":" << addr.port << " as good."
    );

    std::uint32_t nid;
    
    if (auto * ptr_info = find(addr, &nid))
    {
        auto & info = *ptr_info;

        /**
         * Make sure the address and port match.
         */
        if (info.addr == addr && info.addr.port == addr.port)
        {
            /**
             * Update the info.
             */
            info.last_success = timestamp;
            info.addr.last_try = timestamp;
            info.addr.timestamp = static_cast<std::uint32_t> (timestamp);
            info.last_attempts = 0;

            if (info.tried)
            {
                // ...
            }
            else
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_buckets_new_);
                
                auto rnd = random::uint32(
                    static_cast<std::uint32_t> (buckets_new_.size())
                );
                
                auto bucket_index = -1;
                
                for (auto n = 0; n < buckets_new_.size(); n++)
                {
                    int b = (n + rnd) % buckets_new_.size();
                    
                    auto & bucket = buckets_new_[b];
                    
                    if (bucket.count(nid))
                    {
                        bucket_index = b;
                        
                        break;
                    }
                }

                
                if (bucket_index == -1)
                {
                    log_error(
                        "Address manager failed to mark good, invalid bucket "
                        "index = " << bucket_index << "."
                    );
                }
                else
                {
                    /**
                     * Move nid to the tried table.
                     */
                    move_to_tried(info, nid, bucket_index);
                }
            }
        }
    }
}

void address_manager::move_to_tried(
    address_info_t & info, const std::uint32_t & nid,
    const std::uint32_t & bucket_index
    )
{
    std::lock_guard<std::recursive_mutex> l1(mutex_buckets_new_);
    
    assert(buckets_new_[bucket_index].count(nid) == 1);

    /**
     * Remove the entry from all new buckets.
     */
    for (auto it = buckets_new_.begin(); it != buckets_new_.end(); ++it)
    {
        if (it->erase(nid))
        {
            info.reference_count--;
        }
    }
    
    number_new_--;

    assert(info.reference_count == 0);

    /**
     * Calculate the tried bucket to move the entry into.
     */
    auto bucket_tried_index = info.calculate_tried_bucket(key_);
    
    std::lock_guard<std::recursive_mutex> l2(mutex_buckets_tried_);
    
    auto & bucket_tried = buckets_tried_[bucket_tried_index];

    /**
     * Check if we can just add it.
     */
    if (bucket_tried.size() < 64)
    {
        bucket_tried.push_back(nid);
        
        number_tried_++;
        
        info.tried = true;
    }
    else
    {
        /**
         * Try to find an entry to evict.
         */
        auto position = select_tried(bucket_tried_index);

        /**
         * Find which new bucket it belongs to.
         */
        assert(address_info_map_.count(bucket_tried[position]) == 1);
        
        auto bucket_new_index = address_info_map_[
            bucket_tried[position]].calculate_new_bucket(
            key_, protocol::network_address_t::from_array(info.addr_src)
        );
        
        auto & bucket_new = buckets_new_[bucket_new_index];

        /**
         * Remove the to-be-replaced tried entry from the tried.
         */
        auto & info_old = address_info_map_[bucket_tried[position]];
        
        info_old.tried = false;
        
        info_old.reference_count = 1;

        /**
         * Check whether there is place in that one.
         */
        if (bucket_new.size() < 64)
        {
            /**
             * If so, move it back there.
             */
            bucket_new.insert(bucket_tried[position]);
        }
        else
        {
            /**
             * Otherwise, move it to the new bucket that nid came from
             * (there is certainly place there).
             */
            buckets_new_[bucket_index].insert(bucket_tried[position]);
        }
        
        number_new_++;

        bucket_tried[position] = nid;

        /**
         * Set the entry to tried.
         */
        info.tried = true;
    }
}

void address_manager::on_connected(
    const protocol::network_address_t & addr, const std::uint64_t & timestamp
    )
{
    if (auto * ptr_info = find(addr))
    {
        auto & info = *ptr_info;

        /**
         * Make sure the address and port match.
         */
        if (info.addr == addr && info.addr.port == addr.port)
        {
            enum { interval_update = 20 * 60 };
            
            if (timestamp - info.addr.timestamp > interval_update)
            {
                info.addr.timestamp = static_cast<std::uint32_t> (timestamp);
            }
        }
    }
}

address_manager::address_info_t & address_manager::create(
    const protocol::network_address_t & addr,
    const protocol::network_address_t  & addr_src, std::uint32_t  * ptr_id
    )
{
    auto nid = id_count_++;
    address_info_map_[nid] = address_info_t::init(addr, addr_src);
    network_address_map_[addr] = nid;
    address_info_map_[nid].random_position =
        static_cast<std::uint32_t> (random_ids_.size())
    ;
    
    std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
    
    random_ids_.push_back(nid);
    
    if (ptr_id)
    {
        *ptr_id = nid;
    }
    
    return address_info_map_[nid];
}

bool address_manager::add(
    const protocol::network_address_t & addr,
    const protocol::network_address_t & addr_src,
    const std::uint64_t & time_penalty
    )
{
    bool ret = false;
    
    if (addr.is_valid() == false)
    {
        log_debug(
            "Address manager unable to add invalid address = " <<
            addr.ipv4_mapped_address() << "."
        );
    }
    else if (addr.is_routable() == false)
    {
        log_debug(
            "Address manager unable to add non-routable address = " <<
            addr.ipv4_mapped_address() << "."
        );
    }
    else
    {
        /**
         * The nid.
         */
        std::uint32_t nid;
        
        /**
         * Try to find an existing address_info_t for the address.
         */
        auto * ptr_addr_info = find(addr, &nid);

        if (ptr_addr_info)
        {
            bool is_online =
                time::instance().get_adjusted() - addr.timestamp < 24 * 60 * 60
            ;
            
            /**
             * Update the entry's timestamp periodically.
             */
            auto interval_update = (is_online ? 60 * 60 : 24 * 60 * 60);
            
            if (
                addr.timestamp && (!ptr_addr_info->addr.timestamp ||
                ptr_addr_info->addr.timestamp <
                addr.timestamp - interval_update - time_penalty)
                )
            {
                ptr_addr_info->addr.timestamp = static_cast<std::uint32_t> (
                    std::max(static_cast<std::uint32_t> (0),
                    static_cast<std::uint32_t> (addr.timestamp - time_penalty))
                );
            }
            
            /**
             * Add services bitfield.
             */
            ptr_addr_info->addr.services |= addr.services;

            /**
             * Only update the entry if the timestamp is newer.
             */
            if (
                !addr.timestamp || (ptr_addr_info->addr.timestamp &&
                addr.timestamp <= ptr_addr_info->addr.timestamp)
                )
            {
                return false;
            }

            /**
             * Don't update the entry if is in the tried table.
             */
            if (ptr_addr_info->tried)
            {
                return false;
            }
            
            /**
             * Don't update the entry if it has the maximum reference count.
             */
            if (ptr_addr_info->reference_count == 4)
            {
                return false;
            }
            
            auto n_factor = 1;
            
            for (auto n = 0; n < ptr_addr_info->reference_count; n++)
            {
                n_factor *= 2;
            }
            
            if (n_factor > 1 && (random::uint32(n_factor) != 0))
            {
                return false;
            }
        }
        else
        {
            ptr_addr_info = &create(addr, addr_src, &nid);
            
            ptr_addr_info->addr.timestamp = std::max(
                static_cast<std::uint32_t> (0),
                static_cast<std::uint32_t> (
                ptr_addr_info->addr.timestamp - time_penalty)
            );
            
            log_debug(
                "Address manager added " <<
                ptr_addr_info->addr.ipv4_mapped_address().to_string() << ":" <<
                ptr_addr_info->addr.port << ", timestamp = " <<
                (time::instance().get_adjusted() -
                ptr_addr_info->addr.timestamp) / 3600.0 << "."
            );

            number_new_++;
            
            ret = true;
        }
        
        auto index_bucket = ptr_addr_info->calculate_new_bucket(
            key_, addr_src
        );
        
        std::lock_guard<std::recursive_mutex> l1(mutex_buckets_new_);
        
        auto & bucket = buckets_new_[index_bucket];
        
        if (bucket.count(nid) == 0)
        {
            ptr_addr_info->reference_count++;
            
            if (bucket.size() == 64)
            {
                shrink_bucket_new(index_bucket);
            }
            
            buckets_new_[index_bucket].insert(nid);
        }
    }
    
    return ret;
}

std::vector<protocol::network_address_t> address_manager::get_addr(
    const std::size_t & count
    )
{
    std::vector<protocol::network_address_t> ret;
    
    std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
    
    /**
     * Return at most 23% of the addresses.
     */
    auto number_addresses = 23 * random_ids_.size() / 100;
    
    if (number_addresses > count)
    {
        number_addresses = count;
    }
    
    /**
     * Perform a random shuffle over the first number_addresses elements of
     * random_ids_ (selecting from all).
     */
    for (auto n = 0; n < number_addresses; n++)
    {
        auto position = random::uint32(
            static_cast<std::uint32_t> (random_ids_.size()) - n) + n
        ;
        
        swap_random(n, position);
        
        assert(address_info_map_.count(random_ids_[n]) == 1);
        
        ret.push_back(address_info_map_[random_ids_[n]].addr);
    }
    
    return ret;
}

const std::size_t address_manager::size() const
{
    std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
    
    return random_ids_.size();
}

std::int32_t address_manager::select_tried(const std::uint32_t & bucket_index)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_buckets_tried_);
    
    auto & bucket_tried = buckets_tried_[bucket_index];

    std::int64_t oldest = -1;
    
    std::int32_t oldest_position = -1;
    
    for (auto i = 0; i < 4 && i < bucket_tried.size(); i++)
    {
        auto position = random::uint32(
            static_cast<std::uint32_t> (bucket_tried.size()) - i) + i
        ;
        
        auto & tmp = bucket_tried[position];
        
        bucket_tried[position] = bucket_tried[i];
        bucket_tried[i] = tmp;
        
        assert(oldest == -1 || address_info_map_.count(tmp) == 1);
        
        if (
            oldest == -1 ||
            address_info_map_[tmp].last_success <
            address_info_map_[static_cast<std::uint32_t> (oldest)].last_success
            )
        {
           oldest = tmp;
           oldest_position = position;
        }
    }

    return oldest_position;
}

void address_manager::shrink_bucket_new(const std::uint32_t & index)
{
    std::lock_guard<std::recursive_mutex> l1(mutex_buckets_new_);
    
    assert(index >= 0 && index < buckets_new_.size());
    
    auto & bucket_new = buckets_new_[index];

    /**
     * Try to find an entry that can be erased.
     */
    for (auto it = bucket_new.begin(); it != bucket_new.end(); ++it)
    {
        assert(address_info_map_.count(*it));
        
        auto & info = address_info_map_[*it];
        
        if (info.is_terrible())
        {
            if (--info.reference_count == 0)
            {
                std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
                
                swap_random(
                    info.random_position,
                    static_cast<std::uint32_t> (random_ids_.size() - 1)
                );
                
                random_ids_.pop_back();
                network_address_map_.erase(info.addr);
                address_info_map_.erase(*it);
                number_new_--;
            }
            
            bucket_new.erase(it);
            
            return;
        }
    }

    /**
     * Select four random nid's.
     */
    std::uint32_t n[4] =
    {
        random::uint32(static_cast<std::uint32_t> (bucket_new.size())),
        random::uint32(static_cast<std::uint32_t> (bucket_new.size())),
        random::uint32(static_cast<std::uint32_t> (bucket_new.size())),
        random::uint32(static_cast<std::uint32_t> (bucket_new.size()))
    };
    
    auto i = 0;
    
    auto oldest = -1;
    
    for (auto it = bucket_new.begin(); it != bucket_new.end(); ++it)
    {
        if (i == n[0] || i == n[1] || i == n[2] || i == n[3])
        {
            assert(oldest == -1 || address_info_map_.count(*it) == 1);
            
            if (
                oldest == -1 ||
                address_info_map_[*it].addr.timestamp <
                address_info_map_[oldest].addr.timestamp
                )
            {
                oldest = *it;
            }
        }
        
        i++;
    }
    
    assert(address_info_map_.count(oldest) == 1);
    
    auto & info = address_info_map_[oldest];
    
    if (--info.reference_count == 0)
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
        
        swap_random(
            info.random_position,
            static_cast<std::uint32_t> (random_ids_.size() - 1)
        );
        random_ids_.pop_back();
        network_address_map_.erase(info.addr);
        address_info_map_.erase(oldest);
        number_new_--;
    }
    
    bucket_new.erase(oldest);
}

void address_manager::swap_random(
    const std::uint32_t & first, const std::uint32_t & second
    )
{
    if (first == second)
    {
        // ...
    }
    else
    {
        std::lock_guard<std::recursive_mutex> l1(mutex_random_ids_);
        
        assert(first < random_ids_.size() && second < random_ids_.size());

        int nid1 = random_ids_[first];
        int nid2 = random_ids_[second];

        assert(address_info_map_.count(nid1) == 1);
        assert(address_info_map_.count(nid2) == 1);

        address_info_map_[nid1].random_position = second;
        address_info_map_[nid2].random_position = first;

        random_ids_[first] = nid2;
        random_ids_[second] = nid1;
    }
}
