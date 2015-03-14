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

#ifndef COIN_UTILITY_HPP
#define COIN_UTILITY_HPP

#if (defined _MSC_VER)
                
#else
#include <sys/statvfs.h>
#endif // _MSC_VER

#include <cstdint>
#include <string>
#include <vector>

#include <boost/algorithm/string/join.hpp>

#include <coin/constants.hpp>
#include <coin/checkpoints.hpp>
#include <coin/sha256.hpp>

namespace coin {

    class big_number;
    class block;
    class block_index;
    
    class utility
    {
        public:
        
            /**
             * Implements a disk info structure.
             */
            typedef struct
            {
                std::uint64_t capacity;
                std::uint64_t free;
                std::uint64_t available;
            } disk_info_t;
        
            /**
             * Obtains disk information about the given path.
             * @param path The path.
             */
            static disk_info_t disk_info(const std::string & path);
  
            /**
             * abs64
             * @param n n
             */
            static inline std::int64_t abs64(std::int64_t n)
            {
                return (n >= 0 ? n : -n);
            }
        
            /**
             * money_range
             * @param value The value.
             */
            static inline bool money_range(const std::int64_t & value)
            {
                return value >= 0 && value <= constants::max_money_supply;
            }
        
            /**
             * format_money
             * @param n The n.
             * @param plus If true a plus sign will be included.
             */
            static std::string format_money(
                const std::int64_t & n, const bool & plus = false
                )
            {
                std::string ret;

                std::int64_t n_abs = n > 0 ? n : -n;
                
                /**
                 * The quotient
                 */
                std::int64_t quotient = n_abs / constants::coin;
                
                /**
                 * The remainder.
                 */
                std::int64_t remainder = n_abs % constants::coin;
                
                /**
                 * Combine the string.
                 */
                ret =
                    std::to_string(quotient) + "." + std::to_string(remainder)
                ;
                
                /**
                 * Right-trim excess zeros before the decimal point.
                 */
                auto trim = 0;
                
                for (
                    auto i = ret.size() - 1;
                    (ret[i] == '0' && isdigit(ret[i - 2])); --i
                    )
                {
                    ++trim;
                }
                
                if (trim)
                {
                    ret.erase(ret.size() - trim, trim);
                }
                
                if (n < 0)
                {
                    ret.insert((std::uint32_t)0, 1, '-');
                }
                else if (plus && n > 0)
                {
                    ret.insert((std::uint32_t)0, 1, '+');
                }
                
                return ret;
            }

            /**
             * Formats the version
             * @param version The version.
             */
            static std::string format_version(const std::int32_t & version)
            {
                std::string ret;
                
                if (version % 100 == 0)
                {
                    ret += std::to_string(version / 1000000) + ".";
                    ret += std::to_string((version / 10000) % 100) + ".";
                    ret += std::to_string((version / 100) % 100);
                }
                else
                {
                    ret += std::to_string(version / 1000000) + ".";
                    ret += std::to_string((version / 10000) % 100) + ".";
                    ret += std::to_string((version / 100) % 100) + ".";
                    ret += std::to_string(version % 100);
                }
                
                return ret;
            }

            /**
             * Formats the sub-version according to BIP 0014.
             * https://en.bitcoin.it/wiki/BIP_0014
             */
            static std::string format_sub_version(
                const std::string & name, const std::int32_t client_version,
                const std::vector<std::string> & comments
                )
            {
                std::ostringstream ss;
                
                ss << "/";
                
                ss << name << ":" << format_version(client_version);
                
                if (comments.size() > 0)
                {
                    ss << "(" << boost::algorithm::join(comments, "; ") << ")";
                }
                
                ss << "/";
                
                return ss.str();
            }
        
            /**
             * hex_string
             */
            template<typename T>
            static inline std::string hex_string(
                const T it_begin, const T it_end, const bool & spaces = false
                )
            {
                std::string rv;
                static const char hexmap[16] =
                {
                    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                    'a', 'b', 'c', 'd', 'e', 'f'
                };
                
                rv.reserve((it_end - it_begin) * 3);
                
                for (auto it = it_begin; it < it_end; ++it)
                {
                    auto val = static_cast<std::uint8_t> (*it);
                    
                    if (spaces && it != it_begin)
                    {
                        rv.push_back(' ');
                    }
                    
                    rv.push_back(hexmap[val >> 4]);
                    
                    rv.push_back(hexmap[val & 15]);
                }

                return rv;
            }

            /**
             * Converts an array of bytes into a hexidecimal string
             * representation.
             * @param bytes The bytes.
             * @param spaces If true the encoding will including spaces.
             */
            static inline std::string hex_string(
                const std::vector<std::uint8_t> & bytes,
                const bool & spaces = false
                )
            {
                return hex_string(bytes.begin(), bytes.end(), spaces);
            }
        
            /**
             * Converts bits to a hexidecimal string representation.
             */
            static std::string hex_string_from_bits(const std::uint32_t & bits)
            {
                union
                {
                    std::int32_t n;
                    char c[4];
                } u;
                
                u.n = htonl(bits);

                return hex_string(
                    ((char *)&(u.c)), (char *)&((&(u.c))[1])
                );
            }
        
            /**
             * Converts from hexidecimal bytes.
             * @param val The std::string.
             */
            static std::vector<std::uint8_t> from_hex(const std::string & val);
        
            /**
             * Gets the var_int size given size.
             * @param size The size.
             */
            static inline std::uint32_t get_var_int_size(
                const std::uint64_t & size
                )
            {
                if (size < 253)
                {   return sizeof(std::uint8_t);
                }
                else if (size <= std::numeric_limits<unsigned short>::max())
                {
                    return sizeof(std::uint8_t) + sizeof(unsigned short);
                }
                else if (size <= std::numeric_limits<std::uint32_t>::max())
                {
                    return sizeof(std::uint8_t) + sizeof(std::uint32_t);
                }
                
                return sizeof(std::uint8_t) + sizeof(std::uint64_t);
            }
        
            /**
             * Returns true if no blocks have been downloaded.
             */
            static bool is_initial_block_download();

            /**
             * Returns true if if is a chain file.
             * @param path The path.
             */
            static bool is_chain_file(const std::string & file_name);

            /**
             * Gets the orphan root of the given block.
             * @param blk The block.
             */
            static sha256 get_orphan_root(const std::shared_ptr<block> & blk);

            /**
             * Find block wanted by given orphan block (ppcoin).
            */
            static sha256 wanted_by_orphan(const std::shared_ptr<block> & blk);

            /**
             * Adds an orphan transaction.
             * @param buffer The data_buffer.
             */
            static bool add_orphan_tx(const data_buffer & buffer);

            /**
             * Erases an orphan transaction.
             * @param hash_tx The hash of the transaction.
             */
            static void erase_orphan_tx(const sha256 & hash_tx);

            /**
             * Limits the orphan transaction size.
             * @param max_orphans The maximum number of orphans.
             */
            static std::uint32_t limit_orphan_tx_size(
                const std::uint32_t & max_orphans
            );

            /**
             * Find the last block index up to index (ppcoin).
             * @param index The block_index.
             * @param is_pos If true it is proof-of-stake,
             */
            static const std::shared_ptr<block_index> get_last_block_index(
                const std::shared_ptr<block_index> & index, const bool & is_pos
            );
        
            /**
             * Finds a block by it's height.
             * @param height The height.
             */
            static std::shared_ptr<block_index> find_block_index_by_height(
                const std::uint32_t & height
            );
        
            /**
             * The maximum bits value could possibly be required time after
             * minimum proof-of-work required was base.
             * @param target_limit The target limit.
             * @param base The base.
             * @param time The time.
             */
            static std::uint32_t compute_max_bits(
                big_number target_limit, std::uint32_t base, std::int64_t time
            );

            /**
             * The minimum amount of work that could possibly be required time
             * after minimum proof-of-work required was base.
             * @param base The base.
             * @param time The time.
             */
            static std::uint32_t compute_min_work(
                std::uint32_t base, std::int64_t time
            );

            /**
             * The minimum amount of stake that could possibly be required time
             * after minimum proof-of-stake required was base.
             * @param base The base.
             * @param time The time.
             * @param time_block The block time.
             */
            static std::uint32_t compute_min_stake(
                std::uint32_t base, std::int64_t time, std::uint32_t time_block
            );
        
            /**
             * Gets the next required target.
             * @param index_last The last block index.
             * @param is_pos If true it is proof-of-stake.
             */
            static std::uint32_t get_next_target_required(
                const std::shared_ptr<block_index> & index_last,
                const bool & is_pos
            );
        
            /**
             * Gets the next required target.
             * @param index_last The last block index.
             * @param is_pos If true it is proof-of-stake.
             */
            static std::uint32_t get_next_target_required_v020(
                const std::shared_ptr<block_index> & index_last,
                const bool & is_pos
            );
        
            /**
             * Gets the next required target.
             * @param index_last The last block index.
             * @param is_pos If true it is proof-of-stake.
             */
            static std::uint32_t get_next_target_required_v023(
                const std::shared_ptr<block_index> & index_last,
                const bool & is_pos
            );
        
            /**
             * Byte reversal.
             * @param val The std::uint32_t.
             */
            static std::uint32_t byte_reverse(const std::uint32_t & val)
            {
                std::uint32_t ret =
                    ((val & 0xFF00FF00) >> 8) | ((val & 0x00FF00FF) << 8)
                ;
                
                return (ret << 16) | (ret >> 16);
            }
        
            /**
             * Gets a transaction from the pool. If it exists in a block the
             * hash will be set.
             * @param hash_tx The hash of the transaction.
             * @param tx The transaction.
             * @param hash_block_out The hash of the block (out) if found.
             */
            static bool get_transaction(
                const sha256 & hash_tx, transaction & tx,
                sha256 & hash_block_out
            );
        
            /**
             * Calculates the difficulty given bits.
             * @param bits The bits.
             */
            static double difficulty_from_bits(const std::uint32_t & bits)
            {
                int shift = (bits >> 24) & 0xff;

                double diff =
                    static_cast<double> (0x0000ffff) /
                    static_cast<double> (bits & 0x00ffffff)
                ;

                while (shift < 29)
                {
                    diff *= 256.0, shift++;
                }
                
                while (shift > 29)
                {
                    diff /= 256.0, shift--;
                }

                return diff;
            }
        
            /**
             * Align by increasing pointer, must have extra space at end
             * of buffer.
            */
            template <std::size_t len, typename T>
            static T * alignup(T * p)
            {
                union
                {
                    T * ptr;
                    std::size_t n;
                } u;
                
                u.ptr = p;
                u.n = (u.n + (len - 1)) & ~(len - 1);
                
                return u.ptr;
            }

        private:
        
            // ...
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_UTILITY_HPP
