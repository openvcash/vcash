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

#ifndef COIN_SCRIPT_HPP
#define COIN_SCRIPT_HPP

#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

#include <coin/big_number.hpp>
#include <coin/destination.hpp>
#include <coin/key.hpp>
#include <coin/key_public.hpp>
#include <coin/key_store.hpp>
#include <coin/logger.hpp>
#include <coin/ripemd160.hpp>
#include <coin/sha256.hpp>
#include <coin/types.hpp>
#include <coin/utility.hpp>

namespace coin {
    
    class key_store;
    class transaction;
    
    /**
     * Implements a stack machine (Forth-like) that evaluates a predicate
     * returning a bool indicating valid or not.
     */
    class script : public std::vector<std::uint8_t>
    {
        public:
        
            /**
             * Implements a script visitor.
             */
            class visitor : public boost::static_visitor<bool>
            {
                public:

                    /**
                     * Constructor
                     */
                    visitor(script & value) : m_script(value) { }

                    /**
                     * operator ()
                     */
                    bool operator () (const destination::none & dest) const
                    {
                        m_script.clear();
                        
                        return false;
                    }

                    /**
                     * operator ()
                     */
                    bool operator () (const types::id_key_t & id) const
                    {
                        m_script.clear();
                        
                        m_script <<
                            op_dup << op_hash160 << id << op_equalverify <<
                            op_checksig
                        ;
                        
                        return true;
                    }

                    /**
                     * operator ()
                     */
                    bool operator () (const types::id_script_t & id) const
                    {
                        m_script.clear();
                        
                        m_script << op_hash160 << id << op_equal;
                        
                        return true;
                    }
                
                private:
                
                    /**
                     * The script.
                     */
                    script & m_script;
                
                protected:
                
                    // ...
            };

            /**
             * The opcodes.
             */
            typedef enum
            {
                /** push value */
                op_0 = 0x00,
                op_false = op_0,
                op_pushdata1 = 0x4c,
                op_pushdata2 = 0x4d,
                op_pushdata4 = 0x4e,
                op_1negate = 0x4f,
                op_reserved = 0x50,
                op_1 = 0x51,
                op_true = op_1,
                op_2 = 0x52,
                op_3 = 0x53,
                op_4 = 0x54,
                op_5 = 0x55,
                op_6 = 0x56,
                op_7 = 0x57,
                op_8 = 0x58,
                op_9 = 0x59,
                op_10 = 0x5a,
                op_11 = 0x5b,
                op_12 = 0x5c,
                op_13 = 0x5d,
                op_14 = 0x5e,
                op_15 = 0x5f,
                op_16 = 0x60,
                /** control */
                op_nop = 0x61,
                op_ver = 0x62,
                op_if = 0x63,
                op_notif = 0x64,
                op_verif = 0x65,
                op_vernotif = 0x66,
                op_else = 0x67,
                op_endif = 0x68,
                op_verify = 0x69,
                op_return = 0x6a,
                /** stack ops */
                op_toaltstack = 0x6b,
                op_fromaltstack = 0x6c,
                op_2drop = 0x6d,
                op_2dup = 0x6e,
                op_3dup = 0x6f,
                op_2over = 0x70,
                op_2rot = 0x71,
                op_2swap = 0x72,
                op_ifdup = 0x73,
                op_depth = 0x74,
                op_drop = 0x75,
                op_dup = 0x76,
                op_nip = 0x77,
                op_over = 0x78,
                op_pick = 0x79,
                op_roll = 0x7a,
                op_rot = 0x7b,
                op_swap = 0x7c,
                op_tuck = 0x7d,
                /** splice ops */
                op_cat = 0x7e,
                op_substr = 0x7f,
                op_left = 0x80,
                op_right = 0x81,
                op_size = 0x82,
                /** bit logic */
                op_invert = 0x83,
                op_and = 0x84,
                op_or = 0x85,
                op_xor = 0x86,
                op_equal = 0x87,
                op_equalverify = 0x88,
                op_reserved1 = 0x89,
                op_reserved2 = 0x8a,
                /** numeric */
                op_1add = 0x8b,
                op_1sub = 0x8c,
                op_2mul = 0x8d,
                op_2div = 0x8e,
                op_negate = 0x8f,
                op_abs = 0x90,
                op_not = 0x91,
                op_0notequal = 0x92,
                op_add = 0x93,
                op_sub = 0x94,
                op_mul = 0x95,
                op_div = 0x96,
                op_mod = 0x97,
                op_lshift = 0x98,
                op_rshift = 0x99,
                op_booland = 0x9a,
                op_boolor = 0x9b,
                op_numequal = 0x9c,
                op_numequalverify = 0x9d,
                op_numnotequal = 0x9e,
                op_lessthan = 0x9f,
                op_greaterthan = 0xa0,
                op_lessthanorequal = 0xa1,
                op_greaterthanorequal = 0xa2,
                op_min = 0xa3,
                op_max = 0xa4,
                op_within = 0xa5,
                /** crypto */
                op_ripemd160 = 0xa6,
                op_sha1 = 0xa7,
                op_sha256 = 0xa8,
                op_hash160 = 0xa9,
                op_hash256 = 0xaa,
                op_codeseparator = 0xab,
                op_checksig = 0xac,
                op_checksigverify = 0xad,
                op_checkmultisig = 0xae,
                op_checkmultisigverify = 0xaf,
                /* expansion */
                op_nop1 = 0xb0,
                op_nop2 = 0xb1,
                op_nop3 = 0xb2,
                op_nop4 = 0xb3,
                op_nop5 = 0xb4,
                op_nop6 = 0xb5,
                op_nop7 = 0xb6,
                op_nop8 = 0xb7,
                op_nop9 = 0xb8,
                op_nop10 = 0xb9,
                /** template matching params */
                op_smallinteger = 0xfa,
                op_pubkeys = 0xfb,
                op_pubkeyhash = 0xfd,
                op_pubkey = 0xfe,
                op_invalidopcode = 0xff,
            } op_t;
        
            /**
             * Constructor
             */
            script();
        
            /**
             * Copy Constructor
             */
            script(const script & other);

            /**
             * Constructor
             * @param ptr_begin The ptr_begin.
             * @param ptr_end The ptr_end.
             */
            script(
                const std::uint8_t * ptr_begin, const std::uint8_t * ptr_end
            );
        
            /**
             * Constructor
             * @param it_begin The it_begin.
             * @param it_end The it_end.
             */
            script(const_iterator it_begin, const_iterator it_end);

            /**
             * Constructor
             */
            script(std::int8_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::int16_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::int32_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::int64_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::uint8_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::uint16_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::uint32_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(std::uint64_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(op_t b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(const sha256 & b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(const big_number & b) { operator << (b); }
        
            /**
             * Constructor
             */
            script(const std::vector<std::uint8_t> & b) { operator << (b); }
    
            /**
             * Gets the transaction output type.
             * @param t The types::tx_out_t.
             */
            static std::string get_txn_output_type(const types::tx_out_t & t);

            /**
             * Gets the string representation of an operation type.
             * @param value The value.
             */
            static std::string get_op_name(const op_t & value);
        
            /**
             * Solver
             * @param script_public_key The script.
             * @param tx_out_type The types::tx_out_t.
             * @param solutions The std::vector<std::vector<std::uint8_t> >.
            */
            static bool solver(
                const script & script_public_key, types::tx_out_t & tx_out_type,
                std::vector< std::vector<std::uint8_t> > & solutions
            );

            /**
             * Solver
             * @param keystore The key_store.
             * @param script_pub_key The script public key.
             * @param hash The sha256.
             * @param hash_type The types::sighash_t.
             * @return False if script public key is not satisfied.
             */
            static bool solver(
                const key_store & keystore, const script & script_pub_key,
                const sha256 & hash, const types::sighash_t & hash_type,
                script & script_sig_out, types::tx_out_t & which_type_out
            );
                    
            /**
             * Evaluates a script.
             * @param stack The std::vector<std::vector<std::uint8_t> >.
             * @param scr The script.
             * @param tx_to The transaction.
             * @param nIn
             * @param hash_type
             */
            static bool evaluate(
                std::vector<std::vector<std::uint8_t> > & stack,
                const script & scr, const transaction & tx_to,
                const std::uint32_t & n, int hash_type
            );
    
            /**
             * get_op
             * @param it The const_iterator.
             * @param value The op_t.
             * @param out The std::vector<std::uint8_t>.
             */
            bool get_op(
                const_iterator & it, op_t & value,
                std::vector<std::uint8_t> & out
                )
            {
                 auto it2 = it;
                
                 auto ret = get_op2(it2, value, &out);
                
                 it = begin() + (it2 - begin());
                
                 return ret;
            }

            /**
             * get_op
             * @param it The iterator.
             * @param out The op_t.
             */
            bool get_op(iterator & it, op_t & out)
            {
                 const_iterator it2 = it;
                
                 auto ret = get_op2(it2, out, 0);
                
                 it = begin() + (it2 - begin());
                
                 return ret;
            }

            /**
             * get_op
             * @param it The const_iterator.
             * @param out1 The op_t.
             * @param out2 The std::vector<std::uint8_t>.
             */
            bool get_op(
                const_iterator & it, op_t & out1,
                std::vector<std::uint8_t> & out2
                ) const
            {
                return get_op2(it, out1, &out2);
            }

            /**
             * get_op
             * @param it The const_iterator.
             * @param out The op_t.
             */
            bool get_op(const_iterator & it, op_t & out) const
            {
                return get_op2(it, out, 0);
            }

            /**
             * get_op
             * @param it The const_iterator.
             * @param out1 The op_t.
             * @param out2 The std::vector<std::uint8_t>.
             */
            bool get_op2(
                const_iterator & it, op_t & out1,
                std::vector<std::uint8_t> * out2
                ) const
            {
                out1 = op_invalidopcode;
                
                if (out2)
                {
                    out2->clear();
                }
                
                if (it >= end())
                {
                    return false;
                }
                
                /**
                 * Read instruction.
                 */
                if (end() - it < 1)
                {
                    return false;
                }
                
                op_t opcode = static_cast<op_t> (*it++);

                /**
                 * Immediate operand.
                 */
                if (opcode <= op_pushdata4)
                {
                    unsigned int size = 0;
                    
                    if (opcode < op_pushdata1)
                    {
                        size = opcode;
                    }
                    else if (opcode == op_pushdata1)
                    {
                        if (end() - it < 1)
                        {
                            return false;
                        }
                        
                        size = *it++;
                    }
                    else if (opcode == op_pushdata2)
                    {
                        if (end() - it < 2)
                        {
                            return false;
                        }
                        
                        size = 0;
                        
                        std::memcpy(&size, &it[0], 2);
                        
                        it += 2;
                    }
                    else if (opcode == op_pushdata4)
                    {
                        if (end() - it < 4)
                        {
                            return false;
                        }
                        
                        std::memcpy(&size, &it[0], 4);
                        
                        it += 4;
                    }
                    
                    if (
                        end() - it < 0 ||
                        static_cast<unsigned int> ((end() - it) < size)
                        )
                    {
                        return false;
                    }
                    
                    if (out2)
                    {
                        out2->assign(it, it + size);
                    }
                    
                    it += size;
                }

                out1 = (op_t)opcode;
                
                return true;
            }

            /**
             * Encodes small integers.
             * @param n The int.
             */
            static op_t encode_op_n(int n)
            {
                assert(n >= 0 && n <= 16);
                
                if (n == 0)
                {
                    return op_0;
                }
                
                return static_cast<op_t> (op_1 + n - 1);
            }

            /**
             * Decodes small integers.
             * @param opcode The op_t.
             */
            static int decode_op_n(op_t opcode)
            {
                if (opcode == op_0)
                {
                    return 0;
                }
                
                assert(opcode >= op_1 && opcode <= op_16);
                
                return static_cast<int> (opcode) - static_cast<int> (op_1 - 1);
            }
        
            /**
             * find_and_delete
             * @param value The script.
             */
            int find_and_delete(const script & value)
            {
                int ret = 0;
                
                if (value.empty())
                {
                    return ret;
                }
                
                iterator it = begin();
                
                op_t opcode;
                
                do
                {
                    while (
                        end() - it >= static_cast<long> (value.size()) &&
                        std::memcmp(&it[0], &value[0], value.size()) == 0
                        )
                    {
                        erase(it, it + value.size());
                        
                        ++ret;
                    }
                }
                while (get_op(it, opcode));
                
                return ret;
            }
        
            /**
             * find
             * @param value The op_t.
             */
            int find(op_t value) const
            {
                int ret = 0;
                
                op_t opcode;
                
                for (auto pc = begin(); pc != end() && get_op(pc, opcode);)
                {
                    if (opcode == value)
                    {
                        ++ret;
                    }
                }
                
                return ret;
            }

            /**
             * get_sig_op_count
             * @param accurate accurate
             */
            unsigned int get_sig_op_count(const bool & accurate) const;

            /**
             * get_sig_op_count
             * @param script_sig The script.
             */
            unsigned int get_sig_op_count(const script & script_sig) const;

            /**
             * is_pay_to_script_hash
             */
            bool is_pay_to_script_hash() const;

            /**
             * is_push_only
             */
            bool is_push_only() const;

            /**
             * set_destination
             * @param value The destination::tx_t.
             */
            void set_destination(const destination::tx_t & value);
        
            /**
             * set_multi_sig
             * @param required required
             * @param keys keys
             */
            void set_multi_sig(
                const int & required, const std::vector<key> & keys
            );

            /**
             * print_hex
             */
            void print_hex() const;

            /**
             * to_string
             * @param make_short If true makes the short representation.
             */
            std::string to_string(const bool & make_short = false) const;

            /**
             * print
             */
            void print() const;

            /**
             * get_id
             */
            types::id_script_t get_id() const;
    
            /**
             * sig_args_expected
             * @param tx_type The types::tx_out_t.
             * @param solutions The std::vector<std::vector<std::uint8_t> >.
             */
            static int sig_args_expected(
                const types::tx_out_t & tx_type,
                const std::vector<std::vector<std::uint8_t> > & solutions
            );
        
            /**
             * If true it is standard.
             * @param script_public_key The script.
             */
            static bool is_standard(const script & script_public_key);
        
            /**
             * have_keys
             * @param pub_keys The std::vector< std::vector< <std::uint8_t> >.
             * @param store The key_store.
             */
            static std::size_t have_keys(
                const std::vector< std::vector<std::uint8_t> > & pub_keys,
                const key_store & store
            );
        
            /**
             * If true it is mine.
             * @param store The key_store.
             * @param dest The transaction::destination .
             */
            static bool is_mine(
                const key_store & store, const destination::tx_t & dest
            );
        
            /**
             * If true it is mine.
             * @param store The key_store.
             * @param script_public_key The script.
             */
            static bool is_mine(
                const key_store & store, const script & script_public_key
            );
        
            /**
             * Extracts a destination from a script.
             * @param script_public_key The script.
             * @param address_out The destination::tx_t.
             */
            static bool extract_destination(
                const script & script_public_key,
                destination::tx_t & address_out
            );

            /**
             * Extracts destinations from a script.
             * @param script_public_key The script.
             * @param type_out The types::tx_out_t.
             * @param address_out The destination::tx_t objects.
             * @param required_out The required out.
             */
            static bool extract_destinations(
                const script & script_public_key, types::tx_out_t & type_out,
                std::vector<destination::tx_t> & address_out,
                std::int32_t & required_out
            );
        
            /**
             * Sign signature.
             * @param keystore The key_store.
             * @param pub_key_from The script public key (from).
             * @param tx_to The transaction (to).
             * @param n The n.
             * @param hash_type The types::sighash_t.
             */
            static bool sign_signature(
                const key_store & keystore, const script & pub_key_from,
                transaction & tx_to, const std::uint32_t & n,
                const types::sighash_t & hash_type = types::sighash_all
            );
        
            /**
             * Sign signature.
             * @param keystore The key_store.
             * @param tx_from The transaction (from).
             * @param tx_to The transaction (to).
             * @param n The n.
             * @param hash_type The types::sighash_t.
             */
            static bool sign_signature(
                const key_store & keystore, const transaction & tx_from,
                transaction & tx_to, const std::uint32_t & n,
                const types::sighash_t & hash_type = types::sighash_all
            );

            /**
             * verify_script
             * @param script_signature The script.
             * @param script_public_key The script.
             * @param tx_to The transaction.
             * @param in The in.
             * @param validate_pay_to_script_hash
             * @param hash_type The hash type.
             */
            static bool verify_script(
                const script & script_signature,
                const script & script_public_key, const transaction & tx_to,
                const std::uint32_t & in, bool validate_pay_to_script_hash,
                int hash_type
            );

            /**
             * verify_signature
             * @param tx_from The transaction.
             * @param tx_to The transaction.
             * @param in The in.
             * @param validate_pay_to_script_hash
             * @param hash_type The hash type.
             */
            static bool verify_signature(
                const transaction & tx_from, const transaction & tx_to,
                const std::uint32_t & in, bool validate_pay_to_script_hash,
                int hash_type
            );
        
            /**
             * operator ++
             */
            script & operator += (const script & b)
            {
                insert(end(), b.begin(), b.end());
                
                return *this;
            }

            /**
             * operator +
             */
            friend script operator + (const script & a, const script & b)
            {
                script ret = a;
                ret += b;
                return ret;
            }
    
            /**
             * operator <<
             */
            script & operator << (std::int8_t b) { return push_int64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::int16_t b) { return push_int64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::int32_t b) { return push_int64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::int64_t b) { return push_int64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::uint8_t b) { return push_uint64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::uint16_t b) { return push_uint64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::uint32_t b) { return push_uint64(b); }
        
            /**
             * operator <<
             */
            script & operator << (std::uint64_t b) { return push_uint64(b); }

            /**
             * operator <<
             */
            script & operator << (op_t opcode)
            {
                if (opcode < 0 || opcode > 0xff)
                {
                    throw std::runtime_error("invalid opcode");
                }
                
                insert(end(), (std::uint8_t)opcode);
                
                return *this;
            }

            /**
             * operator <<
             */
            script & operator << (const ripemd160 & b)
            {
                insert(end(), b.digest().size());
                
                insert(
                    end(), const_cast<std::uint8_t *> (&b.digest()[0]),
                    const_cast<std::uint8_t *> (&b.digest()[0]) +
                    b.digest().size()
                );
                
                return *this;
            }

            /**
             * operator <<
             */
            script & operator << (const sha256 & b)
            {
                insert(end(), sha256::digest_length);
                
                insert(
                    end(), const_cast<std::uint8_t *> (b.digest()),
                    const_cast<std::uint8_t *> (b.digest()) +
                    sha256::digest_length
                );
                
                return *this;
            }

            /**
             * operator <<
             */
            script & operator << (const key_public & key)
            {
                return *this << key.bytes();
            }

            /**
             * operator <<
             */
            script & operator << (const big_number & b)
            {
                return *this << b.get_vector();
            }

            /**
             * operator <<
             */
            script & operator << (const std::vector<std::uint8_t> & b)
            {
                if (b.size() < op_pushdata1)
                {
                    this->insert(end(), (std::uint8_t)b.size());
                }
                else if (b.size() <= 0xff)
                {
                    this->insert(end(), op_pushdata1);
                    
                    this->insert(end(), (std::uint8_t)b.size());
                }
                else if (b.size() <= 0xffff)
                {
                    this->insert(end(), op_pushdata2);
                    
                    std::uint16_t size = b.size();
                    
                    this->insert(
                        this->end(), reinterpret_cast<std::uint8_t *> (&size),
                        reinterpret_cast<std::uint8_t *> (&size) + sizeof(size)
                    );
                }
                else
                {
                    insert(end(), op_pushdata4);
                    
                    std::uint32_t size = static_cast<std::uint32_t> (b.size());
                    
                    this->insert(
                        this->end(), reinterpret_cast<std::uint8_t *> (&size),
                        reinterpret_cast<std::uint8_t *> (&size) + sizeof(size)
                    );
                }
                
                this->insert(end(), b.begin(), b.end());
                
                return *this;
            }
        
            /**
             * operator <<
             */
            script & operator << (const script & b)
            {
                throw std::runtime_error(
                    "invalid function call, use + to concatenate"
                );

                return *this;
            }
        
        private:
        
            /**
             * value_string
             * @param value The std::vector<std::uint8_t>.
             */
            static std::string value_string(
                const std::vector<std::uint8_t> & value
                )
            {
                if (value.size() <= 4)
                {
                    return std::to_string(big_number(value).get_int());
                }

                return utility::hex_string(value);
            }

            /**
             * stack_string
             * @param value The std::vector< std::vector<std::uint8_t> >.
             */
            static std::string stack_string(
                const std::vector< std::vector<std::uint8_t> > & value
                )
            {
                std::string ret;

                for (auto & i : value)
                {
                    if (ret.size() > 0)
                    {
                        ret += " ";
                    }
                    
                    ret += value_string(i);
                }
                
                return ret;
            }

            /**
             * Sign 1
             * @param address The types::id_key_t.
             * @param keystore The key_store.
             * @param hash The sha256.
             * @param hash_type The types::sighash_t .
             * @param script_sig_out The script signature (out).
             */
            static bool sign_1(
                const types::id_key_t & address, const key_store & keystore,
                const sha256 & hash, const types::sighash_t & hash_type,
                script & script_sig_out
            );

            /**
             * Sign n
             * @param multisig_data The multi-signature data.
             * @param keystore The key_store.
             * @param hash The sha256.
             * @param hash_type The types::sighash_t .
             * @param script_sig_out The script signature (out).
             */
            static bool sign_n(
                const std::vector< std::vector<std::uint8_t> > & multisig_data,
                const key_store & keystore, const sha256 & hash,
                const types::sighash_t & hash_type, script & script_sig_out
            );

        protected:
        
            /**
             * Pushes an std::int64_t.
             * @param n The std::int64_t.
             */
            script & push_int64(std::int64_t n);

            /**
             * Pushes an std::uint64_t.
             * @param n The std::uint64_t.
             */
            script & push_uint64(std::uint64_t n);
        
            /**
             * Checks the signature.
             * @param signature The signature.
             * @param pub_key The public key.
             * @param script_code The script code.
             * @param tx_to The transaction to.
             * @param n The n.
             * @param hash_type The hash type.
             */
            static bool check_signature(
                std::vector<std::uint8_t> signature,
                std::vector<std::uint8_t> pub_key,
                script script_code, const transaction & tx_to,
                const std::uint32_t & n, int hash_type
            );
        
            /**
             * Generates a signature hash.
             */
            static sha256 signature_hash(
                script script_code, const transaction & tx_to,
                const std::uint32_t & n, int hash_type
            );
        
            /**
             * True
             */
            static const std::vector<std::uint8_t> true_;
        
            /**
             * False
             */
            static const std::vector<std::uint8_t> false_;
        
            /**
             * Zero
             */
            static const big_number zero_;

            /**
             * One
             */
            static const big_number one_;
    };
    
} // namespace coin

#endif // COIN_SCRIPT_HPP
