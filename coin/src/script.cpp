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

#include <map>
#include <stdexcept>

#include <openssl/sha.h>

#include <coin/big_number.hpp>
#include <coin/hash.hpp>
#include <coin/ripemd160.hpp>
#include <coin/script.hpp>
#include <coin/signature_cache.hpp>
#include <coin/transaction.hpp>

using namespace coin;

static std::vector<std::uint8_t> & stack_top(
    std::vector< std::vector<std::uint8_t> > & alt_stack,
    const std::int32_t & i
    )
{
    return alt_stack.at(static_cast<std::int32_t> (alt_stack.size()) + i);
}

static void pop_stack(std::vector< std::vector<std::uint8_t> > & stack)
{
    if (stack.size() == 0)
    {
        throw std::runtime_error("popstack() : stack empty");
    }
    
    stack.pop_back();
}

static big_number to_big_number(const std::vector<std::uint8_t> & value)
{
    enum { max_num_size = 4 };
    
    if (value.size() > max_num_size)
    {
        throw std::runtime_error("overflow");
    }
    
    return big_number(big_number(value).get_vector());
}

static bool to_bool(const std::vector<std::uint8_t> & value)
{
    for (auto i = 0; i < value.size(); i++)
    {
        if (value[i] != 0)
        {
            if (i == value.size() - 1 && value[i] == 0x80)
            {
                return false;
            }
            
            return true;
        }
    }
    
    return false;
}

static void make_same_size(
    std::vector<std::uint8_t> & vch1, std::vector<std::uint8_t> & vch2
    )
{
    if (vch1.size() < vch2.size())
    {
        vch1.resize(vch2.size(), 0);
    }
    
    if (vch2.size() < vch1.size())
    {
        vch2.resize(vch1.size(), 0);
    }
}

/**
 * True
 */
const std::vector<std::uint8_t> script::true_ =
    std::vector<std::uint8_t> (1, 1)
;

/**
 * False
 */
const std::vector<std::uint8_t> script::false_ =
    std::vector<std::uint8_t> (0)
;

/**
 * Zero
 */
const big_number script::zero_(0);

/**
 * One
 */
const big_number script::one_(1);

script::script()
{
    // ...
}

script::script(const script & other)
    : std::vector<std::uint8_t> (other)
{
    // ...
}

script::script(
    const std::uint8_t * ptr_begin, const std::uint8_t * ptr_end
    )
    : std::vector<std::uint8_t>(ptr_begin, ptr_end)
{
    // ...
}

script::script(const_iterator it_begin, const_iterator it_end)
    : std::vector<std::uint8_t> (it_begin, it_end)
{
    // ...
}

std::string script::get_txn_output_type(const types::tx_out_t & t)
{
    switch (t)
    {
        case types::tx_out_nonstandard:
            return "nonstandard";
        case types::tx_out_pubkey:
            return "pubkey";
        case types::tx_out_pubkeyhash:
            return "pubkeyhash";
        case types::tx_out_scripthash:
            return "scripthash";
        case types::tx_out_multisig:
            return "multisig";
    }
    
    return std::string();
}

std::string script::get_op_name(const script::op_t & value)
{
    switch (value)
    {
        /** push value */
        case op_0:
            return "0";
        case op_pushdata1:
            return "OP_PUSHDATA1";
        case op_pushdata2:
            return "OP_PUSHDATA2";
        case op_pushdata4:
            return "OP_PUSHDATA4";
        case op_1negate:
            return "-1";
        case op_reserved:
            return "OP_RESERVED";
        case op_1:
            return "1";
        case op_2:
            return "2";
        case op_3:
            return "3";
        case op_4:
            return "4";
        case op_5:
            return "5";
        case op_6:
            return "6";
        case op_7:
            return "7";
        case op_8:
            return "8";
        case op_9:
            return "9";
        case op_10:
            return "10";
        case op_11:
            return "11";
        case op_12:
            return "12";
        case op_13:
            return "13";
        case op_14:
            return "14";
        case op_15:
            return "15";
        case op_16:
            return "16";
        /** control */
        case op_nop:
            return "OP_NOP";
        case op_ver:
            return "OP_VER";
        case op_if:
            return "OP_IF";
        case op_notif:
            return "OP_NOTIF";
        case op_verif:
            return "OP_VERIF";
        case op_vernotif:
            return "OP_VERNOTIF";
        case op_else:
            return "OP_ELSE";
        case op_endif:
            return "OP_ENDIF";
        case op_verify:
            return "OP_VERIFY";
        case op_return:
            return "OP_RETURN";
        /** stack ops */
        case op_toaltstack:
            return "OP_TOALTSTACK";
        case op_fromaltstack:
            return "OP_FROMALTSTACK";
        case op_2drop:
            return "OP_2DROP";
        case op_2dup:
            return "OP_2DUP";
        case op_3dup:
            return "OP_3DUP";
        case op_2over:
            return "OP_2OVER";
        case op_2rot:
            return "OP_2ROT";
        case op_2swap:
            return "OP_2SWAP";
        case op_ifdup:
            return "OP_IFDUP";
        case op_depth:
            return "OP_DEPTH";
        case op_drop:
            return "OP_DROP";
        case op_dup:
            return "OP_DUP";
        case op_nip:
            return "OP_NIP";
        case op_over:
            return "OP_OVER";
        case op_pick:
            return "OP_PICK";
        case op_roll:
            return "OP_ROLL";
        case op_rot:
            return "OP_ROT";
        case op_swap:
            return "OP_SWAP";
        case op_tuck:
            return "OP_TUCK";
        /** splice ops */
        case op_cat:
            return "OP_CAT";
        case op_substr:
            return "OP_SUBSTR";
        case op_left :
            return "OP_LEFT";
        case op_right:
            return "OP_RIGHT";
        case op_size:
            return "OP_SIZE";
        /** bit logic */
        case op_invert:
            return "OP_INVERT";
        case op_and:
            return "OP_AND";
        case op_or:
            return "OP_OR";
        case op_xor:
            return "OP_XOR";
        case op_equal:
            return "OP_EQUAL";
        case op_equalverify:
            return "OP_EQUALVERIFY";
        case op_reserved1:
            return "OP_RESERVED1";
        case op_reserved2:
            return "OP_RESERVED2";
        /** numeric */
        case op_1add:
            return "OP_1ADD";
        case op_1sub:
            return "OP_1SUB";
        case op_2mul:
            return "OP_2MUL";
        case op_2div:
            return "OP_2DIV";
        case op_negate:
            return "OP_NEGATE";
        case op_abs:
            return "OP_ABS";
        case op_not:
            return "OP_NOT";
        case op_0notequal:
            return "OP_0NOTEQUAL";
        case op_add:
            return "OP_ADD";
        case op_sub:
            return "OP_SUB";
        case op_mul:
            return "OP_MUL";
        case op_div:
            return "OP_DIV";
        case op_mod:
            return "OP_MOD";
        case op_lshift:
            return "OP_LSHIFT";
        case op_rshift:
            return "OP_RSHIFT";
        case op_booland:
            return "OP_BOOLAND";
        case op_boolor:
            return "OP_BOOLOR";
        case op_numequal:
            return "OP_NUMEQUAL";
        case op_numequalverify:
            return "OP_NUMEQUALVERIFY";
        case op_numnotequal:
            return "OP_NUMNOTEQUAL";
        case op_lessthan:
            return "OP_LESSTHAN";
        case op_greaterthan:
            return "OP_GREATERTHAN";
        case op_lessthanorequal:
            return "OP_LESSTHANOREQUAL";
        case op_greaterthanorequal:
            return "OP_GREATERTHANOREQUAL";
        case op_min:
            return "OP_MIN";
        case op_max:
            return "OP_MAX";
        case op_within:
            return "OP_WITHIN";
        /** crypto */
        case op_ripemd160:
            return "OP_RIPEMD160";
        case op_sha1:
            return "OP_SHA1";
        case op_sha256:
            return "OP_SHA256";
        case op_hash160:
            return "OP_HASH160";
        case op_hash256:
            return "OP_HASH256";
        case op_codeseparator:
            return "OP_CODESEPARATOR";
        case op_checksig:
            return "OP_CHECKSIG";
        case op_checksigverify:
            return "OP_CHECKSIGVERIFY";
        case op_checkmultisig:
            return "OP_CHECKMULTISIG";
        case op_checkmultisigverify:
            return "OP_CHECKMULTISIGVERIFY";
        /** expanson */
        case op_nop1:
            return "OP_NOP1";
        case op_nop2:
            return "OP_NOP2";
        case op_nop3:
            return "OP_NOP3";
        case op_nop4:
            return "OP_NOP4";
        case op_nop5:
            return "OP_NOP5";
        case op_nop6:
            return "OP_NOP6";
        case op_nop7:
            return "OP_NOP7";
        case op_nop8:
            return "OP_NOP8";
        case op_nop9:
            return "OP_NOP9";
        case op_nop10:
            return "OP_NOP10";
        /** template matching params */
        case op_pubkeyhash:
            return "OP_PUBKEYHASH";
        case op_pubkey:
            return "OP_PUBKEY";
        case op_invalidopcode:
            return "OP_INVALIDOPCODE";
        default:
            return "OP_UNKNOWN";
    }
    
    return "OP_UNKNOWN";
}

bool script::solver(
    const script & script_public_key, types::tx_out_t & tx_out_type,
    std::vector< std::vector<std::uint8_t> > & solutions
    )
{
    /**
     * The templates.
     */
    static std::map<types::tx_out_t, script> g_templates;
    
    if (g_templates.size() == 0)
    {
        /**
         * Standard transaction, sender provides public key, receiver adds
         * signature.
         */
        g_templates.insert(
            std::make_pair(types::tx_out_pubkey, script() <<
            op_pubkey << op_checksig)
        );

        /**
         * Coin address transaction, sender provides hash of public key,
         * receiver provides signature and public key.
         */
        g_templates.insert(
            std::make_pair(types::tx_out_pubkeyhash, script() << op_dup <<
            op_hash160 << op_pubkeyhash << op_equalverify << op_checksig)
        );

        /**
         * Sender provides N public keys, receivers provides M signatures.
         */
        g_templates.insert(
            std::make_pair(types::tx_out_multisig, script() <<
            op_smallinteger << op_pubkeys << op_smallinteger <<
            op_checkmultisig)
        );
    }

    /**
     * Shortcut for pay-to-script-hash.
     */
    if (script_public_key.is_pay_to_script_hash())
    {
        tx_out_type = types::tx_out_scripthash;
        
        std::vector<std::uint8_t> bytes(
            script_public_key.begin() + 2, script_public_key.begin() + 22
        );
        
        solutions.push_back(bytes);

        return true;
    }

    /**
     * Scan templates.
     */
    const script & script1 = script_public_key;
    
    for (auto & i : g_templates)
    {
        const script & script2 = i.second;
        
        solutions.clear();

        op_t opcode1, opcode2;
        
        std::vector<std::uint8_t> vch1, vch2;

        /**
         * Compare
         */
        auto it1 = script1.begin();
        auto it2 = script2.begin();

        for (;;)
        {
            if (it1 == script1.end() && it2 == script2.end())
            {
                /**
                 * Found a match.
                 */
                tx_out_type = i.first;
                
                if (tx_out_type == types::tx_out_multisig)
                {
                    /**
                     * Additional checks for tx_out_multisig.
                     */
                    std::uint8_t m = solutions.front()[0];
                    std::uint8_t n = solutions.back()[0];
                    
                    if (m < 1 || n < 1 || m > n || solutions.size() - 2 != n)
                    {
                        return false;
                    }
                }
                
                return true;
            }
            
            if (script1.get_op(it1, opcode1, vch1) == false)
            {
                break;
            }
            
            if (script2.get_op(it2, opcode2, vch2) == false)
            {
                break;
            }

            /**
             * Template matching opcodes.
             */
            if (opcode2 == op_pubkeys)
            {
                while (vch1.size() >= 33 && vch1.size() <= 120)
                {
                    solutions.push_back(vch1);
                    
                    if (script1.get_op(it1, opcode1, vch1) == false)
                    {
                        break;
                    }
                }
                
                if (script2.get_op(it2, opcode2, vch2) == false)
                {
                    break;
                }
            }

            if (opcode2 == op_pubkey)
            {
                if (vch1.size() < 33 || vch1.size() > 120)
                {
                    break;
                }
                
                solutions.push_back(vch1);
            }
            else if (opcode2 == op_pubkeyhash)
            {
                if (vch1.size() != ripemd160::digest_length)
                {
                    break;
                }
                
                solutions.push_back(vch1);
            }
            else if (opcode2 == op_smallinteger)
            {
                /**
                 * Single-byte small integer pushed onto solutions.
                 */
                if (
                    opcode1 == op_0 || (opcode1 >= op_1 && opcode1 <= op_16)
                    )
                {
                    char n = static_cast<char> (decode_op_n(opcode1));
                    
                    solutions.push_back(std::vector<std::uint8_t>(1, n));
                }
                else
                {
                    break;
                }
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                /**
                 * Others must match exactly.
                 */
                break;
            }
        }
    }

    solutions.clear();
    
    tx_out_type = types::tx_out_nonstandard;

    return false;
}

bool script::solver(
    const key_store & keystore, const script & script_pub_key,
    const sha256 & hash, const types::sighash_t & hash_type,
    script & script_sig_out, types::tx_out_t & which_type_out
    )
{
    script_sig_out.clear();

    std::vector< std::vector<std::uint8_t> > solutions;
    
    if (solver(script_pub_key, which_type_out, solutions) == false)
    {
        return false;
    }
    
    types::id_key_t key_id;
    
    switch (which_type_out)
    {
        case types::tx_out_nonstandard:
        {
            return false;
        }
        break;
        case types::tx_out_pubkey:
        {
            key_id = key_public(solutions[0]).get_id();
            
            return sign_1(key_id, keystore, hash, hash_type, script_sig_out);
        }
        break;
        case types::tx_out_pubkeyhash:
        {
            key_id = types::id_key_t(solutions[0]);
            
            if (
                sign_1(key_id, keystore, hash, hash_type,
                script_sig_out) == false
                )
            {
                return false;
            }
            else
            {
                key_public k;
                
                keystore.get_pub_key(key_id, k);
                
                script_sig_out << k;
            }
            
            return true;
        }
        break;
        case types::tx_out_scripthash:
        {
            return keystore.get_c_script(
                ripemd160(solutions[0]), script_sig_out
            );
        }
        break;
        case types::tx_out_multisig:
        {
            /**
             * @note This is a workaround for the CHECKMULTISIG bug.
             */
            script_sig_out << op_0;
            
            return
                sign_n(solutions, keystore, hash, hash_type, script_sig_out)
            ;
        }
        break;
    }
    
    return false;
}

bool script::evaluate(
    std::vector<std::vector<std::uint8_t> > & stack,
    const script & scr, const transaction & tx_to,
    const std::uint32_t & n, int hash_type
    )
{
    big_number::context bn_ctx;
    
    auto pc = scr.begin();
    auto pend = scr.end();
    auto pbegincodehash = scr.begin();
    op_t opcode;
    std::vector<std::uint8_t> vchPushValue;
    
    std::vector<bool> exec;
    
    std::vector< std::vector<std::uint8_t> > altstack;
    
    if (scr.size() > 10000)
    {
        return false;
    }
    
    int num_ops = 0;

    try
    {
        while (pc < pend)
        {
            bool fExec = count(exec.begin(), exec.end(), false) == 0;
            
            /**
             * Read instruction
             */
            if (scr.get_op(pc, opcode, vchPushValue) == false)
            {
                return false;
            }

            if (vchPushValue.size() > max_element_size)
            {
                return false;
            }
            
            if (opcode > op_16 && ++num_ops > 201)
            {
                return false;
            }
            
            if (
                opcode == op_cat || opcode == op_substr || opcode == op_left ||
                opcode == op_right || opcode == op_invert || opcode == op_and ||
                opcode == op_or || opcode == op_xor || opcode == op_2mul ||
                opcode == op_2div || opcode == op_mul || opcode == op_div ||
                opcode == op_mod || opcode == op_lshift || opcode == op_rshift
                )
            {
                return false;
            }
            
            if (fExec && 0 <= opcode && opcode <= op_pushdata4)
            {
                stack.push_back(vchPushValue);
            }
            else if (fExec || (op_if <= opcode && opcode <= op_endif))
            {
                switch (opcode)
                {
                    /**
                     * Push value
                     */
                    case op_1negate:
                    case op_1:
                    case op_2:
                    case op_3:
                    case op_4:
                    case op_5:
                    case op_6:
                    case op_7:
                    case op_8:
                    case op_9:
                    case op_10:
                    case op_11:
                    case op_12:
                    case op_13:
                    case op_14:
                    case op_15:
                    case op_16:
                    {
                        /**
                         * ( -- value)
                         */
                        big_number val((int)opcode - (int)(op_1 - 1));
                        
                        stack.push_back(val.get_vector());
                    }
                    break;
                    
                    /**
                     * Control
                     */
                    case op_nop:
                    case op_nop1:
                    case op_nop2:
                    case op_nop3:
                    case op_nop4:
                    case op_nop5:
                    case op_nop6:
                    case op_nop7:
                    case op_nop8:
                    case op_nop9:
                    case op_nop10:
                    break;
                    case op_if:
                    case op_notif:
                    {
                        /**
                         * <expression> if [statements] [else [statements]]
                         * endif
                         */
                        bool fValue = false;
                        
                        if (fExec)
                        {
                            if (stack.size() < 1)
                            {
                                return false;
                            }
                            
                            auto & vch = stack_top(stack, -1);
                            
                            fValue = to_bool(vch);
                            
                            if (opcode == op_notif)
                            {
                                fValue = !fValue;
                            }
                            
                            pop_stack(stack);
                        }
                        
                        exec.push_back(fValue);
                    }
                    break;
                    case op_else:
                    {
                        if (exec.size() == 0)
                        {
                            return false;
                        }
                        
                        exec.back() = !exec.back();
                    }
                    break;
                    case op_endif:
                    {
                        if (exec.size() == 0)
                        {
                            return false;
                        }
                        
                        exec.pop_back();
                    }
                    break;
                    case op_verify:
                    {
                        /**
                         * (true -- ) or
                         * (false -- false) and return
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        bool fValue = to_bool(stack_top(stack, -1));
                        
                        if (fValue)
                        {
                            pop_stack(stack);
                        }
                        else
                        {
                            return false;
                        }
                    }
                    break;
                    case op_return:
                    {
                        return false;
                    }
                    break;
                    
                    /**
                     * Stack ops
                     */
                    case op_toaltstack:
                    {
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        altstack.push_back(stack_top(stack, -1));
                        
                        pop_stack(stack);
                    }
                    break;
                    case op_fromaltstack:
                    {
                        if (altstack.size() < 1)
                        {
                            return false;
                        }
                        
                        stack.push_back(stack_top(altstack, -1));
                        
                        pop_stack(altstack);
                    }
                    break;
                    case op_2drop:
                    {
                        /**
                         * (x1 x2 -- )
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        pop_stack(stack);
                        pop_stack(stack);
                    }
                    break;
                    case op_2dup:
                    {
                        /**
                         * (x1 x2 -- x1 x2 x1 x2)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto vch1 = stack_top(stack, -2);
                        auto vch2 = stack_top(stack, -1);
                        
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;
                    case op_3dup:
                    {
                        /**
                         * (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                         */
                        if (stack.size() < 3)
                        {
                            return false;
                        }
                        
                        auto vch1 = stack_top(stack, -3);
                        auto vch2 = stack_top(stack, -2);
                        auto vch3 = stack_top(stack, -1);
                        
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                        stack.push_back(vch3);
                    }
                    break;
                    case op_2over:
                    {
                        /**
                         * (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                         */
                        if (stack.size() < 4)
                        {
                            return false;
                        }
                        
                        auto vch1 = stack_top(stack, -4);
                        auto vch2 = stack_top(stack, -3);
                        
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;
                    case op_2rot:
                    {
                        /**
                         * (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                         */
                        if (stack.size() < 6)
                        {
                            return false;
                        }
                        
                        auto vch1 = stack_top(stack, -6);
                        auto vch2 = stack_top(stack, -5);
                        
                        stack.erase(stack.end() - 6, stack.end() - 4);
                        stack.push_back(vch1);
                        stack.push_back(vch2);
                    }
                    break;
                    case op_2swap:
                    {
                        /**
                         * (x1 x2 x3 x4 -- x3 x4 x1 x2)
                         */
                        if (stack.size() < 4)
                        {
                            return false;
                        }

                        std::swap(stack_top(stack, -4), stack_top(stack, -2));
                        std::swap(stack_top(stack, -3), stack_top(stack, -1));
                    }
                    break;
                    case op_ifdup:
                    {
                        /**
                         * (x - 0 | x x)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        auto vch = stack_top(stack, -1);
                        
                        if (to_bool(vch))
                        {
                            stack.push_back(vch);
                        }
                    }
                    break;
                    case op_depth:
                    {
                        /**
                         * -- stacksize
                         */
                        big_number val(
                            static_cast<std::uint64_t> (stack.size())
                        );
                        
                        stack.push_back(val.get_vector());
                    }
                    break;
                    case op_drop:
                    {
                        /**
                         * (x -- )
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        pop_stack(stack);
                    }
                    break;
                    case op_dup:
                    {
                        /**
                         * (x -- x x)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        auto vch = stack_top(stack, -1);
                        
                        stack.push_back(vch);
                    }
                    break;
                    case op_nip:
                    {
                        /**
                         * (x1 x2 -- x2)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        stack.erase(stack.end() - 2);
                    }
                    break;
                    case op_over:
                    {
                        /**
                         * (x1 x2 -- x1 x2 x1)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto vch = stack_top(stack, -2);
                        
                        stack.push_back(vch);
                    }
                    break;
                    case op_pick:
                    case op_roll:
                    {
                        /**
                         * (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                         * (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        int n = to_big_number(stack_top(stack, -1)).get_int();
                        
                        pop_stack(stack);
                        
                        if (n < 0 || n >= stack.size())
                        {
                            return false;
                        }
                        
                        auto vch = stack_top(stack, -n-1);
                        
                        if (opcode == op_roll)
                        {
                            stack.erase(stack.end()-n-1);
                        }
                        
                        stack.push_back(vch);
                    }
                    break;
                    case op_rot:
                    {
                        /**
                         * (x1 x2 x3 -- x2 x3 x1)
                         * x2 x1 x3 after first swap
                         * x2 x3 x1 after second swap
                         */
                        if (stack.size() < 3)
                        {
                            return false;
                        }

                        std::swap(stack_top(stack, -3), stack_top(stack, -2));
                        std::swap(stack_top(stack, -2), stack_top(stack, -1));
                    }
                    break;
                    case op_swap:
                    {
                        /**
                         * (x1 x2 -- x2 x1)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }

                        std::swap(stack_top(stack, -2), stack_top(stack, -1));
                    }
                    break;
                    case op_tuck:
                    {
                        /**
                         * (x1 x2 -- x2 x1 x2)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto vch = stack_top(stack, -1);
                        
                        stack.insert(stack.end() - 2, vch);
                    }
                    break;
                
                    /**
                     * Splice ops
                     */
                    case op_cat:
                    {
                        /**
                         * (x1 x2 -- out)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto & vch1 = stack_top(stack, -2);
                        auto & vch2 = stack_top(stack, -1);
                        
                        vch1.insert(vch1.end(), vch2.begin(), vch2.end());
                        
                        pop_stack(stack);
                        
                        if (stack_top(stack, -1).size() > max_element_size)
                        {
                            return false;
                        }
                    }
                    break;
                    case op_substr:
                    {
                        /**
                         * (in begin size -- out)
                         */
                        if (stack.size() < 3)
                        {
                            return false;
                        }
                        
                        auto & vch = stack_top(stack, -3);
                        
                        auto nBegin = to_big_number(
                            stack_top(stack, -2)
                        ).get_int();
                        
                        auto nEnd = nBegin + to_big_number(
                            stack_top(stack, -1)
                        ).get_int();
                        
                        if (nBegin < 0 || nEnd < nBegin)
                        {
                            return false;
                        }
                        
                        if (nBegin > vch.size())
                        {
                           nBegin = static_cast<std::int32_t> (vch.size());
                        }
                        
                        if (nEnd > vch.size())
                        {
                            nEnd = static_cast<std::int32_t> (vch.size());
                        }
                        
                        vch.erase(vch.begin() + nEnd, vch.end());
                        vch.erase(vch.begin(), vch.begin() + nBegin);
                        
                        pop_stack(stack);
                        pop_stack(stack);
                    }
                    break;
                    case op_left:
                    case op_right:
                    {
                        /**
                         * (in size -- out)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto & vch = stack_top(stack, -2);
                        
                        auto nSize = to_big_number(
                            stack_top(stack, -1)
                        ).get_int();
                        
                        if (nSize < 0)
                        {
                            return false;
                        }
                        
                        if (nSize > vch.size())
                        {
                            nSize = static_cast<std::int32_t> (vch.size());
                        }
                        
                        if (opcode == op_left)
                        {
                            vch.erase(vch.begin() + nSize, vch.end());
                        }
                        else
                        {
                            vch.erase(vch.begin(), vch.end() - nSize);
                        }
                        
                        pop_stack(stack);
                    }
                    break;
                    case op_size:
                    {
                        /**
                         * (in -- in size)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        big_number val(
                            static_cast<std::uint64_t> (
                            stack_top(stack, -1).size())
                        );
                        
                        stack.push_back(val.get_vector());
                    }
                    break;
                    
                    /**
                     * Bitwise logic
                     */
                    case op_invert:
                    {
                        /**
                         * (in - out)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        auto & vch = stack_top(stack, -1);
                        
                        for (auto i = 0; i < vch.size(); i++)
                        {
                            vch[i] = ~vch[i];
                        }
                    }
                    break;
                
                    /**
                     * WARNING: These disabled opcodes exhibit unexpected
                     * behavior when used on signed integers.
                     */
                    case op_and:
                    case op_or:
                    case op_xor:
                    {
                        /**
                         * (x1 x2 - out)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto & vch1 = stack_top(stack, -2);
                        auto & vch2 = stack_top(stack, -1);
                        
                        /**
                         * This is NOT safe for signed integers.
                         */
                        make_same_size(vch1, vch2);
                        
                        if (opcode == op_and)
                        {
                            for (auto i = 0; i < vch1.size(); i++)
                            {
                                vch1[i] &= vch2[i];
                            }
                        }
                        else if (opcode == op_or)
                        {
                            for (auto i = 0; i < vch1.size(); i++)
                            {
                                vch1[i] |= vch2[i];
                            }
                        }
                        else if (opcode == op_xor)
                        {
                            for (auto i = 0; i < vch1.size(); i++)
                            {
                                vch1[i] ^= vch2[i];
                            }
                        }
                        
                        pop_stack(stack);
                    }
                    break;
                    case op_equal:
                    case op_equalverify:
                    /** case op_notequal: */
                    /** case op_numnotequal: */
                    {
                        /**
                         * (x1 x2 - bool)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto & vch1 = stack_top(stack, -2);
                        auto & vch2 = stack_top(stack, -1);

                        bool equal = vch1 == vch2;

                        pop_stack(stack);
                        pop_stack(stack);
                        
                        stack.push_back(equal ? true_ : false_);
                        
                        if (opcode == op_equalverify)
                        {
                            if (equal)
                            {
                                pop_stack(stack);
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                    break;
                    
                    /**
                     * Numeric
                     */
                    case op_1add:
                    case op_1sub:
                    case op_2mul:
                    case op_2div:
                    case op_negate:
                    case op_abs:
                    case op_not:
                    case op_0notequal:
                    {
                        /**
                         * (in -- out)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        auto val = to_big_number(stack_top(stack, -1));
                        
                        switch (opcode)
                        {
                            case op_1add:
                            {
                                val += one_;
                            }
                            break;
                            case op_1sub:
                            {
                                val -= one_;
                            }
                            break;
                            case op_2mul:
                            {
                                val <<= 1;
                            }
                            break;
                            case op_2div:
                            {
                                val >>= 1;
                            }
                            break;
                            case op_negate:
                            {
                                val = -val;
                            }
                            break;
                            case op_abs:
                            {
                                if (val < zero_)
                                {
                                    val = -val;
                                }
                            }
                            break;
                            case op_not:
                            {
                                val = val == zero_;
                            }
                            break;
                            case op_0notequal:
                            {
                                val = val != zero_;
                            }
                            break;
                            default:
                            {
                                assert(!"invalid opcode");
                            }
                            break;
                        }
                        
                        pop_stack(stack);
                        
                        stack.push_back(val.get_vector());
                    }
                    break;
                    case op_add:
                    case op_sub:
                    case op_mul:
                    case op_div:
                    case op_mod:
                    case op_lshift:
                    case op_rshift:
                    case op_booland:
                    case op_boolor:
                    case op_numequal:
                    case op_numequalverify:
                    case op_numnotequal:
                    case op_lessthan:
                    case op_greaterthan:
                    case op_lessthanorequal:
                    case op_greaterthanorequal:
                    case op_min:
                    case op_max:
                    {
                        /**
                         * (x1 x2 -- out)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto bn1 = to_big_number(stack_top(stack, -2));
                        auto bn2 = to_big_number(stack_top(stack, -1));
                        
                        big_number val;
                        
                        switch (opcode)
                        {
                            case op_add:
                            {
                                val = bn1 + bn2;
                            }
                            break;
                            case op_sub:
                            {
                                val = bn1 - bn2;
                            }
                            break;
                            case op_mul:
                            {
                                if (!BN_mul(&val, &bn1, &bn2, bn_ctx))
                                {
                                    return false;
                                }
                            }
                            break;
                            case op_div:
                            {
                                if (!BN_div(&val, NULL, &bn1, &bn2, bn_ctx))
                                {
                                    return false;
                                }
                            }
                            break;
                            case op_mod:
                            {
                                if (!BN_mod(&val, &bn1, &bn2, bn_ctx))
                                {
                                    return false;
                                }
                            }
                            break;
                            case op_lshift:
                            {
                                if (bn2 < zero_ || bn2 > big_number(2048))
                                {
                                    return false;
                                }
                                
                                val = bn1 << bn2.get_ulong();
                            }
                            break;
                            case op_rshift:
                            {
                                if (bn2 < zero_ || bn2 > big_number(2048))
                                {
                                    return false;
                                }
                                
                                val = bn1 >> bn2.get_ulong();
                            }
                            break;
                            case op_booland:
                            {
                                val = (bn1 != zero_ && bn2 != zero_);
                            }
                            break;
                            case op_boolor:
                            {
                                val = (bn1 != zero_ || bn2 != zero_);
                            }
                            break;
                            case op_numequal:
                            {
                                val = (bn1 == bn2);
                            }
                            break;
                            case op_numequalverify:
                            {
                                val = (bn1 == bn2);
                            }
                            break;
                            case op_numnotequal:
                            {
                                val = (bn1 != bn2);
                            }
                            break;
                            case op_lessthan:
                            {
                                val = (bn1 < bn2);
                            }
                            break;
                            case op_greaterthan:
                            {
                                val = (bn1 > bn2);
                            }
                            break;
                            case op_lessthanorequal:
                            {
                                val = (bn1 <= bn2);
                            }
                            break;
                            case op_greaterthanorequal:
                            {
                                val = (bn1 >= bn2);
                            }
                            break;
                            case op_min:
                            {
                                val = (bn1 < bn2 ? bn1 : bn2);
                            }
                            break;
                            case op_max:
                            {
                                val = (bn1 > bn2 ? bn1 : bn2);
                            }
                            break;
                            default:
                            {
                                assert(!"invalid opcode");
                            }
                            break;
                        }
                        
                        pop_stack(stack);
                        pop_stack(stack);
                        
                        stack.push_back(val.get_vector());

                        if (opcode == op_numequalverify)
                        {
                            if (to_bool(stack_top(stack, -1)))
                            {
                                pop_stack(stack);
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                    break;
                    case op_within:
                    {
                        /**
                         * (x min max -- out)
                         */
                        if (stack.size() < 3)
                        {
                            return false;
                        }
                        
                        auto bn1 = to_big_number(stack_top(stack, -3));
                        auto bn2 = to_big_number(stack_top(stack, -2));
                        auto bn3 = to_big_number(stack_top(stack, -1));
                        
                        bool value = bn2 <= bn1 && bn1 < bn3;
                        
                        pop_stack(stack);
                        pop_stack(stack);
                        pop_stack(stack);
                        
                        stack.push_back(value ? true_ : false_);
                    }
                    break;
                    
                    /**
                     * Crypto
                     */
                    case op_ripemd160:
                    case op_sha1:
                    case op_sha256:
                    case op_hash160:
                    case op_hash256:
                    {
                        /**
                         * (in -- hash)
                         */
                        if (stack.size() < 1)
                        {
                            return false;
                        }
                        
                        auto & val = stack_top(stack, -1);
                        
                        std::vector<std::uint8_t> digest(
                            (opcode == op_ripemd160 || opcode == op_sha1 ||
                            opcode == op_hash160) ?
                            static_cast<std::uint8_t> (ripemd160::digest_length) :
                            static_cast<std::uint8_t> (sha256::digest_length)
                        );
                        
                        if (opcode == op_ripemd160)
                        {
                            auto h = ripemd160::hash(&val[0], val.size());
                            
                            std::memcpy(
                                &digest[0], &h[0], h.size()
                            );
                        }
                        else if (opcode == op_sha1)
                        {
                            SHA1(&val[0], val.size(), &digest[0]);
                        }
                        else if (opcode == op_sha256)
                        {
                            auto h = sha256::hash(&val[0], val.size());
                            
                            std::memcpy(&digest[0], &h[0], h.size());
                        }
                        else if (opcode == op_hash160)
                        {
                            auto h = hash::sha256_ripemd160(
                                &val[0], val.size()
                            );
                            
                            std::memcpy(&digest[0], &h[0], h.size());
                        }
                        else if (opcode == op_hash256)
                        {
                            auto h = hash::sha256d(&val[0], val.size());
                            
                            std::memcpy(&digest[0], &h[0], h.size());
                        }
                        
                        pop_stack(stack);
                   
                        stack.push_back(digest);
                    }
                    break;
                    case op_codeseparator:
                    {
                        /**
                         * Hash starts after the code separator.
                         */
                        pbegincodehash = pc;
                    }
                    break;
                    case op_checksig:
                    case op_checksigverify:
                    {
                        /**
                         * (sig pubkey -- bool)
                         */
                        if (stack.size() < 2)
                        {
                            return false;
                        }
                        
                        auto & signature = stack_top(stack, -2);
                        auto & pub_key = stack_top(stack, -1);

                        /**
                         * Subset of script starting at the most recent
                         * code separator.
                         */
                        script scriptCode(pbegincodehash, pend);

                        /**
                         * Drop the signature, since there's no way for a
                         * signature to sign itself.
                        */
                        scriptCode.find_and_delete(
                            script(&signature[0],
                            &signature[0] + signature.size())
                        );

                        auto success = check_signature(
                            signature, pub_key, scriptCode, tx_to, n,
                            hash_type
                        );

                        pop_stack(stack);
                        pop_stack(stack);
                        
                        stack.push_back(
                            success ? std::vector<std::uint8_t> (1, 1) :
                            std::vector<std::uint8_t> (0)
                        );
                        
                        if (opcode == op_checksigverify)
                        {
                            if (success)
                            {
                                pop_stack(stack);
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                    break;
                    case op_checkmultisig:
                    case op_checkmultisigverify:
                    {
                        /**
                         * ([sig ...] num_of_signatures [pubkey ...]
                         * num_of_pubkeys -- bool)
                         */
                        int i = 1;
                        
                        if (stack.size() < i)
                        {
                            return false;
                        }
                        
                        auto num_keys = to_big_number(
                            stack_top(stack, -i)
                        ).get_int();
                        
                        if (num_keys < 0 || num_keys > 20)
                        {
                            return false;
                        }
                        
                        num_ops += num_keys;
                        
                        if (num_ops > 201)
                        {
                            return false;
                        }
                        
                        int ikey = ++i;
                        
                        i += num_keys;
                        
                        if (stack.size() < i)
                        {
                            return false;
                        }
                        
                        auto num_signatures = to_big_number(
                            stack_top(stack, -i)
                        ).get_int();
                        
                        if (num_signatures < 0 || num_signatures > num_keys)
                        {
                            return false;
                        }
                        
                        auto isig = ++i;
                        
                        i += num_signatures;
                        
                        if (stack.size() < i)
                        {
                            return false;
                        }
                        
                        /**
                         * Subset of script starting at the most recent
                         * codeseparator.
                         */
                        script scriptCode(pbegincodehash, pend);

                        /**
                         * Drop the signatures, since there's no way for a
                         * signature to sign itself.
                         */
                        for (auto k = 0; k < num_signatures; k++)
                        {
                            auto & signature = stack_top(stack, -isig - k);
                            
                            scriptCode.find_and_delete(script(signature));
                        }

                        auto success = true;
                        
                        while (success && num_signatures > 0)
                        {
                            auto & signature = stack_top(stack, -isig);
                            auto & pub_key = stack_top(stack, -ikey);

                            /**
                             * Check signature.
                             */
                            if (
                                check_signature(signature, pub_key, scriptCode,
                                tx_to, n, hash_type)
                                )
                            {
                                isig++;
                                
                                num_signatures--;
                            }
                            
                            ikey++;
                            
                            num_keys--;

                            /**
                             * If there are more signatures left than keys,
                             * then too many signatures have failed.
                             */
                            if (num_signatures > num_keys)
                            {
                                success = false;
                            }
                        }

                        while (i-- > 0)
                        {
                            pop_stack(stack);
                        }
                        
                        stack.push_back(
                            success ? std::vector<std::uint8_t> (1, 1) :
                            std::vector<std::uint8_t> (0)
                        );

                        if (opcode == op_checkmultisigverify)
                        {
                            if (success)
                            {
                                pop_stack(stack);
                            }
                            else
                            {
                                return false;
                            }
                        }
                    }
                    break;
                    default:
                    {
                        return false;
                    }
                    break;
                }
            }
            
            /**
             * Size limits.
             */
            if (stack.size() + altstack.size() > 1000)
            {
                return false;
            }
        }
    }
    catch (std::exception & e)
    {
        log_error("Script, evaluate failed, what = " << e.what() << ".");
        
        return false;
    }

    if (exec.size() > 0)
    {
        return false;
    }
    
    return true;
}

unsigned int script::get_sig_op_count(const bool & accurate) const
{
    unsigned int n = 0;
    
    auto it = begin();
    
    auto last_opcode = op_invalidopcode;
    
    while (it < end())
    {
        op_t opcode;
        
        if (!get_op(it, opcode))
        {
            break;
        }
        
        if (opcode == op_checksig || opcode == op_checksigverify)
        {
            n++;
        }
        else if (
            opcode == op_checkmultisig ||
            opcode == op_checkmultisigverify
            )
        {
            if (accurate && last_opcode >= op_1 && last_opcode <= op_16)
            {
                n += decode_op_n(last_opcode);
            }
            else
            {
                n += 20;
            }
        }
        
        last_opcode = opcode;
    }
    
    return n;
}

unsigned int script::get_sig_op_count(const script & script_sig) const
{
    if (!is_pay_to_script_hash())
    {
        return get_sig_op_count(true);
    }
    
    auto it = script_sig.begin();
    
    std::vector<std::uint8_t> data;
    
    while (it < script_sig.end())
    {
        op_t opcode;
        
        if (!script_sig.get_op(it, opcode, data))
        {
            return 0;
        }
        
        if (opcode > op_16)
        {
            return 0;
            
        }
    }

    script subscript(&data[0], &data[0] + data.size());
    
    return subscript.get_sig_op_count(true);
}

bool script::is_pay_to_script_hash() const
{
    return
        this->size() == 23 && this->at(0) == op_hash160 &&
        this->at(1) == 0x14 && this->at(22) == op_equal
    ;
}

bool script::is_push_only() const
{
    auto it = begin();
    
    while (it < end())
    {
        op_t opcode;
        
        if (!get_op(it, opcode))
        {
            return false;
        }
        
        if (opcode > op_16)
        {
            return false;
        }
    }
    
    return true;
}

void script::set_destination(const destination::tx_t & addr)
{
    boost::apply_visitor(visitor(*this), addr);
}

void script::set_multi_sig(const int & required, const std::vector<key> & keys)
{
    this->clear();

    *this << encode_op_n(required);
    
    for (auto & i : keys)
    {
        *this << i.get_public_key();
    }
    
    *this << encode_op_n(static_cast<int> (keys.size())) << op_checkmultisig;
}

void script::print_hex() const
{
    printf("script(%s)\n", utility::hex_string(begin(), end(), true).c_str());
}

std::string script::to_string(const bool & make_short) const
{
    std::string str;
    
    op_t opcode;
    
    std::vector<std::uint8_t> v;
    
    auto it = begin();
    
    while (it < end())
    {
        if (str.size() > 0)
        {
            str += " ";
        }

        if (!get_op(it, opcode, v))
        {
            str += "[error]";
            
            return str;
        }

        if (0 <= opcode && opcode <= op_pushdata4)
        {
            str +=
                make_short ? value_string(v).substr(0, 10) : value_string(v)
            ;
        }
        else
        {
            str += get_op_name(opcode);
        }
    }
    return str;
}

void script::print() const
{
    log_debug("Script: " << to_string());
}

types::id_script_t script::get_id() const
{
    std::vector<std::uint8_t> bytes = *this;

    types::id_script_t ret;
    
    auto hash160 = hash::sha256_ripemd160(
        &bytes[0], bytes.size()
    );
    
    std::memcpy(&ret.digest()[0], &hash160[0], hash160.size());
    
    return ret;
}

int script::sig_args_expected(
    const types::tx_out_t & tx_type,
    const std::vector<std::vector<std::uint8_t> > & solutions
    )
{
    switch (tx_type)
    {
        case types::tx_out_nonstandard:
        {
            return -1;
        }
        break;
        case types::tx_out_pubkey:
        {
            return 1;
        }
        break;
        case types::tx_out_pubkeyhash:
        {
            return 2;
        }
        break;
        case types::tx_out_multisig:
        {
            if (solutions.size() < 1 || solutions[0].size() < 1)
            {
                return -1;
            }
            
            return solutions[0][0] + 1;
        }
        break;
        case types::tx_out_scripthash:
        {
            return 1;
        }
        break;
        default:
        break;
    }
    
    return -1;
}

bool script::is_standard(const script & script_public_key)
{
    std::vector< std::vector<std::uint8_t> > solutions;
    
    types::tx_out_t which_type;
    
    if (solver(script_public_key, which_type, solutions) == false)
    {
        return false;
    }
    
    if (which_type == types::tx_out_multisig)
    {
        auto m = solutions.front()[0];
        auto n = solutions.back()[0];
        
        /**
         * Support up to x-of-3 multisig transactions as standard.
         */
        if (n < 1 || n > 3)
        {
            return false;
        }
        
        if (m < 1 || m > n)
        {
            return false;
        }
    }

    return which_type != types::tx_out_nonstandard;
}

std::size_t script::have_keys(
    const std::vector< std::vector<std::uint8_t> > & pub_keys,
    const key_store & store
    )
{
    std::size_t ret = 0;
    
    for (auto & i : pub_keys)
    {
        if (store.have_key(key_public(i).get_id()))
        {
            ++ret;
        }
    }
    
    return ret;
}

bool script::is_mine(const key_store & store, const destination::tx_t & dest)
{
    return boost::apply_visitor(key_store::is_mine_visitor(store), dest);
}

bool script::is_mine(
    const key_store & store, const script & script_public_key
    )
{
    std::vector< std::vector<std::uint8_t> > solutions;
    
    types::tx_out_t which_type;
    
    if (solver(script_public_key, which_type, solutions) == false)
    {
        return false;
    }
    
    types::id_key_t key_id;
    
    switch (which_type)
    {
        case types::tx_out_nonstandard:
        {
            return false;
        }
        break;
        case types::tx_out_pubkey:
        {
            key_id = key_public(solutions[0]).get_id();
            
            return store.have_key(key_id);
        }
        break;
        case types::tx_out_pubkeyhash:
        {
            key_id = types::id_key_t(ripemd160(solutions[0]));
            
            return store.have_key(key_id);
        }
        break;
        case types::tx_out_scripthash:
        {
            script subscript;
            
            if (
                store.get_c_script(types::id_script_t(
                ripemd160(solutions[0])), subscript
                ) == false)
            {
                return false;
            }
            
            return is_mine(store, subscript);
        }
        break;
        case types::tx_out_multisig:
        {
            /**
             * Only consider transactions "mine" if we own ALL the keys
             * involved. multi-signature transactions that are partially
             * owned (somebody else has a key that can spend them) enable
             * spend-out-from-under-you attacks, especially in shared-wallet
             * situations.
             */
            std::vector< std::vector<std::uint8_t> > keys(
                solutions.begin() + 1, solutions.begin()+solutions.size()-1
            );
            
            return have_keys(keys, store) == keys.size();
        }
        break;
    }
    
    return false;
}

bool script::extract_destination(
    const script & script_public_key,
    destination::tx_t & address_out
    )
{
    std::vector< std::vector<std::uint8_t> > solutions;
    
    types::tx_out_t which_type;
    
    if (solver(script_public_key, which_type, solutions) == false)
    {
        return false;
    }
    
    if (which_type == types::tx_out_pubkey)
    {
        address_out = key_public(solutions[0]).get_id();
        
        return true;
    }
    else if (which_type == types::tx_out_pubkeyhash)
    {
        address_out = types::id_key_t(ripemd160(solutions[0]));
        
        return true;
    }
    else if (which_type == types::tx_out_scripthash)
    {
        address_out = types::id_script_t(ripemd160(solutions[0]));
        
        return true;
    }
    
    return false;
}

bool script::extract_destinations(
    const script & script_public_key, types::tx_out_t & type_out,
    std::vector<destination::tx_t> & address_out,
    std::int32_t & required_out
    )
{
    address_out.clear();
    
    type_out = types::tx_out_nonstandard;
    
    std::vector< std::vector<std::uint8_t> > solutions;
    
    if (solver(script_public_key, type_out, solutions) == false)
    {
        return false;
    }

    if (type_out == types::tx_out_multisig)
    {
        required_out = solutions.front()[0];
        
        for (auto i = 1; i < solutions.size() - 1; i++)
        {
            destination::tx_t address = key_public(solutions[i]).get_id();
            
            address_out.push_back(address);
        }
    }
    else
    {
        required_out = 1;
        
        destination::tx_t address;
        
        if (extract_destination(script_public_key, address) == false)
        {
           return false;
        }
        
        address_out.push_back(address);
    }

    return true;
}

bool script::sign_signature(
    const key_store & keystore, const script & pub_key_from,
    transaction & tx_to, const std::uint32_t & n,
    const types::sighash_t & hash_type
    )
{
    assert(n < tx_to.transactions_in().size());
    
    auto & tx_in = tx_to.transactions_in()[n];

    auto hash = signature_hash(pub_key_from, tx_to, n, hash_type);
    
    types::tx_out_t which_type;
    
    if (
        solver(keystore, pub_key_from, hash, hash_type,
        tx_in.script_signature(), which_type) == false
        )
    {
        log_debug("Script, sign signature failed, solver is false.");
        
        return false;
    }
    
    if (which_type == types::tx_out_scripthash)
    {
        script subscript = tx_in.script_signature();

        auto hash2 = signature_hash(subscript, tx_to, n, hash_type);

        types::tx_out_t sub_type;
        
        bool solved =
            solver(keystore, subscript, hash2, hash_type,
            tx_in.script_signature(), sub_type) && sub_type !=
            types::tx_out_scripthash
        ;
        
        tx_in.script_signature() <<
            static_cast< std::vector<std::uint8_t> >(subscript)
        ;
        
        if (solved == false)
        {
            log_debug("Script, sign signature failed, solved is false.");
            
            return false;
        }
    }

    return verify_script(
        tx_in.script_signature(), pub_key_from, tx_to, n, true, 0
    );
}

bool script::sign_signature(
    const key_store & keystore, const transaction & tx_from,
    transaction & tx_to, const std::uint32_t & n,
    const types::sighash_t & hash_type
    )
{
    assert(n < tx_to.transactions_in().size());
    
    auto & tx_in = tx_to.transactions_in()[n];
    
    assert(tx_in.previous_out().n() < tx_from.transactions_out().size());
    assert(tx_in.previous_out().get_hash() == tx_from.get_hash());
    
    const auto & tx_out = tx_from.transactions_out()[tx_in.previous_out().n()];

    return sign_signature(
        keystore, tx_out.script_public_key(), tx_to, n, hash_type
    );
}

bool script::verify_script(
    const script & script_signature, const script & script_public_key,
    const transaction & tx_to, const std::uint32_t & in,
    bool validate_pay_to_script_hash, int hash_type
    )
{
    std::vector< std::vector<std::uint8_t> > stack, stack_copy;

    if (evaluate(stack, script_signature, tx_to, in, hash_type) == false)
    {
        log_debug(
            "Script, verify script failed, failed to evaluate script "
            "signature = " << script_signature.to_string() << "."
        );
        
        return false;
    }
    
    if (validate_pay_to_script_hash)
    {
        stack_copy = stack;
    }
    
    if (evaluate(stack, script_public_key, tx_to, in, hash_type) == false)
    {
        log_debug(
            "Script, verify script failed, failed to evaluate script "
            "public key = " << script_public_key.to_string() << "."
        );
        
        return false;
    }
    
    if (stack.size() == 0)
    {
        log_debug("Script, verify script failed, 3.");
        
        return false;
    }
    
    if (to_bool(stack.back()) == false)
    {
        log_debug("Script, verify script failed, 4 (eval = false).");
        
        return false;
    }
    
    /**
     * Additional validation for spend-to-script-hash transactions.
     */
    if (
        validate_pay_to_script_hash && script_public_key.is_pay_to_script_hash()
        )
    {
        /**
         * Must be literals only.
         */
        if (script_signature.is_push_only() == false)
        {
            log_debug("Script, verify script failed, 5.");
            
            return false;
        }
        
        const auto & pub_key_serialized = stack_copy.back();
        
        script pub_key2(pub_key_serialized.begin(), pub_key_serialized.end());
        
        pop_stack(stack_copy);

        if (evaluate(stack_copy, pub_key2, tx_to, in, hash_type) == false)
        {
            log_debug("Script, verify script failed, 6.");
            
            return false;
        }
        
        if (stack_copy.size() == 0)
        {
            log_debug("Script, verify script failed, 7.");
            
            return false;
        }
        
        return to_bool(stack_copy.back());
    }

    return true;
}

bool script::verify_signature(
    const transaction & tx_from, const transaction & tx_to,
    const std::uint32_t & in, bool validate_pay_to_script_hash, int hash_type
    )
{
    assert(in < tx_to.transactions_in().size());
    
    const auto & tx_in = tx_to.transactions_in()[in];

    if (tx_in.previous_out().n() >= tx_from.transactions_out().size())
    {
        return false;
    }
    
    if (tx_in.previous_out().get_hash() != tx_from.get_hash())
    {
        return false;
    }

    const auto & tx_out = tx_from.transactions_out()[tx_in.previous_out().n()];
    
    return verify_script(
        tx_in.script_signature(), tx_out.script_public_key(), tx_to, in,
        validate_pay_to_script_hash, hash_type
    );
}

/** private */

bool script::sign_1(
    const types::id_key_t & address, const key_store & keystore,
    const sha256 & hash, const types::sighash_t & hash_type,
    script & script_sig_out
    )
{
    key k;
    
    if (keystore.get_key(address, k) == false)
    {
        return false;
    }
    
    std::vector<std::uint8_t> signature;
    
    if (k.sign(hash, signature) == false)
    {
        return false;
    }
    
    signature.push_back(static_cast<std::uint8_t> (hash_type));
    
    script_sig_out << signature;

    return true;
}

bool script::sign_n(
    const std::vector< std::vector<std::uint8_t> > & multisig_data,
    const key_store & keystore, const sha256 & hash,
    const types::sighash_t & hash_type, script & script_sig_out
    )
{
    auto count = 0;
    int required = multisig_data.front()[0];
    
    for (auto i = 1; i < multisig_data.size() - 1 && count < required; i++)
    {
        const auto & pub_key = multisig_data[i];
        
        auto key_id = key_public(pub_key).get_id();
        
        if (sign_1(key_id, keystore, hash, hash_type, script_sig_out))
        {
            ++count;
        }
    }
    
    return count == required;
}

/** protected */

script & script::push_int64(std::int64_t n)
{
    if (n == -1 || (n >= 1 && n <= 16))
    {
        this->push_back(n + (op_1 - 1));
    }
    else
    {
        big_number bn(n);
        
        *this << bn.get_vector();
    }
    return *this;
}

script & script::push_uint64(std::uint64_t n)
{
    if (n >= 1 && n <= 16)
    {
        this->push_back(n + (op_1 - 1));
    }
    else
    {
        big_number bn(n);
        
        *this << bn.get_vector();
    }
    return *this;
}

bool script::check_signature(
    std::vector<std::uint8_t> signature, std::vector<std::uint8_t> pub_key,
    script script_code, const transaction & tx_to, const std::uint32_t & n,
    int hash_type
    )
{
    if (signature.size() == 0)
    {
        return false;
    }
    
    if (hash_type == 0)
    {
        hash_type = signature.back();
    }
    else if (hash_type != signature.back())
    {
        return false;
    }
    
    signature.pop_back();

    auto hash = signature_hash(script_code, tx_to, n, hash_type);

    if (signature_cache::instance().get(hash, signature, pub_key))
    {
        return true;
    }
    
    key k;
    
    if (k.set_public_key(pub_key) == false)
    {
        return false;
    }
    
    if (k.verify(hash, signature) == false)
    {
        log_debug(
            "Script, signature verification failed, hash = " <<
            hash.to_string() << "."
        );
    
        return false;
    }
    
    signature_cache::instance().set(hash, signature, pub_key);
    
    return true;
}

sha256 script::signature_hash(
    script script_code, const transaction & tx_to, const std::uint32_t & n,
    int hash_type
    )
{
    if (n >= tx_to.transactions_in().size())
    {
        log_error("Script signature hash, n = " << n << " is out of range.");
        
        return 0;
    }
    
    transaction tx_tmp(tx_to);

    /**
     * Delete all code seperators including multiple trailing code seperators.
     */
    script_code.find_and_delete(script(op_codeseparator));

    /**
     * Blank out other inputs' signatures.
     */
    for (auto i = 0; i < tx_tmp.transactions_in().size(); i++)
    {
        tx_tmp.transactions_in()[i].set_script_signature(script());
    }
    
    tx_tmp.transactions_in()[n].set_script_signature(script_code);

    /**
     * Blank out some of the outputs.
     */
    if ((hash_type & 0x1f) == types::sighash_none)
    {
        /**
         * Wildcard payee.
         */
        tx_tmp.transactions_out().clear();

        /**
         * Let the others update at will.
         */
        for (auto i = 0; i < tx_tmp.transactions_in().size(); i++)
        {
            if (i != n)
            {
                tx_tmp.transactions_in()[i].set_sequence(0);
            }
        }
    }
    else if ((hash_type & 0x1f) == types::sighash_single)
    {
        /**
         * Only lock-in the transaction out payee at same index as
         * tranaction in.
         */
        auto n_out = n;
        
        if (n_out >= tx_tmp.transactions_out().size())
        {
            log_error(
                "Script signature hash, n out = " << n_out <<
                " is out of range."
            );
            
            return 1;
        }
        
        tx_tmp.transactions_out().resize(n_out + 1);
        
        for (auto i = 0; i < n_out; i++)
        {
            tx_tmp.transactions_out()[i].set_null();
        }
        
        /**
         * Let the others update at will.
         */
        for (auto i = 0; i < tx_tmp.transactions_in().size(); i++)
        {
            if (i != n)
            {
                tx_tmp.transactions_in()[i].set_sequence(0);
            }
        }
    }

    /**
     * Blank out other inputs completely. This not recommended for open
     * transactions.
     */
    if (hash_type & types::sighash_anyonecanpay)
    {
        tx_tmp.transactions_in()[0] = tx_tmp.transactions_in()[n];
        tx_tmp.transactions_in().resize(1);
    }
    
    /**
     * Allocate the data_buffer.
     */
    data_buffer buffer;
    
    /**
     * Encode the transaction excluding the version for hashing.
     */
    tx_tmp.encode(buffer, true);
    
    /**
     * Write the hash type.
     */
    buffer.write_int32(hash_type);
    
    return sha256::from_digest(
        &hash::sha256d(reinterpret_cast<std::uint8_t *>(buffer.data()),
        buffer.size())[0]
    );
}

