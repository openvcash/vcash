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
 
#include <cassert>

#include <coin/block.hpp>
#include <coin/checkpoints.hpp>
#include <coin/constants.hpp>
#include <coin/globals.hpp>
#include <coin/hash.hpp>
#include <coin/logger.hpp>
#include <coin/reward.hpp>
#include <coin/time.hpp>
#include <coin/transaction.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/utility.hpp>

using namespace coin;

transaction::transaction()
    : data_buffer()
    , m_version(current_version)
    , m_time(static_cast<std::uint32_t> (time::instance().get_adjusted()))
    , m_time_lock(0)
{
    set_null();
}

void transaction::encode(const bool & encode_version)
{
    encode(*this, encode_version);
}

void transaction::encode(
    data_buffer & buffer, const bool & encode_version
    ) const
{
    if (encode_version)
    {
        /**
         * Write the version.
         */
        buffer.write_uint32(m_version);
    }
    
    /**
     * Write the time.
     */
    buffer.write_uint32(m_time);
    
    /**
     * Write the m_transactions_in size.
     */
    buffer.write_var_int(m_transactions_in.size());
    
    for (auto & i : m_transactions_in)
    {
        i.encode(buffer);
    }
    
    /**
     * Write the m_transactions_out size.
     */
    buffer.write_var_int(m_transactions_out.size());
    
    for (auto & i : m_transactions_out)
    {
        i.encode(buffer);
    }
    
    /**
     * Write the time lock.
     */
    buffer.write_uint32(m_time_lock);
}

bool transaction::decode(data_buffer & buffer)
{
    /**
     * Read the version.
     */
    m_version = buffer.read_uint32();

    /**
     * Read the time.
     */
    m_time = buffer.read_uint32();
    
    /**
     * Read the number of transactions in.
     */
    auto number_transactions_in = buffer.read_var_int();
    
    for (auto i = 0; i < number_transactions_in; i++)
    {
        /**
         * Allocate the transaction_in.
         */
        transaction_in tx_in;
        
        /**
         * Decode the transaction_in.
         */
        tx_in.decode(buffer);

        /**
         * Retain the transaction_in.
         */
        m_transactions_in.push_back(tx_in);
    }
    
    /**
     * Read the number of transactions out.
     */
    auto number_transactions_out = buffer.read_var_int();
    
    for (auto i = 0; i < number_transactions_out; i++)
    {
        /**
         * Allocate the transaction_out.
         */
        transaction_out tx_out;
        
        /**
         * Decode the transaction_out.
         */
        tx_out.decode(buffer);

        /**
         * Retain the transaction_out.
         */
        m_transactions_out.push_back(tx_out);
    }
    
    /**
     * Decode the time lock.
     */
    m_time_lock = buffer.read_uint32();
    
    return true;
}

void transaction::set_null()
{
    m_version = current_version;
    m_time = static_cast<std::uint32_t> (time::instance().get_adjusted());
    m_transactions_in.clear();
    m_transactions_out.clear();
    m_time_lock = 0;
}

bool transaction::is_null() const
{
    return m_transactions_in.size() == 0 && m_transactions_out.size() == 0;
}

sha256 transaction::get_hash() const
{
    /**
     * Allocate the buffer.
     */
    data_buffer buffer;
    
    /**
     * Encode the buffer.
     */
    encode(buffer);
    
    /**
     * Return the hash of the buffer.
     */
    return
        sha256::from_digest(&hash::sha256d(
        reinterpret_cast<const std::uint8_t *> (buffer.data()),
        buffer.size())[0]
    );
}

std::string transaction::to_string()
{
    std::string str;
    
    str +=
        is_coin_base() ? "Coinbase" :
        (is_coin_stake()? "Coinstake" : "transaction")
    ;
    
    str += "(hash = " + get_hash().to_string().substr(0, 10);
    str += ", time = " + std::to_string(m_time);
    str += ", version =  " + std::to_string(m_version);
    str +=
        ", transactions in size = " + std::to_string(m_transactions_in.size()
    );
    str +=
        ", transactions out size = " + std::to_string(m_transactions_out.size()
    );
    str += ", lock time = " + std::to_string(m_time_lock);
    str += "\n";

    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        str += "    " + m_transactions_in[i].to_string() + "\n";
    }
    
    for (auto i = 0; i < m_transactions_out.size(); i++)
    {
        str += "    " + m_transactions_out[i].to_string() + "\n";
    }
    
    return str;
}

std::uint32_t transaction::get_legacy_sig_op_count() const
{
    std::uint32_t ret = 0;

    for (auto & i : m_transactions_in)
    {
        ret += i.script_signature().get_sig_op_count(false);
    }
    
    for (auto & i : m_transactions_out)
    {
        ret += i.script_public_key().get_sig_op_count(false);
    }
    
    return ret;
}

bool transaction::is_final(
    std::uint32_t block_height, std::int64_t block_time
    ) const
{
    if (m_time_lock == 0)
    {
        return true;
    }
    
    if (block_height == 0)
    {
        block_height = globals::instance().best_block_height();
    }
    
    if (block_time == 0)
    {
        block_time = time::instance().get_adjusted();
    }
    
    if (
        m_time_lock <
        (m_time_lock < constants::locktime_threshold ? block_height : block_time)
        )
    {
        return true;
    }
    
    for (auto & i : m_transactions_in)
    {
        if (i.is_final() == false)
        {
            return false;
        }
    }
    
    return true;
}

bool transaction::is_newer_than(const transaction & other) const
{
    if (m_transactions_in.size() != other.m_transactions_in.size())
    {
        return false;
    }
    
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        if (
            m_transactions_in[i].previous_out() !=
            other.m_transactions_in[i].previous_out()
            )
        {
            return false;
        }
    }
    
    bool newer = false;
    
    auto lowest = std::numeric_limits<std::uint32_t>::max();
    
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        if (
            m_transactions_in[i].sequence() !=
            other.m_transactions_in[i].sequence()
            )
        {
            if (m_transactions_in[i].sequence() <= lowest)
            {
                newer = false;
            
                lowest = m_transactions_in[i].sequence();
            }
           
            if (other.m_transactions_in[i].sequence() < lowest)
            {
                newer = true;
                
                lowest = other.m_transactions_in[i].sequence();
            }
        }
    }
    
    return newer;
}

bool transaction::is_coin_base() const
{
    return
        m_transactions_in.size() == 1 &&
        m_transactions_in[0].previous_out().is_null() &&
        m_transactions_out.size() >= 1
    ;
}

bool transaction::is_coin_stake() const
{
    /**
     * The coin stake transaction is marked with the first output empty.
     */
    return
        (m_transactions_in.size() > 0 &&
        (!m_transactions_in[0].previous_out().is_null()) &&
        m_transactions_out.size() >= 2 && m_transactions_out[0].is_empty()
    );
}

bool transaction::is_standard() const
{
    if (m_version > current_version)
    {
        return false;
    }
    
    for (auto & i : m_transactions_in)
    {
        /**
         * Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
         * pay-to-script-hash, which is 3 ~80-byte signatures, 3
         * ~65-byte public keys, plus a few script ops.
         */
        if (i.script_signature().size() > 500)
        {
            return false;
        }
        
        if (i.script_signature().is_push_only() == false)
        {
            return false;
        }
        
        /**
         * Ban any transactions here if needed.
         */
	}

    for (auto & i : m_transactions_out)
    {
        if (script::is_standard(i.script_public_key()) == false)
        {
            return false;
        }
        
        if (i.value() == 0)
        {
            return false;
        }
    }
    
    return true;
}

bool transaction::are_inputs_standard(
    const transaction::previous_t & inputs
    ) const
{
    if (is_coin_base())
    {
        return true;
    }
    
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        const transaction_out & tx_previous = get_output_for(
            m_transactions_in[i], inputs
        );
        
        std::vector<std::vector<std::uint8_t> > solutions;
        
        types::tx_out_t tx_type;
 
        /**
         * Get the scipt public key corresponding to this input.
         */
        const auto & script_previous = tx_previous.script_public_key();
       
        if (script::solver(script_previous, tx_type, solutions) == false)
        {
            return false;
        }
        
        auto args_expected = script::sig_args_expected(tx_type, solutions);
        
        if (args_expected < 0)
        {
            return false;
        }
        
        /**
         * Transactions with extra stuff in their script signatures are
         * non-standard.
         */
        std::vector< std::vector<std::uint8_t> > stack;
        
        if (
            script::evaluate(stack, m_transactions_in[i].script_signature(),
            *this, i, 0) == false)
        {
            return false;
        }
        
        if (tx_type == types::tx_out_scripthash)
        {
            if (stack.size() == 0)
            {
                return false;
            }
            
            script subscript(stack.back().begin(), stack.back().end());
            
            std::vector< std::vector<std::uint8_t> > solutions2;
            
            types::tx_out_t tx_type2;
            
            if (script::solver(subscript, tx_type2, solutions2) == false)
            {
                return false;
            }
            
            if (tx_type2 == types::tx_out_scripthash)
            {
                return false;
            }
            
            auto tmp_expected = script::sig_args_expected(tx_type2, solutions2);
            
            if (tmp_expected < 0)
            {
                return false;
            }
            
            args_expected += tmp_expected;
        }

        if (stack.size() != args_expected)
        {
            return false;
        }
    }
    
    return true;
}

std::int64_t transaction::get_value_out() const
{
    std::int64_t ret = 0;
    
    for (auto & i : m_transactions_out)
    {
        ret += i.value();
        
        if (
            utility::money_range(i.value()) == false ||
            utility::money_range(ret) == false
            )
        {
            throw std::runtime_error("value out of range");
        }
    }
    
    return ret;
}

std::int64_t transaction::get_value_in(
    const transaction::previous_t & inputs
    ) const
{
    std::int64_t ret = 0;
    
    if (is_coin_base() == false)
    {
        for (auto & i : m_transactions_in)
        {
            ret += get_output_for(i, inputs).value();
        }
    }
    
    return ret;
}

std::uint32_t transaction::get_p2sh_sig_op_count(
    const previous_t & inputs
    ) const
{
    if (is_coin_base())
    {
        return 0;
    }
    
    std::uint32_t sig_ops = 0;
    
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        const auto & previous_out = get_output_for(
            m_transactions_in[i], inputs
        );
        
        if (previous_out.script_public_key().is_pay_to_script_hash())
        {
            sig_ops +=
                previous_out.script_public_key().get_sig_op_count(
                m_transactions_in[i].script_signature())
            ;
        }
    }
    
    return sig_ops;
}

bool transaction::allow_free(const double & priority)
{
    /**
     * Large (byte-wise) low-priority (new, small coin) transactions require
     * a fee.
     */
    return priority > constants::coin * 1440 / 250;
}

std::int64_t transaction::get_minimum_fee(
    const std::uint32_t & block_size, const bool & allow_free,
    const types::get_minimum_fee_mode_t & mode, const std::size_t & len
    ) const
{
    /**
     * Base fee is either min_relay_tx_fee or min_tx_fee.
     */
    std::int64_t base_fee =
        (mode == types::get_minimum_fee_mode_relay) ?
        constants::min_relay_tx_fee : constants::min_tx_fee
    ;

    auto new_block_size = block_size + len;
    
    std::int64_t min_fee = (1 + (std::int64_t)len / 1000) * base_fee;

    /**
     * To limit dust spam, require min_tx_fee / min_relay_tx_fee if any output
     * is less than 0.01.
     */
    if (min_fee < base_fee)
    {
        for (auto & i : m_transactions_out)
        {
            if (i.value() < constants::cent)
            {
                min_fee = base_fee;
            }
        }
    }

    /**
     * Raise the price as the block approaches full.
     */
    if (block_size != 1 && new_block_size >= constants::max_block_size_gen / 2)
    {
        if (new_block_size >= constants::max_block_size_gen)
        {
            return constants::max_money_supply;
        }
        
        min_fee *=
            constants::max_block_size_gen /
            (constants::max_block_size_gen - new_block_size)
        ;
    }

    if (utility::money_range(min_fee) == false)
    {
        min_fee = constants::max_money_supply;
    }
    
    return min_fee;
}

std::pair<bool, std::string> transaction::accept_to_transaction_pool(
    db_tx & tx_db, bool * missing_inputs
    )
{
    return
        transaction_pool::instance().accept(tx_db, *this, missing_inputs)
    ;
}

bool transaction::read_from_disk(const transaction_position & position)
{
    auto f = block::file_open(position.file_index(), 0, "rb");
    
    if (f)
    {
        if (f->seek_set(position.tx_position()) == 0)
        {
            /** 
             * Allocate the buffer.
             */
            data_buffer buffer(f);
            
            /**
             * Decode
             */
            decode(buffer);
        }
        else
        {
            throw std::runtime_error("seek failed");
            
            return false;
        }
    }
    else
    {
        throw std::runtime_error("failed to open block file");
            
        return false;
    }

    return true;
}

bool transaction::read_from_disk(
    db_tx & tx_db, const point_out & previous_out, transaction_index & tx_index
    )
{
    set_null();

    if (
        tx_db.read_transaction_index(
        previous_out.get_hash(), tx_index) == false
        )
    {
        log_debug(
            "Transaction failed to read from disk, read transaction index "
            "failed, previous out = " <<
            previous_out.get_hash().to_string().substr(0, 20) << "."
        );
        
        return false;
    }
    
    if (read_from_disk(tx_index.get_transaction_position()) == false)
    {
        log_debug(
            "Transaction failed to read from disk, read from disk failed."
        );
        
        return false;
    }
    
    if (previous_out.n() >= m_transactions_out.size())
    {
        log_debug(
            "Transaction failed to read from disk, n is greater than outputs."
        );
        
        set_null();
        
        return false;
    }
    
    return true;
}

bool transaction::fetch_inputs(
    db_tx & dbtx, const std::map<sha256, transaction_index> & test_pool,
    const bool & best_block, const bool & create_block,
    transaction::previous_t & inputs, bool & invalid
    )
{
    /**
     * If the transaction is invalid this will be set to true.
     */
    invalid = false;

    /**
     * Coinbase transactions have no inputs to fetch.
     */
    if (is_coin_base())
    {
        return true;
    }
    
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        auto previous_out = m_transactions_in[i].previous_out();
        
        if (inputs.count(previous_out.get_hash()) > 0)
        {
            continue;
        }
        
        /**
         * Read the transaction index.
         */
        auto & tx_index = inputs[previous_out.get_hash()].first;
        
        bool found = true;
        
        if (
            (best_block || create_block) &&
            test_pool.count(previous_out.get_hash()) > 0
            )
        {
            /**
             * Get the transaction index from the current proposed changes.
             */
            tx_index = test_pool.find(previous_out.get_hash())->second;
        }
        else
        {
            /**
             * Read transaction index from transaction database.
             */
            found = dbtx.read_transaction_index(
                previous_out.get_hash(), tx_index
            );
        }
        
        if (found == false && (best_block || create_block))
        {
            if (create_block)
            {
                return false;
            }
            else
            {
                log_error(
                    "Transaction " << get_hash().to_string().substr(0, 10) <<
                    " previous transaction " <<
                    previous_out.get_hash().to_string().substr(0, 10) <<
                    " index entry not found."
                );

                return false;
            }
        }
        
        /**
         * Read previous transaction.
         */
        auto & tx_prev = inputs[previous_out.get_hash()].second;
        
        if (
            found == false ||
            tx_index.get_transaction_position() == transaction_position(1, 1, 1)
            )
        {
            if (
                transaction_pool::instance().exists(
                previous_out.get_hash()) == false
                )
            {
                log_error(
                    "Transaction failed to fetch inputs, " <<
                    get_hash().to_string().substr(0, 10) <<
                    " pool previous transaction not found " <<
                    previous_out.get_hash().to_string().substr(0, 10) << "."
                );
                
                return false;
            }
            
            tx_prev = transaction_pool::instance().lookup(
                previous_out.get_hash()
            );
           
            if (found == false)
            {
                tx_index.spent().resize(tx_prev.transactions_out().size());
            }
        }
        else
        {
            /**
             * Read previous transaction from disk.
             */
            if (
                tx_prev.read_from_disk(
                tx_index.get_transaction_position()) == false
                )
            {
                log_error(
                    "Transaction " << get_hash().to_string().substr(0, 10) <<
                    " failed to read previous transaction " <<
                    previous_out.get_hash().to_string().substr(0, 10) <<
                    " from disk."
                );
                
                return false;
            }
        }
    }
    
    /**
     * Check that all previous out's n indexes are valid.
     */
    for (auto i = 0; i < m_transactions_in.size(); i++)
    {
        const auto & previous_out = m_transactions_in[i].previous_out();
        
        assert(inputs.count(previous_out.get_hash()) != 0);
        
        auto & tx_index = inputs[previous_out.get_hash()].first;
        
        auto & tx_prev = inputs[previous_out.get_hash()].second;
        
        if (
            previous_out.n() >= tx_prev.transactions_out().size() ||
            previous_out.n() >= tx_index.spent().size()
            )
        {
            /**
             * Revisit this if/when transaction replacement is implemented
             * and allows adding inputs.
             */
            invalid = true;
            
            log_error(
                "Transaction " << get_hash().to_string().substr(0, 10) <<
                " previous out n out of range " << previous_out.n() << ":" <<
                tx_prev.transactions_out().size() << ":" <<
                tx_index.spent().size() << " previous transaction " <<
                previous_out.get_hash().to_string().substr(0, 10) << "\n" <<
                tx_prev.to_string() << "."
            );
            
            return false;
        }
    }

    return true;
}

const transaction_out & transaction::get_output_for(
    const transaction_in & input, const previous_t & inputs
    ) const
{
    auto it = inputs.find(input.previous_out().get_hash());
    
    if (it == inputs.end())
    {
        throw std::runtime_error("previous out hash not found");
    }
    
    const auto & tx_previous = it->second.second;
    
    if (input.previous_out().n() >= tx_previous.transactions_out().size())
    {
        throw std::runtime_error("previous out n out of range");
    }
    
    return tx_previous.transactions_out()[input.previous_out().n()];
}

bool transaction::connect_inputs(
    db_tx & tx_db,
    std::map<sha256, std::pair<transaction_index, transaction> > & inputs,
    std::map<sha256, transaction_index> & test_pool,
    const transaction_position & position_tx_this,
    const std::shared_ptr<block_index> & ptr_block_index,
    const bool & connect_block, const bool & create_new_block,
    const bool & strict_pay_to_script_hash
    )
{
    if (is_coin_base() == false)
    {
        std::int64_t value_in = 0;
        std::int64_t fees = 0;
        
        for (auto i = 0; i < m_transactions_in.size(); i++)
        {
            auto & prev_out = m_transactions_in[i].previous_out();
            
            assert(inputs.count(prev_out.get_hash()) > 0);
            
            auto & tx_index = inputs[prev_out.get_hash()].first;
            
            auto & tx_previous = inputs[prev_out.get_hash()].second;

            if (
                prev_out.n() >= tx_previous.transactions_out().size() ||
                prev_out.n() >= tx_index.spent().size()
                )
            {
                log_error(
                    "Transaction connect inputs failed, " <<
                    get_hash().to_string().substr(0, 10) <<
                    " previous out n is out of range [" << prev_out.n() <<
                    "-" << tx_previous.transactions_out().size() << "]" <<
                    " previous transaction " <<
                    prev_out.get_hash().to_string() << "\n" <<
                    tx_previous.to_string()
                );
                
                return false;
            }
            
            /**
             * If previous is coinbase or coinstake, check that it's matured.
             */
            if (tx_previous.is_coin_base() || tx_previous.is_coin_stake())
            {
                for (
                    auto pindex = ptr_block_index;
                    pindex && ptr_block_index->height() - pindex->height() <
                    constants::coinbase_maturity;
                    pindex = pindex->block_index_previous()
                    )
                {
                    if (
                        pindex->block_position() ==
                        tx_index.get_transaction_position().block_position() &&
                        pindex->file() ==
                        tx_index.get_transaction_position().file_index()
                        )
                    {
                        log_error(
                            "Transaction connect inputs failed, tried to "
                            "spend " << (tx_previous.is_coin_base() ?
                            "coinbase" : "coinstake") << " at depth " <<
                            pindex->height() << "."
                        );
                        
                        return false;
                    }
                }
            }
            
            /**
             * Check the transaction timestamp (ppcoin).
             */
            if (tx_previous.time() > m_time)
            {
                log_error(
                    "Transaction connect inputs failed, timestamp is earlier "
                    "than the input transaction."
                );
                
                return false;
            }
            
            /**
             * Check for negative or overflow input values.
             */
            value_in += tx_previous.transactions_out()[prev_out.n()].value();
            
            if (
                utility::money_range(
                tx_previous.transactions_out()[prev_out.n()].value()) == false ||
                utility::money_range(value_in) == false
                )
            {
                log_error(
                    "Transaction connect inputs failed, transaction in "
                    "values out of range."
                );
                
                return false;
            }

        }
        /**
         * Only if all inputs pass do we perform expensive ECDSA signature
         * checks. This may help prevent CPU exhaustion attacks.
         */
        for (auto i = 0; i < m_transactions_in.size(); i++)
        {
            auto & prev_out = m_transactions_in[i].previous_out();
            
            assert(inputs.count(prev_out.get_hash()) > 0);
            
            auto & tx_index = inputs[prev_out.get_hash()].first;
            
            auto & tx_previous = inputs[prev_out.get_hash()].second;

            /**
             * Check for conflicts (double-spend).
             */
            if (tx_index.spent()[prev_out.n()].is_null() == false)
            {
                if (create_new_block)
                {
                    return false;
                }
                else
                {
                    log_debug(
                        "Transaction connect inputs failed, " <<
                        get_hash().to_string().substr(0, 10) <<
                        " previous transaction already used at " <<
                        tx_index.spent()[prev_out.n()].to_string() << "."
                    );
                    
                    return false;
                }
            }
            
            /**
             * Skip ECDSA signature verification when connecting blocks before
             * the last blockchain checkpoint. This is safe because block
             * merkle hashes are  still computed and checked, and any change
             * will be caught at the next checkpoint.
             */
            if (
                (connect_block && (globals::instance().best_block_height() <
                checkpoints::instance().get_total_blocks_estimate())) == false
                )
            {
                if (
                    script::verify_signature(tx_previous, *this, i,
                    strict_pay_to_script_hash, 0) == false
                    )
                {
                    /**
                     * Only during transition phase for P2SH.
                     */
                    if (
                        strict_pay_to_script_hash &&
                        script::verify_signature(tx_previous, *this, i,
                        false, 0)
                        )
                    {
                        log_error(
                            "Transaction connect inputs failed, " <<
                            get_hash().to_string().substr(0, 10) <<
                            " P2SH signature verification vailed."
                        );
                        
                        return false;
                    }

                    log_error(
                        "Transaction connect inputs failed, " <<
                        get_hash().to_string().substr(0, 10) <<
                        " signature verification failed."
                    );
                    
                    return false;
                }
            }

            /**
             * Mark outpoints as spent.
             */
            tx_index.spent()[prev_out.n()] = position_tx_this;

            /**
             * Write back.
             */
            if (connect_block || create_new_block)
            {
                test_pool[prev_out.get_hash()] = tx_index;
            }
        }

        if (is_coin_stake())
        {
            /**
             * Coin stake transactions earn reward instead of paying fee
             * (ppcoin).
             */
            std::uint64_t coin_age;
            
            if (get_coin_age(tx_db, coin_age) == false)
            {
                log_error(
                    "Transaction connect inputs failed, " <<
                    get_hash().to_string().substr(0, 10) << " unable to get " <<
                    "coin age for coin stake."
                );
                
                return false;
            }
            
            std::int64_t stake_reward = get_value_out() - value_in;
            
            if (
                stake_reward > reward::get_proof_of_stake(coin_age,
                ptr_block_index->bits(), m_time, ptr_block_index->height()) -
                get_minimum_fee() + constants::min_tx_fee
                )
            {
                log_error(
                    "Transaction connect inputs failed, " <<
                    get_hash().to_string().substr(0, 10) <<
                    " stake reward exceeded."
                );
                
                return false;
            }
        }
        else
        {
            if (value_in < get_value_out())
            {
                log_error(
                    "Transaction connect inputs failed, " <<
                    get_hash().to_string().substr(0, 10) <<
                    " value in is less than value out."
                );
                
                return false;
            }

            /**
             * Tally transaction fees.
             */
            std::int64_t tx_fee = value_in - get_value_out();
            
            if (tx_fee < 0)
            {
                log_error(
                    "Transaction connect inputs failed, " <<
                    get_hash().to_string().substr(0, 10) <<
                    " transaction fee is less than zero."
                );
                
                return false;
            }
            
            /**
             * Enforce transaction fees for every block (ppcoin).
             */
            if (tx_fee < get_minimum_fee())
            {
                if (connect_block)
                {
                    log_error(
                        "Transaction connect inputs failed, " <<
                        get_hash().to_string().substr(0, 10) <<
                        " not paying required fee = " <<
                        utility::format_money(get_minimum_fee()) <<
                        ", paid = " << utility::format_money(tx_fee) << "."
                    );
                    
                    return false;
                }
                else
                {
                    return false;
                }
            }
            
            fees += tx_fee;
            
            if (utility::money_range(fees) == false)
            {
                log_error(
                    "Transaction connect inputs failed, fees out of range."
                );
                
                return false;
            }
        }
    }

    return true;
}

bool transaction::client_connect_inputs()
{
    if (is_coin_base())
    {
        return false;
    }
    
    /**
     * Take over the previous transactions' spent pointers.
     */

    std::int64_t value_in = 0;
    
    for (auto i = 0; i < transactions_in().size(); i++)
    {
        /**
         * Get the previous transaction from single transactions in memory.
         */
        auto prev_out = transactions_in()[i].previous_out();
        
        if (transaction_pool::instance().exists(prev_out.get_hash()) == false)
        {
            return false;
        }
        
        auto & tx_previous = transaction_pool::instance().lookup(
            prev_out.get_hash()
        );

        if (prev_out.n() >= tx_previous.transactions_out().size())
        {
            return false;
        }
        
        /**
         * Verify the signature.
         */
        if (script::verify_signature(tx_previous, *this, i, true, 0) == false)
        {
            log_error(
                "Transaction, client connect inputs failed, verify "
                "signature failed"
            );
        
            return false;
        }
        
        value_in += tx_previous.transactions_out()[prev_out.n()].value();

        if (
            utility::money_range(tx_previous.transactions_out()[
            prev_out.n()].value()) == false ||
            utility::money_range(value_in) == false
            )
        {
            log_error(
                "Transaction, client connect inputs failed, transaction in "
                "values out of range."
            );
            
            return false;
        }
    }
    
    if (get_value_out() > value_in)
    {
        return false;
    }
    
    return true;
}

bool transaction::disconnect_inputs(db_tx & tx_db)
{
    /**
     * Relinquish previous transactions' spent pointers.
     */
    if (is_coin_base() == false)
    {
        for (auto & i : m_transactions_in)
        {
            auto prev_out = i.previous_out();

            /**
             * Get previous transaction index from disk.
             */
            transaction_index txindex;
            
            if (
                tx_db.read_transaction_index(
                prev_out.get_hash(), txindex) == false
                )
            {
                log_error(
                    "Transaction disconnect_inputs failed, "
                    "read_transaction_index failed."
                );
                
                return false;
            }
            
            if (prev_out.n() >= txindex.spent().size())
            {
                log_error(
                    "Transaction disconnect_inputs failed, previous"
                    " out n is out of range"
                );
                
                return false;
            }
            
            /**
             * Mark outpoint as not spent.
             */
            txindex.spent()[prev_out.n()].set_null();

            /**
             * Write back.
             */
            if (
                tx_db.update_transaction_index(
                prev_out.get_hash(), txindex) == false
                )
            {
                log_error(
                    "Transaction disconnect_inputs failed, "
                    "update_transaction_index failed."
                );
                
                return false;
            }
        }
    }

    /**
     * Remove transaction from the index. This can fail if a duplicate of this
     * transaction was in a chain that got reorganized away. This is only
     * possible if this transaction was completely spent, so erasing it would
     * be a no-op anyway.
     */
    tx_db.erase_transaction_index(*this);

    return true;
}

bool transaction::get_coin_age(db_tx & tx_db, std::uint64_t & coin_age) const
{
    /**
     * The coin age in the unit of cent-seconds.
     */
    big_number cent_second = 0;
    
    coin_age = 0;

    if (is_coin_base())
    {
        return true;
    }
    
    for (auto & i : m_transactions_in)
    {
        /**
         * Try to find the previous transaction in the database.
         */
        transaction tx_previous;
     
        /**
         * Allocate the transaction_index.
         */
        transaction_index tx_index;
        
        /**
         * Check if the previous transaction is in the main chain.
         */
        if (
            tx_previous.read_from_disk(tx_db, i.previous_out(),
            tx_index) == false
            )
        {
            continue;
        }
        
        /**
         * Check for timestamp violation.
         */
        if (m_time < tx_previous.time())
        {
            return false;
        }
        
        /**
         * Allocate the block.
         */
        block blk;
        
        /**
         * Read the block header.
         */
        if (
            blk.read_from_disk(tx_index.get_transaction_position().file_index(),
            tx_index.get_transaction_position().block_position(), false
            ) == false
            )
        {
            return false;
        }
        
        /**
         * Only count coins meeting a mininmum age requirement.
         * @note If the network is not secured by PoW miners then using a
         * large minimum stake age could result in an insecure network.
         */
        if (blk.header().timestamp + constants::min_stake_age > m_time)
        {
            continue;
        }
        
        const auto & value_in = tx_previous.transactions_out()[
            i.previous_out().n()
        ].value();
        
        cent_second +=
            big_number(value_in) *
            (m_time - tx_previous.time()) / constants::cent
        ;

        log_none(
            "Transaction coin age value_in = " << value_in <<
            ", time diff = " << m_time - tx_previous.time() <<
            ", cent_seconds = " << cent_second.to_string() << "."
        );
    }

    big_number coin_day =
        cent_second * constants::cent / constants::coin / (24 * 60 * 60)
    ;

    log_none(
        "Transaction coin age coin_day = " << coin_day.to_string() << "."
    );
    
    coin_age = coin_day.get_uint64();
    
    return true;
}

bool transaction::check()
{
    if (m_transactions_in.size() == 0)
    {
        log_error(
            "Transaction check failed, tx in is empty:\n" << to_string()
        );
        
        throw std::runtime_error("tx in empty");
        
        return false;
    }
    
    if (m_transactions_out.size() == 0)
    {
        log_error(
            "Transaction check failed, tx out is empty:\n" << to_string()
        );
        
        throw std::runtime_error("tx out empty");
        
        return false;
    }
    
    /**
     * Clear
     */
    clear();
    
    /**
     * Encode
     */
    encode();
    
    /**
     * Check the size.
     */
    if (size() > constants::max_block_size)
    {
        throw std::runtime_error("size limits failed");
        
        return false;
    }
    
    /**
     * The value out.
     */
    std::int64_t value_out = 0;
    
    /**
     * Check for negative or overflow output values.
     */
    for (auto & i : m_transactions_out)
    {
        if (i.is_empty() && is_coin_base() == false && is_coin_stake() == false)
        {
            throw std::runtime_error("tx out empty for user transaction");
        
            return false;
        }
        
        if (i.value() < 0)
        {
            throw std::runtime_error("tx out value is negative");
        
            return false;
        }
        
        if (i.value() > constants::max_money_supply)
        {
            throw std::runtime_error("tx out value is too high");
        
            return false;
        }
        
        value_out += i.value();
        
        if (utility::money_range(value_out) == false)
        {
            throw std::runtime_error("tx out total out of range");
        
            return false;
        }
    }
    
    /**
     * Check for duplicate inputs.
     */
    std::set<point_out> points_in_out;
    
    for (auto & i : m_transactions_in)
    {
        if (points_in_out.count(i.previous_out()))
        {
            return false;
        }
        
        points_in_out.insert(i.previous_out());
    }
    
    if (is_coin_base())
    {
        if (
            m_transactions_in[0].script_signature().size() < 2 ||
            m_transactions_in[0].script_signature().size() > 100
            )
        {
            throw std::runtime_error("coinbase script size");
        
            return false;
        }
    }
    else
    {
        for (auto & i : m_transactions_in)
        {
            if (i.previous_out().is_null())
            {
                throw std::runtime_error("prev_out is null");
            
                return false;
            }
        }
    }
    
    return true;
}

const std::uint32_t & transaction::version() const
{
    return m_version;
}

void transaction::set_time(const std::uint32_t & value)
{
    m_time = value;
}

const std::uint32_t & transaction::time() const
{
    return m_time;
}

std::vector<transaction_in> & transaction::transactions_in()
{
    return m_transactions_in;
}

std::vector<transaction_out> & transaction::transactions_out()
{
    return m_transactions_out;
}

const std::vector<transaction_in> & transaction::transactions_in() const
{
    return m_transactions_in;
}

const std::vector<transaction_out> & transaction::transactions_out() const
{
    return m_transactions_out;
}

const std::uint32_t & transaction::time_lock() const
{
    return m_time_lock;
}
