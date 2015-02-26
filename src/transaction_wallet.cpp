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

#include <boost/lexical_cast.hpp>

#include <coin/db_wallet.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/transaction_pool.hpp>
#include <coin/transaction_wallet.hpp>
#include <coin/wallet.hpp>

using namespace coin;

transaction_wallet::transaction_wallet()
    : transaction_merkle()
    , m_time_received_is_tx_time(0)
    , m_time_received(0)
    , m_time_smart(0)
    , m_is_from_me(false)
    , m_order_position(-1)
    , wallet_(0)
    , credit_is_cached_(false)
    , credit_cached_(0)
    , debit_is_cached_(false)
    , debit_cached_(0)
    , available_credit_is_cached_(false)
    , available_credit_cached_(0)
    , change_is_cached_(false)
{
    initialize(0);
}

transaction_wallet::transaction_wallet(
    const wallet * ptr_wallet, const transaction & tx_in
    )
    : transaction_merkle(tx_in)
    , m_time_received_is_tx_time(0)
    , m_time_received(0)
    , m_time_smart(0)
    , m_is_from_me(false)
    , m_order_position(-1)
    , wallet_(ptr_wallet)
    , credit_is_cached_(false)
    , credit_cached_(0)
    , debit_is_cached_(false)
    , debit_cached_(0)
    , available_credit_is_cached_(false)
    , available_credit_cached_(0)
    , change_is_cached_(false)
{
    initialize(ptr_wallet);
}

void transaction_wallet::encode()
{
    encode(*this);
}

void transaction_wallet::encode(data_buffer & buffer)
{
    auto is_spent = false;

    m_values["fromaccount"] = m_from_account;

    std::string str;
    
    for (auto & i : m_spent)
    {
        str += (i ? '1' : '0');
        
        if (i)
        {
            is_spent = true;
        }
    }
    
    m_values["spent"] = str;

    wallet::write_order_position(m_order_position, m_values);

    if (m_time_smart)
    {
        m_values["timesmart"] = std::to_string(m_time_smart);
    }
    
    /**
     * Encode the base class.
     */
    transaction_merkle::encode(buffer);
    
    buffer.write_var_int(m_previous_transactions.size());
    
    for (auto & i : m_previous_transactions)
    {
        i.encode(buffer);
    }
    
    buffer.write_var_int(m_values.size());
    
    for (auto & i : m_values)
    {
        buffer.write_var_int(i.first.size());
        buffer.write_bytes(i.first.data(), i.first.size());
        buffer.write_var_int(i.second.size());
        buffer.write_bytes(i.second.data(), i.second.size());
    }
    
    buffer.write_var_int(m_order_form.size());
    
    for (auto & i : m_order_form)
    {
        buffer.write_var_int(i.first.size());
        buffer.write_bytes(i.first.data(), i.first.size());
        buffer.write_var_int(i.second.size());
        buffer.write_bytes(i.second.data(), i.second.size());
    }
    
    buffer.write_uint32(m_time_received_is_tx_time);
    buffer.write_uint32(m_time_received);
    buffer.write_uint8(m_is_from_me);
    buffer.write_uint8(is_spent);

    m_values.erase("fromaccount");
    m_values.erase("version");
    m_values.erase("spent");
    m_values.erase("n");
    m_values.erase("timesmart");
}

void transaction_wallet::decode()
{
    decode(*this);
}

void transaction_wallet::decode(data_buffer & buffer)
{
    /**
     * Initialize
     */
    initialize(0);
    
    auto is_spent = false;

    /**
     * Decode the base class.
     */
    transaction_merkle::decode(buffer);
    
    auto len = buffer.read_var_int();
    
    for (auto i = 0; i < len; i++)
    {
        transaction_merkle tx_merkle;
        
        tx_merkle.decode(buffer);
        
        m_previous_transactions.push_back(tx_merkle);
    }
    
    auto len_values = buffer.read_var_int();
    
    for (auto i = 0; i < len_values; i++)
    {
        std::string first(buffer.read_var_int(), 0);
        
        buffer.read_bytes(const_cast<char *> (first.data()), first.size());
        
        std::string second(buffer.read_var_int(), 0);
        
        buffer.read_bytes(const_cast<char *> (second.data()), second.size());
        
        m_values[first] = second;
    }
    
    m_order_form.resize(buffer.read_var_int());
    
    for (auto i = 0; i < m_order_form.size(); i++)
    {
        std::string first(buffer.read_var_int(), 0);
        
        buffer.read_bytes(const_cast<char *> (first.data()), first.size());
        
        std::string second(buffer.read_var_int(), 0);
        
        buffer.read_bytes(const_cast<char *> (second.data()), second.size());
        
        m_order_form[i] = std::make_pair(first, second);
    }

    m_time_received_is_tx_time = buffer.read_uint32();

    m_time_received = buffer.read_uint32();
    
    m_is_from_me = buffer.read_uint8();
    
    is_spent = buffer.read_uint8();
    
    m_from_account = m_values["fromaccount"];

    if (m_values.count("spent"))
    {
        for (auto & i : m_values["spent"])
        {
            m_spent.push_back(i != '0');
        }
    }
    else
    {
        m_spent.assign(transaction_out().size(), is_spent);
    }
    
    /**
     * Read the order position.
     */
    wallet::read_order_position(m_order_position, m_values);

    m_time_smart =
        m_values.count("timesmart") ?
        boost::lexical_cast<std::uint32_t> (m_values["timesmart"]) : 0
    ;

    m_values.erase("version");
    m_values.erase("spent");
    m_values.erase("n");
    m_values.erase("timesmart");
}

void transaction_wallet::initialize(const wallet * ptr_wallet)
{
    wallet_ = ptr_wallet;
    m_previous_transactions.clear();
    m_values.clear();
    m_order_form.clear();
    m_time_received_is_tx_time = false;
    m_time_received = 0;
    m_time_smart = 0;
    m_is_from_me = false;
    m_from_account.clear();
    m_spent.clear();
    debit_is_cached_ = false;
    credit_is_cached_ = false;
    available_credit_is_cached_ = false;
    change_is_cached_ = false;
    debit_cached_ = 0;
    credit_cached_ = 0;
    available_credit_cached_ = 0;
    change_is_cached_ = false;
    m_order_position = -1;
}

void transaction_wallet::get_amounts(
    std::int64_t & generated_immature, std::int64_t & generated_mature,
    std::list< std::pair<destination::tx_t, std::int64_t> > & received,
    std::list< std::pair<destination::tx_t, std::int64_t> > & sent,
    std::int64_t & fee, std::string & account_sent
    ) const
{
    generated_immature = generated_mature = fee = 0;
    
    received.clear(), sent.clear();
    
    account_sent = m_from_account;

    if (is_coin_base() || is_coin_stake())
    {
        if (get_blocks_to_maturity() > 0)
        {
            generated_immature = wallet_->get_credit(*this);
        }
        else
        {
            generated_mature = get_credit();
        }
        
        return;
    }

    auto debit = get_debit();
    
    /**
     * If debit is greater than zero then we sent the transaction.
     */
    if (debit > 0)
    {
        fee = debit - get_value_out();
    }

    for (auto & i : transactions_out())
    {
        destination::tx_t address;

        if (
            script::extract_destination(i.script_public_key(), address) == false
            )
        {
            log_error(
                "Transaction wallet, unkown transation type " <<
                i.get_hash().to_string() << "."
            );
        }

        if (debit > 0 && wallet_->is_change(i))
        {
            continue;
        }
        
        if (debit > 0)
        {
            sent.push_back(std::make_pair(address, i.value()));
        }
        
        if (wallet_->is_mine(i))
        {
            received.push_back(std::make_pair(address, i.value()));
        }
    }
}

void transaction_wallet::get_account_amounts(
    const std::string & account, std::int64_t & generated,
    std::int64_t & received, std::int64_t & sent, std::int64_t & fee
    ) const
{
    generated = received = sent = fee = 0;

    std::int64_t generated_immature, generated_mature, all_fee;
    
    std::string account_sent;
    
    std::list<std::pair<destination::tx_t, std::int64_t> > r;
    std::list<std::pair<destination::tx_t, std::int64_t> > s;
    
    get_amounts(
        generated_immature, generated_mature, r, s, all_fee, account_sent
    );

    if (account == "")
    {
        generated = generated_mature;
    }
    
    if (account == account_sent)
    {
        for (auto & i : s)
        {
            sent += i.second;
        }
        
        fee = all_fee;
        
        generated = generated_mature;
    }
    
    for (auto & i : r)
    {
        if (wallet_->address_book().count(i.first) > 0)
        {
            auto it = wallet_->address_book().find(i.first);
            
            if (it != wallet_->address_book().end() && it->second == account)
            {
                received += i.second;
            }
        }
        else if (account.size() == 0)
        {
            received += i.second;
        }
    }
}

void transaction_wallet::add_supporting_transactions(db_tx & tx_db)
{
    /**
     * Clear the previois transactions.
     */
    m_previous_transactions.clear();

    const int copy_depth = 3;
    
    if (set_merkle_branch() < copy_depth)
    {
        std::vector<sha256> work_queue;
        
        for (auto & tx_in : transactions_in())
        {
            work_queue.push_back(tx_in.previous_out().get_hash());
        }
        
        std::map<sha256, const transaction_merkle *> wallet_previous;
        
        std::set<sha256> already_done;
        
        for (auto i = 0; i < work_queue.size(); i++)
        {
            sha256 hash = work_queue[i];
            
            if (already_done.count(hash) > 0)
            {
                continue;
            }
            
            already_done.insert(hash);

            transaction_merkle tx;
            
            auto it = wallet_->transactions().find(hash);
            
            if (it != wallet_->transactions().end())
            {
                tx = it->second;
                
                for (auto & tx_previous : it->second.previous_transactions())
                {
                    wallet_previous[tx_previous.get_hash()] = &tx_previous;
                }
            }
            else if (wallet_previous.count(hash) > 0)
            {
                tx = *wallet_previous[hash];
            }
            else if (
                globals::instance().is_client() == false &&
                tx_db.read_disk_transaction(hash, tx)
                )
            {
                // ...
            }
            else
            {
                log_error(
                    "Transaction wallet, add supporting transactions failed, "
                    "unsupported transaction."
                );
                
                continue;
            }

            auto depth = tx.set_merkle_branch();
            
            m_previous_transactions.push_back(tx);

            if (depth < copy_depth)
            {
                for (auto & txin : tx.transactions_in())
                {
                    work_queue.push_back(txin.previous_out().get_hash());
                }
            }
        }
    }

    /**
     * Reverse the previous transactions.
     */
    std::reverse(
        m_previous_transactions.begin(), m_previous_transactions.end()
    );
}

std::pair<bool, std::string> transaction_wallet::accept_wallet_transaction(
    db_tx & tx_db
    )
{
    /**
     * Add previous supporting transactions first.
     */
    for (auto & i : m_previous_transactions)
    {
        if (i.is_coin_base() == false && i.is_coin_stake() == false)
        {
            auto hash_tx = i.get_hash();
            
            if (
                transaction_pool::instance().exists(hash_tx) == false &&
                tx_db.contains_transaction(hash_tx) == false
                )
            {
                i.accept_to_transaction_pool(tx_db);
            }
        }
    }
    
    return transaction::accept_to_transaction_pool(tx_db);
}

std::pair<bool, std::string> transaction_wallet::accept_wallet_transaction()
{
    db_tx tx_db("r");
    
    return accept_wallet_transaction(tx_db);
}

bool transaction_wallet::update_spent(const std::vector<char> & spent_new) const
{
    bool ret = false;
    
    for (auto i = 0; i < spent_new.size(); i++)
    {
        if (i == m_spent.size())
        {
            break;
        }
        
        if (spent_new[i] && !m_spent[i])
        {
            m_spent[i] = true;
            
            ret = true;
            
            available_credit_is_cached_ = false;
        }
    }
    
    return ret;
}

void transaction_wallet::mark_dirty()
{
    credit_is_cached_ = false;
    available_credit_is_cached_ = false;
    debit_is_cached_ = false;
    change_is_cached_ = false;
}

void transaction_wallet::bind_wallet(const wallet & value)
{
    wallet_ = &value;
    
    mark_dirty();
}

void transaction_wallet::mark_spent(const std::uint32_t & out)
{
    if (out >= transactions_out().size())
    {
        throw std::runtime_error(
            "transaction_wallet::mark_unspent() : out out of range"
        );
    }
    
    m_spent.resize(transactions_out().size());
    
    if (!m_spent[out])
    {
        m_spent[out] = true;
        
        available_credit_is_cached_ = false;
    }
}

void transaction_wallet::mark_unspent(const std::uint32_t & out)
{
    if (out >= transactions_out().size())
    {
        throw std::runtime_error(
            "transaction_wallet::mark_unspent() : out out of range"
        );
    }
    
    m_spent.resize(transactions_out().size());
    
    if (m_spent[out])
    {
        m_spent[out] = false;
        
        available_credit_is_cached_ = false;
    }
}

bool transaction_wallet::is_spent(const std::uint32_t & out) const
{
    if (out >= transactions_out().size())
    {
        throw std::runtime_error(
            "transaction_wallet::is_spent() : out out of range"
        );
    }
    
    if (out >= m_spent.size())
    {
        return false;
    }
    
    return (!!m_spent[out]);
}

std::int64_t transaction_wallet::get_debit() const
{
    if (transactions_in().size() == 0)
    {
        return 0;
    }
    
    if (debit_is_cached_)
    {
        return debit_cached_;
    }
    
    debit_cached_ = wallet_->get_debit(*this);
    
    debit_is_cached_ = true;
    
    return debit_cached_;
}

std::int64_t transaction_wallet::get_credit(const bool & use_cache) const
{
    /**
     * Must wait until coinbase is safely deep enough in the chain
     * before valuing it.
     */
    if (
        (is_coin_base() || is_coin_stake()) && get_blocks_to_maturity() > 0
        )
    {
        return 0;
    }
    
    if (use_cache && credit_is_cached_)
    {
        return credit_cached_;
    }
    
    credit_cached_ = wallet_->get_credit(*this);
    
    credit_is_cached_ = true;
    
    return credit_cached_;
}

std::int64_t transaction_wallet::get_available_credit(
    const bool & use_cache
    ) const
{
    std::int64_t ret = 0;
    
    /**
     * We must wait until the coinbase is (safely) deep enough in the chain
     * before valuing it.
     */
    if ((is_coin_base() || is_coin_stake()) && get_blocks_to_maturity() > 0)
    {
        return 0;
    }
    
    if (use_cache && available_credit_is_cached_)
    {
        return available_credit_cached_;
    }
    
    for (auto i = 0; i < transactions_out().size(); i++)
    {
        if (is_spent(i) == false)
        {
            const auto & tx_out = transactions_out()[i];
            
            ret += wallet_->get_credit(tx_out);
            
            if (utility::money_range(ret) == false)
            {
                throw std::runtime_error("credit out of range");
            }
        }
    }

    available_credit_cached_ = ret;
    available_credit_is_cached_ = true;
    
    return ret;
}

bool transaction_wallet::write_to_disk()
{
    return db_wallet("wallet.dat").write_tx(get_hash(), *this);
}

void transaction_wallet::relay_wallet_transaction(
    const std::shared_ptr<tcp_connection_manager> & connection_manager
    )
{
   db_tx tx_db("r");
   
   relay_wallet_transaction(tx_db, connection_manager);
}

void transaction_wallet::relay_wallet_transaction(
    db_tx & tx_db,
    const std::shared_ptr<tcp_connection_manager> & connection_manager
    )
{
    for (auto & i : m_previous_transactions)
    {
        if ((i.is_coin_base() || i.is_coin_stake()) == false)
        {
            auto hash_tx = i.get_hash();
            
            if (tx_db.contains_transaction(hash_tx) == false)
            {
                for (auto & j : connection_manager->tcp_connections())
                {
                    inventory_vector inv(
                        inventory_vector::type_msg_tx, hash_tx
                    );
                    
                    data_buffer buffer;
                
                    i.encode(buffer);
                    
                    if (auto t = j.second.lock())
                    {
                        t->send_relayed_inv_message(inv, buffer);
                    }
                }
            }
        }
    }
    
    if ((is_coin_base() || is_coin_stake()) == false)
    {
        auto hash_tx = get_hash();
        
        if (tx_db.contains_transaction(hash_tx) == false)
        {
            log_debug(
                "Transaction wallet is relaying " <<
                hash_tx.to_string().substr(0, 10) << "."
            );

            for (auto & i : connection_manager->tcp_connections())
            {
                inventory_vector inv(inventory_vector::type_msg_tx, hash_tx);
                
                data_buffer buffer;
                
                reinterpret_cast<transaction *> (this)->encode(buffer);
                
                if (auto t = i.second.lock())
                {
                    t->send_relayed_inv_message(inv, buffer);
                }
            }
        }
    }
}

const std::vector<transaction_merkle> &
    transaction_wallet::previous_transactions() const
{
    return m_previous_transactions;
}

std::map<std::string, std::string> & transaction_wallet::values()
{
    return m_values;
}

const std::map<std::string, std::string> & transaction_wallet::values() const
{
    return m_values;
}

void transaction_wallet::set_time_received_is_tx_time(
    const std::uint32_t & value
    )
{
    m_time_received_is_tx_time = value;
}

const std::uint32_t & transaction_wallet::time_received_is_tx_time() const
{
    return m_time_received_is_tx_time;
}

void transaction_wallet::set_time_received(const std::uint32_t & value)
{
    m_time_received = value;
}

const std::uint32_t & transaction_wallet::time_received() const
{
    return m_time_received;
}

void transaction_wallet::set_time_smart(const std::uint32_t & value)
{
    m_time_smart = value;
}

const std::uint32_t & transaction_wallet::time_smart() const
{
    return m_time_smart;
}

void transaction_wallet::set_is_from_me(const bool & value)
{
    m_is_from_me = value;
}

const bool & transaction_wallet::is_from_me() const
{
    return m_is_from_me;
}

void transaction_wallet::set_from_account(const std::string & val)
{
    m_from_account = val;
}

std::string & transaction_wallet::from_account()
{
    return m_from_account;
}

bool transaction_wallet::is_confirmed() const
{
    /**
     * Quick answer in most cases.
     */
    if (is_final() == false)
    {
        return false;
    }
    
    if (get_depth_in_main_chain() >= confirmations)
    {
        return true;
    }
    
    if (is_from_me() == false)
    {
        return false;
    }
    
    /**
     * If no confirmations but it's from us, we can still consider it
     * confirmed if all dependencies are confirmed.
     */
    std::map<sha256, const transaction_merkle *> previous_transactions;
    std::vector<const transaction_merkle *> work_queue;
    
    work_queue.reserve(m_previous_transactions.size() + 1);
    
    work_queue.push_back(this);
    
    for (unsigned int i = 0; i < work_queue.size(); i++)
    {
        const auto * ptr = work_queue[i];

        if (ptr->is_final() == false)
        {
            return false;
        }
        
        if (ptr->get_depth_in_main_chain() >= confirmations)
        {
            continue;
        }
        
        if (wallet_->is_from_me(*ptr) == false)
        {
            return false;
        }
        
        if (previous_transactions.empty())
        {
            for (auto & i : m_previous_transactions)
            {
                previous_transactions[i.get_hash()] = &i;
            }
        }
        
        for (auto & i : ptr->transactions_in())
        {
            if (previous_transactions.count(i.previous_out().get_hash()) == 0)
            {
                return false;
            }
            
            work_queue.push_back(
                previous_transactions[i.previous_out().get_hash()]
            );
        }
    }
    
    return true;
}

const std::vector<char> & transaction_wallet::spent() const
{
    return m_spent;
}

void transaction_wallet::set_order_position(const std::int64_t & value)
{
    m_order_position = value;
}

const std::int64_t & transaction_wallet::order_position() const
{
    return m_order_position;
}
