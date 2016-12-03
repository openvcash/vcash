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

#include <coin/address_manager.hpp>
#include <coin/configuration.hpp>
#include <coin/constants.hpp>
#include <coin/logger.hpp>
#include <coin/protocol.hpp>
#include <coin/stack.hpp>
#include <coin/stack_impl.hpp>

using namespace coin;

stack::stack()
    : stack_impl_(0)
{
    // ...
}

void stack::start(const std::map<std::string, std::string> & args)
{
    if (stack_impl_)
    {
        throw std::runtime_error("Stack is already allocated");
    }
    else
    {
        /**
         * Allocate the stack implementation.
         */
        stack_impl_ = new stack_impl(*this);
        
        /**
         * Set the arguments.
         */
        stack_impl_->get_configuration().set_args(args);

        /**
         * Use different bootstrap endpoints for test networks.
         */
        if (constants::test_net == true)
        {
            /**
             * Add any test network nodes here.
             */
        }
        else
        {
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.105", 32809)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.106", 40006)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.107", 40008)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.108", 60912)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.115", 53389)
            );
            stack_impl_->get_configuration().bootstrap_nodes().push_back(
                std::make_pair("23.254.243.12", 38548)
            );
        }

        /**
         * Start the stack implementation.
         */
        stack_impl_->start();
    }
}

void stack::stop()
{
    if (stack_impl_)
    {
        /**
         * Stop the stack implementation.
         */
        stack_impl_->stop();
        
        /**
         * Deallocate the stack implementation.
         */
        delete stack_impl_, stack_impl_ = 0;
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::send_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->send_coins(amount, destination, wallet_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::start_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->start_mining(mining_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::stop_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (stack_impl_)
    {
        stack_impl_->stop_mining(mining_values);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::broadcast_alert(const std::map<std::string, std::string> & pairs)
{
    if (stack_impl_)
    {
        stack_impl_->broadcast_alert(pairs);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

bool stack::wallet_exists(const bool & is_client)
{
    return stack_impl::wallet_exists(is_client);
}

void stack::wallet_encrypt(const std::string & passphrase)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_encrypt(passphrase);
    }
}

void stack::wallet_lock()
{
    if (stack_impl_)
    {
        stack_impl_->wallet_lock();
    }
}

void stack::wallet_unlock(const std::string & passphrase)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_unlock(passphrase);
    }
}

void stack::wallet_change_passphrase(
    const std::string & passphrase_old, const std::string & password_new
    )
{
    if (stack_impl_)
    {
        stack_impl_->wallet_change_passphrase(passphrase_old, password_new);
    }
}

bool stack::wallet_is_crypted(const std::uint32_t & wallet_id)
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_is_crypted(wallet_id);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return false;
}

bool stack::wallet_is_locked(const std::uint32_t & wallet_id)
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_is_locked(wallet_id);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return false;
}

void stack::wallet_zerotime_lock(const std::string & tx_id)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_zerotime_lock(tx_id);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

std::string stack::wallet_hd_keychain_seed()
{
    if (stack_impl_)
    {
        return stack_impl_->wallet_hd_keychain_seed();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return std::string();
}

void stack::wallet_generate_address(const std::string & label)
{
    if (stack_impl_)
    {
        stack_impl_->wallet_generate_address(label);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::chainblender_start()
{
    if (stack_impl_)
    {
        stack_impl_->chainblender_stop();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::chainblender_stop()
{
    if (stack_impl_)
    {
        stack_impl_->chainblender_stop();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::on_error(const std::map<std::string, std::string> & pairs)
{
    log_error("Stack got error, pairs = " << pairs.size() << ".");
}

void stack::rpc_send(const std::string & command_line)
{
    if (stack_impl_)
    {
        stack_impl_->rpc_send(command_line);
    }
}

void stack::rescan_chain()
{
    if (stack_impl_)
    {
        stack_impl_->rescan_chain();
    }
}

void stack::set_configuration_wallet_transaction_history_maximum(
    const std::time_t & val
    )
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_wallet_transaction_history_maximum(val);
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

void stack::set_configuration_chainblender_use_common_output_denominations(
    const bool & val
    )
{
    if (stack_impl_)
    {
        stack_impl_->set_configuration_chainblender_use_common_output_denominations(
            val
        );
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
}

const bool stack::configuration_chainblender_use_common_output_denominations() const
{
    if (stack_impl_)
    {
        return
            stack_impl_->configuration_chainblender_use_common_output_denominations()
        ;
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return false;
}

const std::time_t
    stack::configuration_wallet_transaction_history_maximum() const
{
    if (stack_impl_)
    {
        return stack_impl_->configuration_wallet_transaction_history_maximum();
    }
    else
    {
        throw std::runtime_error("Stack is not allocated");
    }
    
    return 0;
}

void stack::on_status(const std::map<std::string, std::string> & pairs)
{
    log_none("Stack got info, pairs = " << pairs.size() << ".");
}

void stack::on_alert(const std::map<std::string, std::string> & pairs)
{
    log_none("Stack got alert, pairs = " << pairs.size() << ".");
}

