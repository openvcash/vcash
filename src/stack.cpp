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

        stack_impl_->get_configuration().bootstrap_nodes().push_back(
            std::make_pair("94.102.60.170", 55555)
        );

        stack_impl_->get_configuration().bootstrap_nodes().push_back(
            std::make_pair("72.47.234.147", 41134)
        );

        stack_impl_->get_configuration().bootstrap_nodes().push_back(
            std::make_pair("72.47.234.148", 45874)
        );

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

void stack::on_status(const std::map<std::string, std::string> & pairs)
{
    log_none("Stack got info, pairs = " << pairs.size() << ".");
}

void stack::on_alert(const std::map<std::string, std::string> & pairs)
{
    log_none("Stack got alert, pairs = " << pairs.size() << ".");
}

