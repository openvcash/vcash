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
 
#ifndef COIN_STACK_HPP
#define COIN_STACK_HPP

#include <cstdint>
#include <map>
#include <string>

namespace coin {

    class stack_impl;
    
    /**
     * The stack.
     */
    class stack
    {
        public:
        
            /**
             * Constructor
             */
            stack();
            
            /**
             * Starts the stack.
             * @param args The arguments.
             */
            void start(
                const std::map<std::string, std::string> & args =
                std::map<std::string, std::string> ()
            );
            
            /**
             * Stops the stack.
             */
            void stop();
        
            /**
             * Sends coins.
             * @param amount The amount.
             * @param destination The destination.
             * @param wallet_values The wallet ke/values.
             */
            void send_coins(
                const std::int64_t & amount, const std::string & destination,
                const std::map<std::string, std::string> & wallet_values
            );
        
            /** 
             * Starts mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void start_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /** 
             * Stops mining.
             * @param mining_values An std::map<std::string, std::string>.
             */
            void stop_mining(
                const std::map<std::string, std::string> & mining_values
            );
        
            /**
             * Broadcasts an alert.
             * @param pairs An std::map<std::string, std::string>.
             */
            void broadcast_alert(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Encrypts the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_encrypt(const std::string & passphrase);
        
            /**
             * Locks the wallet.
             */
            void wallet_lock();
            
            /**
             * Unlocks the wallet.
             * @param passphrase The passphrase.
             */
            void wallet_unlock(const std::string & passphrase);
        
            /**
             * If true the wallet is crypted.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_crypted(const std::uint32_t & wallet_id = 0);
        
            /**
             * If true the wallet is locked.
             * @param wallet_id The wallet id.
             */
            bool wallet_is_locked(const std::uint32_t & wallet_id = 0);
        
            /**
             * Sends an RPC command line.
             * @param command_line The command line.
             */
            void rpc_send(const std::string & command_line);
            
            /**
             * Called when an error occurs.
             * @param pairs The key/value pairs.
             */
            virtual void on_error(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when a status update occurs.
             * @param pairs The key/value pairs.
             */
            virtual void on_status(
                const std::map<std::string, std::string> & pairs
            );
        
            /**
             * Called when an alert is received.
             * @param pairs The key/value pairs.
             */
            virtual void on_alert(
                const std::map<std::string, std::string> & pairs
            );
        
        private:
        
            // ...
            
        protected:
        
            /**
             * The stack implementation.
             */
            stack_impl * stack_impl_;
    };

} // namespace coin

#endif // COIN_STACK_HPP
