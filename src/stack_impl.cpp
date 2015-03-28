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

#if (! defined _MSC_VER)
#include <sys/file.h>
#endif // _MSC_VER

#include <fstream>
#include <iostream>
#include <random>

#include <boost/asio.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <coin/address.hpp>
#include <coin/address_manager.hpp>
#include <coin/alert_manager.hpp>
#include <coin/block.hpp>
#include <coin/block_index.hpp>
#include <coin/checkpoint_sync.hpp>
#include <coin/db_env.hpp>
#include <coin/db_tx.hpp>
#include <coin/filesystem.hpp>
#include <coin/globals.hpp>
#include <coin/http_transport.hpp>
#include <coin/kernel.hpp>
#include <coin/logger.hpp>
#include <coin/message.hpp>
#include <coin/mining_manager.hpp>
#include <coin/nat_pmp_client.hpp>
#include <coin/protocol.hpp>
#include <coin/random.hpp>
#include <coin/rpc_json_parser.hpp>
#include <coin/rpc_manager.hpp>
#include <coin/stack.hpp>
#include <coin/stack_impl.hpp>
#include <coin/status_manager.hpp>
#include <coin/tcp_acceptor.hpp>
#include <coin/tcp_connection.hpp>
#include <coin/tcp_connection_manager.hpp>
#include <coin/transaction.hpp>
#include <coin/upnp_client.hpp>
#include <coin/wallet.hpp>
#include <coin/wallet_manager.hpp>

using namespace coin;

std::shared_ptr<db_env> stack_impl::g_db_env;
std::shared_ptr<block_index> stack_impl::g_block_index_genesis;
std::set< std::pair<point_out, std::uint32_t> > stack_impl::g_seen_stake;
std::shared_ptr<block_index> stack_impl::g_block_index_best;
big_number stack_impl::g_best_chain_trust(0);
big_number stack_impl::g_best_invalid_trust;

stack_impl::stack_impl(coin::stack & owner)
    : stack_(owner)
    , timer_wallet_flush_(globals::instance().io_service())
    , timer_status_block_(globals::instance().io_service())
    , timer_status_wallet_(globals::instance().io_service())
    , timer_status_blockchain_(globals::instance().io_service())
{
    // ...
}

void stack_impl::start()
{
    /**
     * Make sure only a single instance per directory is allowed.
     */
    lock_file_or_exit();

    /**
     * Set the state to starting.
     */
    globals::instance().set_state(globals::state_starting);

    try
    {
        create_directories();
    }
    catch (std::exception & e)
    {
        log_error(
            "Stack failed to create directories, what = " << e.what() << "."
        );
    }
    
    /**
     * Load the configuration.
     */
    if (m_configuration.load() == false)
    {
        /**
         * If loading the configuration from disk failed then try to save it.
         */
        if (m_configuration.save() == false)
        {
            throw std::runtime_error(
                "Stack failed saving configuration to disk."
            );
        }
        else
        {
            log_info("Stack saved configuration to disk.");
        }
    }
    else
    {
        log_info("Stack loaded configuration from disk.");
    }
    
    if (
        m_configuration.network_port_tcp() == protocol::default_tcp_port
        )
    {
        /**
         * Set the TCP port to zero (random).
         */
        m_configuration.set_network_port_tcp(0);
        
        /**
         * Save the configuration file.
         */
        m_configuration.save();
    }

    /**
     * Reset the boost::asio::io_service.
     */
    globals::instance().io_service().reset();
    
    /**
     * Allocate the boost::asio::io_service::work.
     */
    work_.reset(new boost::asio::io_service::work(
        globals::instance().io_service())
    );

    /**
     * Allocate the thread.
     */
    auto thread = std::make_shared<std::thread> (
        std::bind(&stack_impl::loop, this)
    );
    
    /**
     * Retain the thread.
     */
    threads_.push_back(thread);

    /**
     * Allocate the db_env.
     */
    g_db_env.reset(new db_env());
    
    /**
     * Allocate the status manager.
     */
    m_status_manager.reset(
        new status_manager(globals::instance().io_service(),
        globals::instance().strand(), *this)
    );
    
    /**
     * Start the status manager.
     */
    m_status_manager->start();
    
    /**
     * Allocate the status.
     */
    std::map<std::string, std::string> status;
    
    /**
     * Set the status type.
     */
    status["type"] = "database";
    
    /**
     * Set the status value.
     */
    status["value"] = "Opening database environment";

    /**
     * Callback
     */
    m_status_manager->insert(status);
    
    /**
     * Open the db_env.
     */
    if (g_db_env->open())
    {
        log_info("Stack is loading block index...");
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the status type.
         */
        status["type"] = "database";
    
        /**
         * Set the status value.
         */
        status["value"] = "Loading blockchain";

        /**
         * Callback
         */
        m_status_manager->insert(status);
    
        /**
         * Load the block index.
         */
        load_block_index([this] (const bool & success)
        {
            if (success)
            {
                log_info("Stack loaded block index.");
                
                /**
                 * Allocate the status.
                 */
                std::map<std::string, std::string> status;

                /**
                 * Set the status type.
                 */
                status["type"] = "database";
    
                /**
                 * Set the status value.
                 */
                status["value"] = "Loaded block index";

                /**
                 * Callback
                 */
                m_status_manager->insert(status);
                
                /**
                 * Check that the wallet.dat file exists.
                 */
                std::ifstream ifs(filesystem::data_path() + "/wallet.dat");
            
                bool exists = false;
                
                if (ifs.good() == true)
                {
                    if (g_db_env->verify("wallet.dat"))
                    {
                        log_info("Stack verified wallet.dat.");
                        
                        exists = true;
                    }
                    else
                    {
                        throw std::runtime_error(
                            "failed to verify wallet.dat."
                        );
                    }
                    
                    ifs.close();
                }
                else
                {
                    log_info("Stack is initializing wallet.dat.");
                    
                    exists = false;
                }
                
                /**
                 * Load the wallet.
                 */
                load_wallet([this] (
                    const bool & first_run, const db_wallet::error_t & error
                    )
                {
                    if (error != db_wallet::error_load_ok)
                    {
                        if (error == db_wallet::error_corrupt)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Wallet is corrupted";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_noncritical_error)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet keys loaded correctly but "
                                "transaction or address book entries might be "
                                "missing or incorrect"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_too_new)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet requires a newer software version"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else if (error == db_wallet::error_need_rewrite)
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet has been rewritten, please restart to "
                                "complete the process"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Wallet failed to load";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                    }
                    else
                    {
                        /**
                         * Allocate the status.
                         */
                        std::map<std::string, std::string> status;
                    
                        /**
                         * Set the status type.
                         */
                        status["type"] = "wallet";
    
                        /**
                         * Set the status value.
                         */
                        status["value"] = "Loaded wallet";

                        /**
                         * Callback
                         */
                        m_status_manager->insert(status);
                    }
                
                    /**
                     * -upgradewallet
                     */
             
                    /**
                     * If this is the first run we need to create a wallet.
                     */
                    if (first_run)
                    {
                        /**
                         * Use the latest wallet features for new wallets.
                         */
                        globals::instance().wallet_main()->set_min_version(
                            wallet::feature_latest
                        );
                        
                        /**
                         * Seed RNG.
                         */
                        std::srand(static_cast<std::uint32_t> (std::clock()));

                        /**
                         * Allocate a new public key.
                         */
                        key_public key_default;
                        
                        if (
                            globals::instance().wallet_main()->get_key_from_pool(
                            key_default, false) == false
                            )
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] = "Failed to initialize key pool";

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        
                        /**
                         * Set the main wallet's default public key.
                         */
                        globals::instance().wallet_main()->set_key_public_default(
                            key_default, true
                        );
                        
                        if (
                            globals::instance().wallet_main()->set_address_book_name(
                            globals::instance().wallet_main()->key_public_default(
                            ).get_id(), "") == false
                            )
                        {
                            /**
                             * Allocate the error.
                             */
                            std::map<std::string, std::string> error;
                            
                            /**
                             * Set the error type.
                             */
                            error["type"] = "wallet";
                            
                            /**
                             * Set the error value.
                             */
                            error["value"] =
                                "Wallet failed to set default address"
                            ;

                            /**
                             * Callback
                             */
                            on_error(error);
                        }
                        else
                        {
                            /**
                             * Backup the new wallet.
                             */
                            db_wallet::backup(
                                *globals::instance().wallet_main()
                            );
                        }
                    }

                    log_info(
                        "Stack, wallet default address = " <<
                        address(globals::instance().wallet_main(
                        )->key_public_default().get_id()).to_string() << "."
                    );
                    
                    /**
                     * Register the main wallet.
                     */
                    wallet_manager::instance().register_wallet(
                        globals::instance().wallet_main()
                    );
                    
                    log_info(
                        "Stack, block indexes = " <<
                        globals::instance().block_indexes().size() <<
                        ", best block height = " <<
                        globals::instance().best_block_height() <<
                        ", best block hash = " <<
                        stack_impl::get_block_index_best(
                        )->get_block_hash().to_string() <<
                        ", key pool size = " <<
                        globals::instance().wallet_main()->get_key_pool().size()
                        << ", wallet transactions = " <<
                        globals::instance().wallet_main()->transactions().size()
                        << ", address book entries = " <<
                        globals::instance().wallet_main()->address_book().size()
                        << "."
                    );
    
                    /**
                     * Allocate the status.
                     */
                    std::map<std::string, std::string> status;
                    
                    /**
                     * Set the status type.
                     */
                    status["type"] = "wallet";

                    /**
                     * Set the status value.
                     */
                    status["value"] = "address";
    
                    /**
                     * Set the wallet.address.
                     */
                    status["wallet.address"] =
                        address(globals::instance().wallet_main(
                        )->key_public_default().get_id()).to_string()
                    ;

                    /**
                     * Callback
                     */
                    m_status_manager->insert(status);

                    auto args = m_configuration.args();
                    
                    /**
                     * Check for erase-wallet-transactions.
                     */
                    auto it1 = args.find("erase-wallet-transactions");

                    if (it1 != args.end())
                    {
                        log_info("Stack is erasing wallet transactions.");
                        
                        /**
                         * Erase transactions.
                         */
                        globals::instance().wallet_main()->erase_transactions();
                        
                        /**
                         * Flush the wallet.
                         */
                        globals::instance().wallet_main()->flush();
                    }
                    
                    /**
                     * Callback all transactions from the main wallet.
                     */
                    for (
                        auto & i :
                        globals::instance().wallet_main()->transactions()
                        )
                    {
                        /**
                         * Do not inform the status_manager of transactions
                         * greater than N days.
                         */
                        if (
                            std::time(0) - i.second.time() >
                            m_configuration.wallet_transaction_history_maximum()
                            )
                        {
                            continue;
                        }
                        
                        if (i.second.is_coin_base())
                        {
                            /**
                             * Only callback generated/mined transactions
                             * at depth 1.
                             */
                            if (i.second.is_in_main_chain() == false)
                            {
                                continue;
                            }
                        }
    
                        /**
                         * Allocate the info.
                         */
                        std::map<std::string, std::string> status;
                        
                        /**
                         * Set the type.
                         */
                        status["type"] = "wallet.transaction";

                        /**
                         * Set the value.
                         */
                        status["value"] = "updated";
                        
                        /**
                         * Set the wallet.transaction.hash.
                         */
                        status["wallet.transaction.hash"] =
                            i.second.get_hash().to_string()
                        ;
                        
                        /**
                         * Set the wallet.transaction.in_main_chain.
                         */
                        status["wallet.transaction.in_main_chain"] =
                            std::to_string(i.second.is_in_main_chain())
                        ;
                        
                        /**
                         * Set the wallet.transaction.is_from_me.
                         */
                        status["wallet.transaction.is_from_me"] =
                            std::to_string(i.second.is_from_me())
                        ;

                        /**
                         * Set the wallet.transaction.confirmations.
                         */
                        status["wallet.transaction.confirmations"] =
                            std::to_string(i.second.get_depth_in_main_chain())
                        ;
                        
                        /**
                         * Set the wallet.transaction.confirmed.
                         */
                        status["wallet.transaction.confirmed"] =
                            std::to_string(i.second.is_confirmed())
                        ;
                        
                        /**
                         * Set the wallet.transaction.credit.
                         */
                        status["wallet.transaction.credit"] =
                            std::to_string(i.second.get_credit(true))
                        ;
                        
                        /**
                         * Set the wallet.transaction.debit.
                         */
                        status["wallet.transaction.debit"] =
                            std::to_string(i.second.get_debit())
                        ;
                        
                        /**
                         * Set the wallet.transaction.net.
                         */
                        status["wallet.transaction.net"] =
                            std::to_string(i.second.get_credit(true) -
                            i.second.get_debit())
                        ;
                        
                        /**
                         * Set the wallet.transaction.time.
                         */
                        status["wallet.transaction.time"] = std::to_string(
                            i.second.time()
                        );
                        
                        if (i.second.is_coin_stake())
                        {
                            /**
                             * Set the wallet.transaction.coin_stake.
                             */
                            status["wallet.transaction.coin_stake"] = "1";
                            
                            /**
                             * Set the wallet.transaction.credit.
                             */
                            status["wallet.transaction.credit"] =
                                std::to_string(-i.second.get_debit())
                            ;
                            
                            /**
                             * Set the wallet.transaction.credit.
                             */
                            status["wallet.transaction.value_out"] =
                                std::to_string(i.second.get_value_out()
                            );
                            
                            /**
                             * Set the wallet.transaction.type.
                             */
                            status["wallet.transaction.type"] = "stake";
                        }
                        else if (i.second.is_coin_base())
                        {
                            /**
                             * Set the wallet.transaction.coin_base.
                             */
                            status["wallet.transaction.coin_base"] = "1";
                            
                            std::int64_t credit = 0;
                            
                            /**
                             * Since this is a coin base transaction we only
                             * add the first value from the first transaction
                             * out.
                             */
                            for (auto & j : i.second.transactions_out())
                            {
                                if (
                                    globals::instance().wallet_main(
                                    )->is_mine(j)
                                    )
                                {
                                    credit += j.value();
                                    
                                    break;
                                }
                            }
                            
                            /**
                             * Set the wallet.transaction.credit.
                             */
                            status["wallet.transaction.credit"] =
                                std::to_string(credit)
                            ;
                            
                            /**
                             * Set the wallet.transaction.type.
                             */
                            status["wallet.transaction.type"] = "mined";
                        }
                    
                        /**
                         * Callback on new or updated transaction.
                         */
                        m_status_manager->insert(status);
                    }
                    
                    /**
                     * Periodically flush the main wallet.
                     * :FIXME: Move this into the wallet_manager so that it can
                     * flush all wallets.
                     */
                    timer_wallet_flush_.expires_from_now(
                        std::chrono::seconds(300)
                    );
                    timer_wallet_flush_.async_wait(
                        globals::instance().strand().wrap(
                            [this](boost::system::error_code ec)
                            {
                                if (ec)
                                {
                                    // ...
                                }
                                else
                                {
                                    globals::instance().wallet_main()->flush();
                                }
                            }
                        )
                    );
            
                    auto index_rescan = stack_impl::get_block_index_best();

                    /**
                     * Check for erase-wallet-transactions.
                     */
                    auto it2 = args.find("erase-wallet-transactions");

                    if (it2 != args.end())
                    {
                        index_rescan = stack_impl::get_block_index_genesis();
                    }
                    else
                    {
                        /**
                         * If the configuration is set to rescan the wallet
                         * we set it to false again and set the globals option
                         * to perform the rescan.
                         */
                        if (m_configuration.wallet_rescan() == true)
                        {
                            m_configuration.set_wallet_rescan(false);
                            
                            m_configuration.save();
                            
                            globals::instance().set_option_rescan(true);
                        }

                        if (globals::instance().option_rescan() == true)
                        {
                            index_rescan =
                                stack_impl::get_block_index_genesis()
                            ;
                        }
                        else
                        {
                            db_wallet wallet_db("wallet.dat");
                            
                            block_locator locator;
                            
                            if (wallet_db.read_bestblock(locator))
                            {
                                index_rescan = locator.get_block_index();
                            }
                        }
                    }
                    
                    if (
                        stack_impl::get_block_index_best() !=
                        index_rescan && stack_impl::get_block_index_best() &&
                        index_rescan &&
                        stack_impl::get_block_index_best()->height() >
                        index_rescan->height()
                        )
                    {
                        log_debug("Stack, rescanning wallet for transactions.");
                        
                        /**
                         * Allocate the status.
                         */
                        std::map<std::string, std::string> status;
                        
                        /**
                         * Set the status type.
                         */
                        status["type"] = "wallet";
    
                        /**
                         * Set the status value.
                         */
                        status["value"] = "Rescanning wallet";

                        /**
                         * Callback
                         */
                        m_status_manager->insert(status);

                        log_debug(
                            "Stack, wallet is rescanning last " <<
                            stack_impl::get_block_index_best()->height() -
                            index_rescan->height() <<
                            " blocks from block " << index_rescan->height() <<
                            "."
                        );
                    
                        globals::instance().wallet_main()->scan_for_transactions(
                            index_rescan, true
                        );
                    }
                });
#if 1
                /**
                 * Use a single std::thread to run the asio::io_service to
                 * obtain the maximum performance to energy usage ratio.
                 */
                auto cores = 0;
#else
                /**
                 * Now that the block index is loaded increase the thread
                 * count to max(1, cores - 1) if required.
                 */
                auto cores = std::max(
                    static_cast<std::uint32_t> (1),
                    std::thread::hardware_concurrency() - 1
                );
#endif
                log_info("Stack is adding " << cores << " threads.");
                
                for (auto i = 0; i < cores; i++)
                {
                    auto thread = std::make_shared<std::thread> (
                        std::bind(&stack_impl::loop, this)
                    );
                    
                    /**
                     * Retain the thread.
                     */
                    threads_.push_back(thread);
                }
            }
            else
            {
                log_info("Stack failed to load block index.");
                
                /**
                 * Allocate the error.
                 */
                std::map<std::string, std::string> error;
                
                /**
                 * Set the error type.
                 */
                error["type"] = "database";
                
                /**
                 * Set the error value.
                 */
                error["value"] = "Failed to load blkindex.dat";

                /**
                 * Callback
                 */
                on_error(error);
            }
        });
    }
    else
    {
        /**
         * Allocate the error.
         */
        std::map<std::string, std::string> error;
        
        /**
         * Set the error type.
         */
        error["type"] = "database";
        
        /**
         * Set the error value.
         */
        error["value"] =
            "Failed to initialize database environment. Backup " +
            filesystem::data_path() + " and remove everything except for "
            "wallet.dat" + "."
        ;

        /**
         * Callback
         */
        on_error(error);
    }
    
    /**
     * The minimum disk space required (50 Megabytes).
     */
    const std::uint64_t minimum_disk_space = 52428800;

    /**
     * Get the available disk space.
     */
    auto disk_info = utility::disk_info(filesystem::data_path());
    
    log_debug("Stack, disk info.space = " << disk_info.available << ".");
    
    if (disk_info.available < minimum_disk_space)
    {
        /**
         * Allocate the error.
         */
        std::map<std::string, std::string> error;
        
        /**
         * Set the error type.
         */
        error["type"] = "disk";
        
        /**
         * Set the error value.
         */
        error["value"] = "Disk space is too low";

        /**
         * Callback
         */
        on_error(error);
    }

    globals::instance().io_service().post(
        globals::instance().strand().wrap([this]()
    {
        /**
         * If stop was previously called then don't proceed.
         */
        if (globals::instance().state() >= globals::state_stopping)
        {
            return;
        }
    
        /**
         * Add wallet transactions that aren't already in a block to the
         * transactions.
         */
        globals::instance().wallet_main()->reaccept_wallet_transactions();
    
        /**
         * Allocate the tcp_acceptor.
         */
        m_tcp_acceptor.reset(
            new tcp_acceptor(globals::instance().io_service(),
            globals::instance().strand())
        );
        
        /**
         * Set the accept handler.
         */
        m_tcp_acceptor->set_on_accept(
            [this] (std::shared_ptr<tcp_transport> transport)
            {
                /**
                 * Inform the tcp_connection_manager.
                 */
                m_tcp_connection_manager->handle_accept(transport);
            }
        );
        
        /**
         * Try to use the given port.
         */
        std::uint16_t tcp_port = m_configuration.network_port_tcp();
        
        /**
         * If the port is zero generate a random one.
         */
        if (tcp_port == 0)
        {
            /**
             * Get a random ephemeral port.
             */
            tcp_port = random::uint16_random_range(32768, 61000);
            
            /**
             * Set the network port.
             */
            m_configuration.set_network_port_tcp(tcp_port);
            
            /**
             * Save the confiuration.
             */
            m_configuration.save();
        }
        
        bool ret = false;
        
        while (ret == false)
        {
            ret = m_tcp_acceptor->open(tcp_port);
            
            if (ret == false)
            {
                tcp_port += 2;
            }
            else
            {
                /**
                 * Set the network tcp port.
                 */
                m_configuration.set_network_port_tcp(tcp_port);
                
                /**
                 * Save the configuration.
                 */
                m_configuration.save();
                
                break;
            }
            
            /**
             * Try 50 even ports before giving up.
             */
            if (tcp_port > m_configuration.network_port_tcp() + 100)
            {
                break;
            }
        }
        
        if (ret == false)
        {
            throw std::runtime_error("failed to start tcp_acceptor");
        }
        else
        {
            assert(m_tcp_acceptor->local_endpoint().port() == tcp_port);
            
            /**
             * Set the local endpoint.
             */
            m_local_endpoint = m_tcp_acceptor->local_endpoint();

            log_info(
                "TCP Acceptor started, local endpoint = " <<
                m_local_endpoint << "."
            );
      
            /**
             * Set the nonce used in the version message.
             */
            globals::instance().set_version_nonce(random::uint64());

            log_info(
                "Stack generated version nonce = " <<
                globals::instance().version_nonce() << "."
            );

            /**
             * Allocate the address_manager.
             */
            m_address_manager.reset(new address_manager());
            
            /**
             * Allocate the alert_manager.
             */
            m_alert_manager.reset(
                new alert_manager(globals::instance().io_service(), *this)
            );
            
            /**
             * Allocate the tcp_connection_manager.
             */
            m_tcp_connection_manager.reset(
                new tcp_connection_manager(globals::instance().io_service(),
                *this)
            );
            
            /**
             * Allocate the nat_pmp_client.
             */
            m_nat_pmp_client.reset(
                new nat_pmp_client(globals::instance().io_service())
            );
            
            /**
             * Start the nat_pmp_client.
             */
            m_nat_pmp_client->start();

            /**
             * Allocate the rpc_manager.
             */
            m_rpc_manager.reset(
                new rpc_manager(globals::instance().io_service(),
                globals::instance().strand(), *this)
            );

            /**
             * Start the rpc_manager.
             */
            m_rpc_manager->start();

            /**
             * Allocate the upnp_client.
             */
            m_upnp_client.reset(new upnp_client(
                globals::instance().io_service(), globals::instance().strand())
            );
            
            /**
             * Start the upnp_client.
             */
            m_upnp_client->start();
            
            /**
             * Allocate the status.
             */
            std::map<std::string, std::string> status;
            
            /**
             * Set the status type.
             */
            status["type"] = "network";
    
            /**
             * Set the status value.
             */
            status["value"] = "Loading network addresses";

            /**
             * Callback
             */
            m_status_manager->insert(status);
            
            /**
             * Start the address_manager.
             */
            m_address_manager->start();
            
            /**
             * Set the status type.
             */
            status["type"] = "network";
    
            /**
             * Set the status value.
             */
            status["value"] = "Loaded network addresses";

            /**
             * Callback
             */
            m_status_manager->insert(status);
            
            /**
             * Start the tcp_connection_manager.
             */
            m_tcp_connection_manager->start();
            
            /**
             * Set the status type.
             */
            status["type"] = "network";
    
            /**
             * Set the status value.
             */
            status["value"] = "Connecting";

            /**
             * Callback
             */
            m_status_manager->insert(status);
            
            /**
             * Starts the block status timer.
             */
            timer_status_block_.expires_from_now(std::chrono::seconds(1));
            timer_status_block_.async_wait(
                globals::instance().strand().wrap(
                    [this](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            on_status_block();
                        }
                    }
                )
            );
            
            /**
             * Starts the wallet status timer.
             */
            timer_status_wallet_.expires_from_now(std::chrono::seconds(1));
            timer_status_wallet_.async_wait(
                globals::instance().strand().wrap(
                    [this](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            on_status_wallet();
                        }
                    }
                )
            );
            
            /**
             * Starts the status blockchain timer.
             */
            timer_status_blockchain_.expires_from_now(std::chrono::seconds(8));
            timer_status_blockchain_.async_wait(
                globals::instance().strand().wrap(
                    [this](boost::system::error_code ec)
                    {
                        if (ec)
                        {
                            // ...
                        }
                        else
                        {
                            on_status_blockchain();
                        }
                    }
                )
            );
            
            /**
             * Allocate the mining_manager.
             */
            m_mining_manager.reset(
                new mining_manager(globals::instance().io_service(), *this)
            );
            
            /**
             * Start the mining manager.
             */
            m_mining_manager->start();
            
            /**
             * Add port mappings by posting to the boost::asio::io_service to
             * induce a slight delay.
             */
            globals::instance().io_service().post(
                globals::instance().strand().wrap([this, tcp_port]()
            {
                /**
                 * Add a mapping for our TCP port.
                 */
                m_nat_pmp_client->add_mapping(nat_pmp::protocol_tcp, tcp_port);
            
                /**
                 * Add a mapping for out TCP port.
                 */
                m_upnp_client->add_mapping(upnp_client::protocol_tcp, tcp_port);
                
                /**
                 * Download centrally hosted bootstrap peers.
                 */
                do_check_peers(0);
            }));
        }
    }));
    
    /**
     * Set the state to started.
     */
    globals::instance().set_state(globals::state_started);
}

void stack_impl::stop()
{
    /**
     * Set the state to stopping.
     */
    globals::instance().set_state(globals::state_stopping);
    
    /**
     * Save the configuration to disk.
     */
    if (m_configuration.save() == false)
    {
        log_error("Stack failed to save configuration to disk.");
    }
    
    /**
     * Stop the mining_manager.
     */
    if (m_mining_manager)
    {
        m_mining_manager->stop();
    }
    
    /**
     * Stop the tcp_acceptor.
     */
    if (m_tcp_acceptor)
    {
        m_tcp_acceptor->close();
    }
    
    /**
     * Stop the address_manager.
     */
    if (m_address_manager)
    {
        m_address_manager->stop();
    }
    
    /**
     * Stop the tcp_connection_manager.
     */
    if (m_tcp_connection_manager)
    {
        m_tcp_connection_manager->stop();
    }
    
    /**
     * Stop the nat_pmp_client.
     */
    if (m_nat_pmp_client)
    {
        m_nat_pmp_client->stop();
    }
    
    /**
     * Stop the nat_pmp_client.
     */
    if (m_rpc_manager)
    {
        m_rpc_manager->stop();
    }
    
    /**
     * Stop the upnp_client.
     */
    if (m_upnp_client)
    {
        m_upnp_client->stop();
    }
    
    /**
     * Stop the status_manager.
     */
    m_status_manager->stop();
    
    /**
     * Flush the db_env.
     */
    g_db_env->flush();
    
    /**
     * Unregister the main wallet.
     */
    wallet_manager::instance().unregister_wallet(
        globals::instance().wallet_main()
    );
    
    /**
     * Cancel the wallet flush timer.
     */
    timer_wallet_flush_.cancel();
    
    /**
     * Cancel the block status timer.
     */
    timer_status_block_.cancel();
    
    /**
     * Cancel the wallet status timer.
     */
    timer_status_wallet_.cancel();
    
    /**
     * Cancel the blockchain status timer.
     */
    timer_status_blockchain_.cancel();
    
    /**
     * Reset the work.
     */
    work_.reset();

    /**
     * :FIXME: There is an io_service object that is not being cancelled so
     * calling join will block preventing exit.
     */
    globals::instance().io_service().stop();
    
    /**
     * Join the threads.
     */
    for (auto & i : threads_)
    {
        try
        {
            if (i->joinable())
            {
                i->join();
            }
        }
        catch (std::exception & e)
        {
            // ...
        }
    }
    
    /**
     * Clear the threads.
     */
    threads_.clear();
    
    /**
     * Close the db_env.
     */
    if (g_db_env)
    {
        g_db_env->close_DbEnv();
    }
    
    /**
     * Reset
     */
    m_address_manager.reset();
    
    /**
     * Reset
     */
    m_alert_manager.reset();
    
    /**
     * Reset
     */
    m_mining_manager.reset();
    
    /**
     * Reset
     */
    m_tcp_acceptor.reset();
    
    /**
     * Reset
     */
    m_tcp_connection_manager.reset();
    
    /**
     * Reset
     */
    m_nat_pmp_client.reset();
    
    /**
     * Reset
     */
    m_status_manager.reset();
    
    /**
     * Reset
     */
    g_db_env.reset();
    
    /**
     * Set the state to stopped.
     */
    globals::instance().set_state(globals::state_stopped);
}

void stack_impl::send_coins(
    const std::int64_t & amount, const std::string & destination,
    const std::map<std::string, std::string> & wallet_values
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, amount, destination, wallet_values]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "transaction";
        
        address addr(destination);
        
        bool perform_send = true;
        
        if (
            addr.to_string() == address(globals::instance().wallet_main(
            )->key_public_default().get_id()).to_string()
            )
        {
            log_error(
                "Stack, send coins failed, tried to send to our own address."
            );
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "can't to send to our own address";
        }
        
        if (addr.is_valid() == false)
        {
            log_error("Stack, send coins failed, invalid destination address.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "invalid destination address";
        }

        if (amount < constants::min_txout_amount)
        {
            log_error("Stack, send coins failed, amount too small.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "amount too small";
        }
        
        if (
            amount + globals::instance().transaction_fee() >
            globals::instance().wallet_main()->get_balance()
            )
        {
            log_error("Stack, send coins failed, insufficient funds.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "insufficient funds";
        }
        
        if (globals::instance().wallet_main()->is_locked())
        {
            log_error("Stack, send coins failed, wallet is locked.");
            
            perform_send = false;
            
            pairs["error.code"] = "-1";
            pairs["error.message"] = "wallet is locked";
        }
        
        if (perform_send)
        {
            /**
             * Allocate the transaction_wallet.
             */
            transaction_wallet wtx;
            
            auto it = wallet_values.find("comment");
            
            if (it != wallet_values.end())
            {
                wtx.values()["comment"] = it->second;
            }
            
            it = wallet_values.find("to");
            
            if (it != wallet_values.end())
            {
                wtx.values()["to"] = it->second;
            }

            destination::tx_t dest_tx = addr.get();

            auto ret =
                globals::instance().wallet_main()->send_money_to_destination(
                dest_tx, amount, wtx
            );
            
            if (ret.first)
            {
                pairs["error.code"] = "0";
                pairs["error.message"] = "success";
            }
            else
            {
                log_error(
                    "Stack, send coins failed, error = " << ret.second << "."
                );

                pairs["error.code"] = "-1";
                pairs["error.message"] = ret.second;
            }
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::start_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (m_mining_manager)
    {
        auto it = mining_values.find("algorithm");
        
        if (it != mining_values.end())
        {
            if (it->second == "proof-of-work")
            {
                m_mining_manager->start_proof_of_work();
            }
        }
    }
}

void stack_impl::stop_mining(
    const std::map<std::string, std::string> & mining_values
    )
{
    if (m_mining_manager)
    {
        globals::instance().io_service().post(globals::instance().strand().wrap(
            [this, mining_values]()
        {
            auto it = mining_values.find("algorithm");
            
            if (it != mining_values.end())
            {
                if (it->second == "proof-of-work")
                {
                    m_mining_manager->stop_proof_of_work();
                }
            }
        }));
    }
}

void stack_impl::broadcast_alert(
    const std::map<std::string, std::string> & pairs
    )
{
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, pairs]()
    {
        /**
         * Allocate the alert.
         */
        alert a;
        
        /**
         * Check for the status.
         */
        auto it = pairs.find("status");

        if (it != pairs.end())
        {
            if (it->second.size() > 0)
            {
                a.set_status(it->second);
            }
        }
        
        /**
         * Check for the comment.
         */
        it = pairs.find("comment");

        if (it != pairs.end())
        {
            if (it->second.size() > 0)
            {
                a.set_comment(it->second);
            }
        }
        
        /**
         * :JC: Add support for setting priority and id.
         */
        
        /**
         * Set the minimum version.
         */
        a.set_minimum_version(0);
        
        /**
         * Set the maxium version.
         */
        a.set_maximum_version(protocol::version);
        
        /**
         * Set the version.
         */
        a.set_version(protocol::version);
        
        /**
         * Set the cancel.
         */
        a.set_cancel(0);
        
        /**
         * Set the relay until.
         */
        a.set_relay_until(
            static_cast<std::int32_t> (
            time::instance().get_adjusted() + 365 * 24 * 60 * 60)
        );
    
        /**
         * Set the expiration.
         */
        a.set_expiration(
            static_cast<std::int32_t> (
            time::instance().get_adjusted() + 365 * 24 * 60 * 60)
        );
        
        /**
         * Allocate the key.
         */
        key k;
        
        /**
         * Allocate the (message) buffer.
         */
        data_buffer buffer;
        
        /**
         * Encode the alert into the buffer.
         */
        ((alert_unsigned)a).encode(buffer);
        
        /**
         * Set the message from the buffer.
         */
        a.set_message(
            std::vector<std::uint8_t>(buffer.data(),
            buffer.data() + buffer.size())
        );

        /**
         * Allocate an empty private key.
         */
        key::private_t key_private;
        
        /**
         * Check for the private key.
         */
        it = pairs.find("key_private");

        if (it != pairs.end())
        {
            /**
             * Set the private key from the hexidecimal representation.
             */
            key_private = utility::from_hex(it->second);
        }
        
        assert(key_private.size());
        
        /**
         * Set the private key.
         */
        k.set_private_key(
            key::private_t(key_private.begin(), key_private.end())
        );
        
        /**
         * Sign the message.
         */
        if (
            k.sign(sha256::from_digest(&hash::sha256d(&a.message()[0],
            a.message().size())[0]), a.signature()) == false
            )
        {
            throw std::runtime_error("Unable to sign alert, check private key?\n");
        }
        
        /**
         * Process the alert.
         */
        if (m_alert_manager)
        {
            if (m_alert_manager->process(a) == false)
            {
                throw std::runtime_error("Failed to process alert.\n");
            }
        }
        
        /**
         * Broadcast the alert to all connected peers.
         */
        if (m_tcp_connection_manager)
        {
            /**
             * Allocate the message.
             */
            message msg("alert");
            
            /**
             * Set the message.
             */
            msg.protocol_alert().a = std::make_shared<alert> (a);
            
            /**
             * Encode the message.
             */
            msg.encode();
            
            /**
             * Broadcast the message.
             */
            m_tcp_connection_manager->broadcast(msg.data(), msg.size());
        }
    }));
}

void stack_impl::wallet_encrypt(const std::string & passphrase)
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this, passphrase]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "encrypt";
        
        if (globals::instance().wallet_main()->encrypt(passphrase))
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to encrypt wallet";
        }
    
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::wallet_lock()
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "lock";
        
        if (globals::instance().wallet_main()->lock())
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to lock wallet";
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

void stack_impl::wallet_unlock(const std::string & passphrase)
{
    globals::instance().io_service().post(
        globals::instance().strand().wrap([this, passphrase]()
    {
        /**
         * Allocate the pairs.
         */
        std::map<std::string, std::string> pairs;
        
        /**
         * Set the pairs type.
         */
        pairs["type"] = "wallet";
        
        /**
         * Set the pairs value (action in this case).
         */
        pairs["value"] = "unlock";
        
        if (globals::instance().wallet_main()->unlock(passphrase))
        {
            pairs["error.code"] = "0";
            pairs["error.message"] = "success";
        }
        else
        {
            pairs["error.code"] = "-1";
            pairs["error.message"] = "failed to unlock wallet";
        }
        
        /**
         * Callback
         */
        if (m_status_manager)
        {
            m_status_manager->insert(pairs);
        }
    }));
}

bool stack_impl::wallet_is_crypted(const std::uint32_t & wallet_id)
{
    if (wallet_id == 0)
    {
        return globals::instance().wallet_main()->is_crypted();
    }
    
    return false;
}

bool stack_impl::wallet_is_locked(const std::uint32_t & wallet_id)
{
    if (wallet_id == 0)
    {
        return globals::instance().wallet_main()->is_locked();
    }
    
    return false;
}

void stack_impl::rpc_send(const std::string & command_line)
{
    auto tmp = command_line;
    
    /**
     * Trim whitespace.
     */
    boost::algorithm::trim(tmp);
    
    std::vector<std::string> parts;
    
    /**
     * Split the command line.
     */
    boost::split(parts, tmp, boost::is_any_of(" "));
    
    if (parts.size() > 0)
    {
        std::string command;
        
        std::vector<std::string> params;
        
        auto index = 0;
        
        for (auto & i : parts)
        {
            /**
             * Get the command and params.
             */
            if (index++ == 0)
            {
                command = i;
            }
            else
            {
                params.push_back(i);
            }
        }
        
        if (command.size() > 0)
        {
            /**
             * The url.
             */
            auto url = "http://localhost";

            /**
             * The headers.
             */
            std::map<std::string, std::string> headers;
            
            /**
             * The body.
             */
            std::string body;
            
            /**
             * A JSON-RPC request.
             */
            struct
            {
                std::string method;
                boost::property_tree::ptree params;
                std::string id;
            } request;
            
            /**
             * Set the method.
             */
            request.method = command;
            
            /**
             * Set the id.
             */
            request.id = std::to_string(std::rand());

            try
            {
                boost::property_tree::ptree pt;

                /**
                 * Put method into property tree.
                 */
                pt.put(
                    "method", request.method,
                    rpc_json_parser::translator<std::string> ()
                );
                
                boost::property_tree::ptree pt_params;
                
                /** 
                 * Put the params.
                 */
                if (params.size() > 0)
                {
                    for (auto & i : params)
                    {
                        boost::property_tree::ptree pt_param;
                        
                        pt_param.put(
                            "", i, rpc_json_parser::translator<std::string> ()
                        );
                        
                        pt_params.push_back(std::make_pair("", pt_param));
                    }
                
                    pt.put_child("params", pt_params);
                }
                else
                {
                    boost::property_tree::ptree pt_params;
                    
                    pt_params.push_back(
                        std::make_pair("", boost::property_tree::ptree())
                    );
                    
                    pt.put_child("params", pt_params);
                }
                
                /**
                 * Put id into property tree.
                 */
                pt.put(
                    "id", request.id,
                    rpc_json_parser::translator<std::string> ()
                );
                
                /**
                 * The std::stringstream.
                 */
                std::stringstream ss;
                
                /**
                 * Write property tree to json file.
                 */
                rpc_json_parser::write_json(ss, pt, true);
                
                /**
                 * Set the body.
                 */
                body = ss.str();
                
                /**
                 * Set the content-length.
                 */
                headers["content-length"] = body.size();
                
                /**
                 * POST the request.
                 */
                url_post(url, protocol::default_rpc_port, headers, body,
                    [this] (const std::map<std::string, std::string> & headers,
                    const std::string & body)
                {
                    if (body.size() > 0)
                    {
                        /**
                         * The JSON
                         */
                        std::stringstream json;

                        std::stringstream ss;

                        ss << body;

                        boost::property_tree::ptree pt;
                        
                        std::map<std::string, std::string> result;
                        
                        try
                        {
                            read_json(ss, pt);

                            /**
                             * Allocate the pairs.
                             */
                            std::map<std::string, std::string> pairs;
                            
                            /**
                             * Set the pairs type.
                             */
                            pairs["type"] = "rpc";
                            
                            try
                            {
                                auto & error = pt.get_child("error");
                                
                                (void)error;

                                /**
                                 * Set the pairs value.
                                 */
                                pairs["value"] =
                                    error.get_child("code"
                                    ).get<std::string> ("") + " : " +
                                    error.get_child("message"
                                    ).get<std::string> ("")
                                ;

                                /**
                                 * Set the pairs error.code.
                                 */
                                pairs["error.code"] = "-1";
                                
                                /**
                                 * Set the pairs error.message.
                                 */
                                pairs["error.message"] =
                                    error.get_child("message"
                                    ).get<std::string> ("")
                                ;
                                
                            }
                            catch (...)
                            {
                                auto & result = pt.get_child("result");
                             
                                try
                                {
                                    rpc_json_parser::write_json(json, result);
                                }
                                catch (...)
                                {
                                    json << result.get<std::string> ("");
                                }

                                /**
                                 * Set the pairs value.
                                 */
                                pairs["value"] =
                                    json.str() == "null" ? "" : json.str()
                                ;

                                /**
                                 * Set the pairs error.code.
                                 */
                                pairs["error.code"] = "0";
                                
                                /**
                                 * Set the pairs error.message.
                                 */
                                pairs["error.message"] = "success";
                            }
                            
                            /**
                             * Callback
                             */
                            if (m_status_manager)
                            {
                                m_status_manager->insert(pairs);
                            }
                        }
                        catch (std::exception & e)
                        {
                            log_error(
                                "Stack rpc send failed to parse JSON-RPC "
                                "response, what = " << e.what() << "."
                            );
                        }
                    }
                });
            }
            catch (std::exception & e)
            {
                log_error(
                    "Stack failed to create RPC request, what = " <<
                    e.what() << "."
                );
            }
        }
    }
}

void stack_impl::url_get(
    const std::string & url,
    const std::function<void (const std::map<std::string, std::string> &,
    const std::string &)> & f
    )
{
    std::shared_ptr<http_transport> t =
        std::make_shared<http_transport>(globals::instance().io_service(), url)
    ;

    t->start(
        [this, f](
        boost::system::error_code ec, std::shared_ptr<http_transport> t)
    {
        if (ec)
        {
            f(std::map<std::string, std::string> (), std::string());
		}
		else
		{
            f(t->headers(), t->response_body());
		}
	});
}

void stack_impl::url_post(
    const std::string & url, const std::uint16_t & port,
    const std::map<std::string, std::string> & headers,
    const std::string & body,
    const std::function<void (const std::map<std::string, std::string> &,
    const std::string &)> & f
    )
{
    std::shared_ptr<http_transport> t =
        std::make_shared<http_transport>(globals::instance().io_service(), url)
    ;

    t->headers() = headers;
    
    t->set_request_body(body);
    
    t->start(
        [this, f](
        boost::system::error_code ec, std::shared_ptr<http_transport> t)
    {
        if (ec)
        {
            f(std::map<std::string, std::string> (), std::string());
		}
		else
		{
            f(t->headers(), t->response_body());
		}
	}, port);
}

bool stack_impl::process_block(
    const std::shared_ptr<tcp_connection> & connection,
    const std::shared_ptr<block> & blk
    )
{
    if (globals::instance().state() < globals::state_stopping)
    {
        /**
         * Check for duplicate.
         */
        auto hash_block = blk->get_hash();
        
        if (globals::instance().block_indexes().count(hash_block) > 0)
        {
            log_debug(
                "Stack failed to process block, already have " <<
                globals::instance().block_indexes()[hash_block]->height()
                << " " << hash_block.to_string().substr(0, 20) << "."
            );
            
            return false;
        }
        
        if (globals::instance().orphan_blocks().count(hash_block) > 0)
        {
            log_debug(
                "Stack failed to process block, already have (orphan) " <<
                hash_block.to_string().substr(0, 20) << "."
            );
            
            return false;
        }
        
        /**
         * Check proof-of-stake (ppcoin).
         */
        
        /**
         * Duplicate stake allowed only when there is orphan child block (prevents
         * block flood attack).
         */
        if (
            blk->is_proof_of_stake() &&
            get_seen_stake().count(blk->get_proof_of_stake()) &&
            globals::instance().orphan_blocks_by_previous().count(hash_block) == 0
            && checkpoints::instance().wanted_by_pending_sync_checkpoint(
            hash_block) == false
            )
        {
            log_debug(
                "Stack failed to process block, duplicate proof-of-stake (" <<
                blk->get_proof_of_stake().first.to_string() << ", " <<
                blk->get_proof_of_stake().second << ")" << " for block " <<
                hash_block.to_string() << "."
            );
            
            return false;
        }

        try
        {
            /**
             * Preliminary checks.
             */
            if (blk->check_block(connection) == false)
            {
                log_error("Stack failed to process block, check block failed.");
            
                return false;
            }
        }
        catch (std::exception & e)
        {
            log_error(
                "Stack failed to process block, check block failed, "
                "what = " << e.what() << "."
            );
            
            return false;
        }
        
        /**
         * Verify the hash of the target and signature of coinstake transaction
         * (ppcoin).
         */
        if (blk->is_proof_of_stake())
        {
            sha256 hash_pos;
            
            if (
                kernel::instance().check_proof_of_stake(
                connection, blk->transactions()[1], blk->header().bits,
                hash_pos) == false
                )
            {
                log_debug(
                    "Stack failed to process block, check proof-of-stake failed "
                    "for block " << hash_block.to_string() << "."
                );
             
                /**
                 * To be expected during initial block download.
                 */
                return false;
            }
            
            if (globals::instance().proofs_of_stake().count(hash_block) == 0)
            {
                globals::instance().proofs_of_stake().insert(
                    std::make_pair(hash_block, hash_pos)
                );
            }
        }
        
        auto sync_checkpoint = checkpoints::instance().get_last_sync_checkpoint();
        
        if (
            sync_checkpoint && blk->header().hash_previous_block !=
            globals::instance().hash_best_chain() &&
            checkpoints::instance().wanted_by_pending_sync_checkpoint(
            hash_block) == false
            )
        {
            /**
             * Extra checks to prevent "fill up memory by spamming with bogus
             * blocks".
             */
            auto time_delta = blk->header().timestamp - sync_checkpoint->time();
            
            big_number bn_new_block;
            
            bn_new_block.set_compact(blk->header().bits);
            
            big_number bn_required;

            if (blk->is_proof_of_stake())
            {
                bn_required.set_compact(
                    utility::compute_min_stake(
                    utility::get_last_block_index(sync_checkpoint, true)->bits(),
                    time_delta, blk->header().timestamp)
                );
            }
            else
            {
                bn_required.set_compact(
                    utility::compute_min_work(
                    utility::get_last_block_index(sync_checkpoint, false)->bits(),
                    time_delta)
                );
            }
            
            if (bn_new_block > bn_required)
            {
                log_debug(
                    "Stack failed to process block, block with too little " <<
                    (blk->is_proof_of_stake() ?
                    "proof-of-stake" : "proof-of-work") << "."
                );

                /**
                 * Set the Denial-of-Service score for the connection.
                 */
                if (connection)
                {
                    connection->set_dos_score(100);
                }
                
                return false;
            }
        }

        /**
         * Ask for pending sync-checkpoint if any (ppcoin).
         */
        if (utility::is_initial_block_download() == false)
        {
            checkpoints::instance().ask_for_pending_sync_checkpoint(connection);
        }

        /**
         * If don't already have its previous block, shunt it off to holding
         * area until we get it.
         */
        if (
            globals::instance().block_indexes().count(
            blk->header().hash_previous_block) == 0
            )
        {
            log_debug(
                "Stack failed to process block, orphan block, previous = " <<
                blk->header().hash_previous_block.to_string().substr(0, 20) << "."
            );
            
            std::shared_ptr<block> blk2(new block(*blk));
            
            /**
             * Check proof-of-stake (ppcoin).
             */
            if (blk2->is_proof_of_stake())
            {
                /**
                 * Limited duplicity on stake: prevents block flood attack.
                 * Duplicate stake allowed only when there is orphan child block.
                 */
                if (
                    globals::instance().stake_seen_orphan().count(
                    blk2->get_proof_of_stake()) > 0 &&
                    globals::instance().orphan_blocks_by_previous().count(
                    hash_block) == 0 &&
                    checkpoints::instance().wanted_by_pending_sync_checkpoint(
                    hash_block) == false
                    )
                {
                    log_debug(
                        "Stack failed to process block, duplicate "
                        "proof-of-stake (" <<
                        blk2->get_proof_of_stake().first.to_string() << ", " <<
                        blk2->get_proof_of_stake().second << ")" << " for block " <<
                        hash_block.to_string() << "."
                    );
                    
                    return false;
                }
                else
                {
                    globals::instance().stake_seen_orphan().insert(
                        blk2->get_proof_of_stake()
                    );
                }
            }
            
            globals::instance().orphan_blocks().insert(
                std::make_pair(hash_block, blk2)
            );
            
            globals::instance().orphan_blocks_by_previous().insert(
                std::make_pair(blk2->header().hash_previous_block, blk2)
            );

            /**
             * Ask this guy to fill in what we're missing.
             */
            if (connection)
            {
                connection->send_getblocks_message(
                    stack_impl::get_block_index_best(),
                    utility::get_orphan_root(blk2)
                );
                
                /**
                 * Getblocks may not obtain the ancestor block rejected earlier
                 * by duplicate-stake check so we ask for it again directly
                 * (ppcoin).
                 */
                if (utility::is_initial_block_download() == false)
                {
                    std::vector<inventory_vector> getdata;
                    
                    getdata.push_back(
                        inventory_vector(inventory_vector::type_msg_block,
                        utility::wanted_by_orphan(blk2))
                    );
                    
                    connection->send_getdata_message(getdata);
                }
            }
            
            return true;
        }
        
        /**
         * Store to disk.
         */
        if (blk->accept_block(m_tcp_connection_manager) == false)
        {
            log_error("Stack failed to process block, accept block failed.");
         
            return false;
        }

        /**
         * Recursively process any orphan blocks that depended on this one.
         */
        std::vector<sha256> work_queue;
        
        work_queue.push_back(hash_block);
        
        for (auto i = 0; i < work_queue.size(); i++)
        {
            auto hash_previous = work_queue[i];
            
            for (
                auto it = globals::instance().orphan_blocks_by_previous(
                ).lower_bound(hash_previous); it != globals::instance(
                ).orphan_blocks_by_previous().upper_bound(hash_previous); ++it
                )
            {
                std::shared_ptr<block> & block_orphan = it->second;

                log_debug(
                    "Stack is processing orphan block " <<
                    block_orphan->get_hash().to_string().substr(0, 29) << "."
                );
                
                if (block_orphan->accept_block(m_tcp_connection_manager))
                {
                    work_queue.push_back(block_orphan->get_hash());
                }

                globals::instance().orphan_blocks().erase(
                    block_orphan->get_hash()
                );
                
                globals::instance().stake_seen_orphan().erase(
                    block_orphan->get_proof_of_stake()
                );
            }
            
            globals::instance().orphan_transactions_by_previous().erase(
                hash_previous
            );
        }
        
        log_debug("Stack processed block, accepted.");
        
        /**
         * If responsible for sync-checkpoint send it (ppcoin).
         */
        if (connection && checkpoint_sync::master_private_key().size() > 0)
        {
            checkpoints::instance().send_sync_checkpoint(
                m_tcp_connection_manager,
                checkpoints::instance().auto_select_sync_checkpoint()
            );
        }

        return true;
    }
    
    return false;
}

configuration & stack_impl::get_configuration()
{
    return m_configuration;
}

std::shared_ptr<address_manager> & stack_impl::get_address_manager()
{
    return m_address_manager;
}

std::shared_ptr<alert_manager> & stack_impl::get_alert_manager()
{
    return m_alert_manager;
}

std::shared_ptr<mining_manager> & stack_impl::get_mining_manager()
{
    return m_mining_manager;
}

std::shared_ptr<status_manager> & stack_impl::get_status_manager()
{
    return m_status_manager;
}

std::shared_ptr<tcp_acceptor> & stack_impl::get_tcp_acceptor()
{
    return m_tcp_acceptor;
}

std::shared_ptr<tcp_connection_manager> &
    stack_impl::get_tcp_connection_manager()
{
    return m_tcp_connection_manager;
}

std::shared_ptr<db_env> & stack_impl::get_db_env()
{
    return g_db_env;
}

std::shared_ptr<block_index> & stack_impl::get_block_index_genesis()
{
    return g_block_index_genesis;
}

std::set< std::pair<point_out, std::uint32_t> > & stack_impl::get_seen_stake()
{
    return g_seen_stake;
}

std::shared_ptr<block_index> & stack_impl::get_block_index_best()
{
    return g_block_index_best;
}

big_number & stack_impl::get_best_chain_trust()
{
    return g_best_chain_trust;
}

big_number & stack_impl::get_best_invalid_trust()
{
    return g_best_invalid_trust;
}

std::shared_ptr<block_index> stack_impl::insert_block_index(
    const sha256 & hash_block
    )
{
    std::shared_ptr<block_index> ret;
    
    if (hash_block == 0)
    {
        return ret;
    }
    
    auto it = globals::instance().block_indexes().find(hash_block);
    
    if (it != globals::instance().block_indexes().end())
    {
        ret = it->second;
    }
    else
    {
        ret = std::make_shared<block_index> ();
    
        ret->set_hash_block(hash_block);
        
        globals::instance().block_indexes()[hash_block] = ret;
    }
    
    return ret;
}

const std::int32_t & stack_impl::local_block_count() const
{
    return globals::instance().best_block_height();
}

const std::uint32_t stack_impl::peer_block_count() const
{
    return
        std::max(globals::instance().peer_block_counts().median(),
        checkpoints::instance().get_total_blocks_estimate())
    ;
}

double stack_impl::difficulty(const std::shared_ptr<block_index> & index) const
{
    std::shared_ptr<block_index> index_tmp;
    
    if (index)
    {
        index_tmp = index;
    }
    else
    {
        index_tmp = utility::get_last_block_index(
            stack_impl::get_block_index_best(), false
        );
    }

    if (index_tmp)
    {
        return utility::difficulty_from_bits(index_tmp->bits());
    }
    
    return 1.0;
}

std::uint64_t stack_impl::network_hash_per_second()
{
    if (g_block_index_best)
    {
        enum { target_spacing_work_minimum = 30 };
        
        std::int64_t target_spacing_work = target_spacing_work_minimum;
        
        auto interval = 72;
        
        auto index = get_block_index_genesis();
        
        auto index_previous = get_block_index_genesis();
        
        while (index)
        {
            if (index->is_proof_of_work())
            {
                std::int64_t actual_spacing_work =
                    index->time() - index_previous->time()
                ;
                
                target_spacing_work =
                    ((interval - 1) * target_spacing_work +
                    actual_spacing_work + actual_spacing_work) / (interval + 1)
                ;
                
                target_spacing_work = std::max(
                    target_spacing_work,
                    static_cast<std::int64_t> (target_spacing_work_minimum)
                );
                
                index_previous = index;
            }
            
            index = index->block_index_next();
        }
        
        double ghps = difficulty() * 4.294967296 / target_spacing_work;
        
        return ghps * 1000000000.0f;
    }

    return 0;
}

void stack_impl::on_error(const std::map<std::string, std::string> & pairs)
{
    stack_.on_error(pairs);
}

void stack_impl::on_status(const std::map<std::string, std::string> & pairs)
{
    stack_.on_status(pairs);
}

void stack_impl::on_alert(const std::map<std::string, std::string> & pairs)
{
    stack_.on_alert(pairs);
}

void stack_impl::on_status_block()
{
    /**
     * Allocate the status.
     */
    std::map<std::string, std::string> status;
    
    /**
     * Set the status type.
     */
    status["type"] = "block";
    
    /**
     * Set the status value.
     */
    status["value"] = "Downloading blocks";
    
    /**
     * The local block count.
     */
    status["block.count.local"] = std::to_string(local_block_count());
    
    /**
     * The peer block count.
     */
    status["block.count.peer"] = std::to_string(peer_block_count());

    /**
     * Calculate the percentage of the number of downloaded blocks.
     */
    double percentage =
        (static_cast<double> (local_block_count()) /
        static_cast<double> (peer_block_count()) * 100.0f)
    ;
    
    /**
     * The block download percent.
     */
    status["block.download.percent"] = std::to_string(percentage);

    /**
     * The block difficulty.
     */
    status["block.difficulty"] = std::to_string(difficulty());
    
    /**
     * Callback
     */
    m_status_manager->insert(status);
    
    /**
     * Starts the block status timer.
     */
    timer_status_block_.expires_from_now(std::chrono::seconds(1));
    timer_status_block_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_block();
                }
            }
        )
    );
}

void stack_impl::on_status_wallet()
{
    /**
     * Get the balance.
     */
    auto balance = globals::instance().wallet_main()->get_balance();
    
    /**
     * Get the unconfirmed balance.
     */
    auto unconfirmed_balance =
        globals::instance().wallet_main()->get_unconfirmed_balance()
    ;

    /**
     * Get the stake.
     */
    auto stake =
        globals::instance().wallet_main()->get_stake()
    ;
    
    /**
     * Get the immature.
     */
    auto immature_balance =
        globals::instance().wallet_main()->get_immature_balance()
    ;
    
    /**
     * Keep that last known balance.
     */
    static std::int64_t g_balance = 0;
    
    /**
     * If the balance has changed callback status.
     */
    if (balance != g_balance)
    {
        g_balance = balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.
         */
        status["wallet.balance.unconfirmed"] =
            std::to_string(unconfirmed_balance)
        ;
        
        /**
         * Set the wallet.stake.
         */
        status["wallet.stake"] = std::to_string(stake);
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Keep that last known unconfirmed balance.
     */
    static std::int64_t g_unconfirmed_balance = 0;
    
    /**
     * If the unconfirmed balance has changed callback status.
     */
    if (unconfirmed_balance != g_unconfirmed_balance)
    {
        g_unconfirmed_balance = unconfirmed_balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.
         */
        status["wallet.balance.unconfirmed"] =
            std::to_string(unconfirmed_balance)
        ;
        
        /**
         * Set the wallet.stake.
         */
        status["wallet.stake"] = std::to_string(stake);
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Keep that last known immature balance.
     */
    static std::int64_t g_immature_balance = 0;
    
    /**
     * If the immature balance has changed callback status.
     */
    if (immature_balance != g_immature_balance)
    {
        g_immature_balance = immature_balance;
        
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "wallet";

        /**
         * Set the wallet.balance.
         */
        status["wallet.balance"] = std::to_string(balance);
        
        /**
         * Set the wallet.balance.immature
         */
        status["wallet.balance.immature"] =
            std::to_string(immature_balance)
        ;
        
        /**
         * Set the wallet.stake.
         */
        status["wallet.stake"] = std::to_string(stake);
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Keep the last known block height.
     */
    static std::uint64_t g_best_block_height =
        globals::instance().best_block_height()
    ;
    
    /**
     * If the block has changed callback status.
     */
    if (g_best_block_height != globals::instance().best_block_height())
    {
        g_best_block_height = globals::instance().best_block_height();
        
        /**
         * Get the transactions.
         */
        auto transactions = globals::instance().wallet_main()->transactions();
        
        /**
         * Callback each transaction that has less than (confirmations - 1)
         * confirmations.
         */
        for (auto & i : transactions)
        {
            if (
                i.second.is_confirmed() &&
                i.second.get_depth_in_main_chain() <=
                (transaction::confirmations + 1)
                )
            {
                globals::instance().wallet_main()->on_transaction_updated(
                    i.first
                );
            }
        }
    }
    
    /**
     * Starts the block status timer.
     */
    timer_status_wallet_.expires_from_now(std::chrono::seconds(8));
    timer_status_wallet_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_wallet();
                }
            }
        )
    );
}

void stack_impl::on_status_blockchain()
{
    if (globals::instance().money_supply() > 0)
    {
        /**
         * Allocate the status.
         */
        std::map<std::string, std::string> status;
        
        /**
         * Set the type.
         */
        status["type"] = "database";
        
        /**
         * Set the blockchain.money.
         */
        status["blockchain.money_supply"] =
            std::to_string(globals::instance().money_supply() / 1000000)
        ;
        
        /**
         * Callback
         */
        m_status_manager->insert(status);
    }
    
    /**
     * Starts the blockchain status timer.
     */
    timer_status_blockchain_.expires_from_now(std::chrono::seconds(60));
    timer_status_blockchain_.async_wait(
        globals::instance().strand().wrap(
            [this](boost::system::error_code ec)
            {
                if (ec)
                {
                    // ...
                }
                else
                {
                    on_status_blockchain();
                }
            }
        )
    );
}

const boost::asio::ip::tcp::endpoint & stack_impl::local_endpoint() const
{
    return m_local_endpoint;
}

void stack_impl::create_directories()
{
    std::string path = filesystem::data_path();
    
    log_info(
        "Stack creating path = " << path << "."
    );

    auto result = filesystem::create_path(path);
    
    if (result == 0 || result == filesystem::error_already_exists)
    {
        log_none("Stack, path already exists.");
    }
    else
    {
        throw std::runtime_error(
            "failed to create path " + filesystem::data_path()
        );
    }
}

void stack_impl::load_block_index(
    const std::function<void (const bool & success)> & f
    )
{
    /**
     * Load the block index by posting it to the boost::asio::io_service.
     */
    globals::instance().io_service().post(globals::instance().strand().wrap(
        [this, f]()
    {
        /**
         * Load the block index.
         */
        db_tx tx_db("cr");
        
        if (tx_db.load_block_index(*this))
        {
            /**
             * Close the transaction database.
             */
            tx_db.close();

            /**
             * Initialize with the genesis block (if necessary).
             */
            if (globals::instance().block_indexes().size() == 0)
            {
                /**
                 * Genesis block creation.
                 */
                std::string timestamp_quote =
                    "December 22, 2014 - New York Times calls for Cheney, "
                    "Bush officials to be investigated and prosecuted for "
                    "torture."
                ;
                
                /**
                 * Allocate a new transaction.
                 */
                transaction tx_new;
                
                /**
                 * Set the transaction time to the time of the start of the
                 * chain.
                 */
                tx_new.set_time(constants::chain_start_time);
                
                /**
                 * Allocate one input.
                 */
                tx_new.transactions_in().resize(1);
                
                /**
                 * Allocate one output.
                 */
                tx_new.transactions_out().resize(1);

                /**
                 * Create the script signature.
                 */
                auto script_signature =
                    script() << 486604799 << big_number(9999) <<
                    std::vector<std::uint8_t>(
                    (const std::uint8_t *)timestamp_quote.c_str(),
                    (const std::uint8_t *)timestamp_quote.c_str() +
                    timestamp_quote.size()
                );

                /**
                 * Set the script signature on the input.
                 */
                tx_new.transactions_in()[0].set_script_signature(
                    script_signature
                );
                
                /**
                 * Set the output to empty.
                 */
                tx_new.transactions_out()[0].set_empty();

                /**
                 * Allocate the genesis block.
                 */
                block blk;
                
                /**
                 * Add the transactions.
                 */
                blk.transactions().push_back(tx_new);
                
                /**
                 * There is no previous block.
                 */
                blk.header().hash_previous_block = 0;
                
                /**
                 * Build the merkle tree.
                 */
                blk.header().hash_merkle_root = blk.build_merkle_tree();
                
                /**
                 * Set the header version.
                 */
                blk.header().version = 1;
                
                /**
                 * Set the header timestamp.
                 */
                blk.header().timestamp = constants::chain_start_time;
                
                /**
                 * Set the header bits.
                 */
                blk.header().bits =
                    constants::proof_of_work_limit.get_compact()
                ;
                
                assert(blk.header().bits == 504365055);
                
                /**
                 * Set the header nonce.
                 */
                blk.header().nonce = constants::chain_start_time - 10000;

                /**
                 * Print the block.
                 */
                blk.print();

                log_debug(
                    "Block hash = " << blk.get_hash().to_string() << "."
                );
                log_debug(
                    "Block header hash merkle root = " <<
                    blk.header().hash_merkle_root.to_string() << "."
                );
                log_debug(
                    "Block header time = " << blk.header().timestamp << "."
                );
                log_debug(
                    "Block header nonce = " << blk.header().nonce << "."
                );

                /**
                 * Check the merkle root hash.
                 */
                assert(
                    blk.header().hash_merkle_root ==
                    sha256("e6dc22fdcfcbffccb14cacfab0f0af67721d38f2929d8344cb"
                    "1635ac400e2e68")
                    
                );
                
                /**
                 * Check the genesis block hash.
                 */
                assert(
                    blk.get_hash() ==
                    (constants::test_net ? block::get_hash_genesis_test_net() :
                    block::get_hash_genesis())
                );

                /**
                 * Start new block file.
                 */
                std::uint32_t file_number;
                std::uint32_t block_position;
                
                if (blk.write_to_disk(file_number, block_position) == false)
                {
                    log_error(
                        "Load block index failed, writing genesis block to "
                        "disk failed."
                    );
                    
                    if (f)
                    {
                        f(false);
                    }
                }

                if (
                    blk.add_to_block_index(file_number, block_position) == false
                    )
                {
                    log_error(
                        "Load block index failed, genesis block not accepted"
                    );
                    
                    if (f)
                    {
                        f(false);
                    }
                }

                /**
                 * Initialize the synchronized checkpoint (ppcoin).
                 */
                if (
                    checkpoints::instance().write_sync_checkpoint(
                    (constants::test_net ? block::get_hash_genesis_test_net() :
                    block::get_hash_genesis())) == false
                    )
                {
                    log_error(
                        "Load block index failed, write sync checkpoint failed."
                    );
                    
                    if (f)
                    {
                        f(false);
                    }
                }
            }
            
            /**
             * If checkpoint master key changed must reset sync-checkpoint
             * (ppcoin).
             */
            db_tx tx_db;
            
            std::string public_key;
            
            if (
                tx_db.read_checkpoint_public_key(public_key) == false ||
                public_key != checkpoint_sync::master_public_key()
                )
            {
                /**
                 * Write the checkpoint master key to the database.
                 */
                tx_db.txn_begin();
                
                if (
                    tx_db.write_checkpoint_public_key(
                    checkpoint_sync::master_public_key()) == false
                    )
                {
                    log_error(
                        "Load block index failed, write new checkpoint "
                        "master key to database failed."
                    );
                    
                    if (f)
                    {
                        f(false);
                        
                         return;
                    }
                }
                
                if (tx_db.txn_commit() == false)
                {
                    log_error(
                        "Load block index failed to commit new checkpoint "
                        "master key to database."
                    );
                
                    if (f)
                    {
                        f(false);
                        
                         return;
                    }
                }

                if (
                    constants::test_net == false &&
                    checkpoints::instance().reset_sync_checkpoint() == false
                    )
                {
                    log_error(
                        "Load block index failed to reset sync-checkpoint."
                    );
                 
                    if (f)
                    {
                        f(false);
                        
                        return;
                    }
                }
            }
            
            /**
             * Close the transaction database.
             */
            tx_db.close();

            if (f)
            {
                f(true);
            }

        }
        else
        {
            if (f)
            {
                f(false);
            }
        }
    }));
}

void stack_impl::load_wallet(
    const std::function<void (const bool & first_run,
    const db_wallet::error_t & err)> & f
    )
{
    bool first_run = true;

    globals::instance().set_wallet_main(std::make_shared<wallet> (*this));
    
    db_wallet::error_t ret =
        globals::instance().wallet_main()->load_wallet(first_run)
    ;
    
    if (f)
    {
        f(first_run, ret);
    }
}

void stack_impl::lock_file_or_exit()
{
#if (! defined _MSC_VER && ! defined __IPHONE_OS_VERSION_MAX_ALLOWED)
    static file f;
    
    if (
        f.open((filesystem::data_path() + ".lock").c_str(), "a") == false
        )
    {
        printf(
            "Unable to open lock file %s\n",
            (filesystem::data_path() + ".lock").c_str()
        );

        exit(0);
    }
    else
    {
        auto result = flock(fileno(f.get_FILE()), LOCK_EX | LOCK_NB);
        
        if (result == 0)
        {
            std::string pid = std::to_string(getpid());
        
            f.write(pid.data(), pid.size());
            
            f.fflush();
        }
        else
        {
            printf(
                "Failed to obtain lock on file %s\n",
                (filesystem::data_path() + ".lock").c_str()
            );
            
            exit(0);
        }
    }
#endif // _MSC_VER
}

void stack_impl::loop()
{
    while (
        globals::instance().state() == globals::state_starting ||
        globals::instance().state() == globals::state_started
        )
    {
        try
        {
            globals::instance().io_service().run();
            
            if (work_ == 0)
            {
                break;
            }
        }
        catch (const boost::system::system_error & e)
        {
            // ...
        }
    }
}

void stack_impl::do_check_peers(const std::uint32_t & interval)
{
    log_debug("Stack is checking peers.");
    
    url_get("http://vanillacoin.net/p/",
        [this]
        (const std::map<std::string, std::string> & headers,
        const std::string & body
        )
    {
        if (headers.size() > 0 && body.size() > 0)
        {
            std::stringstream ss;

            ss << body;

            boost::property_tree::ptree pt;
            
            std::map<std::string, std::string> result;
            
            try
            {
                read_json(ss, pt);

                auto & pos = pt.get_child("peers");
                
                std::for_each(
                    std::begin(pos), std::end(pos),
                    [this](
                    boost::property_tree::ptree::value_type & pair
                    )
                {
                    std::vector<std::string> parts;
                    
                    std::string endpoint = pair.second.get<std::string> ("");
                    
                    boost::split(
                        parts, endpoint, boost::is_any_of(":")
                    );
                    
                    auto ip = parts[0];
                    
                    auto port = parts[1];

                    log_debug(
                        "Stack got peer endpoint = " << ip << ":" << port << "."
                    );
                    
                    /**
                     * Create the network address.
                     */
                    protocol::network_address_t addr =
                        protocol::network_address_t::from_endpoint(
                        boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address::from_string(ip.c_str()),
                        std::stoi(port))
                    );
                    
                    /**
                     * Add to the address manager.
                     */
                    if (m_address_manager->add(
                        addr, protocol::network_address_t::from_endpoint(
                        boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address::from_string("127.0.0.1"), 0))
                    ))
                    {
                        log_debug(
                            "Stack added bootstrap peer " << ip << ":" <<
                            port << " to the address manager."
                        );
                    }
                });
            }
            catch (std::exception & e)
            {
                // ...
            }
        }
        else
        {
            // ...
        }
    });
}
