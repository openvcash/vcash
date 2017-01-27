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

#include <coin/alert_manager.hpp>
#include <coin/globals.hpp>
#include <coin/stack_impl.hpp>

using namespace coin;

alert_manager::alert_manager(
    boost::asio::io_service & ios, stack_impl & owner
    )
    : io_service_(ios)
    , strand_(globals::instance().strand())
    , stack_impl_(owner)
{
    // ...
}

bool alert_manager::process(const alert & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    if (val.check_signature() && val.is_in_effect())
    {
        /**
         * If the id is equal to int max then the alert private key has been
         * compromised.
         */
        auto max_int = std::numeric_limits<std::int32_t>::max();
        
        if (val.id() == max_int)
        {
            if (
                (val.expiration() == max_int && val.cancel() == (max_int - 1) &&
                val.minimum_version() == 0 &&
                val.maximum_version() == max_int &&
                val.sub_versions().size() == 0 && val.priority() == max_int &&
                val.status() == "private_key_compromised") == false
                )
            {
                return false;
            }
        }

        /**
         * Cancel any previous alerts.
         */
        for (auto it = m_alerts.begin(); it != m_alerts.end();)
        {
            const auto & alert = it->second;
            
            if (val.cancels(alert))
            {
                log_debug(
                    "Alert manager is canceling alert " << alert.id() << "."
                );
                
                /**
                 * Allocate the pairs.
                 */
                std::map<std::string, std::string> pairs;
                
                /**
                 * Set the pairs type.
                 */
                pairs["type"] = "alert";
                
                /**
                 * Set the pairs value.
                 */
                pairs["value"] = "deleted";

                /**
                 * Set the pairs hash.
                 */
                pairs["alert.hash"] = alert.get_hash().to_string();
            
                /**
                 * Callback
                 */
                stack_impl_.on_alert(pairs);
                
                m_alerts.erase(it++);
            }
            else if (alert.is_in_effect() == false)
            {
                log_debug(
                    "Alert manager is expiring alert " << alert.id() << "."
                );
                
                /**
                 * Allocate the pairs.
                 */
                std::map<std::string, std::string> pairs;
                
                /**
                 * Set the pairs type.
                 */
                pairs["type"] = "alert";
                
                /**
                 * Set the pairs value.
                 */
                pairs["value"] = "deleted";

                /**
                 * Set the pairs hash.
                 */
                pairs["alert.hash"] = alert.get_hash().to_string();
            
                /**
                 * Callback
                 */
                stack_impl_.on_alert(pairs);
                
                m_alerts.erase(it++);
            }
            else
            {
                it++;
            }
        }

        /**
         * Check if this alert has been cancelled.
         */
        for (auto & i : m_alerts)
        {
            const auto & alert = i.second;
            
            if (alert.cancels(val))
            {
                log_debug(
                    "Alert manager, alert already cancelled by " <<
                    alert.id() << "."
                );
                
                return false;
            }
        }

        /**
         * Add to the alerts.
         */
        m_alerts.insert(std::make_pair(val.get_hash(), val));
        
        /**
         * Callback if necessary.
         */
        if (val.applies_to_me())
        {
            if (val.status().size() > 0 && val.comment().size() > 0)
            {
                /**
                 * Allocate the pairs.
                 */
                std::map<std::string, std::string> pairs;
            
                /**
                 * Set the pairs type.
                 */
                pairs["type"] = "alert";
                
                /**
                 * Set the pairs value.
                 */
                pairs["value"] = "new";

                /**
                 * Set the pairs hash.
                 */
                pairs["alert.hash"] = val.get_hash().to_string();
                
                /**
                 * Set the pairs comment.
                 */
                pairs["alert.comment"] = val.comment();
                
                /**
                 * Set the pairs status.
                 */
                pairs["alert.status"] = val.status();
                
                /**
                 * Set the pairs reserved.
                 */
                pairs["alert.reserved"] = val.comment();
            
                /**
                 * Callback
                 */
                stack_impl_.on_alert(pairs);
            }
        }

        log_debug(
            "Alert manager, accepted alert " << val.id() <<
            ", applies to me = " << val.applies_to_me() << "."
        );
        
        return true;
    }

    return false;
}

alert alert_manager::get(const sha256 & val)
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    alert ret;
    
    auto it = m_alerts.find(val);

    if (it != m_alerts.end())
    {
        ret = it->second;
    }
    
    return ret;
}

const std::map<sha256, alert> & alert_manager::alerts() const
{
    std::lock_guard<std::mutex> l1(mutex_);
    
    return m_alerts;
}
