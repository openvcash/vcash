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

#ifndef COIN_ALERT_UNSIGNED_HPP
#define COIN_ALERT_UNSIGNED_HPP

#include <cstdint>
#include <set>
#include <string>

#include <coin/data_buffer.hpp>

namespace coin {

    /**
     * Implements an unsigned alert.
     */
    class alert_unsigned : public data_buffer
    {
        public:
        
            /**
             * Constructor
             */
            alert_unsigned();
        
            /**
             * Encodes
             */
            void encode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            void encode(data_buffer & buffer);
        
            /**
             * Decodes
             */
            bool decode();
        
            /**
             * Encodes
             * @param buffer The data_buffer.
             */
            bool decode(data_buffer & buffer);
        
            /**
             * Set's null.
             */
            void set_null();
        
            /**
             * Sets the version.
             * @param val The value.
             */
            void set_version(const std::int32_t & val);
        
            /**
             * The version.
             */
            const std::int32_t & version() const;
        
            /**
             * Sets the relay until.
             * @param val The value.
             */
            void set_relay_until(const std::int32_t & val);
        
            /**
             * The time to stop relaying.
             */
            const std::int64_t & relay_until() const;
        
            /**
             * Sets the expiration.
             * @param val The value.
             */
            void set_expiration(const std::int32_t & val);
        
            /**
             * The expiration.
             */
            const std::int64_t & expiration() const;
        
            /**
             * The id.
             */
            const std::int32_t & id() const;
        
            /**
             * Sets cancel.
             * @param val The value.
             */
            void set_cancel(const std::int32_t & val);
        
            /**
             * The cancel.
             */
            const std::int32_t & cancel() const;
        
            /**
             * The cancels.
             */
            const std::set<std::int32_t> & cancels() const;

            /**
             * Sets the minimum version.
             * @param val The value.
             */
            void set_minimum_version(const std::int32_t & val);
        
            /**
             * The lowest version (inclusive).
             */
            const std::int32_t & minimum_version() const;
        
           /**
             * Sets the maximum version.
             * @param val The value.
             */
            void set_maximum_version(const std::int32_t & val);
        
            /**
             * The highest version (inclusive).
             */
            const std::int32_t & maximum_version() const;
        
            /**
             * The sub versions.
             */
            const std::set<std::string> & sub_versions() const;
        
            /**
             * The priority.
             */
            const std::int32_t & priority() const;

            /**
             * Sets the comment.
             * @param val The value.
             */
            void set_comment(const std::string & val);
        
            /**
             * The comment.
             */
            const std::string & comment() const;
        
            /**
             * Sets the status.
             * @param val The value.
             */
            void set_status(const std::string & val);
        
            /**
             * The status.
             */
            const std::string & status() const;
        
            /**
             * The reserved.
             */
            const std::string & reserved() const;
        
            /**
             * The string representation.
             */
            std::string to_string() const;
        
        private:
        
            friend class alert;
        
            /**
             * The version.
             */
            enum { current_version = 1 };
        
            /**
             * The version.
             */
            std::int32_t m_version;
        
            /**
             * The time to stop relaying.
             */
            std::int64_t m_relay_until;
        
            /**
             * The expiration.
             */
            std::int64_t m_expiration;
        
            /**
             * The id.
             */
            std::int32_t m_id;
        
            /**
             * The cancel.
             */
            std::int32_t m_cancel;
        
            /**
             * The cancels.
             */
            std::set<std::int32_t> m_cancels;

            /**
             * The lowest version (inclusive).
             */
            std::int32_t m_minimum_version;
        
            /**
             * The highest version (inclusive).
             */
            std::int32_t m_maximum_version;
        
            /**
             * The sub versions.
             */
            std::set<std::string> m_sub_versions;
        
            /**
             * The priority.
             */
            std::int32_t m_priority;

            /**
             * The comment.
             */
            std::string m_comment;
        
            /**
             * The status.
             */
            std::string m_status;
        
            /**
             * The reserved.
             */
            std::string m_reserved;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_ALERT_UNSIGNED_HPP
