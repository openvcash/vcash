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

#ifndef COIN_ALERT_HPP
#define COIN_ALERT_HPP

#include <cstdint>
#include <vector>

#include <coin/alert_unsigned.hpp>
#include <coin/sha256.hpp>

namespace coin {

    /** 
     * Implements an alert.
     */
    class alert : public alert_unsigned
    {
        public:
        
            alert()
                : alert_unsigned()
            {
                // ...
            }
        
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
             * Verify the signature of the message.
             */
            bool check_signature() const;
        
            /**
             * Set's null.
             */
            void set_null();
        
            /**
             * If true it is null.
             */
            bool is_null() const;
        
            /**
             * The hash.
             */
            sha256 get_hash() const;
        
            /**
             * If true it is still in effect.
             */
            bool is_in_effect() const;
        
            /**
             * If true the given alert cancels this one.
             * @param val The alert.
             */
            bool cancels(const alert & val) const;
        
            /**
             * If true it applies to the given version.
             * @param version The version.
             * @param sub_version The sub version.
             */
            bool applies_to(
                const std::int32_t & version, const std::string & sub_version
            ) const;
        
            /**
             * If true it applies to our version.
             */
            bool applies_to_me() const;
        
            /**
             * Sets the message.
             * @param val The value.
             */
            void set_message(const std::vector<std::uint8_t> & val);
        
            /**
             * The message.
             */
            const std::vector<std::uint8_t> & message() const;
        
            /**
             * Sets the signature.
             * @param val The value.
             */
            void set_signature(const std::vector<std::uint8_t> & val);
        
            /**
             * The signature.
             */
            std::vector<std::uint8_t> & signature();
        
            /**
             * The signature.
             */
            const std::vector<std::uint8_t> & signature() const;
        
        private:
        
            /**
             * The message.
             */
            std::vector<std::uint8_t> m_message;
        
            /**
             * The signature.
             */
            std::vector<std::uint8_t> m_signature;
        
        protected:
        
            // ...
    };

} // namespace coin

#endif // COIN_ALERT_HPP
