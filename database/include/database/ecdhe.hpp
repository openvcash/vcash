/*
 * Copyright (c) 2008-2015 John Connor (BM-NC49AxAjcqVcF5jNPu85Rb8MJ2d9JqZt)
 *
 * This is free software: you can redistribute it and/or modify
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

#ifndef DATABASE_ECDHE_HPP
#define DATABASE_ECDHE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include <database/ecdhe.h>

namespace database {

    class ecdhe
    {
        public:
        
            /**
             * Constructor
             */
            ecdhe()
                : m_ecdhe(EC_DHE_new(NID_secp256k1))
            {
                // ...
            }
        
            /**
             * Destructor
             */
            ~ecdhe()
            {
                if (m_ecdhe)
                {
                    EC_DHE_free(m_ecdhe), m_ecdhe = 0;
                }
            }
        
            /**
             * Returns the public key generating it needed.
             */
            const std::string & public_key()
            {
                if (m_public_key.size() == 0)
                {
                    auto len = 0;
                    
                    auto buf = EC_DHE_getPublicKey(m_ecdhe, &len);
                    
                    m_public_key = std::string(buf, len);
                }
                
                return m_public_key;
            }
        
            /**
             * Derives a secret key from the remote peer's public key.
             * @param peer_public_key The remote peer's public key.
             */
            std::vector<std::uint8_t> derive_secret_key(
                const std::string & peer_public_key
                )
            {
                std::vector<std::uint8_t> ret;
                
                auto len = 0;
                
                auto buf = EC_DHE_deriveSecretKey(
                    m_ecdhe, peer_public_key.c_str(),
                    peer_public_key.size(), &len
                );
                
                ret.insert(ret.begin(), buf, buf + len);
                
                return ret;
            }

            /**
             * Gets the EC_DHE.
             */
            EC_DHE * get_EC_DHE()
            {
                return m_ecdhe;
            }
        
        private:
        
            /**
             * The EC_DHE.
             */
            EC_DHE * m_ecdhe;
        
            /**
             * The public key.
             */
            std::string m_public_key;
        
        protected:
        
            // ...
    };
}

#endif // DATABASE_ECDHE_HPP
