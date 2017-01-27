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

#ifndef COIN_HD_KEYCHAIN_HPP
#define COIN_HD_KEYCHAIN_HPP

#include <cstdint>
#include <vector>

#include <coin/crypto.hpp>
#include <coin/utility.hpp>

namespace coin {

    /**
     * Implements a BIP-0032 keychain.
     */
    class hd_keychain
    {
        public:
        
            /**
             * Implements a seed.
             */
            class seed
            {
                public:
                
                    /**
                     * Constructor
                     * @param seed The see.
                     */
                    explicit seed(
                        const std::vector<std::uint8_t> & seed_value,
                        const std::vector<std::uint8_t> & seed_key =
                        utility::from_hex("426974636f696e2073656564")
                        )
                    {
                        auto digest = crypto::hmac_sha512(
                            seed_key, seed_value
                        );
                        
                        m_master_key.assign(
                            digest.begin(), digest.begin() + 32
                        );
                        
                        m_master_chain_code.assign(
                            digest.begin() + 32, digest.end()
                        );
                    }
                
                    /**
                     * The master key.
                     */
                    const std::vector<std::uint8_t> & get_master_key() const
                    {
                        return m_master_key;
                    }
                
                    /**
                     * The master chain code.
                     */
                    const std::vector<std::uint8_t> &
                        get_master_chain_code() const
                    {
                        return m_master_chain_code;
                    }
                
                private:
                
                    /**
                     * The master key.
                     */
                    std::vector<std::uint8_t> m_master_key;
                
                    /**
                     * The master chain code.
                     */
                    std::vector<std::uint8_t> m_master_chain_code;
                
                protected:
                
                    // ...
            };
        
            /**
             * The private version.
             */
            enum { private_version = 0x0488ade4 };
        
            /**
             * The public version.
             */
            enum { public_version  = 0x0488b21e };
        
            /**
             * Constructor
             */
            hd_keychain();
        
            /**
             * Constructor
             * @param key The key.
             * @param chain_code The chain code.
             * @param child_num The number of children.
             * @param parent_fingerprint The parent fingerprint.
             * @param depth The depth.
             */
            hd_keychain(
                const std::vector<std::uint8_t> & key,
                const std::vector<std::uint8_t> & chain_code,
                const std::uint32_t & child_num = 0,
                const std::uint32_t & parent_fingerprint = 0,
                const std::uint32_t & depth = 0
            );
        
            /**
             * Constructor
             * @param extkey The extended key,
             */
            hd_keychain(const std::vector<std::uint8_t> & extkey);

            /**
             * Constructor
             * @param other The hd_keychain.
             */
            hd_keychain(const hd_keychain & other);
        
            /**
             * operator =
             */
            hd_keychain & operator = (const hd_keychain & rhs);
        
            /**
             * operator ==
             */
            bool operator == (const hd_keychain & rhs) const;
        
            /**
             * operator !=
             */
            bool operator != (const hd_keychain & rhs) const;
        
            /**
             * Set's if it is valid.
             * @param val bool.
             */
            void set_is_valid(const bool & val);
        
            /**
             * If true it is valid.
             */
            const bool is_valid() const;
        
            /**
             * If true it is private.
             */
            const bool is_private() const;
        
            /**
             * The extended key.
             */
            const std::vector<std::uint8_t> extended_key() const;

            /**
             * Sets the version.
             * @param val The value.
             */
            void set_version(const std::uint32_t & val);
        
            /**
             * The version.
             */
            const std::uint32_t & version() const;
        
            /**
             * Sets the depth.
             * @param val The value.
             */
            void set_depth(const std::uint8_t & val);
        
            /**
             * The depth.
             */
            const std::uint8_t & depth() const;
        
            /**
             * Sets the parent fingerprint.
             * @param val The value.
             */
            void set_parent_fingerprint(const std::uint32_t & val);
        
            /**
             * The parent fingerprint.
             */
            const std::uint32_t & parent_fingerprint() const;
        
            /**
             * Sets the child count.
             * @param val The value.
             */
            void set_child_count(const std::uint32_t & val);
        
            /**
             * The child count.
             */
            const std::uint32_t & child_count() const;
        
            /**
             * Set's the chain code.
             * @param val The std::vector<std::uint8_t>.
             */
            void set_chain_code(const std::vector<std::uint8_t> & val);
        
            /**
             * The chain code.
             */
            const std::vector<std::uint8_t> & chain_code() const;
        
            /**
             * Set's the key.
             * @param val The std::vector<std::uint8_t>.
             */
            void set_key(const std::vector<std::uint8_t> & val);
        
            /**
             * The key.
             */
            const std::vector<std::uint8_t> & key() const;

            /**
             * The private key.
             */
            std::vector<std::uint8_t> privkey() const;

            /**
             * Set's the public key.
             * @param val The std::vector<std::uint8_t>.
             */
            void set_pubkey(const std::vector<std::uint8_t> & val);
        
            /**
             * The public key.
             */
            const std::vector<std::uint8_t> & pubkey() const;
        
            /**
             * Returns the uncompressed public key.
             */
            std::vector<std::uint8_t> uncompressed_pubkey() const;
        
            /**
             * The hash.
             */
            std::vector<std::uint8_t> get_hash() const;
        
            /**
             * The fingerprint (first 32 bits of the digest.
             */
            std::uint32_t fingerprint() const;
        
            /**
             * The full hash.
             */
            std::vector<std::uint8_t> full_hash() const;

            /**
             * Gets the public hd_keychain.
             */
            hd_keychain get_public() const;
        
            /**
             * Gets the child hd_keychain at the given index.
             * @param index The index.
             */
            hd_keychain get_child(const std::uint32_t & index) const;
        
            /**
             * Gets the child hd_keychain at the given path.
             * @param path The path.
             */
            hd_keychain get_child(const std::string & path) const;

            /**
             * Gets a child node.
             * @param index The index.
             * @param private_derivation If true private key derivation is used.
             */
            hd_keychain get_child_node(
                const std::uint32_t & index,
                const bool & private_derivation = false
            ) const;

            /**
             * Get sthe private signing key.
             * @param index The index.
             */
            std::vector<std::uint8_t> get_private_signing_key(
                const std::uint32_t & index
            ) const;

            /**
             * Gets the public signing key.
             * @param index The index.
             * @param compressed If true it is compressed.
             */
            std::vector<std::uint8_t> get_public_signing_key(
                const std::uint32_t & index, const bool & compressed = true
            ) const;

            /**
             * Sets the private and public versions to use.
             * @param private_version The private version.
             * @param public_version The public version.
             */
            static void set_versions(
                const std::uint32_t & private_version,
                const std::uint32_t & public_version
            );

            /**
             * The string representation.
             */
            std::string to_string() const;
        
            /**
             * Runs test case.
             */
            static int run_test();
        
        private:
        
            /**
             * Updates the public key.
             */
            void update_public_key();
        
            /**
             * The private version.
             */
            static std::uint32_t g_private_version;
        
            /**
             * The public version.
             */
            static std::uint32_t g_public_version;

            /**
             * The version.
             */
            std::uint32_t m_version;
        
            /**
             * The depth.
             */
            std::uint8_t m_depth;
        
            /**
             * The parent fingerprint.
             */
            std::uint32_t m_parent_fingerprint;
        
            /**
             * The child count.
             */
            std::uint32_t m_child_count;
        
            /**
             * The chain code.
             */
            std::vector<std::uint8_t> m_chain_code;
        
            /**
             * The key.
             */
            std::vector<std::uint8_t> m_key;

            /**
             * The public key.
             */
            std::vector<std::uint8_t> m_pubkey;

            /**
             * If true it is valid.
             */
            bool m_is_valid;
        
        protected:
        
            // ...
    };
    
} // namespace coin

#endif // COIN_HD_KEYCHAIN_HPP
