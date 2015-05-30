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

#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

typedef struct EC_DHE_st
{
    int EC_NID;
    
    EVP_PKEY_CTX * ctx_params;
    EVP_PKEY_CTX * ctx_keygen;
    EVP_PKEY_CTX * ctx_derive;
	EVP_PKEY * privkey;
    EVP_PKEY * peerkey;
    EVP_PKEY * params;

    char * publicKey;
	unsigned char * sharedSecret;
    
} EC_DHE;

/**
 * EC_DHE_new
 * @param EC_Curve_NID
 */
EC_DHE * EC_DHE_new(int EC_Curve_NID);

/**
 * EC_DHE_free
 * @param EC_DHE
 */
void EC_DHE_free(EC_DHE * ecdhe);

/**
 * EC_DHE_getPublicKey
 * @param ecdhe The EC_DHE.
 * @param publicKeyLength The public key length.
 */
char * EC_DHE_getPublicKey(EC_DHE * ecdhe, int * publicKeyLength);

/**
 * EC_DHE_deriveSecretKey
 * @param ecdhe The EC_DHE.
 * @param peerPublicKey The peer public key.
 * @param peerPublicKeyLength The peer public key length.
 * @param sharedSecretLength The shared secret length.
 * @note Always hash the return value to produce a key.
 */
unsigned char * EC_DHE_deriveSecretKey(
    EC_DHE * ecdhe, const char * peerPublicKey, int peerPublicKeyLength,
    int * sharedSecretLength
);

/**
 * EC_DHE_handleErrors
 * @param msg The error message.
 */
static void EC_DHE_handleErrors(const char * msg);

#ifdef __cplusplus
}
#endif

#endif // DATABASE_ECDHE_HPP
