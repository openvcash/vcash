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

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <database/ecdhe.hpp>

EC_DHE * EC_DHE_new(int EC_NID)
{
    EC_DHE * ec_dhe = (EC_DHE *)calloc(1, sizeof(*ec_dhe));
    
    ec_dhe->EC_NID = EC_NID;
    
    return ec_dhe;
}

void EC_DHE_free(EC_DHE * ec_dhe)
{
    if (ec_dhe->ctx_params != 0)
    {
        EVP_PKEY_CTX_free(ec_dhe->ctx_params);
    }
    
    if (ec_dhe->ctx_keygen != 0)
    {
        EVP_PKEY_CTX_free(ec_dhe->ctx_keygen);
    }
    
    if (ec_dhe->ctx_derive != 0)
    {
        EVP_PKEY_CTX_free(ec_dhe->ctx_derive);
    }
    
    if (ec_dhe->privkey != 0)
    {
        EVP_PKEY_free(ec_dhe->privkey);
    }
    
    if (ec_dhe->peerkey != 0)
    {
        EVP_PKEY_free(ec_dhe->peerkey);
    }
    
    if (ec_dhe->params != 0)
    {
        EVP_PKEY_free(ec_dhe->params);
    }
    
    if (ec_dhe->publicKey != 0)
    {
        ec_dhe->publicKey[0] = '\0', free(ec_dhe->publicKey);
    }
    
    if (ec_dhe->sharedSecret != 0)
    {
        ec_dhe->sharedSecret[0] = '\0', free(ec_dhe->sharedSecret);
    }
    
    free(ec_dhe);
}

char * EC_DHE_getPublicKey(EC_DHE * ec_dhe, int * publicKeyLength)
{
	if (0 == (ec_dhe->ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, 0)))
    {
        EC_DHE_handleErrors("Could not create EC_DHE contexts.");
        
        return 0;
    }
    
	if (1 != EVP_PKEY_paramgen_init(ec_dhe->ctx_params))
    {
        EC_DHE_handleErrors("Could not intialize parameter generation.");
        
        return 0;
    }
    
	if (
        1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
        ec_dhe->ctx_params, ec_dhe->EC_NID)
        )
    {
        EC_DHE_handleErrors("Likely unknown elliptical curve ID specified.");
        
        return 0;
    }
    
	if (!EVP_PKEY_paramgen(ec_dhe->ctx_params, &ec_dhe->params))
    {
        EC_DHE_handleErrors("Could not create parameter object parameters.");
        return 0;
    }
    
	if (0 == (ec_dhe->ctx_keygen = EVP_PKEY_CTX_new(ec_dhe->params, 0)))
    {
        EC_DHE_handleErrors(
            "Could not create the context for the key generation"
        );
        
        return 0;
    }
    
	
	if (1 != EVP_PKEY_keygen_init(ec_dhe->ctx_keygen))
    {
        EC_DHE_handleErrors("Could not init context for key generation.");
        
        return 0;
    }
    
	if (1 != EVP_PKEY_keygen(ec_dhe->ctx_keygen, &ec_dhe->privkey))
    {
        EC_DHE_handleErrors("Could not generate DHE keys in final step");
        
        return 0;
    }

    BIO * bp = BIO_new(BIO_s_mem());
    
    if (1 !=  PEM_write_bio_PUBKEY(bp, ec_dhe->privkey))
    {
        EC_DHE_handleErrors("Could not write public key to memory");
        
        return 0;
    }
    
    BUF_MEM * bptr;

    BIO_get_mem_ptr(bp, &bptr);

    ec_dhe->publicKey = (char *)calloc(1, bptr->length);
    memcpy(ec_dhe->publicKey, bptr->data, bptr->length);
    
    (*publicKeyLength) = bptr->length;
    
    BIO_free(bp);
    
    return ec_dhe->publicKey;
}

unsigned char * EC_DHE_deriveSecretKey(
    EC_DHE * ec_dhe, const char *peerPublicKey, int peerPublicKeyLength,
    int * sharedSecretLength
    )
{
    BUF_MEM * bptr = BUF_MEM_new();
    
    BUF_MEM_grow(bptr, peerPublicKeyLength);

    BIO * bp = BIO_new(BIO_s_mem());
    
    memcpy(bptr->data, peerPublicKey, peerPublicKeyLength);
    
    BIO_set_mem_buf(bp, bptr, BIO_NOCLOSE);
    
    ec_dhe->peerkey = PEM_read_bio_PUBKEY(bp, 0, 0, 0);
    
    BIO_free(bp);
    BUF_MEM_free(bptr);
    
    size_t secret_len = 0;
    
	if (0 == (ec_dhe->ctx_derive = EVP_PKEY_CTX_new(ec_dhe->privkey, 0)))
    {
        EC_DHE_handleErrors(
            "Could not create the context for the shared secret derivation"
        );
        
        return 0;
    }
    
	if (1 != EVP_PKEY_derive_init(ec_dhe->ctx_derive))
    {
        EC_DHE_handleErrors("Could not init derivation context");
        
        return 0;
    }
    
	if (1 != EVP_PKEY_derive_set_peer(ec_dhe->ctx_derive, ec_dhe->peerkey))
    {
        EC_DHE_handleErrors(
            "Could not set the peer key into derivation context"
        );
        
        return 0;
    }
    
	if (1 != EVP_PKEY_derive(ec_dhe->ctx_derive, 0, &secret_len))
    {
        EC_DHE_handleErrors(
            "Could not determine buffer length for shared secret"
        );
        
        return 0;
    }
    
	if (
        0 == (ec_dhe->sharedSecret =
        (unsigned char *)OPENSSL_malloc(secret_len))
        )
    {
        EC_DHE_handleErrors("Could not create the sharedSecret buffer");
        
        return 0;
    }
    
	if (
        1 != (EVP_PKEY_derive(ec_dhe->ctx_derive, ec_dhe->sharedSecret,
        &secret_len))
        )
    {
        EC_DHE_handleErrors("Could not dervive the shared secret");
        
        return 0;
    }
    
    (*sharedSecretLength) = (int)secret_len;

	return ec_dhe->sharedSecret;
}

static void EC_DHE_handleErrors(const char * msg)
{
    if (msg != 0)
    {
        printf("%s", msg);
    }
}
