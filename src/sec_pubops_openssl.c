/**
 * Copyright 2014 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sec_pubops.h"
#include "sec_security_common.h"
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

static Sec_Result _SecUtils_BigNumToBuffer(const BIGNUM *bignum, SEC_BYTE *buffer, SEC_SIZE buffer_len)
{
    SEC_SIZE num_bytes;

    memset(buffer, 0, buffer_len);
    num_bytes = BN_num_bytes(bignum);

    if (num_bytes > buffer_len) {
        SEC_LOG_ERROR("buffer not large enough.  needed: %d, actual: %d", num_bytes, buffer_len);
        return SEC_RESULT_FAILURE;
    }

    BN_bn2bin(bignum, buffer + buffer_len - num_bytes);

    return SEC_RESULT_SUCCESS;
}

static RSA *_SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey *binary)
{
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
#else
    RSA_set0_key(rsa,
        BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL),
        BN_bin2bn(binary->e, 4, NULL),
        NULL);
#endif

    return rsa;
}

static EC_KEY *_SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    if (   binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC
        && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp;

    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL))
        goto done;

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                                        BN_bin2bn(binary->x, Sec_BEBytesToUint32(binary->key_len), xp),
                                        BN_bin2bn(binary->y, Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

done:
    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
}

static int _SecUtils_ElGamal_Encrypt_Rand(EC_KEY *ec_key,
                                  SEC_BYTE* input, SEC_SIZE inputSize,
                                  SEC_BYTE* output, SEC_SIZE outputSize,
                                  BIGNUM *sender_rand)
{
    int res = -1;
    BIGNUM *inputAsBN = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *P = NULL;
    const EC_POINT *PK_recipient = NULL;
    EC_POINT *shared_secret = NULL;
    EC_POINT *key_2_wrap_point = NULL;
    EC_POINT *sender_share = NULL;
    EC_POINT *wrapped_key = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;

    if (inputSize != SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Input size needed != One BIGNUM");
        goto done;
    }

    if (outputSize < 4 * SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Output size needed < Four BIGNUMs");
        goto done;
    }

    // Convert the input buffer to be encrypted to a BIGNUM
    inputAsBN = BN_new();
    if (inputAsBN == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }
    if (BN_bin2bn(input, inputSize, inputAsBN) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed. Error: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto done;
    }

    group = EC_KEY_get0_group(ec_key);
    if (NULL == group)
    {
        SEC_LOG_ERROR("EC_KEY_get0_group failed");
        goto done;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        SEC_LOG_ERROR("BN_CTX_new failed");
        goto done;
    }

    // Convert the X coordinate to an EC Point.  This takes the desired Y value in 1 bit (to choose
    // which of the two possible Y values to use).  This *calculates* an actual Y value for the point.
    key_2_wrap_point = EC_POINT_new(group);
    if (key_2_wrap_point == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    if (!EC_POINT_set_compressed_coordinates_GFp(group, key_2_wrap_point, inputAsBN, 0, ctx)) //$$$ 1=>0 on 7/8/15
    {
        // Don't print an error message if the error is "point not on curve" 100A906E, but still fail
        if (ERR_get_error() != 0x100A906E) // i.e. error:100A906E:lib(16):func(169):reason(110)
        {
            SEC_LOG_ERROR("Set EC_POINT_set_compressed_coordinates_GFp failed. Error: %s",
                          ERR_error_string(ERR_get_error(), NULL));
        }
        goto done;
    }

    // Calc sender's shared point 'wP' => this gets sent back to receiver
    sender_share = EC_POINT_new(group);
    if (sender_share == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    P = EC_GROUP_get0_generator(group);
    if (P == NULL)
    {
        SEC_LOG_ERROR("EC_GROUP_get0_generator failed");
        goto done;
    }
    EC_POINT_mul(group, sender_share, NULL, P, sender_rand, ctx);

    // Calc sender's Shared Secret 'wRr'  => this hides the key I want to send
    shared_secret = EC_POINT_new(group);
    if (shared_secret == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    PK_recipient = EC_KEY_get0_public_key(ec_key);
    if (PK_recipient == NULL)
    {
        SEC_LOG_ERROR("EC_KEY_get0_public_key failed");
        goto done;
    }
    EC_POINT_mul(group, shared_secret, NULL, PK_recipient, sender_rand, ctx);

    // key_2_wrap_point is a point on the curve, we add the shared_secret
    // to it and send the result, the wrapped_key, to the receiver.
    wrapped_key = EC_POINT_new(group);
    if (wrapped_key == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }
    EC_POINT_add(group, wrapped_key, key_2_wrap_point, shared_secret, ctx);

    // Dissect the wrapped point to get its coordinates
    x = BN_new();
    if (x == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }
    y = BN_new();
    if (y == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }

    // Dissect shared_secret to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, sender_share, x, y, ctx);

    if (SEC_RESULT_SUCCESS != _SecUtils_BigNumToBuffer(x, (unsigned char *) &output[0 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("_SecUtils_BigNumToBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_BigNumToBuffer(y, (unsigned char *) &output[1 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("_SecUtils_BigNumToBuffer failed");
        goto done;
    }

    // Dissect wrapped_key to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, wrapped_key, x, y, ctx);

    if (SEC_RESULT_SUCCESS != _SecUtils_BigNumToBuffer(x, (unsigned char *) &output[2 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("_SecUtils_BigNumToBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_BigNumToBuffer(y, (unsigned char *) &output[3 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("_SecUtils_BigNumToBuffer failed");
        goto done;
    }

    res = 4 * SEC_ECC_NISTP256_KEY_LEN;

done:
    if (NULL != x)
        BN_free(x);
    if (NULL != y)
        BN_free(y);
    if (NULL != inputAsBN)
        BN_free(inputAsBN);
    if (NULL != sender_rand)
        BN_free(sender_rand);
    if (NULL != shared_secret)
        EC_POINT_free(shared_secret);
    if (NULL != sender_share)
        EC_POINT_free(sender_share);
    if (NULL != key_2_wrap_point)
        EC_POINT_free(key_2_wrap_point);
    if (NULL != wrapped_key)
        EC_POINT_free(wrapped_key);
    BN_CTX_free(ctx);

    return res;
}

static int _SecUtils_ElGamal_Encrypt(EC_KEY *ec_key,
                             SEC_BYTE* input, SEC_SIZE inputSize,
                             SEC_BYTE* output, SEC_SIZE outputSize)
{
    // Generate random number 'w' (multiplier) for the sender
    BIGNUM *sender_rand = BN_new();

    if (sender_rand == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        return SEC_RESULT_FAILURE;
    }
    if (0 == BN_rand(sender_rand, 256, -1, 0))
    {
        SEC_LOG_ERROR("BN_rand failed");
        if (NULL != sender_rand)
            BN_free(sender_rand);
        return SEC_RESULT_FAILURE;
    }

    return _SecUtils_ElGamal_Encrypt_Rand(ec_key,
                                         input, inputSize,
                                         output, outputSize,
                                         sender_rand);
}

static Sec_Result _SecUtils_VerifyX509WithRawRSAPublicKey(X509 *x509,
                                                  Sec_RSARawPublicKey* public_key)
{
    RSA *rsa = NULL;
    EVP_PKEY *evp_key = NULL;
    int verify_res;

    rsa = _SecUtils_RSAFromPubBinary(public_key);
    if (rsa == NULL)
    {
        SEC_LOG_ERROR("_Sec_ReadRSAPublic failed");
        goto error;
    }

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto error;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_RSA_FREE(rsa);
    SEC_EVPPKEY_FREE(evp_key);

    if (1 != verify_res)
    {
        SEC_LOG_ERROR("X509_verify failed, %s",
                      ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;

error: if (rsa != NULL)
    SEC_RSA_FREE(rsa);
    if (evp_key != NULL)
        SEC_EVPPKEY_FREE(evp_key);

    return SEC_RESULT_FAILURE;
}

Sec_Result _Pubops_VerifyWithPubRsa(Sec_RSARawPublicKey *pub_key, Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *sig, SEC_SIZE sig_len, int salt_len) {
	RSA *rsa = _SecUtils_RSAFromPubBinary(pub_key);
	Sec_Result res = SEC_RESULT_FAILURE;

	if (rsa == NULL) {
		SEC_LOG_ERROR("_SecUtils_RSAFromPubBinary failed");
		goto done;
	}

	if (sig_len != Sec_BEBytesToUint32(pub_key->modulus_len_be)) {
		SEC_LOG_ERROR("Invalid signature size %d, expected %d", sig_len, Sec_BEBytesToUint32(pub_key->modulus_len_be));
		goto done;
	}

	Sec_DigestAlgorithm digest_alg = SecSignature_GetDigestAlgorithm(alg);

    if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST) {
        //pss padding
        SEC_BYTE decrypted[SEC_RSA_KEY_MAX_LEN];
        if (RSA_public_decrypt(RSA_size(rsa), sig, decrypted, rsa, RSA_NO_PADDING) == -1)
        {
            SEC_LOG_ERROR("RSA_public_decrypt failed with error %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto done;
        }

        if (salt_len < 0) {
            salt_len = (digest_alg == SEC_DIGESTALGORITHM_SHA1) ? 20 : 32;
        }

        /* verify the data */
        int openssl_res = RSA_verify_PKCS1_PSS(rsa, digest, (digest_alg == SEC_DIGESTALGORITHM_SHA1) ? EVP_sha1() : EVP_sha256(), decrypted, salt_len);
	    if (1 != openssl_res)
	    {
	        SEC_LOG_ERROR("RSA_verify_PKCS1_PSS failed");
	        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
	        goto done;
	    }
    } else {
        int openssl_res = RSA_verify((digest_alg == SEC_DIGESTALGORITHM_SHA1) ? NID_sha1 : NID_sha256, digest, digest_len, sig, sig_len, rsa);
	    if (1 != openssl_res)
	    {
	        SEC_LOG_ERROR("RSA_verify failed");
	        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
	        goto done;
	    }
    }

	res = SEC_RESULT_SUCCESS;

done:
	SEC_RSA_FREE(rsa);

	return res;
}

Sec_Result _Pubops_VerifyWithPubEcc(Sec_ECCRawPublicKey *pub_key, Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *sig, SEC_SIZE sig_len) {
	EC_KEY *ec_key = _SecUtils_ECCFromPubBinary(pub_key);
	Sec_Result res = SEC_RESULT_FAILURE;

	if (NULL == ec_key)
	{
	    SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
	    goto done;
	}

	if (sig_len != Sec_BEBytesToUint32(pub_key->key_len)*2) {
		SEC_LOG_ERROR("Invalid signature size  %d, expected %d", sig_len, Sec_BEBytesToUint32(pub_key->key_len)*2);
		goto done;
	}

    ECDSA_SIG esig;
    esig.r = BN_new();
    esig.s = BN_new();
    BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, esig.r);
    BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, esig.s);

    int openssl_res = ECDSA_do_verify(digest, digest_len, &esig, ec_key);
    BN_free(esig.r);
    BN_free(esig.s);

    if (1 != openssl_res)
    {
        SEC_LOG_ERROR("ECDSA_do_verify failed");

        if (-1 == openssl_res) { // -1 is not an "error", just a verification failure, so don't log as much
            SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
    	}

    	goto done;
    }

	res = SEC_RESULT_SUCCESS;

done:
    SEC_ECC_FREE(ec_key);

    return res;
}

Sec_Result _Pubops_EncryptWithPubRsa(Sec_RSARawPublicKey *pub_key, Sec_CipherAlgorithm alg, SEC_BYTE *in, SEC_SIZE in_len, SEC_BYTE *out, SEC_SIZE out_len) {
	RSA *rsa = _SecUtils_RSAFromPubBinary(pub_key);
	Sec_Result res = SEC_RESULT_FAILURE;

	if (rsa == NULL) {
		SEC_LOG_ERROR("_SecUtils_RSAFromPubBinary failed");
		goto done;
	}

	if (out_len != Sec_BEBytesToUint32(pub_key->modulus_len_be)) {
		SEC_LOG_ERROR("Invalid output length encountered.  out_len=%d, mod_len=%d", out_len, Sec_BEBytesToUint32(pub_key->modulus_len_be));
		goto done;
	}

	int padding;
	switch (alg) {
		case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
			padding = RSA_PKCS1_PADDING;
			break;

		case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
			padding = RSA_PKCS1_OAEP_PADDING;
			break;

		default:
			SEC_LOG_ERROR("Unknown algorithm encountered: %d", alg);
		goto done;
	}

	int openssl_res = RSA_public_encrypt(in_len, in, out, rsa, padding);

    if (openssl_res < 0) {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
		goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
	SEC_RSA_FREE(rsa);
	return res;
}

static Sec_Result _SecUtils_VerifyX509WithRawECCPublicKey(X509 *x509,
                                                  Sec_ECCRawPublicKey* public_key)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evp_key = NULL;
    int verify_res;

    ec_key = _SecUtils_ECCFromPubBinary(public_key);
    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
        goto error;
    }

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_EC_KEY(evp_key, ec_key))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
        goto error;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_ECC_FREE(ec_key);
    SEC_EVPPKEY_FREE(evp_key);

    if (1 != verify_res)
    {
        SEC_LOG_ERROR("X509_verify failed, %s",
                      ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;

error:
    SEC_ECC_FREE(ec_key);
    SEC_EVPPKEY_FREE(evp_key);

    return SEC_RESULT_FAILURE;
}

Sec_Result _Pubops_EncryptWithPubEcc(Sec_ECCRawPublicKey *pub_key, Sec_CipherAlgorithm alg, SEC_BYTE *in, SEC_SIZE in_len, SEC_BYTE *out, SEC_SIZE out_len) {
	EC_KEY *ec_key = _SecUtils_ECCFromPubBinary(pub_key);
	Sec_Result res = SEC_RESULT_FAILURE;

	if (NULL == ec_key)
	{
	    SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
	    goto done;
	}

	if (in_len != out_len || in_len != Sec_BEBytesToUint32(pub_key->key_len)) {
		SEC_LOG_ERROR("Invalid lengths encountered.  in_len=%d, out_len=%d, mod_len=%d", in_len, out_len, Sec_BEBytesToUint32(pub_key->key_len));
	    goto done;
	}

    int ec_res = _SecUtils_ElGamal_Encrypt(ec_key, in, in_len, out, out_len);
    if (ec_res < 0)
    {
        SEC_LOG_ERROR("_SecUtils_ElGamal_Encrypt failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
	SEC_ECC_FREE(ec_key);
	return res;
}

Sec_Result _Pubops_VerifyX509WithPubRsa(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub) {
    X509 *x509 = SecCertificate_DerToX509(cert, cert_len);
	Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == x509) {
    	SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
    	goto done;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_VerifyX509WithRawRSAPublicKey(x509, pub)) {
    	SEC_LOG_ERROR("_SecUtils_VerifyX509WithRawRSAPublicKey failed");
    	goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
	SEC_X509_FREE(x509);

	return res;
}

Sec_Result _Pubops_VerifyX509WithPubEcc(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub) {
    X509 *x509 = SecCertificate_DerToX509(cert, cert_len);
	Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == x509) {
    	SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
    	goto done;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_VerifyX509WithRawECCPublicKey(x509, pub)) {
    	SEC_LOG_ERROR("_SecUtils_VerifyX509WithRawECCPublicKey failed");
    	goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
	SEC_X509_FREE(x509);

	return res;
}

Sec_Result _Pubops_ExtractRSAPubFromX509Der(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub) {
    X509 *x509 = SecCertificate_DerToX509(cert, cert_len);
    EVP_PKEY *evp_key = NULL;
    RSA *rsa = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == x509) {
    	SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
    	goto done;
    }

    evp_key = X509_get_pubkey(x509);
    if (evp_key == NULL)
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        goto done;
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL)
    {
        goto done;
    }

    Sec_Uint32ToBEBytes(RSA_size(rsa), pub->modulus_len_be);
    _SecUtils_BigNumToBuffer(rsa->n, pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    _SecUtils_BigNumToBuffer(rsa->e, pub->e, 4);

    res = SEC_RESULT_SUCCESS;
done:
	SEC_X509_FREE(x509);
	SEC_EVPPKEY_FREE(evp_key);
	SEC_RSA_FREE(rsa);

	return res;
}

static Sec_Result _SecUtils_Extract_EC_KEY_X_Y(const EC_KEY *ec_key, BIGNUM **xp, BIGNUM **yp, Sec_KeyType *keyTypep)
{
    const EC_GROUP *group = NULL;
    const EC_POINT *ec_point = NULL;
    BN_CTX *ctx = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == xp)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: X cannot be NULL");
        goto error;
    }

    group = EC_KEY_get0_group(ec_key);
    if (NULL == group)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_group: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    if (NULL == ec_point)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_public_key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    ctx = BN_CTX_new();
    if (NULL == ctx)
    {
        SEC_LOG_ERROR("BN_CTX_new() failed");
        goto error;
    }

    *xp = BN_new();
    if (NULL == *xp)
    {
        SEC_LOG_ERROR("BN_new() failed");
        goto error;
    }

    if (NULL != yp) { // if caller wants y coordinate returned
        *yp = BN_new();
        if (NULL == *yp)
        {
            SEC_LOG_ERROR("BN_new() failed");
            goto error;
        }
    }

    if (NULL != keyTypep) // if caller wants key type returned
    {
        *keyTypep = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
    }

    // Get the X coordinate and optionally the Y coordinate
    if (EC_POINT_get_affine_coordinates_GFp(group, ec_point,
                                            *xp,
                                            yp != NULL ? *yp : NULL,
                                            ctx) != 1)
    {
        BN_clear_free(*xp);
        if (NULL != yp)
            BN_clear_free(*yp);
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_POINT_get_affine_coordinates_GFp: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    res = SEC_RESULT_SUCCESS;
    // continue into "error"

error:
    if (NULL != ctx)
        BN_CTX_free(ctx);

    return res;
}

Sec_Result _Pubops_ExtractECCPubFromX509Der(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub) {
    X509 *x509 = SecCertificate_DerToX509(cert, cert_len);
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ec_key = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    Sec_KeyType key_type;
	Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == x509) {
    	SEC_LOG_ERROR("SecCertificate_DerToX509 failed");
    	goto done;
    }

    evp_key = X509_get_pubkey(x509);
    if (evp_key == NULL)
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
        goto done;
    }

    ec_key = EVP_PKEY_get1_EC_KEY(evp_key);
    if (ec_key == NULL)
    {
        goto done;
    }

    if (_SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &key_type) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y failed");
        goto done;
    }

    pub->type = key_type;

    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(key_type), pub->key_len);
    _SecUtils_BigNumToBuffer(x, pub->x, Sec_BEBytesToUint32(pub->key_len));
    _SecUtils_BigNumToBuffer(y, pub->y, Sec_BEBytesToUint32(pub->key_len));

    res = SEC_RESULT_SUCCESS;
done:
	if (x != NULL) {
	    BN_clear_free(x);
	}
	if (y != NULL) {
	    BN_clear_free(y);
	}
	SEC_X509_FREE(x509);
	SEC_EVPPKEY_FREE(evp_key);
	SEC_ECC_FREE(ec_key);

	return res;
}

static RSA *_SecUtils_RSAFromDERPub(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    RSA *rsa = NULL;

    rsa = d2i_RSAPublicKey(&rsa, &p, der_len);

    if (!rsa)
    {
        p = (const unsigned char *) der;
        rsa = d2i_RSA_PUBKEY(&rsa, &p, der_len);
    }

    if (!rsa)
    {
        SEC_LOG_ERROR("Invalid RSA key container");
        goto done;
    }

done:
    return rsa;
}

Sec_Result _Pubops_ExtractRSAPubFromPUBKEYDer(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub) {
	RSA *rsa = _SecUtils_RSAFromDERPub(cert, cert_len);
	Sec_Result res = SEC_RESULT_FAILURE;
	if (rsa == NULL) {
		SEC_LOG_ERROR("_SecUtils_RSAFromDERPub failed");
		goto done;
	}

    Sec_Uint32ToBEBytes(RSA_size(rsa), pub->modulus_len_be);
    _SecUtils_BigNumToBuffer(rsa->n, pub->n, Sec_BEBytesToUint32(pub->modulus_len_be));
    _SecUtils_BigNumToBuffer(rsa->e, pub->e, 4);

    res = SEC_RESULT_SUCCESS;

done:
	SEC_RSA_FREE(rsa);
	return res;
}

static EC_KEY *_SecUtils_ECCFromDERPub(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    EC_KEY *ec_key = NULL;

    ec_key = d2i_EC_PUBKEY(&ec_key, &p, der_len);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    return ec_key;
}

Sec_Result _Pubops_ExtractECCPubFromPUBKEYDer(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub) {
	EC_KEY *ec_key = _SecUtils_ECCFromDERPub(cert, cert_len);
	Sec_Result res = SEC_RESULT_FAILURE;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
	if (ec_key == NULL) {
		SEC_LOG_ERROR("_SecUtils_ECCFromDERPub failed");
		goto done;
	}

	Sec_KeyType key_type;
    if (_SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &key_type) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y failed");
        goto done;
    }

    pub->type = key_type;

    Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(key_type), pub->key_len);
    _SecUtils_BigNumToBuffer(x, pub->x, Sec_BEBytesToUint32(pub->key_len));
    _SecUtils_BigNumToBuffer(y, pub->y, Sec_BEBytesToUint32(pub->key_len));

    res = SEC_RESULT_SUCCESS;
done:
	if (x != NULL) {
	    BN_clear_free(x);
	}
	if (y != NULL) {
	    BN_clear_free(y);
	}
	SEC_ECC_FREE(ec_key);
	return res;
}

Sec_Result _Pubops_Random(SEC_BYTE* out, SEC_SIZE out_len) {
	if (1 != RAND_bytes(out, out_len)) {
		SEC_LOG_ERROR();
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result _Pubops_RandomPrng(SEC_BYTE* out, SEC_SIZE out_len) {
	if (1 != RAND_pseudo_bytes(out, out_len)) {
		SEC_LOG_ERROR();
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result _Pubops_HMAC(Sec_MacAlgorithm alg, SEC_BYTE *key, SEC_SIZE key_len, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac, SEC_SIZE mac_len) {
	switch (alg) {
		case SEC_MACALGORITHM_HMAC_SHA1:
		case SEC_MACALGORITHM_HMAC_SHA256:
			{
				unsigned int osl_mac_len = mac_len;
				if (NULL == HMAC(alg == SEC_MACALGORITHM_HMAC_SHA1 ? EVP_sha1() : EVP_sha256(),
					key, key_len, input, input_len, mac, &osl_mac_len)) {
					SEC_LOG_ERROR("HMAC failed");
			        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
			        return SEC_RESULT_FAILURE;
				}
			}
			break;

		case SEC_MACALGORITHM_CMAC_AES_128:
			{
				CMAC_CTX *cmac_ctx = CMAC_CTX_new();

		        if (1 != CMAC_Init(cmac_ctx, &key[0], key_len, key_len== 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), NULL )) {
		            SEC_LOG_ERROR("Comcast_CMAC_Init failed");
		            return SEC_RESULT_FAILURE;
		        }

		        if (1 != CMAC_Update(cmac_ctx, &input[0], input_len)) {
		        	SEC_LOG_ERROR("CMAC_Update failed");
			        CMAC_CTX_free(cmac_ctx);
		        	return SEC_RESULT_FAILURE;
		        }
		        size_t outl = mac_len;
		        if (1 != CMAC_Final(cmac_ctx, &mac[0], &outl)) {
		        	SEC_LOG_ERROR("CMAC_Final failed");
			        CMAC_CTX_free(cmac_ctx);
		        	return SEC_RESULT_FAILURE;
		        }
		        mac_len = outl;
		        CMAC_CTX_free(cmac_ctx);
		    }
	        break;

        default:
        	SEC_LOG_ERROR("Unknown algorithm encountered: %d", alg);
        	return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

struct _Pubops_DH_struct {
	DH *osl_dh;
};

_Pubops_DH* _Pubops_DH_create(SEC_BYTE *p, SEC_SIZE p_len, SEC_BYTE *g, SEC_SIZE g_len)
{
    DH *dh = NULL;

    if ((dh=DH_new()) == NULL) {
        SEC_LOG_ERROR("DH_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(p, p_len, NULL);
    dh->g = BN_bin2bn(g, g_len, NULL);
#else
    BIGNUM *bnp = BN_bin2bn(p, p_len, NULL);
    BIGNUM *bng = BN_bin2bn(g, g_len, NULL);
    DH_set0_pqg(dh, bnp, NULL, bng);
#endif

    _Pubops_DH* ret = (_Pubops_DH*) malloc(sizeof(_Pubops_DH));
    if (ret == NULL) {
    	SEC_LOG_ERROR("malloc failed");
    	DH_free(dh);
    	return NULL;
    }
    memset(ret, 0, sizeof(_Pubops_DH));
    ret->osl_dh = dh;

    return ret;
}

void _Pubops_DH_free(_Pubops_DH *dh) {
	if (dh == NULL) {
		return;
	}

	DH_free(dh->osl_dh);
	free(dh);
}

Sec_Result _Pubops_DH_generate_key(_Pubops_DH* dh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize) {
    if (!DH_generate_key(dh->osl_dh)) {
        SEC_LOG_ERROR("DH_generate_key failed");
        return SEC_RESULT_FAILURE;
    }

    const BIGNUM *pub_key = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    pub_key = dh->osl_dh->pub_key;
#else
    DH_get0_key(dh->osl_dh, &pub_key, NULL);
#endif

    if (pubKeySize < BN_num_bytes(pub_key)) {
        SEC_LOG_ERROR("buffer to small");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_BigNumToBuffer(pub_key, publicKey, pubKeySize)) {
        SEC_LOG_ERROR("_SecUtils_BigNumToBuffer failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result _Pubops_DH_compute(_Pubops_DH* dh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len, SEC_SIZE* written) {
    if (key_len < (SEC_SIZE) DH_size(dh->osl_dh)) {
        SEC_LOG_ERROR("key_len is not large enough to hold the computed DH key: %d", DH_size(dh->osl_dh));
        return SEC_RESULT_FAILURE;
    }

    BIGNUM * pub_key_bn = BN_bin2bn(pub_key, pub_key_len, NULL);
    if (pub_key_bn == NULL) {
        SEC_LOG_ERROR("BN_bin2bn failed");
        return SEC_RESULT_FAILURE;
    }

    *written = DH_compute_key(key, pub_key_bn, dh->osl_dh);
    BN_free(pub_key_bn);
    pub_key_bn = NULL;
    if (*written <= 0) {
        SEC_LOG_ERROR("DH_compute_key failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

struct _Pubops_ECDH_struct {
	EC_KEY *priv;
};

_Pubops_ECDH* _Pubops_ECDH_create()
{
    EC_KEY *key = NULL;

    /* Create an Elliptic Curve Key object and set it up to use the ANSI X9.62 Prime 256v1 curve */
    if(NULL == (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
        SEC_LOG_ERROR("EC_KEY_new_by_curve_name failed");
        return NULL;
    }

    _Pubops_ECDH* ret = (_Pubops_ECDH*) malloc(sizeof(_Pubops_ECDH));
    if (ret == NULL) {
    	SEC_LOG_ERROR("malloc failed");
    	SEC_ECC_FREE(key);
    	return NULL;
    }
    memset(ret, 0, sizeof(_Pubops_ECDH));
    ret->priv = key;

    return ret;
}

void _Pubops_ECDH_free(_Pubops_ECDH *ecdh) {
	if (ecdh == NULL) {
		return;
	}

	SEC_ECC_FREE(ecdh->priv);
	free(ecdh);
}

static Sec_Result _SecUtils_ECCToPubBinary(EC_KEY *ec_key, Sec_ECCRawPublicKey *binary)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if (_SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, NULL) != SEC_RESULT_SUCCESS)
    {

        SEC_LOG_ERROR("_SecUtils_ECCToPubBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }
    else
    {
        binary->type = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(binary->type), binary->key_len);
        _SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        _SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}

Sec_Result _Pubops_ECDH_generate_key(_Pubops_ECDH *ecdh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize) {
    if (pubKeySize != sizeof(Sec_ECCRawPublicKey)) {
        SEC_LOG_ERROR("pub key size does not match the size of Sec_ECCRawPublicKey");
        return SEC_RESULT_FAILURE;
    }

    //generate ephemeral ec key
    if (1 != EC_KEY_generate_key(ecdh->priv)) {
        SEC_LOG_ERROR("EC_KEY_generate_key failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != _SecUtils_ECCToPubBinary(ecdh->priv, (Sec_ECCRawPublicKey *) publicKey))
    {
        SEC_LOG_ERROR("_SecUtils_ECCToPubBinary failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result _Pubops_ECDH_compute(_Pubops_ECDH *ecdh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len, SEC_SIZE* written) {
    Sec_Result res = SEC_RESULT_FAILURE;
    EC_KEY *ec_key_pub = NULL;

    if (pub_key_len != sizeof(Sec_ECCRawPublicKey)) {
        SEC_LOG_ERROR("pub_key_len does not match size of Sec_ECCRawPublicKey");
        goto done;
    }

    ec_key_pub = _SecUtils_ECCFromPubBinary((Sec_ECCRawPublicKey*) pub_key);
    if (ec_key_pub == NULL) {
        SEC_LOG_ERROR("_SecUtils_ECCFromPubBinary failed");
        goto done;
    }

    /* Derive the shared secret */
    *written = ECDH_compute_key(key, key_len, EC_KEY_get0_public_key(ec_key_pub), ecdh->priv, NULL);
    if (*written <= 0) {
        SEC_LOG_ERROR("ECDH_compute_key failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_ECC_FREE(ec_key_pub);

    return res;
}

