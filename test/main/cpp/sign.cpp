/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
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

#include "sign.h"
#include "digest.h"
#include "test_ctx.h"
#include "sec_security_utils.h"
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>

static Sec_Result _BigNumToBuffer(const BIGNUM *bignum, SEC_BYTE *buffer, SEC_SIZE buffer_len)
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

std::vector<SEC_BYTE> signOpenSSL(
		Sec_SignatureAlgorithm alg,
		TestKey key,
		const std::vector<SEC_BYTE>& input) {

	std::vector<SEC_BYTE> digest;
	const EVP_MD * evp_md = NULL;

	SEC_BOOL pss = (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS);

	if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST) {
		digest = input;
		evp_md = EVP_sha1();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST) {
		digest = input;
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST) {
		digest = input;
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA1, input);
		evp_md = EVP_sha1();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA256, input);
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA256, input);
		evp_md = EVP_sha256();
	} else {
		SEC_LOG_ERROR("Unknown signature algorithm");
		return std::vector<SEC_BYTE>();
	}

	TestCtx::printHex("digest to sign", digest);

	if (SecKey_IsEcc(TestCreds::getKeyType(key))) {
        ECDSA_SIG *esig = NULL;

        EC_KEY *ec_key = TestCreds::asOpenSslEcKey(key);
        if (NULL == ec_key)
        {
            SEC_LOG_ERROR("TestCreds::asOpenSslEcKey failed");
    		return std::vector<SEC_BYTE>();
        }

        esig = ECDSA_do_sign(&digest[0], digest.size(), ec_key);
        SEC_ECC_FREE(ec_key);

        if (NULL == esig)
        {
            SEC_LOG_ERROR("ECDSA_do_sign failed");
    		return std::vector<SEC_BYTE>();
        }

		std::vector<SEC_BYTE> sig;
		sig.resize(256);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
		_BigNumToBuffer(esig->r, &sig[0], SEC_ECC_NISTP256_KEY_LEN);
        _BigNumToBuffer(esig->s, &sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN);
#else
        const BIGNUM *esigr = NULL;
        const BIGNUM *esigs = NULL;
        ECDSA_SIG_get0(esig, &esigr, &esigs);
		_BigNumToBuffer((BIGNUM *) esigr, &sig[0], SEC_ECC_NISTP256_KEY_LEN);
        _BigNumToBuffer((BIGNUM *) esigs, &sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN);
#endif

        sig.resize(SecSignature_GetEccSignatureSize(alg));

        return sig;
	} else {
		EVP_PKEY *evp_pkey = TestCreds::asOpenSslEvpPkey(key);
		if (evp_pkey == NULL) {
			SEC_LOG_ERROR("TestCreds::asOpenSslEvpPkey failed");
			return std::vector<SEC_BYTE>();
		}

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
		if (ctx == NULL) {
			EVP_PKEY_free(evp_pkey);
			SEC_LOG_ERROR("EVP_PKEY_CTX_new failed");
			return std::vector<SEC_BYTE>();
		}

		if (EVP_PKEY_sign_init(ctx) <= 0
				|| EVP_PKEY_CTX_set_rsa_padding(ctx, pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING) <= 0
				|| EVP_PKEY_CTX_set_signature_md(ctx, evp_md) <= 0) {
			EVP_PKEY_free(evp_pkey);
			EVP_PKEY_CTX_free(ctx);
			SEC_LOG_ERROR("Could not setup EVP_PKEY_CTX");
			return std::vector<SEC_BYTE>();
		}

        if (pss && EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, evp_md == EVP_sha1() ? 20 : 32) <= 0) {
            EVP_PKEY_free(evp_pkey);
            EVP_PKEY_CTX_free(ctx);
            SEC_LOG_ERROR("Could not setup EVP_PKEY_CTX");
            return std::vector<SEC_BYTE>();
        }

		std::vector<SEC_BYTE> sig;
		sig.resize(256);
		size_t siglen = 256;

		if (EVP_PKEY_sign(ctx, NULL, &siglen, &digest[0], digest.size()) <= 0 ||
				EVP_PKEY_sign(ctx, &sig[0], &siglen, &digest[0], digest.size()) <= 0) {
			EVP_PKEY_free(evp_pkey);
			EVP_PKEY_CTX_free(ctx);
			SEC_LOG_ERROR("EVP_PKEY_sign failed");
			return std::vector<SEC_BYTE>();
		}

		EVP_PKEY_free(evp_pkey);
		EVP_PKEY_CTX_free(ctx);

		sig.resize(siglen);

		return sig;
	}
}

static EC_KEY *_ECCFromPubBinary(Sec_ECCRawPublicKey *binary)
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

static SEC_BOOL verifyOpenSSLEccPub(
        Sec_SignatureAlgorithm alg,
        Sec_ECCRawPublicKey *eccPub,
        const std::vector<SEC_BYTE>& input,
        const std::vector<SEC_BYTE>& sig) {

    std::vector<SEC_BYTE> digest;
    const EVP_MD * evp_md = NULL;

    if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST) {
        digest = input;
        evp_md = EVP_sha256();
    } else if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256) {
        digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA256, input);
        evp_md = EVP_sha256();
    } else {
        SEC_LOG_ERROR("Unknown signature algorithm");
        return SEC_FALSE;
    }

    TestCtx::printHex("digest to verify", digest);

    if (sig.size() != SecSignature_GetEccSignatureSize(alg))
    {
        SEC_LOG_ERROR("Incorrect ECC signature size");
        return SEC_FALSE;
    }

    EC_KEY *ec_key = _ECCFromPubBinary(eccPub);
    if (NULL == ec_key)
    {
        SEC_LOG_ERROR("TestCreds::_ECCFromPubBinary failed");
        return SEC_FALSE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ECDSA_SIG esig;
    esig.r = BN_new();
    esig.s = BN_new();
    BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, esig.r);
    BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, esig.s);
    int openssl_res = ECDSA_do_verify(&digest[0], digest.size(), &esig, ec_key);
    BN_free(esig.r);
    BN_free(esig.s);
#else
    ECDSA_SIG *esig = ECDSA_SIG_new();
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, r);
    BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, s);
    ECDSA_SIG_set0(esig, r, s);
    int openssl_res = ECDSA_do_verify(&digest[0], digest.size(), esig, ec_key);
    ECDSA_SIG_free(esig);
#endif
    SEC_ECC_FREE(ec_key);

    if (1 != openssl_res)
    {
        SEC_LOG_ERROR("ECDSA_do_verify failed");
        return SEC_FALSE;
    }

    return SEC_TRUE;
}

SEC_BOOL verifyOpenSSL(
		Sec_SignatureAlgorithm alg,
		TestKey key,
		const std::vector<SEC_BYTE>& input,
		const std::vector<SEC_BYTE>& sig) {

	std::vector<SEC_BYTE> digest;
	const EVP_MD * evp_md = NULL;

	SEC_BOOL pss = (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS);

	if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST) {
		digest = input;
		evp_md = EVP_sha1();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST) {
		digest = input;
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST) {
		digest = input;
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA1, input);
		evp_md = EVP_sha1();
	} else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA256, input);
		evp_md = EVP_sha256();
	} else if (alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256) {
		digest = digestOpenSSL(SEC_DIGESTALGORITHM_SHA256, input);
		evp_md = EVP_sha256();
	} else {
		SEC_LOG_ERROR("Unknown signature algorithm");
		return SEC_FALSE;
	}

	TestCtx::printHex("digest to verify", digest);

	if (SecKey_IsEcc(TestCreds::getKeyType(key))) {
        if (sig.size() != SecSignature_GetEccSignatureSize(alg))
        {
            SEC_LOG_ERROR("Incorrect ECC signature size");
            return SEC_FALSE;
        }

		EC_KEY *ec_key = TestCreds::asOpenSslEcKey(key);
        if (NULL == ec_key)
        {
            SEC_LOG_ERROR("TestCreds::asOpenSslEcKey failed");
            return SEC_FALSE;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ECDSA_SIG esig;
        esig.r = BN_new();
        esig.s = BN_new();
        BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, esig.r);
        BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, esig.s);
        int openssl_res = ECDSA_do_verify(&digest[0], digest.size(), &esig, ec_key);
        BN_free(esig.r);
        BN_free(esig.s);
#else
        ECDSA_SIG *esig = ECDSA_SIG_new();
        BIGNUM *r = BN_new();
        BIGNUM *s = BN_new();
        BN_bin2bn(&sig[0], SEC_ECC_NISTP256_KEY_LEN, r);
        BN_bin2bn(&sig[SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN, s);
        ECDSA_SIG_set0(esig, r, s);
        int openssl_res = ECDSA_do_verify(&digest[0], digest.size(), esig, ec_key);
        ECDSA_SIG_free(esig);
#endif
        SEC_ECC_FREE(ec_key);

        if (1 != openssl_res)
        {
            SEC_LOG_ERROR("ECDSA_do_verify failed");
            return SEC_FALSE;
        }

        return SEC_TRUE;
	} else {
		EVP_PKEY *evp_pkey = TestCreds::asOpenSslEvpPkey(key);
		if (evp_pkey == NULL) {
			SEC_LOG_ERROR("TestCreds::asOpenSslEvpPkey failed");
			return SEC_FALSE;
		}

		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_pkey, NULL);
		if (ctx == NULL) {
			EVP_PKEY_free(evp_pkey);
			SEC_LOG_ERROR("EVP_PKEY_CTX_new failed");
			return SEC_FALSE;
		}

		if (EVP_PKEY_verify_init(ctx) <= 0
				|| EVP_PKEY_CTX_set_rsa_padding(ctx, pss ? RSA_PKCS1_PSS_PADDING : RSA_PKCS1_PADDING) <= 0
				|| EVP_PKEY_CTX_set_signature_md(ctx, evp_md) <= 0) {
			EVP_PKEY_free(evp_pkey);
			EVP_PKEY_CTX_free(ctx);
			SEC_LOG_ERROR("Could not setup EVP_PKEY_CTX");
			return SEC_FALSE;
		}

        if (pss && EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, evp_md == EVP_sha1() ? 20 : 32) <= 0) {
            EVP_PKEY_free(evp_pkey);
            EVP_PKEY_CTX_free(ctx);
            SEC_LOG_ERROR("Could not setup EVP_PKEY_CTX");
            return SEC_FALSE;
        }

		if (EVP_PKEY_verify(ctx, &sig[0], sig.size(), &digest[0], digest.size()) <= 0) {
			EVP_PKEY_free(evp_pkey);
			EVP_PKEY_CTX_free(ctx);
			SEC_LOG_ERROR("EVP_PKEY_verify failed");
			return SEC_FALSE;
		}

		EVP_PKEY_free(evp_pkey);
		EVP_PKEY_CTX_free(ctx);

		return SEC_TRUE;
	}

	return SEC_FALSE;
}

std::vector<SEC_BYTE> signSecApi(TestCtx *ctx,
		Sec_SignatureAlgorithm alg,
		Sec_KeyHandle *key,
		const std::vector<SEC_BYTE>& input) {

	Sec_SignatureHandle *handle = ctx->acquireSignature(alg, SEC_SIGNATUREMODE_SIGN, key);
	if (handle == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireSignature failed");
		return std::vector<SEC_BYTE>();
	}

	std::vector<SEC_BYTE> sig;
	sig.resize(256);
	SEC_SIZE sig_len;

	if (SEC_RESULT_SUCCESS != SecSignature_Process(handle,
        (SEC_BYTE *) &input[0], input.size(),
		&sig[0], &sig_len)) {
		SEC_LOG_ERROR("SecSignature_Process failed");
		return std::vector<SEC_BYTE>();
	}

	sig.resize(sig_len);

	return sig;
}

SEC_BOOL verifySecApi(TestCtx *ctx,
		Sec_SignatureAlgorithm alg,
		Sec_KeyHandle *key,
		const std::vector<SEC_BYTE>& input,
		const std::vector<SEC_BYTE>& sig) {

	Sec_SignatureHandle *handle = ctx->acquireSignature(alg, SEC_SIGNATUREMODE_VERIFY, key);
	if (handle == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireSignature failed");
		return SEC_FALSE;
	}

	SEC_SIZE sig_len = sig.size();

	if (SEC_RESULT_SUCCESS != SecSignature_Process(handle,
        (SEC_BYTE *) &input[0], input.size(),
		(SEC_BYTE *) &sig[0], &sig_len)) {
		SEC_LOG_ERROR("SecSignature_Process failed");
		return SEC_FALSE;
	}

	return SEC_TRUE;
}

Sec_Result testSignature(
		SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
		Sec_SignatureAlgorithm alg, Sec_SignatureMode mode, SEC_SIZE inputSize) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	//mode
	SEC_BOOL testSign = (mode == SEC_SIGNATUREMODE_SIGN);

	Sec_KeyHandle *keyHandle = NULL;
	if (testSign) {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, priv, kc))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, pub, kc))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	}

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
	TestCtx::printHex("clear", clear);

	//sign
	std::vector<SEC_BYTE> sig;
	if (testSign) {
		sig = signSecApi(&ctx, alg, keyHandle, clear);
	} else {
		//use openssl to sign
		sig = signOpenSSL(alg, priv, clear);
	}

	TestCtx::printHex("sig", sig);

	//verify
	SEC_BOOL ver_res;
	if (testSign) {
        //use openssl to verify
        if (kc == TESTKC_GENERATED) {
            //extract pub from the generated key
            Sec_ECCRawPublicKey eccPub;
            if (SEC_RESULT_SUCCESS != SecKey_ExtractECCPublicKey(keyHandle, &eccPub)) {
                SEC_LOG_ERROR("SecKey_ExtractECCPublicKey failed");
                return SEC_RESULT_FAILURE;
            }

            ver_res = verifyOpenSSLEccPub(alg, &eccPub, clear, sig);
        } else {
    		ver_res = verifyOpenSSL(alg, pub, clear, sig);
        }
	} else {
		//use sec api to verify
		ver_res = verifySecApi(&ctx, alg, keyHandle, clear, sig);
	}

	//check if results match
	if (!ver_res) {
		SEC_LOG_ERROR("Verification failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
