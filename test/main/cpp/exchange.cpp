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

#include "exchange.h"
#include "test_ctx.h"
#include "sec_security_utils.h"
#include "cipher.h"
#include "mac.h"
#include <openssl/dh.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>

static SEC_BYTE g_dh_p[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
  0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
  0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
  0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
  0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
  0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
  0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
  0xa6, 0x37, 0xed, 0x6b, 0x0b, 0xff, 0x5c, 0xb6, 0xf4, 0x06, 0xb7, 0xed,
  0xee, 0x38, 0x6b, 0xfb, 0x5a, 0x89, 0x9f, 0xa5, 0xae, 0x9f, 0x24, 0x11,
  0x7c, 0x4b, 0x1f, 0xe6, 0x49, 0x28, 0x66, 0x51, 0xec, 0xe4, 0x5b, 0x3d,
  0xc2, 0x00, 0x7c, 0xb8, 0xa1, 0x63, 0xbf, 0x05, 0x98, 0xda, 0x48, 0x36,
  0x1c, 0x55, 0xd3, 0x9a, 0x69, 0x16, 0x3f, 0xa8, 0xfd, 0x24, 0xcf, 0x5f,
  0x83, 0x65, 0x5d, 0x23, 0xdc, 0xa3, 0xad, 0x96, 0x1c, 0x62, 0xf3, 0x56,
  0x20, 0x85, 0x52, 0xbb, 0x9e, 0xd5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6d,
  0x67, 0x0c, 0x35, 0x4e, 0x4a, 0xbc, 0x98, 0x04, 0xf1, 0x74, 0x6c, 0x08,
  0xca, 0x18, 0x21, 0x7c, 0x32, 0x90, 0x5e, 0x46, 0x2e, 0x36, 0xce, 0x3b,
  0xe3, 0x9e, 0x77, 0x2c, 0x18, 0x0e, 0x86, 0x03, 0x9b, 0x27, 0x83, 0xa2,
  0xec, 0x07, 0xa2, 0x8f, 0xb5, 0xc5, 0x5d, 0xf0, 0x6f, 0x4c, 0x52, 0xc9,
  0xde, 0x2b, 0xcb, 0xf6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7c,
  0xea, 0x95, 0x6a, 0xe5, 0x15, 0xd2, 0x26, 0x18, 0x98, 0xfa, 0x05, 0x10,
  0x15, 0x72, 0x8e, 0x5a, 0x8a, 0xaa, 0xc4, 0x2d, 0xad, 0x33, 0x17, 0x0d,
  0x04, 0x50, 0x7a, 0x33, 0xa8, 0x55, 0x21, 0xab, 0xdf, 0x1c, 0xba, 0x64,
  0xec, 0xfb, 0x85, 0x04, 0x58, 0xdb, 0xef, 0x0a, 0x8a, 0xea, 0x71, 0x57,
  0x5d, 0x06, 0x0c, 0x7d, 0xb3, 0x97, 0x0f, 0x85, 0xa6, 0xe1, 0xe4, 0xc7,
  0xab, 0xf5, 0xae, 0x8c, 0xdb, 0x09, 0x33, 0xd7, 0x1e, 0x8c, 0x94, 0xe0,
  0x4a, 0x25, 0x61, 0x9d, 0xce, 0xe3, 0xd2, 0x26, 0x1a, 0xd2, 0xee, 0x6b,
  0xf1, 0x2f, 0xfa, 0x06, 0xd9, 0x8a, 0x08, 0x64, 0xd8, 0x76, 0x02, 0x73,
  0x3e, 0xc8, 0x6a, 0x64, 0x52, 0x1f, 0x2b, 0x18, 0x17, 0x7b, 0x20, 0x0c,
  0xbb, 0xe1, 0x17, 0x57, 0x7a, 0x61, 0x5d, 0x6c, 0x77, 0x09, 0x88, 0xc0,
  0xba, 0xd9, 0x46, 0xe2, 0x08, 0xe2, 0x4f, 0xa0, 0x74, 0xe5, 0xab, 0x31,
  0x43, 0xdb, 0x5b, 0xfc, 0xe0, 0xfd, 0x10, 0x8e, 0x4b, 0x82, 0xd1, 0x20,
  0xa9, 0x3a, 0xd2, 0xca, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static SEC_BYTE g_dh_g[] = {
    0x02,
};

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

static Sec_KeyType _GroupToKeyType(const EC_GROUP *group)
{
    if (NULL == group)
        return SEC_KEYTYPE_NUM;
    switch (EC_GROUP_get_curve_name(group))
    {
        case NID_X9_62_prime256v1:
            return SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
        case 0:
        default:
            return SEC_KEYTYPE_NUM;
    }
}

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

static Sec_Result _Extract_EC_KEY_X_Y(const EC_KEY *ec_key, BIGNUM **xp, BIGNUM **yp, Sec_KeyType *keyTypep)
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
        *keyTypep = _GroupToKeyType(group);
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

static Sec_Result _ECCToPubBinary(EC_KEY *ec_key, Sec_ECCRawPublicKey *binary)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    Sec_KeyType keyType;

    if (_Extract_EC_KEY_X_Y(ec_key, &x, &y, &keyType) != SEC_RESULT_SUCCESS)
    {

        SEC_LOG_ERROR("_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }
    else
    {
        binary->type = keyType;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
        _BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        _BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}

static DH* _DH_create(SEC_BYTE *p, SEC_SIZE p_len, SEC_BYTE *g, SEC_SIZE g_len)
{
    DH *dh = NULL;

    if ((dh=DH_new()) == NULL) {
        SEC_LOG_ERROR("DH_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dh->p = BN_bin2bn(p, p_len, NULL);
    dh->g = BN_bin2bn(g, g_len, NULL);

    if ((dh->p == NULL) || (dh->g == NULL)) {
        SEC_LOG_ERROR("BN_bin2bn failed");
        DH_free(dh);
        return NULL;
    }

    dh->length = p_len * 8;
#else
    BIGNUM *bnp = BN_bin2bn(p, p_len, NULL);
    BIGNUM *bng = BN_bin2bn(g, g_len, NULL);
    DH_set0_pqg(dh, bnp, NULL, bng);
#endif

    return dh;
}

static Sec_Result _DH_generate_key(DH* dh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize) {
    if (!DH_generate_key(dh)) {
        SEC_LOG_ERROR("DH_generate_key failed");
        DH_free(dh);
        return SEC_RESULT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (pubKeySize < (SEC_SIZE) BN_num_bytes(dh->pub_key)) {
        SEC_LOG_ERROR("buffer to small");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE len = BN_bn2bin(dh->pub_key, publicKey);
    if (len < pubKeySize) {
        memmove(publicKey + pubKeySize - len, publicKey, len);
        memset(publicKey, 0, pubKeySize - len);
    }
#else
    const BIGNUM *pub_key = NULL;
    DH_get0_key(dh, &pub_key, NULL);

    if ((int)pubKeySize < BN_num_bytes(pub_key)) {
        SEC_LOG_ERROR("buffer to small");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE len = BN_bn2bin(pub_key, publicKey);
    if (len < pubKeySize) {
        memmove(publicKey + pubKeySize - len, publicKey, len);
        memset(publicKey, 0, pubKeySize - len);
    }
#endif

    return SEC_RESULT_SUCCESS;
}

static Sec_Result _DH_compute(DH* dh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len, SEC_SIZE* written) {
    if (key_len < (SEC_SIZE) DH_size(dh)) {
        SEC_LOG_ERROR("key_len is not large enough to hold the computed DH key: %d", DH_size(dh));
        return SEC_RESULT_FAILURE;
    }

    BIGNUM * pub_key_bn = BN_bin2bn(pub_key, pub_key_len, NULL);
    if (pub_key_bn == NULL) {
        SEC_LOG_ERROR("BN_bin2bn failed");
        return SEC_RESULT_FAILURE;
    }

    *written = DH_compute_key(key, pub_key_bn, dh);
    BN_free(pub_key_bn);
    pub_key_bn = NULL;
    if (*written <= 0) {
        SEC_LOG_ERROR("DH_compute_key failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyExchangeDH(
	SEC_OBJECTID idComputed,
	Sec_StorageLoc loc,
	Sec_KeyType typeComputed) {

	TestCtx ctx;
	Sec_KeyExchangeHandle *key_ex_handle = NULL;
	DH* dh = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

	Sec_DHParameters dh_params;
	memcpy(dh_params.p, g_dh_p, sizeof(g_dh_p));
	dh_params.pLen = sizeof(g_dh_p);
	memcpy(dh_params.g, g_dh_g, sizeof(g_dh_g));
	dh_params.gLen = sizeof(g_dh_g);

	SEC_BYTE pub_secapi[512];
	SEC_BYTE pub_test[512];
	SEC_BYTE ss_test[512];
	SEC_SIZE ss_len;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKeyExchange_GetInstance(ctx.proc(), SEC_KEYEXCHANGE_DH, &dh_params, &key_ex_handle)) {
		SEC_LOG_ERROR("SecKeyExchange_GetInstance failed");
		goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKeyExchange_GenerateKeys(key_ex_handle, pub_secapi, sizeof(pub_secapi))) {
		SEC_LOG_ERROR("SecKeyExchange_GenerateKeys failed");
		goto done;
	}

	//create other side info
	dh = _DH_create(g_dh_p, sizeof(g_dh_p), g_dh_g, sizeof(g_dh_g));
	if (dh == NULL) {
		SEC_LOG_ERROR("_DH_create failed");
		goto done;
	}

	if (SEC_RESULT_SUCCESS != _DH_generate_key(dh, pub_test, sizeof(pub_test))) {
		SEC_LOG_ERROR("_DH_generate_key failed");
		goto done;
	}

	//compute shared secret
	if (SEC_RESULT_SUCCESS != SecKeyExchange_ComputeSecret(key_ex_handle, pub_test, sizeof(pub_test), typeComputed, idComputed, loc)) {
		SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
		goto done;
	}

	if (SEC_RESULT_SUCCESS != _DH_compute(dh, pub_secapi, sizeof(pub_secapi), ss_test, sizeof(ss_test), &ss_len)) {
		SEC_LOG_ERROR("_DH_compute failed");
		goto done;
	}

	//test enc/dec or mac
	if (SecKey_IsAES(typeComputed)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idComputed, ss_test, SecKey_GetKeyLenForKeyType(typeComputed))) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			goto done;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idComputed, ss_test, SecKey_GetKeyLenForKeyType(typeComputed))) {
			SEC_LOG_ERROR("macCheck failed");
			goto done;
		}
	}

	res = SEC_RESULT_SUCCESS;

done:
	if (key_ex_handle != NULL) {
		SecKeyExchange_Release(key_ex_handle);
	}

	if (dh != NULL) {
		DH_free(dh);
	}

	return res;
}

Sec_Result testKeyExchangeECDH(
  SEC_OBJECTID idComputed,
  Sec_StorageLoc loc,
  Sec_KeyType typeComputed) {

  TestCtx ctx;
  Sec_KeyExchangeHandle *key_ex_handle = NULL;
  EC_KEY *priv_test = NULL;
  EC_KEY *pub_secapi_key = NULL;
  Sec_Result res = SEC_RESULT_FAILURE;

  Sec_ECCRawPublicKey pub_secapi;
  Sec_ECCRawPublicKey pub_test;
  SEC_BYTE ss_test[32];
  SEC_SIZE ss_len;

  Sec_ECDHParameters ecdh_params;
  ecdh_params.curve = NISTP256;

  if (ctx.init() != SEC_RESULT_SUCCESS) {
    SEC_LOG_ERROR("TestCtx.init failed");
    goto done;
  }

  if (SEC_RESULT_SUCCESS != SecKeyExchange_GetInstance(ctx.proc(), SEC_KEYEXCHANGE_ECDH, &ecdh_params, &key_ex_handle)) {
    SEC_LOG_ERROR("SecKeyExchange_GetInstance failed");
    goto done;
  }

  if (SEC_RESULT_SUCCESS != SecKeyExchange_GenerateKeys(key_ex_handle, (SEC_BYTE *) &pub_secapi, sizeof(pub_secapi))) {
    SEC_LOG_ERROR("SecKeyExchange_GenerateKeys failed");
    goto done;
  }

  //create other side info
  if(NULL == (priv_test = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) {
      SEC_LOG_ERROR("EC_KEY_new_by_curve_name failed");
      goto done;
  }

  if (1 != EC_KEY_generate_key(priv_test)) {
      SEC_LOG_ERROR("EC_KEY_generate_key failed");
      goto done;
  }

  if (SEC_RESULT_SUCCESS != _ECCToPubBinary(priv_test, &pub_test))
  {
      SEC_LOG_ERROR("_ECCToPubBinary failed");
      goto done;
  }


  //compute shared secret
  if (SEC_RESULT_SUCCESS != SecKeyExchange_ComputeSecret(key_ex_handle, (SEC_BYTE*) &pub_test, sizeof(pub_test), typeComputed, idComputed, loc)) {
    SEC_LOG_ERROR("SecKeyExchange_ComputeSecret failed");
    goto done;
  }

  pub_secapi_key = _ECCFromPubBinary(&pub_secapi);
  if (pub_secapi_key == NULL) {
      SEC_LOG_ERROR("SecUtils_ECCFromPubBinary failed");
      goto done;
  }

  /* Derive the shared secret */
  ss_len = ECDH_compute_key(ss_test, sizeof(ss_test), EC_KEY_get0_public_key(pub_secapi_key), priv_test, NULL);
  if (ss_len <= 0) {
      SEC_LOG_ERROR("ECDH_compute_key failed");
      goto done;
  }

  //test enc/dec or mac
  if (SecKey_IsAES(typeComputed)) {
    if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idComputed, ss_test, SecKey_GetKeyLenForKeyType(typeComputed))) {
      SEC_LOG_ERROR("aesKeyCheck failed");
      goto done;
    }
  } else {
    if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idComputed, ss_test, SecKey_GetKeyLenForKeyType(typeComputed))) {
      SEC_LOG_ERROR("macCheck failed");
      goto done;
    }
  }

  res = SEC_RESULT_SUCCESS;

done:
  if (key_ex_handle != NULL) {
    SecKeyExchange_Release(key_ex_handle);
  }

  SEC_ECC_FREE(priv_test);
  SEC_ECC_FREE(pub_secapi_key);

  return res;
}
