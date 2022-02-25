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

#include "key.h"
#include "cipher.h"
#include "test_ctx.h"
#include "sec_security_utils.h"
#include <string>
#include <stdlib.h>
#include "sec_security_store.h"
#include <openssl/err.h>
#include <openssl/pem.h>

static int _Sec_DisablePassphrasePrompt(char *buf, int size, int rwflag, void *u)
{
    return 0;
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

static void _RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    _BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    _BigNumToBuffer(rsa->e, binary->e, 4);
#else
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(rsa, &n, &e, NULL);
    _BigNumToBuffer((BIGNUM *) n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    _BigNumToBuffer((BIGNUM *) e, binary->e, 4);
#endif
}


static Sec_Result aesKeyCheck(Sec_ProcessorHandle *proc, SEC_OBJECTID id_first, SEC_OBJECTID id_second) {
    SEC_PRINT("--- aes key check ---\n");

    std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE);
    TestCtx::printHex("clear", clear);

    std::vector<SEC_BYTE> cipher_first;
    cipher_first.resize(SEC_AES_BLOCK_SIZE);
    SEC_SIZE cipher_first_len;

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, id_first,
        NULL, &clear[0], clear.size(), &cipher_first[0],
        cipher_first.size(), &cipher_first_len)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }
    cipher_first.resize(cipher_first_len);
    TestCtx::printHex("cipher_first", cipher_first);

    std::vector<SEC_BYTE> cipher_second;
    cipher_second.resize(SEC_AES_BLOCK_SIZE);
    SEC_SIZE cipher_second_len;

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, id_second,
        NULL, &clear[0], clear.size(), &cipher_second[0],
        cipher_second.size(), &cipher_second_len)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }
    cipher_second.resize(cipher_second_len);
    TestCtx::printHex("cipher_second", cipher_second);

    SEC_PRINT("---------------------\n");

    //check if results match
    if (cipher_first != cipher_second) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result macCheck(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg, SEC_OBJECTID id_first, SEC_OBJECTID id_second) {
    std::vector<SEC_BYTE> clear = TestCtx::random(256);
    TestCtx::printHex("clear", clear);

    std::vector<SEC_BYTE> mac_first;
    mac_first.resize(SEC_MAC_MAX_LEN);
    SEC_SIZE mac_first_len;
    if (SEC_RESULT_SUCCESS != SecMac_SingleInputId(proc, alg, id_first, &clear[0], clear.size(), &mac_first[0], &mac_first_len)) {
        SEC_LOG_ERROR("SecMac_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    mac_first.resize(mac_first_len);
    TestCtx::printHex("mac_first", mac_first);

    std::vector<SEC_BYTE> mac_second;
    mac_second.resize(SEC_MAC_MAX_LEN);
    SEC_SIZE mac_second_len;
    if (SEC_RESULT_SUCCESS != SecMac_SingleInputId(proc, alg, id_first, &clear[0], clear.size(), &mac_second[0], &mac_second_len)) {
        SEC_LOG_ERROR("SecMac_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    mac_second.resize(mac_second_len);
    TestCtx::printHex("macSecApi", mac_second);

    //check if results match
    if (mac_first != mac_second) {
        SEC_LOG_ERROR("Results do not match");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testStore(SEC_BOOL encrypt, SEC_BOOL mac) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> data = ctx.random(20);
	TestCtx::printHex("data: ", data);

	//fill header
	SecUtils_KeyStoreHeader keystore_header;
    if (SEC_RESULT_SUCCESS != SecUtils_FillKeyStoreUserHeader(ctx.proc(), &keystore_header, SEC_KEYCONTAINER_RAW_HMAC_160))
    {
        SEC_LOG_ERROR("SecUtils_FillKeyStoreUserHeader failed");
        return SEC_RESULT_FAILURE;
    }

    //write store
    std::vector<SEC_BYTE> store;
    store.resize(SEC_KEYCONTAINER_MAX_LEN);
    if (SEC_RESULT_SUCCESS != SecStore_StoreData(ctx.proc(), encrypt, mac,
            (SEC_BYTE *) SEC_UTILS_KEYSTORE_MAGIC, &keystore_header, sizeof(keystore_header),
            &data[0], data.size(), &store[0], store.size()))
    {
        SEC_LOG_ERROR("SecStore_StoreData failed");
        return SEC_RESULT_FAILURE;
    }
	store.resize(SecStore_GetStoreLen(&store[0]));
	TestCtx::printHex("store: ", store);

    //read from store
	SecUtils_KeyStoreHeader keystore_header2;
	std::vector<SEC_BYTE> extracted_data;
	extracted_data.resize(SEC_KEYCONTAINER_MAX_LEN);
	if (SEC_RESULT_SUCCESS != SecStore_RetrieveData(ctx.proc(), mac, &keystore_header2, sizeof(keystore_header2), &extracted_data[0], extracted_data.size(), &store[0], store.size())) {
		SEC_LOG_ERROR("SecStore_RetrieveData failed");
		return SEC_RESULT_FAILURE;
	}
	extracted_data.resize(SecStore_GetDataLen(&store[0]));
	TestCtx::printHex("extracted_data: ", extracted_data);

	if (data != extracted_data) {
		SEC_LOG_ERROR("Extracted data does not match what was put into the store");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testStoreProvision(SEC_OBJECTID id, SEC_BOOL encrypt, SEC_BOOL mac) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> data = ctx.random(20);
	TestCtx::printHex("data: ", data);

	//fill header
	SecUtils_KeyStoreHeader keystore_header;
    if (SEC_RESULT_SUCCESS != SecUtils_FillKeyStoreUserHeader(ctx.proc(), &keystore_header, SEC_KEYCONTAINER_RAW_HMAC_160))
    {
        SEC_LOG_ERROR("SecUtils_FillKeyStoreUserHeader failed");
        return SEC_RESULT_FAILURE;
    }

    //write store
    std::vector<SEC_BYTE> store;
    store.resize(SEC_KEYCONTAINER_MAX_LEN);
    if (SEC_RESULT_SUCCESS != SecStore_StoreData(ctx.proc(), encrypt, mac,
            (SEC_BYTE *) SEC_UTILS_KEYSTORE_MAGIC, &keystore_header, sizeof(keystore_header),
            &data[0], data.size(), &store[0], store.size()))
    {
        SEC_LOG_ERROR("SecStore_StoreData failed");
        return SEC_RESULT_FAILURE;
    }
	store.resize(SecStore_GetStoreLen(&store[0]));
	TestCtx::printHex("store: ", store);

	//provision store
	if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id,
	        SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_KEYCONTAINER_STORE, &store[0],
	        store.size())) {
		SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyProvision(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	if (NULL == ctx.provisionKey(id, loc, key, kc)) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyProvisionDouble(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, TestKey key2, TestKc kc2, Sec_StorageLoc loc2) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = ctx.provisionKey(id, loc, key, kc);
	if (NULL == handle) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}
	ctx.releaseKey(handle);

	handle = ctx.provisionKey(SEC_OBJECTID_USER_BASE, loc2, key2, kc2);
	if (NULL == handle) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyGetKeyInfo(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = ctx.provisionKey(id, loc, key, kc);
	if (NULL == handle) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyType kt = SecKey_GetKeyType(handle);
	if (kt < 0 || kt >= SEC_KEYTYPE_NUM) {
		SEC_LOG_ERROR("Invalid key type");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_GetKeyLen(handle) == 0) {
		SEC_LOG_ERROR("Invalid key length");
		return SEC_RESULT_FAILURE;
	}

	if (ctx.proc() != SecKey_GetProcessor(handle)) {
		SEC_LOG_ERROR("SecKey_GetProcessor failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
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

Sec_Result testKeyExtractPublicKey(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = ctx.provisionKey(id, loc, key, kc);
	if (NULL == handle) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsEcc(TestCreds::getKeyType(key))) {
		Sec_ECCRawPublicKey public_key;
		memset(&public_key, 0, sizeof(public_key));
		if (SEC_RESULT_SUCCESS != SecKey_ExtractECCPublicKey(handle, &public_key)) {
			SEC_LOG_ERROR("SecKey_ExtractECCPublicKey failed");
			return SEC_RESULT_FAILURE;
		}

		std::vector<SEC_BYTE> secapi((SEC_BYTE *) &public_key, ((SEC_BYTE *) &public_key) + sizeof(Sec_ECCRawPublicKey));

		TestCtx::printHex("secapi", secapi);

        if (kc != TESTKC_GENERATED) {
    		EC_KEY *ec = TestCreds::asOpenSslEcKey(key);
    		if (ec == NULL) {
    			SEC_LOG_ERROR("TestCreds::asOpenSslEc failed");
    			return SEC_RESULT_FAILURE;
    		}

    		memset(&public_key, 0, sizeof(public_key));
    		_ECCToPubBinary(ec, &public_key);
    		SEC_ECC_FREE(ec);

    		std::vector<SEC_BYTE> openssl((SEC_BYTE *) &public_key, ((SEC_BYTE *) &public_key) + sizeof(Sec_ECCRawPublicKey));
    		TestCtx::printHex("openssl", openssl);

    		if (secapi != openssl) {
    			return SEC_RESULT_FAILURE;
    		}
        }
	} else {
		Sec_RSARawPublicKey public_key;
		memset(&public_key, 0, sizeof(public_key));
		if (SEC_RESULT_SUCCESS != SecKey_ExtractRSAPublicKey(handle, &public_key)) {
			SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
			return SEC_RESULT_FAILURE;
		}

		std::vector<SEC_BYTE> secapi((SEC_BYTE *) &public_key, ((SEC_BYTE *) &public_key) + sizeof(Sec_RSARawPublicKey));

		TestCtx::printHex("secapi", secapi);

		RSA *rsa = TestCreds::asOpenSslRsa(key);
		if (rsa == NULL) {
			SEC_LOG_ERROR("TestCreds::asOpenSslRsa failed");
			return SEC_RESULT_FAILURE;
		}

		memset(&public_key, 0, sizeof(public_key));
		_RSAToPubBinary(rsa, &public_key);
		SEC_RSA_FREE(rsa);

		std::vector<SEC_BYTE> openssl((SEC_BYTE *) &public_key, ((SEC_BYTE *) &public_key) + sizeof(Sec_RSARawPublicKey));
		TestCtx::printHex("openssl", openssl);

		if (secapi != openssl) {
			return SEC_RESULT_FAILURE;
		}
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyGenerate(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecKey_Generate(ctx.proc(), id, keyType, loc)) {
		SEC_LOG_ERROR("SecKey_Generate failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	if (keyType == SEC_KEYTYPE_ECC_NISTP256) {
		Sec_KeyHandle *keyHandle;
		if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id, &keyHandle)) {
			SEC_LOG_ERROR("SecKey_GetInstance failed");
			SecKey_Delete(ctx.proc(), id);
			return SEC_RESULT_FAILURE;
		}

		Sec_ECCRawPublicKey public_key;
		if (SEC_RESULT_SUCCESS != SecKey_ExtractECCPublicKey(keyHandle, &public_key)) {
			SEC_LOG_ERROR("SecKey_ExtractECCPublicKey failed");
			SecKey_Release(keyHandle);
			SecKey_Delete(ctx.proc(), id);
			return SEC_RESULT_FAILURE;
		}

		SecKey_Release(keyHandle);
	}

	SecKey_Delete(ctx.proc(), id);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveHKDF(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_MacAlgorithm macAlgorithm, SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);
	std::vector<SEC_BYTE> salt = TestCtx::random(25);
	TestCtx::printHex("salt", salt);
	std::vector<SEC_BYTE> info = TestCtx::random(17);
	TestCtx::printHex("info", info);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_HKDF(ctx.proc(),
	        id, keyType, loc, macAlgorithm,
	        &nonce[0], &salt[0], salt.size(), &info[0], info.size())) {
		SEC_LOG_ERROR("SecKey_Derive_HKDF failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	SecKey_Delete(ctx.proc(), id);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveConcatKDF(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_DigestAlgorithm digestAlgorithm, SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);
	std::vector<SEC_BYTE> otherInfo = TestCtx::random(17);
	TestCtx::printHex("otherInfo", otherInfo);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_ConcatKDF(ctx.proc(),
	        id, keyType,loc, digestAlgorithm,
	        &nonce[0], &otherInfo[0], otherInfo.size())) {
		SEC_LOG_ERROR("SecKey_Derive_ConcatKDF failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	SecKey_Delete(ctx.proc(), id);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveVendorAes128(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_MacAlgorithm macAlgorithm, SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> input = TestCtx::random(25);
	TestCtx::printHex("input", input);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_VendorAes128(ctx.proc(),
	        id, loc, &input[0], input.size())) {
		SEC_LOG_ERROR("SecKey_Derive_VendorAes128 failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	SecKey_Delete(ctx.proc(), id);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveKeyLadderAes128(SEC_OBJECTID id, Sec_KeyType keyType, Sec_StorageLoc loc, Sec_KeyLadderRoot root, SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<std::vector<SEC_BYTE> > inputs;
	inputs.resize(SecProcessor_GetKeyLadderMaxDepth(ctx.proc(), root));

	if (inputs.size() == 0) {
		SEC_LOG_ERROR("Key ladder not available");
		return SEC_RESULT_FAILURE;
	}

	for (unsigned int i=0; i<inputs.size(); ++i) {
		inputs[i] = TestCtx::random(16);

		char buf[8];
		sprintf(buf, "%d", i);

		std::string name;
		name += "input[";
		name += buf;
		name += "]";
		TestCtx::printHex(name.c_str(), inputs[i]);
	}

	if (SEC_RESULT_SUCCESS != SecKey_Derive_KeyLadderAes128(ctx.proc(), id, loc, root,
			inputs.size() > 0 ? &(inputs[0])[0] : NULL,
			inputs.size() > 1 ? &(inputs[1])[0] : NULL,
			inputs.size() > 2 ? &(inputs[2])[0] : NULL,
			inputs.size() > 3 ? &(inputs[3])[0] : NULL)) {
		SEC_LOG_ERROR("SecKey_Derive_KeyLadderAes128 failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	SecKey_Delete(ctx.proc(), id);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyComputeBaseKeyDigest(SEC_OBJECTID id, Sec_DigestAlgorithm alg) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);

	std::vector<SEC_BYTE> digest;
	digest.resize(SEC_DIGEST_MAX_LEN);
	SEC_SIZE digestLen;

	if (SEC_RESULT_SUCCESS != SecKey_ComputeBaseKeyDigest(ctx.proc(), &nonce[0],
	        alg, &digest[0], &digestLen)) {
		SEC_LOG_ERROR("SecKey_ComputeBaseKeyDigest failed");
		return SEC_RESULT_FAILURE;
	}

	digest.resize(digestLen);
	TestCtx::printHex("digest", digest);

	return SEC_RESULT_SUCCESS;
}

static EC_KEY *_ECCFromDERPriv(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ecc = NULL;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, der_len);
    if (p8 != NULL)
    {
        evp_key = EVP_PKCS82PKEY(p8);
        if (evp_key == NULL)
        {
            SEC_LOG_ERROR("EVP_PKCS82PKEY failed");
            goto done;
        }
    }
    else
    {
        evp_key = d2i_AutoPrivateKey(NULL, &p, der_len);
        if (evp_key == NULL)
        {
            SEC_LOG_ERROR("d2i_AutoPrivateKey failed");
            goto done;
        }
    }

    ecc = EVP_PKEY_get1_EC_KEY(evp_key);
    if (ecc == NULL)
    {
        SEC_LOG_ERROR("EVP_PKEY_get1_EC_KEY failed");
        goto done;
    }

done:
    SEC_EVPPKEY_FREE(evp_key);

    if (p8 != NULL)
    {
        PKCS8_PRIV_KEY_INFO_free(p8);
    }

    return ecc;
}

static EC_KEY *_ECCFromPEMPub(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    ec_key = PEM_read_bio_EC_PUBKEY(bio, &ec_key, _Sec_DisablePassphrasePrompt, NULL);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return ec_key;
}

static EC_KEY *_ECCFromDERPub(SEC_BYTE *der, SEC_SIZE der_len)
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

static EC_KEY *_ECCFromPrivBinary(Sec_ECCRawPrivateKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    // Note that SEC_KEYTYPE_ECC_NISTP256_PUBLIC is not acceptable,
    // because it won't have a private key value
    if (binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp, *prvp;
    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL)
        || ((prvp = BN_CTX_get(ctx)) == NULL))
        goto done;

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                                        BN_bin2bn(binary->x, Sec_BEBytesToUint32(binary->key_len), xp),
                                        BN_bin2bn(binary->y, Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

    EC_KEY_set_private_key(ec_key,
                           BN_bin2bn(binary->prv, Sec_BEBytesToUint32(binary->key_len), prvp));

done:
    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
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

static EC_KEY *_ECCFromPEMPriv(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    ec_key = PEM_read_bio_ECPrivateKey(bio, &ec_key, _Sec_DisablePassphrasePrompt, NULL);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return ec_key;
}

static EC_KEY* _ECCFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc,
                                SEC_BYTE *data, SEC_SIZE data_len)
{ //$$$ could add SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256
    EC_KEY *ec_key = NULL;
    SecUtils_KeyStoreHeader store_header;
    SEC_BYTE store_data[SEC_KEYCONTAINER_MAX_LEN];

    if (kc == SEC_KEYCONTAINER_DER_ECC_NISTP256)
    {
        ec_key = _ECCFromDERPriv(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromDERPriv failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC)
    {
        ec_key = _ECCFromDERPub(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromDERPub failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256)
    {
        if (data_len == sizeof(Sec_ECCRawPrivateKey))
        {
            ec_key = _ECCFromPrivBinary((Sec_ECCRawPrivateKey *) data);
            if (ec_key == NULL)
            {
                SEC_LOG_ERROR("SecUtils_ECCFromPrivBinary failed");
                goto done;
            }
        }
        else
        {
            SEC_LOG_ERROR("Invalid priv key structure size: %d", data_len);
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC)
    {
        if (data_len != sizeof(Sec_ECCRawPublicKey))
        {
            SEC_LOG_ERROR("Invalid pub key structure size: %d", data_len);
            goto done;
        }

        ec_key = _ECCFromPubBinary((Sec_ECCRawPublicKey *) data);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPubBinary failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256)
    {
        ec_key = _ECCFromPEMPriv(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPEMPriv failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC)
    {
        ec_key = _ECCFromPEMPub(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPEMPub failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_STORE)
    {
        if (SEC_RESULT_SUCCESS
            != SecStore_RetrieveData(proc, SEC_FALSE, &store_header,
                                     sizeof(store_header), store_data, sizeof(store_data),
                                     data, data_len))
        {
            SEC_LOG_ERROR("SecStore_RetrieveData failed");
            goto done;
        }

        ec_key = _ECCFromClearKC(proc, (Sec_KeyContainer) store_header.inner_kc_type,
                                         store_data, SecStore_GetDataLen(data));
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("_ECCFromClearKC failed");
            goto done;
        }
    }
    else
    {
        SEC_LOG_ERROR("Unknown container type");
        goto done;
    }

done: return ec_key;
}

Sec_Result testKeyECDHKeyAgreementWithKDF(
		SEC_OBJECTID id_derived,
		SEC_OBJECTID id_priv, TestKey priv, TestKc priv_kc, TestKey pub,
		Sec_KeyType keyType, Sec_StorageLoc loc, Sec_DigestAlgorithm digestAlgorithm,
		SEC_BOOL testEncDec) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *priv_handle = NULL;
	if (NULL == (priv_handle = ctx.provisionKey(id_priv, loc, priv, priv_kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	ProvKey* keyPubRaw = TestCreds::getKey(pub, TESTKC_RAW, SEC_OBJECTID_INVALID);
	EC_KEY* ec_key_pub = _ECCFromClearKC(ctx.proc(), keyPubRaw->kc, &(keyPubRaw->key[0]), keyPubRaw->key.size());
	if (ec_key_pub == NULL) {
		SEC_ECC_FREE(ec_key_pub);
		SEC_LOG_ERROR("_ECCFromClearKC failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_ECCRawPublicKey pub_other;
	if (SEC_RESULT_SUCCESS != _ECCToPubBinary(ec_key_pub, &pub_other)) {
		SEC_ECC_FREE(ec_key_pub);
		SEC_LOG_ERROR("_ECCToPubBinary failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> other_info = TestCtx::random(52);
	TestCtx::printHex("other_info: ", other_info);

	if (SEC_RESULT_SUCCESS != SecKey_ECDHKeyAgreementWithKDF(priv_handle,
			&pub_other, keyType, id_derived, loc,
			SEC_KDF_CONCAT,
	        digestAlgorithm, &other_info[0], other_info.size())) {
		SEC_LOG_ERROR("SecKey_ECDHKeyAgreementWithKDF failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id_derived, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
			SEC_LOG_ERROR("cipherEncDecSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	SecKey_Delete(ctx.proc(), id_derived);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, TestKc baseKc, Sec_KeyType keyType, Sec_StorageLoc loc, SEC_BOOL testEncDec, SEC_BYTE counter, uint32_t L) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	if (NULL == ctx.provisionKey(idBase, loc, TESTKEY_AES128, baseKc)) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//base key
	TestCtx::printHex("baseKey", TestCreds::asOpenSslAes(TESTKEY_AES128));

	//label
	std::vector<SEC_BYTE> otherData = TestCtx::random(10);
	//separator
	otherData.push_back(0);
	//ctx
	std::vector<SEC_BYTE> ctx2 = TestCtx::random(32);
	otherData.insert(otherData.end(), ctx2.begin(), ctx2.end());

	otherData.push_back(0); otherData.push_back(0); otherData.push_back(0); otherData.push_back(0);
	Sec_Uint32ToBEBytes(L, &otherData[otherData.size() - 4]);

	TestCtx::printHex("otherData", otherData);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_CMAC_AES128(ctx.proc(),
	        idDerived, keyType,loc,
	        idBase,
	        &otherData[0], otherData.size(),
	        &counter, 1)) {
		SEC_LOG_ERROR("SecKey_Derive_CMAC_AES128 failed");
		return SEC_RESULT_FAILURE;
	}

	if (testEncDec) {
		if (SecKey_IsAES(keyType)) {
			if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idDerived, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
				SEC_LOG_ERROR("cipherEncDecSingle failed");
				return SEC_RESULT_FAILURE;
			}
		}
	}

	SecKey_Delete(ctx.proc(), idDerived);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveBaseKey(SEC_OBJECTID idDerived, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_BaseKey(ctx.proc(), idDerived, SEC_KEYTYPE_HMAC_128, loc, &nonce[0])) {
		SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
		return SEC_RESULT_FAILURE;
	}

	SecKey_Delete(ctx.proc(), idDerived);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyDeriveHKDFBaseKey(Sec_KeyType typeDerived, Sec_StorageLoc loc, Sec_MacAlgorithm macAlgorithm) {
    Sec_Result res = SEC_RESULT_FAILURE;
    SEC_OBJECTID baseKeyId = SEC_OBJECTID_USER_BASE;
    SEC_OBJECTID idDerived = baseKeyId + 1;
    SEC_OBJECTID idDerivedSecond = idDerived + 1;

	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);

    std::vector<SEC_BYTE> salt = TestCtx::random(20);
    TestCtx::printHex("salt", salt);

    std::vector<SEC_BYTE> info = TestCtx::random(40);
    TestCtx::printHex("info", info);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_BaseKey(ctx.proc(), baseKeyId, SEC_KEYTYPE_HMAC_128, loc, &nonce[0])) {
		SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKey_Derive_HKDF_BaseKey(ctx.proc(), idDerived, typeDerived, loc, macAlgorithm, &salt[0], salt.size(), &info[0], info.size(), baseKeyId)) {
		SEC_LOG_ERROR("SecKey_Derive_HKDF_BaseKey failed");
        goto done;
	}

    //repeat derivation
    if (SEC_RESULT_SUCCESS != SecKey_Derive_BaseKey(ctx.proc(), baseKeyId, SEC_KEYTYPE_HMAC_128, loc, &nonce[0])) {
        SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_Derive_HKDF_BaseKey(ctx.proc(), idDerivedSecond, typeDerived, loc, macAlgorithm, &salt[0], salt.size(), &info[0], info.size(), baseKeyId)) {
        SEC_LOG_ERROR("SecKey_Derive_HKDF_BaseKey failed");
        goto done;
    }

    //test enc/dec or mac
    if (SecKey_IsAES(typeDerived)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idDerived, idDerivedSecond)) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            goto done;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idDerived, idDerivedSecond)) {
            SEC_LOG_ERROR("macCheck failed");
            goto done;
        }
    }

    res = SEC_RESULT_SUCCESS;

done:
	SecKey_Delete(ctx.proc(), baseKeyId);
	SecKey_Delete(ctx.proc(), idDerived);
    SecKey_Delete(ctx.proc(), idDerivedSecond);

	return res;
}

Sec_Result testKeyDeriveConcatKDFBaseKey(Sec_KeyType typeDerived, Sec_StorageLoc loc, Sec_DigestAlgorithm digestAlgorithm) {
    SEC_OBJECTID baseKeyId = SEC_OBJECTID_USER_BASE;
    SEC_OBJECTID idDerived = baseKeyId + 1;
    SEC_OBJECTID idDerivedSecond = idDerived + 1;
    Sec_Result res = SEC_RESULT_FAILURE;

	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> nonce = TestCtx::random(SEC_NONCE_LEN);
	TestCtx::printHex("nonce", nonce);

    std::vector<SEC_BYTE> info = TestCtx::random(40);
    TestCtx::printHex("info", info);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_BaseKey(ctx.proc(), baseKeyId, SEC_KEYTYPE_AES_128, loc, &nonce[0])) {
		SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKey_Derive_ConcatKDF_BaseKey(ctx.proc(), idDerived, typeDerived, loc, digestAlgorithm, &info[0], info.size(), baseKeyId)) {
		SEC_LOG_ERROR("SecKey_Derive_ConcatKDF_BaseKey failed");
		SecKey_Delete(ctx.proc(), baseKeyId);
        goto done;
	}

    //repeat derivation
    if (SEC_RESULT_SUCCESS != SecKey_Derive_BaseKey(ctx.proc(), baseKeyId, SEC_KEYTYPE_AES_128, loc, &nonce[0])) {
        SEC_LOG_ERROR("SecKey_Derive_BaseKey failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_Derive_ConcatKDF_BaseKey(ctx.proc(), idDerivedSecond, typeDerived, loc, digestAlgorithm, &info[0], info.size(), baseKeyId)) {
        SEC_LOG_ERROR("SecKey_Derive_ConcatKDF_BaseKey failed");
        SecKey_Delete(ctx.proc(), baseKeyId);
        goto done;
    }

    //test enc/dec or mac
    if (SecKey_IsAES(typeDerived)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idDerived, idDerivedSecond)) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            goto done;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idDerived, idDerivedSecond)) {
            SEC_LOG_ERROR("macCheck failed");
            goto done;
        }
    }

    res = SEC_RESULT_SUCCESS;

done:
    SecKey_Delete(ctx.proc(), baseKeyId);
    SecKey_Delete(ctx.proc(), idDerived);
    SecKey_Delete(ctx.proc(), idDerivedSecond);

    return res;
}

Sec_Result testExportProvisionedKey(TestKey key, TestKc kc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    //provision encryption key
    Sec_KeyHandle *key_handle = ctx.provisionKey(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, key, kc);
    if (NULL == key_handle) {
        SEC_LOG_ERROR("provisionKey failed");
        return SEC_RESULT_FAILURE;
    }

    //export j-type key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(key_handle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *key_handle_exported;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &key_handle_exported)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    //grab properties from exported
    Sec_KeyProperties exported_props;
    if (SEC_RESULT_SUCCESS != SecKey_GetProperties(key_handle_exported, &exported_props)) {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        return SEC_RESULT_FAILURE;
    }


    return SEC_RESULT_SUCCESS;
}
