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

#include "jtype.h"
#include "mac.h"
#include "test_ctx.h"
#include "sec_security_comcastids.h"
#include "cipher.h"
#include "sec_security_utils.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

std::string toB64(SEC_BYTE *data, SEC_SIZE len) {
	std::string res;
	SEC_SIZE res_len;
	res.resize(SEC_KEYCONTAINER_MAX_LEN);

    if (SEC_RESULT_SUCCESS != SecUtils_Base64Encode((const SEC_BYTE*) data, len, (SEC_BYTE *) res.data(), res.size(), &res_len)) {
        SEC_LOG_ERROR("SecSrv_B64Encode failed");
        return "";
    }

    res.resize(res_len);

    return res;
}

std::string createJTypeHeader(const char *kid, const char *alg) {
	std::string res;

	res += "{\"kid\":\"";
	res += kid;
	res += "\",\"alg\":\"";
	res += alg;
	res += "\"}";

	return toB64((SEC_BYTE*) res.c_str(), res.size());
}

std::string createJTypeBodyV1(const char *contentKey, const char *contentKeyId, const char *contentKeyRights, SEC_BOOL cachable, int contentKeyUsage, const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter) {
	std::string res;
	char tmp[4096];

	res += "{\"contentKeyNotOnOrAfter\":\"";
	res += contentKeyNotOnOrAfter;

	res += "\",\"contentKey\":\"";
	res += contentKey;

	res += "\",\"contentKeyId\":\"";
	res += contentKeyId;

	res += "\",\"contentKeyRights\":\"";
	res += contentKeyRights;

	res += "\",\"contentKeyCacheable\":";
	res += (cachable ? "true" : "false");

	sprintf(tmp, "%d", contentKeyUsage);

	res += ",\"contentKeyUsage\":";
	res += tmp;

	res += ",\"contentKeyNotBefore\":\"";
	res += contentKeyNotBefore;

	res += "\"}";

	return toB64((SEC_BYTE*) res.c_str(), res.size());
}

std::string createJTypeBodyV2(const char *contentKey, const char *contentKeyId, const char *contentKeyRights, SEC_BOOL cachable, int contentKeyUsage, const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter, int cklen, const char *alg, const char *iv) {
    std::string res;
    char tmp[4096];

    res += "{";

    res += "\"contentKeyContainerVersion\":2";

    res += ",\"contentKeyNotOnOrAfter\":\"";
    res += contentKeyNotOnOrAfter;

    res += "\",\"contentKey\":\"";
    res += contentKey;

    res += "\",\"contentKeyId\":\"";
    res += contentKeyId;

    res += "\",\"contentKeyRights\":\"";
    res += contentKeyRights;

    res += "\",\"contentKeyCacheable\":";
    res += (cachable ? "true" : "false");

    sprintf(tmp, "%d", contentKeyUsage);

    res += ",\"contentKeyUsage\":";
    res += tmp;

    res += ",\"contentKeyNotBefore\":\"";
    res += contentKeyNotBefore;

    res += "\",\"contentKeyLength\":";
    sprintf(tmp, "%d", cklen);
    res += tmp;
    res += "";

    res += ",\"contentKeyTransportAlgorithm\":\"";
    res += alg;

    if (iv != NULL) {
        res += "\",\"contentKeyTransportIv\":\"";
        res += iv;
    }

    res += "\"}";

    return toB64((SEC_BYTE*) res.c_str(), res.size());
}

std::string createContentKeyV1(TestKey contentKey, TestKey encryptionKey) {
	std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
	if (conK.size() == 0) {
		SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
		return std::string();
	}

    if (conK.size() != 16) {
        SEC_LOG_ERROR("V1 Jtype cannot support keys that are not 128 bits");
        return std::string();
    }

	std::vector<SEC_BYTE> encK = TestCreds::asOpenSslAes(encryptionKey);
	if (encK.size() == 0) {
		SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
		return std::string();
	}

	std::vector<SEC_BYTE> encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, NULL, conK);
    if (encConK.empty()) {
        SEC_LOG_ERROR("opensslAesEcb failed");
        return std::string();
    }

	return toB64(encConK.data(), encConK.size());
}

std::string createContentKeyV2(TestKey contentKey, TestKey encryptionKey, Sec_CipherAlgorithm alg, SEC_BYTE *iv) {
    std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
    if (conK.size() == 0) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return std::string();
    }

    std::vector<SEC_BYTE> encK = TestCreds::asOpenSslAes(encryptionKey);
    if (encK.size() == 0) {
        SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
        return std::string();
    }

    std::vector<SEC_BYTE> encConK;

    if (alg == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING) {
        encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, iv, conK);
        if (encConK.empty()) {
            SEC_LOG_ERROR("opensslAesEcb failed");
            return std::string();
        }
    } else if (alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING) {
        encConK = opensslAesEcb(encryptionKey, SEC_CIPHERMODE_ENCRYPT, SEC_TRUE, iv, conK);
        if (encConK.empty()) {
            SEC_LOG_ERROR("opensslAesEcb failed");
            return std::string();
        }
    } else {
        SEC_LOG_ERROR("Unexpected algorithm encountered: %d", alg);
    }

    return toB64(encConK.data(), encConK.size());
}

std::string createJTypeMac(const std::string& header, const std::string& body, TestKey macKey) {
	std::string data = header + "." + body;
	std::vector<SEC_BYTE> input((SEC_BYTE *) data.data(), (SEC_BYTE *) (data.data()+data.size()));
	std::vector<SEC_BYTE> mac = macOpenSSL(SEC_MACALGORITHM_HMAC_SHA256, macKey, input);
	return toB64(mac.data(), mac.size());
}

std::string createJTypeContainer(const char *kid, const char *macalg,
	TestKey contentKey, TestKey encryptionKey, const char *contentKeyId, const char *contentKeyRights, SEC_BOOL cachable, int contentKeyUsage, const char* contentKeyNotBefore, const char* contentKeyNotOnOrAfter,
	TestKey macKey, int version, const char *alg) {

	std::string header_b64 = createJTypeHeader(kid, macalg);
	if (header_b64.size() == 0) {
		SEC_LOG_ERROR("createJTypeHeader failed");
		return std::string();
	}

    std::string body_b64;
    if (version == 1) {
        std::string encConK = createContentKeyV1(contentKey, encryptionKey);
        if (encConK.empty()) {
            SEC_LOG_ERROR("createContentKeyV1 failed");
            return std::string();
        }

        body_b64 = createJTypeBodyV1(encConK.c_str(), contentKeyId, contentKeyRights, cachable, contentKeyUsage, contentKeyNotBefore, contentKeyNotOnOrAfter);
        if (body_b64.size() == 0) {
            SEC_LOG_ERROR("createJTypeBody failed");
            return std::string();
        }
    } else if (version == 2) {
        Sec_CipherAlgorithm salg = SEC_CIPHERALGORITHM_NUM;
        if (strcmp(alg, "aesEcbNone") == 0) {
            salg = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
        } else if (strcmp(alg, "aesEcbPkcs5") == 0) {
            salg = SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
        } else {
            SEC_LOG_ERROR("Unknown algorithm encountered: %s", alg);
            return std::string();
        }

        std::string encConK = createContentKeyV2(contentKey, encryptionKey, salg, NULL);
        if (encConK.empty()) {
            SEC_LOG_ERROR("createContentKeyV2 failed");
            return std::string();
        }

        std::vector<SEC_BYTE> conK = TestCreds::asOpenSslAes(contentKey);
        if (conK.size() == 0) {
            SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
            return std::string();
        }

        body_b64 = createJTypeBodyV2(encConK.c_str(), contentKeyId, contentKeyRights, cachable, contentKeyUsage, contentKeyNotBefore, contentKeyNotOnOrAfter, conK.size(), alg, NULL);
        if (body_b64.size() == 0) {
            SEC_LOG_ERROR("createJTypeBody failed");
            return std::string();
        }
    } else {
        SEC_LOG_ERROR("Unknown version encountered: %d", version);
            return std::string();
    }

	std::string mac_b64 = createJTypeMac(header_b64, body_b64, macKey);
	if (mac_b64.size() == 0) {
		SEC_LOG_ERROR("createJTypeMac failed");
		return std::string();
	}

	return header_b64 + "." + body_b64 + "." + mac_b64;
}

Sec_Result testProvisionJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc, int version, const char *alg) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
		contentKey, encryptionKey,
		"9c621060-3a17-4813-8dcb-2e9187aaa903",
		createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
        SEC_FALSE, 1,
		"2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
		macKey, version, alg);
	if (jtype.size() == 0) {
		SEC_LOG_ERROR("createJTypeContainer failed");
		return SEC_RESULT_FAILURE;
	}

	//provision encryption key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM, encryptionKey, encKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provision maccing key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, macKey, macKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provsion j-type key
	if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
	        SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
	        (SEC_BYTE *) &jtype[0], jtype.size())) {
		SEC_LOG_ERROR("SecKey_Provision failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testExportKey(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc, Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char *calg) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
		contentKey, encryptionKey,
		"9c621060-3a17-4813-8dcb-2e9187aaa903",
		createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
        SEC_TRUE, 1,
		"2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
		macKey, version, calg);
	if (jtype.size() == 0) {
		SEC_LOG_ERROR("createJTypeContainer failed");
		return SEC_RESULT_FAILURE;
	}

	//provision encryption key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM, encryptionKey, encKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provision maccing key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM, macKey, macKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provsion j-type key
	if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
	        SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
	        (SEC_BYTE *) &jtype[0], jtype.size())) {
		SEC_LOG_ERROR("SecKey_Provision failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *key_handle;
	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &key_handle)) {
		SEC_LOG_ERROR("SecKey_GetInstance failed");
		return SEC_RESULT_FAILURE;
	}

	//get properties from j-type
	Sec_KeyProperties jtype_props;
	if (SEC_RESULT_SUCCESS != SecKey_GetProperties(key_handle, &jtype_props)) {
		SEC_LOG_ERROR("SecKey_GetProperties failed");
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

	if (memcmp(&jtype_props, &exported_props, sizeof(Sec_KeyProperties)) != 0) {
		SEC_LOG_ERROR("Key properties on jtype and exported container do not match");
		return SEC_RESULT_FAILURE;
	}

	//test exported encryption
	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, SEC_OBJECTID_USER_BASE, alg, input_len)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

std::string createDefaultRights(Sec_KeyType kt) {
    Sec_KeyProperties props;
    SecKeyProperties_SetDefault(&props, kt);

    return toB64(props.rights, sizeof(props.rights));
}

Sec_Result testDecryptJType(TestKey contentKey, TestKey encryptionKey, TestKc encKc, TestKey macKey, TestKc macKc, Sec_CipherAlgorithm alg, SEC_SIZE input_len, int version, const char *salg) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
		contentKey, encryptionKey,
		"9c621060-3a17-4813-8dcb-2e9187aaa903",
		createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
        SEC_FALSE, 1,
		"2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
		macKey, version, salg);
	if (jtype.size() == 0) {
		SEC_LOG_ERROR("createJTypeContainer failed");
		return SEC_RESULT_FAILURE;
	}

    Sec_StorageLoc loc = SEC_STORAGELOC_RAM;

	//provision encryption key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, loc, encryptionKey, encKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provision maccing key
	if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, loc, macKey, macKc)) {
		SEC_LOG_ERROR("provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	//provision jtype key
	if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
	        SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
	        (SEC_BYTE *) &jtype[0], jtype.size())) {
		SEC_LOG_ERROR("SecKey_Provision failed");
		return SEC_RESULT_FAILURE;
	}

	//test encryption
	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, SEC_OBJECTID_USER_BASE, alg, input_len)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
