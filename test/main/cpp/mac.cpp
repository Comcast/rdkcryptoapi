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

#include "mac.h"
#include "test_ctx.h"
#include <openssl/hmac.h>
#include <openssl/cmac.h>

std::vector<SEC_BYTE> macOpenSSL(
		Sec_MacAlgorithm alg, const std::vector<SEC_BYTE>& openssl_key, const std::vector<SEC_BYTE>& input) {
	std::vector<SEC_BYTE> mac;
	SEC_SIZE mac_len;
	CMAC_CTX *cmac_ctx;

	switch (alg) {
	case SEC_MACALGORITHM_HMAC_SHA1:
		mac.resize(20);
		HMAC(EVP_sha1(),
				&openssl_key[0], openssl_key.size(),
				&input[0], input.size(),
		        &mac[0], &mac_len);
		return mac;

	case SEC_MACALGORITHM_HMAC_SHA256:
		mac.resize(32);
		HMAC(EVP_sha256(),
				&openssl_key[0], openssl_key.size(),
				&input[0], input.size(),
		        &mac[0], &mac_len);
		return mac;

	case SEC_MACALGORITHM_CMAC_AES_128:
	{
		mac.resize(16);
		cmac_ctx = CMAC_CTX_new();
        if (1 != CMAC_Init(cmac_ctx, &openssl_key[0], openssl_key.size(), openssl_key.size() == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), NULL )) {
            SEC_LOG_ERROR("Comcast_CMAC_Init failed");
    		return std::vector<SEC_BYTE>();
        }
        CMAC_Update(cmac_ctx, &input[0], input.size());
        size_t outl;
        CMAC_Final(cmac_ctx, &mac[0], &outl);
        mac_len = outl;
        CMAC_CTX_free(cmac_ctx);
		return mac;
	}
	default:
		break;
	}

	SEC_LOG_ERROR("Unimplemented");
	return std::vector<SEC_BYTE>();
}

std::vector<SEC_BYTE> macOpenSSL(
		Sec_MacAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input) {
	std::vector<SEC_BYTE> mac;
	SEC_SIZE mac_len;
	CMAC_CTX *cmac_ctx;

	std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
	if (openssl_key.size() == 0) {
		SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
		return std::vector<SEC_BYTE>();
	}

	switch (alg) {
	case SEC_MACALGORITHM_HMAC_SHA1:
		mac.resize(20);
		HMAC(EVP_sha1(),
				&openssl_key[0], openssl_key.size(),
				&input[0], input.size(),
		        &mac[0], &mac_len);
		return mac;

	case SEC_MACALGORITHM_HMAC_SHA256:
		mac.resize(32);
		HMAC(EVP_sha256(),
				&openssl_key[0], openssl_key.size(),
				&input[0], input.size(),
		        &mac[0], &mac_len);
		return mac;

	case SEC_MACALGORITHM_CMAC_AES_128:
	{
		mac.resize(16);
		cmac_ctx = CMAC_CTX_new();
        if (1 != CMAC_Init(cmac_ctx, &openssl_key[0], openssl_key.size(), openssl_key.size() == 16 ? EVP_aes_128_cbc() : EVP_aes_256_cbc(), NULL )) {
            SEC_LOG_ERROR("Comcast_CMAC_Init failed");
    		return std::vector<SEC_BYTE>();
        }
        CMAC_Update(cmac_ctx, &input[0], input.size());
        size_t outl;
        CMAC_Final(cmac_ctx, &mac[0], &outl);
        mac_len = outl;
        CMAC_CTX_free(cmac_ctx);
		return mac;
	}
	default:
		break;
	}

	SEC_LOG_ERROR("Unimplemented");
	return std::vector<SEC_BYTE>();
}

std::vector<SEC_BYTE> macSecApi(TestCtx *ctx,
		Sec_MacAlgorithm alg,
		Sec_KeyHandle *key,
		const std::vector<SEC_BYTE>& input,
		const std::vector<SEC_SIZE>& inputSizes) {

	std::vector<SEC_BYTE> output;
	output.resize(SEC_MAC_MAX_LEN);

	SEC_SIZE inputProcessed = 0;
	SEC_SIZE written = 0;

	Sec_MacHandle *mac = ctx->acquireMac(alg, key);
	if (mac == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireMac failed");
		return std::vector<SEC_BYTE>();
	}

	for (unsigned int i=0; i<inputSizes.size(); ++i) {
		if (inputSizes[i] > 0) {
			if (SEC_RESULT_SUCCESS != SecMac_Update(mac, (SEC_BYTE *) &input[inputProcessed],
					inputSizes[i])) {
				SEC_LOG_ERROR("SecMac_Update failed");
				return std::vector<SEC_BYTE>();
			}
		}

		inputProcessed += inputSizes[i];
	}

	if (SEC_RESULT_SUCCESS != ctx->releaseMac(mac, &output[0], &written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	return output;
}

std::vector<SEC_BYTE> macSecApi(TestCtx *ctx,
		Sec_MacAlgorithm alg, Sec_KeyHandle *key, Sec_KeyHandle *payloadKey) {

	std::vector<SEC_BYTE> output;
	output.resize(SEC_MAC_MAX_LEN);;

	SEC_SIZE written = 0;

	Sec_MacHandle *mac = ctx->acquireMac(alg, key);
	if (mac == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireMac failed");
		return std::vector<SEC_BYTE>();
	}

	if (SEC_RESULT_SUCCESS != SecMac_UpdateWithKey(mac, payloadKey)) {
		SEC_LOG_ERROR("SecDigest_Update failed");
		return std::vector<SEC_BYTE>();
	}

	if (SEC_RESULT_SUCCESS != ctx->releaseMac(mac, &output[0], &written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	return output;
}

Sec_Result testMacOverKey(Sec_MacAlgorithm alg, SEC_OBJECTID id_mac, TestKey keyMac, TestKc kc, SEC_OBJECTID id_payload, TestKey keyPayload, Sec_StorageLoc loc) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *keyHandleMac = NULL;
	if (NULL == (keyHandleMac = ctx.provisionKey(id_mac, loc, keyMac, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *keyHandlePayload = NULL;

	if ((TestCreds::supports(CAPABILITY_HMAC_OVER_HWKEY) && alg != SEC_MACALGORITHM_CMAC_AES_128)
		|| (TestCreds::supports(CAPABILITY_CMAC_OVER_HWKEY) && alg == SEC_MACALGORITHM_CMAC_AES_128)) {
		if (NULL == (keyHandlePayload = ctx.provisionKey(id_payload, loc, keyPayload, TESTKC_RAW))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (NULL == (keyHandlePayload = ctx.provisionKey(id_payload, loc, keyPayload, TESTKC_RAW, SEC_TRUE))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	}

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(keyPayload);
	TestCtx::printHex("key", clear);

	//mac
	std::vector<SEC_BYTE> macSA = macSecApi(&ctx, alg, keyHandleMac, keyHandlePayload);
	TestCtx::printHex("macSecApi", macSA);

	std::vector<SEC_BYTE> macOS = macOpenSSL(alg, keyMac, clear);
	TestCtx::printHex("macOpenssl", macOS);

	//check if results match
	if (macSA != macOS || macSA.size() == 0) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testMacSingle(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_MacAlgorithm alg, SEC_SIZE inputSize) {
	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	return testMacMult(id, key, kc, loc, alg, inputSizes);
}

Sec_Result testMacMult(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_MacAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *keyHandle = NULL;
	if (NULL == (keyHandle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//mac
	std::vector<SEC_BYTE> macSA = macSecApi(&ctx, alg, keyHandle, clear, inputSizes);
	TestCtx::printHex("macSecApi", macSA);

	std::vector<SEC_BYTE> macOS = macOpenSSL(alg, key, clear);
	TestCtx::printHex("macOpenssl", macOS);

	//check if results match
	if (macSA != macOS) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result macCheck(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg, SEC_OBJECTID id, SEC_BYTE *key, SEC_SIZE key_len) {
	std::vector<SEC_BYTE> mac_secapi;
	mac_secapi.resize(SEC_MAC_MAX_LEN);
	SEC_SIZE mac_len;

	std::vector<SEC_BYTE> clear = TestCtx::random(256);
	TestCtx::printHex("clear", clear);

	if (SEC_RESULT_SUCCESS != SecMac_SingleInputId(proc, alg, id, &clear[0], clear.size(), &mac_secapi[0], &mac_len)) {
		SEC_LOG_ERROR("SecMac_SingleInputId failed");
		return SEC_RESULT_FAILURE;
	}
	
	mac_secapi.resize(mac_len);
	TestCtx::printHex("macSecApi", mac_secapi);

	std::vector<SEC_BYTE> openssl_key = std::vector<SEC_BYTE> (key, key + key_len);

	std::vector<SEC_BYTE> macOS = macOpenSSL(alg, openssl_key, clear);
	TestCtx::printHex("macOpenssl", macOS);

	//check if results match
	if (mac_secapi != macOS) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
