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

#include "digest.h"
#include "test_ctx.h"
#include <openssl/sha.h>

std::vector<SEC_BYTE> digestOpenSSL(
		Sec_DigestAlgorithm alg, const std::vector<SEC_BYTE>& input) {
	std::vector<SEC_BYTE> digest;

	switch (alg) {
	case SEC_DIGESTALGORITHM_SHA1:
		digest.resize(20);
		SHA1(&input[0], input.size(), &digest[0]);
		return digest;

	case SEC_DIGESTALGORITHM_SHA256:
		digest.resize(32);
		SHA256(&input[0], input.size(), &digest[0]);
		return digest;

	default:
		break;
	}

	SEC_LOG_ERROR("Unimplemented");
	return std::vector<SEC_BYTE>();
}

std::vector<SEC_BYTE> digestSecApi(TestCtx *ctx,
		Sec_DigestAlgorithm alg,
		const std::vector<SEC_BYTE>& input,
		const std::vector<SEC_SIZE>& inputSizes) {

	std::vector<SEC_BYTE> output;
	output.resize(SEC_DIGEST_MAX_LEN);;

	SEC_SIZE inputProcessed = 0;
	SEC_SIZE written = 0;

	Sec_DigestHandle *digest = ctx->acquireDigest(alg);
	if (digest == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireDigest failed");
		return std::vector<SEC_BYTE>();
	}

	for (unsigned int i=0; i<inputSizes.size(); ++i) {
		if (inputSizes[i] > 0) {
			if (SEC_RESULT_SUCCESS != SecDigest_Update(digest, (SEC_BYTE *) &input[inputProcessed],
					inputSizes[i])) {
				SEC_LOG_ERROR("SecDigest_Update failed");
				return std::vector<SEC_BYTE>();
			}
		}

		inputProcessed += inputSizes[i];
	}

	//last input
	if (SEC_RESULT_SUCCESS != ctx->releaseDigest(digest, &output[0], &written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	return output;
}

std::vector<SEC_BYTE> digestSecApi(TestCtx *ctx,
		Sec_DigestAlgorithm alg, Sec_KeyHandle *key) {

	std::vector<SEC_BYTE> output;
	output.resize(SEC_DIGEST_MAX_LEN);;

	SEC_SIZE written = 0;

	Sec_DigestHandle *digest = ctx->acquireDigest(alg);
	if (digest == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireDigest failed");
		return std::vector<SEC_BYTE>();
	}

	if (SEC_RESULT_SUCCESS != SecDigest_UpdateWithKey(digest, key)) {
		SEC_LOG_ERROR("SecDigest_Update failed");
		return std::vector<SEC_BYTE>();
	}

	if (SEC_RESULT_SUCCESS != ctx->releaseDigest(digest, &output[0], &written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	return output;
}

Sec_Result testDigestOverKey(Sec_DigestAlgorithm alg, SEC_OBJECTID id, TestKey key, Sec_StorageLoc loc) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *keyHandle = NULL;

	if (TestCreds::supports(CAPABILITY_DIGEST_OVER_HWKEY)) {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, key, TESTKC_RAW))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, key, TESTKC_RAW, SEC_TRUE))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	}

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);
	TestCtx::printHex("key", clear);

	//digest
	std::vector<SEC_BYTE> digestSA = digestSecApi(&ctx, alg, keyHandle);
	TestCtx::printHex("digestSecApi", digestSA);

	std::vector<SEC_BYTE> digestOS = digestOpenSSL(alg, clear);
	TestCtx::printHex("digestOpenssl", digestOS);

	//check if results match
	if (digestSA != digestOS) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testDigestSingle(
		Sec_DigestAlgorithm alg, SEC_SIZE inputSize) {
	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	return testDigestMult(alg, inputSizes);
}

Sec_Result testDigestMult(
		Sec_DigestAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//digest
	std::vector<SEC_BYTE> digestSA = digestSecApi(&ctx, alg, clear, inputSizes);
	TestCtx::printHex("digestSecApi", digestSA);

	std::vector<SEC_BYTE> digestOS = digestOpenSSL(alg, clear);
	TestCtx::printHex("digestOpenssl", digestOS);

	//check if results match
	if (digestSA != digestOS) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
