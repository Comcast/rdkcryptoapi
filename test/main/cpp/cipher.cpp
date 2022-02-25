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

#include "cipher.h"
#include "test_ctx.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static std::vector<SEC_BYTE> opensslAesCbc(
		TestKey key, Sec_CipherMode mode, SEC_BOOL padding,
		SEC_BYTE *iv, const std::vector<SEC_BYTE>& input) {

	std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
	if (openssl_key.size() == 0) {
		SEC_LOG_ERROR("TestCreds::asOpenSslAes failed");
		return std::vector<SEC_BYTE>();
	}
    const EVP_CIPHER *evp_cipher = NULL;
    if (openssl_key.size() == 16) {
    	evp_cipher = EVP_aes_128_cbc();
    } else {
    	evp_cipher = EVP_aes_256_cbc();
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX evp_ctx;
    EVP_CIPHER_CTX_init(&evp_ctx);
    EVP_CIPHER_CTX *p_evp_ctx = &evp_ctx;
#else
    EVP_CIPHER_CTX *p_evp_ctx = EVP_CIPHER_CTX_new();
#endif

    if (1 != EVP_CipherInit_ex(p_evp_ctx, evp_cipher, NULL,
                    NULL, NULL, (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CIPHER_CTX_set_padding(p_evp_ctx, padding))
    {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CipherInit_ex(p_evp_ctx, NULL, NULL, &openssl_key[0], iv,
                    (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

	std::vector<SEC_BYTE> output;
    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;

    if (1 != EVP_CipherUpdate(p_evp_ctx, &output[0], &outlen, &input[0], input.size()))
    {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;
    outlen = 0;

    if (1 != EVP_CipherFinal_ex(p_evp_ctx, &output[written], &outlen))
    {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;

    output.resize(written);

    return output;
}

std::vector<SEC_BYTE> opensslAesEcb(
		std::vector<SEC_BYTE> openssl_key, Sec_CipherMode mode, SEC_BOOL padding,
		SEC_BYTE *iv, const std::vector<SEC_BYTE>& input) {
	std::vector<SEC_BYTE> output;
    const EVP_CIPHER *evp_cipher;

    if (openssl_key.size() == 16) {
    	evp_cipher = (EVP_CIPHER *) EVP_aes_128_ecb();
    } else {
    	evp_cipher = (EVP_CIPHER *) EVP_aes_256_ecb();
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX evp_ctx;
    EVP_CIPHER_CTX_init(&evp_ctx);
    EVP_CIPHER_CTX *p_evp_ctx = &evp_ctx;
#else
    EVP_CIPHER_CTX *p_evp_ctx = EVP_CIPHER_CTX_new();
#endif

    if (1 != EVP_CipherInit_ex(p_evp_ctx, evp_cipher, NULL,
                    NULL, NULL, (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CIPHER_CTX_set_padding(p_evp_ctx, padding))
    {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CipherInit_ex(p_evp_ctx, NULL, NULL, &openssl_key[0], iv,
                    (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;
    if (1 != EVP_CipherUpdate(p_evp_ctx, &output[0], &outlen, &input[0], input.size()))
    {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;
    outlen = 0;

    if (1 != EVP_CipherFinal_ex(p_evp_ctx, &output[written], &outlen))
    {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;

    output.resize(written);

    return output;
}

std::vector<SEC_BYTE> opensslAesEcb(
		TestKey key, Sec_CipherMode mode, SEC_BOOL padding,
		SEC_BYTE *iv, const std::vector<SEC_BYTE>& input) {
	std::vector<SEC_BYTE> output;
	std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
    const EVP_CIPHER *evp_cipher;

    if (openssl_key.size() == 16) {
    	evp_cipher = (EVP_CIPHER *) EVP_aes_128_ecb();
    } else {
    	evp_cipher = (EVP_CIPHER *) EVP_aes_256_ecb();
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX evp_ctx;
    EVP_CIPHER_CTX_init(&evp_ctx);
    EVP_CIPHER_CTX *p_evp_ctx = &evp_ctx;
#else
    EVP_CIPHER_CTX *p_evp_ctx = EVP_CIPHER_CTX_new();
#endif

    if (1 != EVP_CipherInit_ex(p_evp_ctx, evp_cipher, NULL,
                    NULL, NULL, (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CIPHER_CTX_set_padding(p_evp_ctx, padding))
    {
        SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
        return std::vector<SEC_BYTE>();
    }

    if (1 != EVP_CipherInit_ex(p_evp_ctx, NULL, NULL, &openssl_key[0], iv,
                    (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0))
    {
        SEC_LOG_ERROR("EVP_CipherInit failed");
        return std::vector<SEC_BYTE>();
    }

    output.resize(input.size() + SEC_AES_BLOCK_SIZE);

    SEC_SIZE written = 0;
    int outlen = 0;
    if (1 != EVP_CipherUpdate(p_evp_ctx, &output[0], &outlen, &input[0], input.size()))
    {
        SEC_LOG_ERROR("EVP_CipherUpdate failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;
    outlen = 0;

    if (1 != EVP_CipherFinal_ex(p_evp_ctx, &output[written], &outlen))
    {
        SEC_LOG_ERROR("EVP_CipherFinal failed");
        return std::vector<SEC_BYTE>();
    }
    written += outlen;

    output.resize(written);

    return output;
}

static size_t bytesToProcessToRollover(uint64_t ctr, size_t inputLen) {
    uint64_t maxBlocksToProcess = (ctr == 0) ? UINT64_MAX : (UINT64_MAX - ctr + 1);
    uint64_t inputBlocks = inputLen/SEC_AES_BLOCK_SIZE + (inputLen%SEC_AES_BLOCK_SIZE > 0) ? 1 : 0;
    uint64_t blocksToProcess = SEC_MIN(inputBlocks, maxBlocksToProcess);

    return SEC_MIN(inputLen, (size_t) blocksToProcess * SEC_AES_BLOCK_SIZE);
}

static std::vector<SEC_BYTE> opensslAesCtr(
		TestKey key, Sec_CipherMode mode,
		SEC_BYTE *iv, const std::vector<SEC_BYTE>& input) {

    //store nonce
    SEC_BYTE nonce[8];
    memcpy(nonce, iv, 8);

    SEC_BYTE ivToUse[SEC_AES_BLOCK_SIZE];
    memcpy(ivToUse, iv, SEC_AES_BLOCK_SIZE);

	std::vector<SEC_BYTE> output;
    output.resize(input.size());

	std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);

    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_init(evp_ctx);

    uint64_t ctr = Sec_BEBytesToUint64(&ivToUse[8]);
    size_t idx = 0;
    while (size_t bytesToProcess = bytesToProcessToRollover(ctr, input.size() - idx)) {
        if (1 != EVP_CipherInit_ex(evp_ctx, (openssl_key.size() == 16) ? EVP_aes_128_ctr() : EVP_aes_256_ctr(), NULL,
                            &openssl_key[0], ivToUse, (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) ? 1 : 0)) {
            SEC_LOG_ERROR("EVP_CipherInit_ex failed");
    		return std::vector<SEC_BYTE>();
        }

        int out_len = bytesToProcess;
        if (1 != EVP_CipherUpdate(evp_ctx, &output[idx], &out_len, &input[idx], bytesToProcess)) {
            SEC_LOG_ERROR("EVP_CipherUpdate failed");
            return std::vector<SEC_BYTE>();
        }

        if (1 != EVP_CipherFinal_ex(evp_ctx, &output[output.size()], &out_len)) {
            SEC_LOG_ERROR("EVP_CipherFinal failed");
            return std::vector<SEC_BYTE>();
        }

        //increment ctr
        size_t blocksProcessed = bytesToProcess/SEC_AES_BLOCK_SIZE;
        ctr += blocksProcessed;
        idx += bytesToProcess;

        //set the new iv
        memcpy(ivToUse, nonce, 8);
        Sec_Uint64ToBEBytes(ctr, &ivToUse[8]);

    }

    return output;
}

static std::vector<SEC_BYTE> opensslRsaCrypt(
		TestKey key, Sec_CipherAlgorithm algorithm, Sec_CipherMode mode,
		const std::vector<SEC_BYTE>& input) {

	RSA *rsa = TestCreds::asOpenSslRsa(key);
	if (rsa == NULL) {
		SEC_LOG_ERROR("TestCreds::asOpenSslRsa failed");
		return std::vector<SEC_BYTE>();
	}

    int padding;
    if (algorithm == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }

    int openssl_res;
    std::vector<SEC_BYTE> output;
    output.resize(RSA_size(rsa));

    if (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM) {
        openssl_res = RSA_public_encrypt(input.size(), &input[0], &output[0],
                rsa, padding);
    } else {
        openssl_res = RSA_private_decrypt(input.size(), &input[0], &output[0],
                rsa, padding);
    }

    SEC_RSA_FREE(rsa);

    if (openssl_res < 0)
    {
        SEC_LOG_ERROR("%s", ERR_error_string(ERR_get_error(), NULL));
		return std::vector<SEC_BYTE>();
    }

    output.resize(openssl_res);

    return output;
}

std::vector<SEC_BYTE> cipherOpenSSL(
		TestKey key, Sec_CipherAlgorithm alg, Sec_CipherMode mode,
		SEC_BYTE *iv, const std::vector<SEC_BYTE>& input) {

	switch (alg) {
	case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
		return opensslAesCbc(key, mode, alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, iv, input);

	case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
		return opensslAesEcb(key, mode, alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, iv, input);

	case SEC_CIPHERALGORITHM_AES_CTR:
		return opensslAesCtr(key, mode, iv, input);

	case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
	case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
		return opensslRsaCrypt(key, alg, mode, input);

	default:
		break;
	}

	SEC_LOG_ERROR("Unimplemented");
	return std::vector<SEC_BYTE>();
}

std::vector<SEC_BYTE> cipherSecApi(TestCtx *ctx, Sec_KeyHandle *key_handle,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode,
		const std::vector<SEC_BYTE>& iv,
		const std::vector<SEC_BYTE>& input,
		const std::vector<SEC_SIZE>& inputSizes,
		SEC_BOOL inplace) {

	std::vector<SEC_BYTE> output = input;
	output.resize(input.size() + 4096);

	SEC_SIZE inputProcessed = 0;
	SEC_SIZE outputWritten = 0;
	SEC_SIZE written = 0;

	Sec_CipherHandle *cipher = ctx->acquireCipher(alg, mode, key_handle, (SEC_BYTE *) &iv[0]);
	if (cipher == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireCipher failed");
		return std::vector<SEC_BYTE>();
	}

	for (unsigned int i=0; i<inputSizes.size()-1; ++i) {
		if (inputSizes[i] > 0) {
			if (SEC_RESULT_SUCCESS != SecCipher_Process(cipher,
					inplace ? ((SEC_BYTE *) &output[inputProcessed]) : ((SEC_BYTE *) &input[inputProcessed]),
					inputSizes[i], SEC_FALSE, (SEC_BYTE *) &output[outputWritten], output.size() - outputWritten,
					&written)) {
				SEC_LOG_ERROR("SecCipher_Process failed");
				return std::vector<SEC_BYTE>();
			}

			outputWritten += written;
		}

		inputProcessed += inputSizes[i];
	}

	//last input
	if (SEC_RESULT_SUCCESS != SecCipher_Process(cipher,
			inplace ? (SEC_BYTE *) &output[inputProcessed] : (SEC_BYTE *) &input[inputProcessed],
			input.size() - inputProcessed, SEC_TRUE, (SEC_BYTE *) &output[outputWritten], output.size() - outputWritten,
			&written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	outputWritten += written;

	output.resize(outputWritten);

	ctx->releaseCipher(cipher);

	return output;
}

std::vector<SEC_BYTE> cipherSecApiSingle(TestCtx *ctx, Sec_KeyHandle *key_handle,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode,
		const std::vector<SEC_BYTE>& iv,
		const std::vector<SEC_BYTE>& input,
		SEC_BOOL inplace) {

	std::vector<SEC_BYTE> output = input;
	output.resize(input.size() + 4096);

	SEC_SIZE written = 0;

	Sec_CipherHandle *cipher = ctx->acquireCipher(alg, mode, key_handle, (SEC_BYTE *) &iv[0]);
	if (cipher == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireCipher failed");
		return std::vector<SEC_BYTE>();
	}

	if (SEC_RESULT_SUCCESS != SecCipher_Process(cipher,
			inplace ? ((SEC_BYTE *) &output[0]) : ((SEC_BYTE *) &input[0]),
			input.size(), SEC_TRUE, (SEC_BYTE *) &output[0], output.size(),
			&written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	ctx->releaseCipher(cipher);

	return output;
}

std::vector<SEC_BYTE> cipherSecApiSingle(TestCtx *ctx, Sec_CipherHandle *cipher_handle, const std::vector<SEC_BYTE>& iv,
		const std::vector<SEC_BYTE>& input, SEC_BOOL inplace) {

	std::vector<SEC_BYTE> output = input;
	output.resize(input.size() + 4096);

	SEC_SIZE written = 0;

	if (iv.size() > 0) {
		if (SEC_RESULT_SUCCESS != SecCipher_UpdateIV(cipher_handle, (SEC_BYTE *) &iv[0])) {
			SEC_LOG_ERROR("SecCipher_UpdateIV failed");
			return std::vector<SEC_BYTE>();
		}
	}

	if (SEC_RESULT_SUCCESS != SecCipher_Process(cipher_handle,
			inplace ? ((SEC_BYTE *) &output[0]) : ((SEC_BYTE *) &input[0]),
			input.size(), SEC_FALSE, (SEC_BYTE *) &output[0], output.size(),
			&written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	output.resize(written);

	return output;
}

Sec_Result testCipherSingle(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	return testCipherMult(id, key, kc, loc, alg, mode, inputSizes, inplace);
}

Sec_Result testCtrRollover(
        SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

    std::vector<SEC_SIZE> inputSizes;
    inputSizes.resize(3);
    inputSizes[0] = 16;
    inputSize -= inputSizes[0];
    inputSizes[1] = 16;
    inputSize -= inputSizes[1];
    inputSizes[2] = inputSize;

    return testCipherMult(id, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, mode, inputSizes, inplace, SEC_TRUE);
}

Sec_Result testCipherSingle(
		SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	return testCipherMult(id, pub, priv, kc, loc, alg, mode, inputSizes, inplace);
}

Sec_Result testCipherMult(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace, SEC_BOOL testRolloverCtr) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = NULL;
	if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(key);
	TestCtx::printHex("key", openssl_key);

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    if (alg == SEC_CIPHERALGORITHM_AES_CTR && testRolloverCtr) {
        //set iv to rollover
        memset(&iv[8], 0xff, 8);
    }

	TestCtx::printHex("iv", iv);

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted;
	if (testEncrypt) {
		encrypted = cipherSecApi(&ctx, handle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, inputSizes, inplace);
	} else {
		//use openssl to encrypt
		encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
	}

	TestCtx::printHex("encrypted", encrypted);

	//decrypt
	std::vector<SEC_BYTE> decrypted;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
	} else {
		//use sec api to decrypt
		decrypted = cipherSecApi(&ctx, handle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inputSizes, inplace);
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherMult(
		SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	Sec_KeyHandle *keyHandle = NULL;
	if (testEncrypt) {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, pub, kc))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (NULL == (keyHandle = ctx.provisionKey(id, loc, priv, kc))) {
			SEC_LOG_ERROR("TestCtx.provision failed");
			return SEC_RESULT_FAILURE;
		}
	}

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv", iv);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted;
	if (testEncrypt) {
		encrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, inputSizes, inplace);
	} else {
		//use openssl to encrypt
		encrypted = cipherOpenSSL(pub, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
	}

	TestCtx::printHex("encrypted", encrypted);

	//decrypt
	std::vector<SEC_BYTE> decrypted;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted = cipherOpenSSL(priv, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
	} else {
		//use sec api to decrypt
		decrypted = cipherSecApi(&ctx, keyHandle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inputSizes, inplace);
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecSingle(TestCtx *ctx, SEC_OBJECTID id,
		Sec_CipherAlgorithm alg, SEC_SIZE inputSize, SEC_BOOL inplace) {

	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	Sec_Result res = cipherEncDecMult(ctx, id, alg, inputSizes, inplace);
	if (res != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("cipherEncDecMult failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecSingle(TestCtx *ctx, SEC_OBJECTID id_pub, SEC_OBJECTID id_priv,
		Sec_CipherAlgorithm alg, SEC_SIZE inputSize, SEC_BOOL inplace) {

	std::vector<SEC_SIZE> inputSizes;
	inputSizes.resize(1);
	inputSizes[0] = inputSize;

	Sec_Result res = cipherEncDecMult(ctx, id_pub, id_priv, alg, inputSizes, inplace);
	if (res != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("cipherEncDecMult failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecMult(TestCtx *ctx,
		SEC_OBJECTID id, Sec_CipherAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv", iv);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted = cipherSecApi(ctx, ctx->getKey(id), alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, inputSizes, inplace);
	if (encrypted.size() == 0) {
		SEC_LOG_ERROR("cipherSecApi failed");
		return SEC_RESULT_FAILURE;
	}
	TestCtx::printHex("encrypted", encrypted);

	//decrypt
	std::vector<SEC_BYTE> decrypted = cipherSecApi(ctx, ctx->getKey(id), alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inputSizes, inplace);
	if (decrypted.size() == 0) {
		SEC_LOG_ERROR("cipherSecApi failed");
		return SEC_RESULT_FAILURE;
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result cipherEncDecMult(TestCtx *ctx,
		SEC_OBJECTID id_pub, SEC_OBJECTID id_priv, Sec_CipherAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes, SEC_BOOL inplace) {

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(TestCtx::coalesceInputSizes(inputSizes));
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted = cipherSecApi(ctx, ctx->getKey(id_pub), alg, SEC_CIPHERMODE_ENCRYPT, std::vector<SEC_BYTE>(), clear, inputSizes, inplace);
	if (encrypted.size() == 0) {
		SEC_LOG_ERROR("cipherSecApi failed");
		return SEC_RESULT_FAILURE;
	}

	TestCtx::printHex("encrypted", encrypted);

	//decrypt
	std::vector<SEC_BYTE> decrypted = cipherSecApi(ctx, ctx->getKey(id_priv), alg, SEC_CIPHERMODE_DECRYPT, std::vector<SEC_BYTE>(), encrypted, inputSizes, inplace);
	if (decrypted.size() == 0) {
		SEC_LOG_ERROR("cipherSecApi failed");
		return SEC_RESULT_FAILURE;
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherBandwidth(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_SIZE intervalS) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = NULL;
	if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv", iv);

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted;
	time_t start_t = 0;
	time_t end_t = 0;
	int loops = 0;
	if (testEncrypt) {
		start_t = time(NULL);
	    end_t = start_t;

	    while ((end_t - start_t) < (int) intervalS) {
			encrypted = cipherSecApiSingle(&ctx, handle, alg, SEC_CIPHERMODE_ENCRYPT, iv, clear, SEC_FALSE);
			++loops;
	    	end_t = time(NULL);
	    }
	} else {
		//use openssl to encrypt
		encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
	}

	TestCtx::printHex("encrypted", encrypted);

	//decrypt
	std::vector<SEC_BYTE> decrypted;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
	} else {
		start_t = time(NULL);
	    end_t = start_t;

	    while ((end_t - start_t) < (int) intervalS) {
			decrypted = cipherSecApiSingle(&ctx, handle, alg, SEC_CIPHERMODE_DECRYPT, iv, encrypted, SEC_FALSE);
			++loops;
	    	end_t = time(NULL);
	    }
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	//print timing data
    SEC_PRINT("Data processed: %d MB\n", (inputSize * loops) / (1024 * 1024));
    SEC_PRINT("Time elapsed: %d s\n", end_t - start_t);
    if (end_t != start_t) {
        SEC_PRINT("Bandwidth: %d MB/s\n",
        		((inputSize * loops) / (1024 * 1024)) / (end_t - start_t));
    }

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherBandwidthSingleCipher(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_SIZE intervalS) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = NULL;
	if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv", iv);

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted;
	time_t start_t = 0;
	time_t end_t = 0;
	int loops = 0;
	if (testEncrypt) {
		start_t = time(NULL);
	    end_t = start_t;

		Sec_CipherHandle *cipher = ctx.acquireCipher(alg, mode, handle, (SEC_BYTE *) &iv[0]);
		if (cipher == NULL) {
			SEC_LOG_ERROR("TestCtx::acquireCipher failed");
			return SEC_RESULT_FAILURE;
		}

	    while ((end_t - start_t) < (int) intervalS) {
			encrypted = cipherSecApiSingle(&ctx, cipher, iv, clear, SEC_FALSE);
			++loops;
	    	end_t = time(NULL);
	    }
	} else {
		//use openssl to encrypt
		encrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv[0], clear);
	}

	//decrypt
	std::vector<SEC_BYTE> decrypted;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
	} else {
		start_t = time(NULL);
	    end_t = start_t;

		Sec_CipherHandle *cipher = ctx.acquireCipher(alg, mode, handle, (SEC_BYTE *) &iv[0]);
		if (cipher == NULL) {
			SEC_LOG_ERROR("TestCtx::acquireCipher failed");
			return SEC_RESULT_FAILURE;
		}

	    while ((end_t - start_t) < (int) intervalS) {
			decrypted = cipherSecApiSingle(&ctx, cipher, iv, encrypted, SEC_FALSE);
			++loops;
	    	end_t = time(NULL);
	    }
	}

	//print timing data
    SEC_PRINT("Data processed: %d MB\n", (inputSize * loops) / (1024 * 1024));
    SEC_PRINT("Time elapsed: %d s\n", end_t - start_t);
    if (end_t != start_t) {
        SEC_PRINT("Bandwidth: %d MB/s\n",
        		((inputSize * loops) / (1024 * 1024)) / (end_t - start_t));
    }

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCipherUpdateIV(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_SIZE inputSize, SEC_BOOL inplace) {

	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = NULL;
	if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//gen ivs
	std::vector<SEC_BYTE> iv1 = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv1", iv1);
	std::vector<SEC_BYTE> iv2 = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv2", iv2);

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(inputSize);
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted1;
	std::vector<SEC_BYTE> encrypted2;
	if (testEncrypt) {
		Sec_CipherHandle *cipher = ctx.acquireCipher(alg, SEC_CIPHERMODE_ENCRYPT, handle, (SEC_BYTE *) &iv1[0]);
		if (cipher == NULL) {
			SEC_LOG_ERROR("TestCtx::acquireCipher failed");
			return SEC_RESULT_FAILURE;
		}

		encrypted1 = cipherSecApiSingle(&ctx, cipher, iv1, clear, SEC_FALSE);
		if (encrypted1.size() == 0) {
			SEC_LOG_ERROR("cipherSecApiSingle failed");
			return SEC_RESULT_FAILURE;
		}
		encrypted2 = cipherSecApiSingle(&ctx, cipher, iv2, clear, SEC_FALSE);
		if (encrypted2.size() == 0) {
			SEC_LOG_ERROR("cipherSecApiSingle failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		//use openssl to encrypt
		encrypted1 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv1[0], clear);
		if (encrypted1.size() == 0) {
			SEC_LOG_ERROR("cipherOpenSSL failed");
			return SEC_RESULT_FAILURE;
		}
		encrypted2 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_ENCRYPT, &iv2[0], clear);
		if (encrypted2.size() == 0) {
			SEC_LOG_ERROR("cipherOpenSSL failed");
			return SEC_RESULT_FAILURE;
		}
	}

	TestCtx::printHex("encrypted1", encrypted1);
	TestCtx::printHex("encrypted2", encrypted2);

	//decrypt
	std::vector<SEC_BYTE> decrypted1;
	std::vector<SEC_BYTE> decrypted2;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted1 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv1[0], encrypted1);
		if (decrypted1.size() == 0) {
			SEC_LOG_ERROR("cipherOpenSSL failed");
			return SEC_RESULT_FAILURE;
		}
		decrypted2 = cipherOpenSSL(key, alg, SEC_CIPHERMODE_DECRYPT, &iv2[0], encrypted2);
		if (decrypted2.size() == 0) {
			SEC_LOG_ERROR("cipherOpenSSL failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		//use sec api to decrypt
		Sec_CipherHandle *cipher = ctx.acquireCipher(alg, SEC_CIPHERMODE_DECRYPT, handle, (SEC_BYTE *) &iv1[0]);
		if (cipher == NULL) {
			SEC_LOG_ERROR("TestCtx::acquireCipher failed");
			return SEC_RESULT_FAILURE;
		}

		decrypted1 = cipherSecApiSingle(&ctx, cipher, iv1, encrypted1, SEC_FALSE);
		if (decrypted1.size() == 0) {
			SEC_LOG_ERROR("cipherSecApiSingle failed");
			return SEC_RESULT_FAILURE;
		}
		decrypted2 = cipherSecApiSingle(&ctx, cipher, iv2, encrypted2, SEC_FALSE);
		if (decrypted2.size() == 0) {
			SEC_LOG_ERROR("cipherSecApiSingle failed");
			return SEC_RESULT_FAILURE;
		}
	}

	TestCtx::printHex("decrypted1", decrypted1);
	TestCtx::printHex("decrypted2", decrypted2);

	//check if results match
	if (clear != decrypted1 || clear != decrypted2 || encrypted1 == encrypted2) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

std::vector<SEC_BYTE> cipherSecApiCtrSubBlock(
	    TestCtx *ctx, Sec_KeyHandle *key_handle,
		Sec_CipherMode mode,
		const std::vector<SEC_BYTE>& iv,
		const std::vector<SEC_BYTE>& input,
		SEC_BOOL inplace) {

	std::vector<SEC_BYTE> output = input;
	output.resize(input.size() + 4096);

	SEC_SIZE inputProcessed = 0;
	SEC_SIZE outputWritten = 0;
	SEC_SIZE written = 0;

	Sec_CipherHandle *cipher = ctx->acquireCipher(SEC_CIPHERALGORITHM_AES_CTR, mode, key_handle, (SEC_BYTE *) &iv[0]);
	if (cipher == NULL) {
		SEC_LOG_ERROR("TestCtx::acquireCipher failed");
		return std::vector<SEC_BYTE>();
	}

	//calculate the offset and make sure it is not on the SEC_AES_BLOCK_SIZE boundary
	SEC_SIZE split_offset = input.size() / 2;
	if (split_offset % SEC_AES_BLOCK_SIZE == 0) {
		split_offset -= 1;
	}

	SEC_PRINT("init ctr: %d\n", Sec_BEBytesToUint64((SEC_BYTE*) &iv[8]));
	uint64_t init_counter = Sec_BEBytesToUint64((SEC_BYTE*) &iv[8]);

	if (SEC_RESULT_SUCCESS != SecCipher_Process(cipher,
			inplace ? ((SEC_BYTE *) &output[0]) : ((SEC_BYTE *) &input[0]),
			split_offset, SEC_FALSE, (SEC_BYTE *) &output[0], output.size(),
			&written)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	outputWritten += written;
	inputProcessed += split_offset;

	//set the iv
	uint64_t counter = Sec_BEBytesToUint64((SEC_BYTE*) &iv[8]);
	counter = init_counter + split_offset/SEC_AES_BLOCK_SIZE;
	Sec_Uint64ToBEBytes(counter, (SEC_BYTE*) &iv[8]);

	SEC_PRINT("updated ctr: %d\n", Sec_BEBytesToUint64((SEC_BYTE*) &iv[8]));

	/* TODO
	if (SEC_RESULT_SUCCESS != SecCipher_UpdateIV(cipher, (SEC_BYTE*) &iv[0])) {
		SEC_LOG_ERROR("SecCipher_UpdateIV failed");
		return std::vector<SEC_BYTE>();
	}
	*/

	//last input
	if (SEC_RESULT_SUCCESS != SecCipher_ProcessCtrWithDataShift(cipher,
			inplace ? (SEC_BYTE *) &output[inputProcessed] : (SEC_BYTE *) &input[inputProcessed],
			input.size() - inputProcessed, (SEC_BYTE *) &output[outputWritten], output.size() - outputWritten,
			&written, split_offset % SEC_AES_BLOCK_SIZE)) {
		SEC_LOG_ERROR("SecCipher_Process failed");
		return std::vector<SEC_BYTE>();
	}

	outputWritten += written;

	output.resize(outputWritten);

	ctx->releaseCipher(cipher);

	return output;
}

Sec_Result testProcessCtrWithDataShift(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_CipherMode mode, SEC_BOOL inplace) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *handle = NULL;
	if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//gen iv
	std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("iv", iv);

    /* TODO
    //set the counter to ff to test rollover
    memset(&iv[8], 0xff, 8);
    */

	//mode
	SEC_BOOL testEncrypt = (mode == SEC_CIPHERMODE_ENCRYPT || mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM);

	//gen clear input
	std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE * 3);
	TestCtx::printHex("clear", clear);

	//encrypt
	std::vector<SEC_BYTE> encrypted;
	std::vector<SEC_BYTE> ivCopy = iv;
	if (testEncrypt) {
		encrypted = cipherSecApiCtrSubBlock(&ctx, handle, SEC_CIPHERMODE_ENCRYPT, ivCopy, clear, inplace);
	} else {
		//use openssl to encrypt
		encrypted = cipherOpenSSL(key, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, &ivCopy[0], clear);
	}

	TestCtx::printHex("encrypted", encrypted);
	TestCtx::printHex("iv", iv);

	//decrypt
	std::vector<SEC_BYTE> decrypted;
	if (testEncrypt) {
		//use openssl to decrypt
		decrypted = cipherOpenSSL(key, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, &iv[0], encrypted);
	} else {
		//use sec api to decrypt
		decrypted = cipherSecApiCtrSubBlock(&ctx, handle, SEC_CIPHERMODE_DECRYPT, iv, encrypted, inplace);
	}

	TestCtx::printHex("decrypted", decrypted);

	//check if results match
	if (clear != decrypted) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result aesKeyCheck(Sec_ProcessorHandle *proc, SEC_OBJECTID id, SEC_BYTE *key, SEC_SIZE key_len) {
	SEC_PRINT("--- aes key check ---\n");

	std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE);
	TestCtx::printHex("clear", clear);

	std::vector<SEC_BYTE> cipher_secapi;
	cipher_secapi.resize(SEC_AES_BLOCK_SIZE);
	SEC_SIZE cipher_secapi_len;

	if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
		SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, id,
		NULL, &clear[0], clear.size(), &cipher_secapi[0],
		cipher_secapi.size(), &cipher_secapi_len)) {
		SEC_LOG_ERROR("SecCipher_SingleInputId failed");
		return SEC_RESULT_FAILURE;
	}
	cipher_secapi.resize(cipher_secapi_len);
	TestCtx::printHex("cipher_secapi", cipher_secapi);

	std::vector<SEC_BYTE> openssl_key = std::vector<SEC_BYTE> (key, key + key_len);

	std::vector<SEC_BYTE> cipher_ssl = opensslAesEcb(
		openssl_key, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE,
		NULL, clear);

	TestCtx::printHex("cipher_ssl", cipher_ssl);

	SEC_PRINT("---------------------\n");

	//check if results match
	if (cipher_secapi != cipher_ssl) {
		SEC_LOG_ERROR("Results do not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
