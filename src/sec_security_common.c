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

#include "sec_security.h"
#ifndef SEC_COMMON_17
#include "sec_security_asn1kc.h"
#endif
#include <string.h>
#include <stdlib.h>

#ifndef SEC_TRACE_UNWRAP
#define SEC_TRACE_UNWRAP 0
#endif

#if SEC_TRACE_UNWRAP
#pragma message "SEC_TRACE_UNWRAP is enabled.  Please disable in production builds."
#endif

int Sec_Memcmp(const void* ptr1, const void* ptr2, const size_t num)
{
	size_t i;
	SEC_BYTE result = 0;
	SEC_BYTE* a = (SEC_BYTE*) ptr1;
	SEC_BYTE* b = (SEC_BYTE*) ptr2;

	for (i=0; i<num; ++i)
	{
		result |= a[i] ^ b[i];
	}

	return result;
}

void *Sec_Memset(void *ptr, int value, size_t num)
{
	volatile SEC_BYTE *p = (SEC_BYTE *) ptr;
	while (num--)
		*p++ = value;
	return ptr;
}

int SecCipher_IsModeEncrypt(Sec_CipherMode mode)
{
	return mode == SEC_CIPHERMODE_ENCRYPT
		|| mode == SEC_CIPHERMODE_ENCRYPT_NATIVEMEM;
}

int SecCipher_IsModeDecrypt(Sec_CipherMode mode)
{
	return mode == SEC_CIPHERMODE_DECRYPT
		|| mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM;
}

Sec_Result SecCipher_IsValidKey(Sec_KeyType key_type,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_BYTE *iv)
{
	switch (alg)
	{
	case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
	case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
	case SEC_CIPHERALGORITHM_AES_CTR:
		if (SecKey_IsAES(key_type))
		{
			if (iv == NULL
					&& alg != SEC_CIPHERALGORITHM_AES_CTR
					&& alg != SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING
					&& alg != SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING)
			{
				SEC_LOG_ERROR("IV cannot be null in CBC and CTR modes.");
				return SEC_RESULT_FAILURE;
			}

			return SEC_RESULT_SUCCESS;
		}
		else
		{
			SEC_LOG_ERROR("Not an AES key: %d", key_type);
			return SEC_RESULT_FAILURE;
		}
		break;

	case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
	case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
		if (SecCipher_IsModeEncrypt(mode))
		{
			if (!SecKey_IsRsa(key_type))
			{
				SEC_LOG_ERROR("Not an RSA key");
				return SEC_RESULT_FAILURE;
			}

			return SEC_RESULT_SUCCESS;
		}
		else if (SecCipher_IsModeDecrypt(mode))
		{
			if (!SecKey_IsPrivRsa(key_type))
			{
				SEC_LOG_ERROR("Not an RSA key");
				return SEC_RESULT_FAILURE;
			}

			return SEC_RESULT_SUCCESS;
		}
		else
		{
			SEC_LOG_ERROR(
					"Unknown cipher mode encountered: %d", mode);
			return SEC_RESULT_FAILURE;
		}
		break;

	case SEC_CIPHERALGORITHM_ECC_ELGAMAL:
		if (SecCipher_IsModeEncrypt(mode))
		{
			if (!SecKey_IsEcc(key_type))
			{
				SEC_LOG_ERROR("Not an ECC key");
				return SEC_RESULT_FAILURE;
			}

			return SEC_RESULT_SUCCESS;
		}
		else if (SecCipher_IsModeDecrypt(mode))
		{
			if (!SecKey_IsPrivEcc(key_type))
			{
				SEC_LOG_ERROR("Not an ECC key");
				return SEC_RESULT_FAILURE;
			}

			return SEC_RESULT_SUCCESS;
		}
		else
		{
			SEC_LOG_ERROR("Unknown cipher mode encountered: %d", mode);
			return SEC_RESULT_FAILURE;
		}
		break;

		/* NEW: add new key types and cipher algorithms */
	default:
		break;
	}

	SEC_LOG_ERROR("Unimplemented algorithm: %d", alg);
	return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_GetRequiredOutputSize(Sec_CipherAlgorithm alg,
		Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
		SEC_SIZE *outputSize, SEC_BOOL lastInput)
{
	SEC_SIZE maxClearSize = 0;
	SEC_SIZE rsa_block_size = 0;
	SEC_SIZE bn_size = 0;
	*outputSize = 0;

	switch (alg)
	{
	case SEC_CIPHERALGORITHM_AES_CTR:
		*outputSize = inputSize;
		break;

	case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
		if (inputSize % SEC_AES_BLOCK_SIZE != 0)
		{
			SEC_LOG_ERROR("Input size is not a multiple of block size");
            return SEC_RESULT_INVALID_INPUT_SIZE;
        }

        *outputSize = inputSize;
		break;

	case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
	case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
		if (SecCipher_IsModeEncrypt(mode)
				&& !lastInput
				&& inputSize % SEC_AES_BLOCK_SIZE != 0)
		{
			SEC_LOG_ERROR("Encryption input size is not a multiple of block size and is not last input");
			return SEC_RESULT_INVALID_INPUT_SIZE;
		}

		if (SecCipher_IsModeDecrypt(mode) && inputSize % SEC_AES_BLOCK_SIZE != 0)
		{
			SEC_LOG_ERROR("Decryption input size is not a multiple of block size");
			return SEC_RESULT_INVALID_INPUT_SIZE;
		}

		*outputSize = (inputSize / 16) * 16
				+ ((lastInput && (SecCipher_IsModeEncrypt(mode))) ? 16 : 0);
		break;

	case SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING:
	case SEC_CIPHERALGORITHM_RSA_OAEP_PADDING:
		rsa_block_size = *outputSize = SecKey_GetKeyLenForKeyType(keyType);

		if (alg == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING)
		{
			maxClearSize = rsa_block_size - 41;
		}
		else
		{
			maxClearSize = rsa_block_size - 11;
		}

		if (SecCipher_IsModeDecrypt(mode) && inputSize != rsa_block_size)
		{
			SEC_LOG_ERROR(
					"Decrypt input size is not equal to the RSA block size");
			return SEC_RESULT_INVALID_INPUT_SIZE;
		}
		else if ((SecCipher_IsModeEncrypt(mode)) && inputSize > maxClearSize)
		{
			SEC_LOG_ERROR( "Encrypt input size is too large");
			return SEC_RESULT_INVALID_INPUT_SIZE;
		}
		break;

    case SEC_CIPHERALGORITHM_ECC_ELGAMAL:
        bn_size  = SecKey_GetKeyLenForKeyType(keyType);  // one bignum

        if (SecCipher_IsModeEncrypt(mode))
        {
            if (inputSize != bn_size )     // one bignum
            {
                SEC_LOG_ERROR("input size invalid for El Gamal encryption");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }
            *outputSize = 4 * bn_size;     // two points, which are four bignums
        }
        else
        {
            if (inputSize != 4 * bn_size ) // two points, which are four bignums
            {
                SEC_LOG_ERROR("input size invalid for El Gamal encryption");
                return SEC_RESULT_INVALID_INPUT_SIZE;
            }
            *outputSize = bn_size;         // one bignum
        }

		break;

		/* NEW: other cipher algorithms */
	default:
		SEC_LOG_ERROR("Unimplemented cipher algorithm");
		goto unimplemented;
	}

	return SEC_RESULT_SUCCESS;

	unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecCipher_GetRequiredOutputSizeFragmented(Sec_CipherAlgorithm alg,
		Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
		SEC_SIZE *outputSizeNeeded, SEC_BOOL lastInput, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod)
{
	*outputSizeNeeded = 0;

	if ((inputSize % fragmentPeriod) != 0)
	{
		SEC_LOG_ERROR("Input size is not a multiple of a fragment period");
		return SEC_RESULT_INVALID_INPUT_SIZE;
	}

	if ((fragmentSize % SEC_AES_BLOCK_SIZE) != 0)
	{
		SEC_LOG_ERROR("fragment size is not a multiple of block size");
		return SEC_RESULT_INVALID_INPUT_SIZE;
	}

	if ((fragmentOffset + fragmentSize) > fragmentPeriod)
	{
		SEC_LOG_ERROR("Invalid fragment parameters");
		return SEC_RESULT_INVALID_INPUT_SIZE;
	}

	switch (alg)
	{
	case SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING:
	case SEC_CIPHERALGORITHM_AES_CTR:
	case SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING:
	case SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING:
		*outputSizeNeeded = inputSize;
		break;

		/* NEW: other cipher algorithms */
	default:
		SEC_LOG_ERROR("Unimplemented cipher algorithm");
		goto unimplemented;
	}

	return SEC_RESULT_SUCCESS;
	unimplemented: return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

void SecCipher_PadAESPKCS7Block(SEC_BYTE *inputBlock, SEC_SIZE inputSize,
		SEC_BYTE *outputBlock)
{
	SEC_BYTE pad_val = (SEC_BYTE) (SEC_AES_BLOCK_SIZE
			- inputSize % SEC_AES_BLOCK_SIZE);

	memset(outputBlock, pad_val, SEC_AES_BLOCK_SIZE);
	memcpy(outputBlock, inputBlock, inputSize % SEC_AES_BLOCK_SIZE);
}

Sec_Result SecCipher_SingleInput(Sec_ProcessorHandle *proc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, Sec_KeyHandle *key,
		SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
		SEC_SIZE output_len, SEC_SIZE *written)
{
	Sec_Result res;
	Sec_CipherHandle *cipher_handle = NULL;

	res = SecCipher_GetInstance(proc, alg, mode, key, iv, &cipher_handle);
	if (res != SEC_RESULT_SUCCESS)
		return res;

	res = SecCipher_Process(cipher_handle, input, input_len, 1, output,
			output_len, written);
	SecCipher_Release(cipher_handle);

	return res;
}

Sec_Result SecCipher_SingleInputId(Sec_ProcessorHandle *proc,
		Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_OBJECTID key,
		SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
		SEC_SIZE output_len, SEC_SIZE *written)
{
	Sec_Result res = SEC_RESULT_FAILURE;
	Sec_KeyHandle *key_handle = NULL;

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, key, &key_handle))
	{
		SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecCipher_SingleInput(proc, alg, mode, key_handle, iv, input, input_len, output, output_len, written))
	{
		SEC_LOG_ERROR("SecCipher_SingleInput failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

done:
	if (key_handle != NULL)
		SecKey_Release(key_handle);

	return res;
}

SEC_BOOL SecCipher_IsCBC(Sec_CipherAlgorithm alg)
{
	return alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING
			|| alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING;
}

SEC_BOOL SecCipher_IsAES(Sec_CipherAlgorithm alg)
{
	return alg == SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING
			|| alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING
			|| alg == SEC_CIPHERALGORITHM_AES_CTR
			|| alg == SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING
			|| alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING;
}

SEC_BOOL SecCipher_IsRsa(Sec_CipherAlgorithm alg)
{
	return alg == SEC_CIPHERALGORITHM_RSA_OAEP_PADDING
			|| alg == SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
}

SEC_BOOL SecSignature_IsRsaPss(Sec_SignatureAlgorithm alg)
{
	return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST;
}

SEC_BOOL SecCipher_IsEcc(Sec_CipherAlgorithm alg)
{
	return alg == SEC_CIPHERALGORITHM_ECC_ELGAMAL;
}

SEC_BOOL SecCipher_IsPKCS7Padded(Sec_CipherAlgorithm alg)
{
	return alg == SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING
			|| alg == SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING;
}

SEC_BOOL SecCipher_IsDecrypt(Sec_CipherMode mode)
{
	return mode == SEC_CIPHERMODE_DECRYPT
			|| mode == SEC_CIPHERMODE_DECRYPT_NATIVEMEM;
}

SEC_BOOL SecSignature_IsRsa(Sec_SignatureAlgorithm alg)
{
	switch (alg)
	{
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
  case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
  case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
  case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
  case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
		return SEC_TRUE;
	default:
		return SEC_FALSE;
	}
}

SEC_BOOL SecSignature_IsEcc(Sec_SignatureAlgorithm alg)
{
	switch (alg)
	{
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
		return SEC_TRUE;
	default:
		return SEC_FALSE;
	}
}

SEC_SIZE SecSignature_GetEccSignatureSize(Sec_SignatureAlgorithm alg)
{
    switch (alg)
    {
    case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
    case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
        return SEC_ECC_NISTP256_KEY_LEN + SEC_ECC_NISTP256_KEY_LEN;
    // $$$ Add other curves here...
    default:
        break;
    }

    return 0; // Failed
}

Sec_DigestAlgorithm SecSignature_GetDigestAlgorithm(Sec_SignatureAlgorithm alg)
{
	switch (alg)
	{
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
    case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
    case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
		return SEC_DIGESTALGORITHM_SHA1;
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
    case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
    case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
		return SEC_DIGESTALGORITHM_SHA256;
	default:
		break;
	}

	SEC_LOG_ERROR("Unexpected alg encountered: %d", alg);
	return SEC_DIGESTALGORITHM_NUM;
}

Sec_Result SecSignature_IsValidKey(Sec_KeyType key_type,
		Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode)
{
	switch (algorithm)
	{
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST:
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS:
	case SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST:
    case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS:
    case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS:
    case SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST:
    case SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST:
		if (mode == SEC_SIGNATUREMODE_SIGN)
		{
			if (key_type == SEC_KEYTYPE_RSA_1024
					|| key_type == SEC_KEYTYPE_RSA_2048
					|| key_type == SEC_KEYTYPE_RSA_3072)
				return SEC_RESULT_SUCCESS;
			else
				return SEC_RESULT_FAILURE;
		}
		else
		{
			if (key_type == SEC_KEYTYPE_RSA_1024
					|| key_type == SEC_KEYTYPE_RSA_2048
					|| key_type == SEC_KEYTYPE_RSA_3072
					|| key_type == SEC_KEYTYPE_RSA_1024_PUBLIC
					|| key_type == SEC_KEYTYPE_RSA_2048_PUBLIC
					|| key_type == SEC_KEYTYPE_RSA_3072_PUBLIC)
				return SEC_RESULT_SUCCESS;
			else
				return SEC_RESULT_FAILURE;
		}
		break;
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256:
	case SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST:
		if (mode == SEC_SIGNATUREMODE_SIGN)
		{
			if (key_type == SEC_KEYTYPE_ECC_NISTP256)
				return SEC_RESULT_SUCCESS;
			else
				return SEC_RESULT_FAILURE;
		}
		else
		{
			if (key_type == SEC_KEYTYPE_ECC_NISTP256
					|| key_type == SEC_KEYTYPE_ECC_NISTP256_PUBLIC)
				return SEC_RESULT_SUCCESS;
			else
				return SEC_RESULT_FAILURE;
		}
		break;


		/* NEW: add new key types and signature algorithms */
	default:
		break;
	}

	return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_Result SecSignature_SingleInput(Sec_ProcessorHandle* secProcHandle,
		Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
		Sec_KeyHandle* key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
		SEC_SIZE *signatureSize)
{
	Sec_Result res = SEC_RESULT_FAILURE;
	Sec_SignatureHandle *sig = NULL;

	if (SEC_RESULT_SUCCESS != SecSignature_GetInstance(secProcHandle, algorithm, mode, key, &sig))
	{
		SEC_LOG_ERROR("SecSignature_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecSignature_Process(sig, input, inputSize, signature, signatureSize))
	{
		SEC_LOG_ERROR("SecSignature_Process failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

done:
	if (sig != NULL)
	{
		SecSignature_Release(sig);
	}

	return res;
}

Sec_KeyType SecKey_GetRSAKeyTypeForBitLength(int numBits) {
	switch (numBits) {
		case 1024:
			return SEC_KEYTYPE_RSA_1024;
		case 2048:
			return SEC_KEYTYPE_RSA_2048;
		case 3072:
			return SEC_KEYTYPE_RSA_3072;
		default:
		  SEC_LOG_ERROR("Invalid numBits encountered: %d", numBits);
		  return SEC_KEYTYPE_NUM;
	}
}

Sec_KeyType SecKey_GetRSAPubKeyTypeForBitLength(int numBits) {
	switch (numBits) {
		case 1024:
			return SEC_KEYTYPE_RSA_1024_PUBLIC;
		case 2048:
			return SEC_KEYTYPE_RSA_2048_PUBLIC;
		case 3072:
			return SEC_KEYTYPE_RSA_3072_PUBLIC;
		default:
		  SEC_LOG_ERROR("Invalid numBits encountered: %d", numBits);
		  return SEC_KEYTYPE_NUM;
	}
}

Sec_KeyContainer SecKey_GetRSAKCForBitLength(int numBits) {
	switch (numBits) {
		case 1024:
			return SEC_KEYCONTAINER_RAW_RSA_1024;
		case 2048:
			return SEC_KEYCONTAINER_RAW_RSA_2048;
		case 3072:
			return SEC_KEYCONTAINER_RAW_RSA_3072;
		default:
		  SEC_LOG_ERROR("Invalid numBits encountered: %d", numBits);
		  return SEC_KEYCONTAINER_NUM;
	}
}

Sec_KeyContainer SecKey_GetRSAPubKCForBitLength(int numBits) {
	switch (numBits) {
		case 1024:
			return SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC;
		case 2048:
			return SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC;
		case 3072:
			return SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC;
		default:
		  SEC_LOG_ERROR("Invalid numBits encountered: %d", numBits);
		  return SEC_KEYCONTAINER_NUM;
	}
}

Sec_KeyType SecKey_GetRSAKeyTypeForByteLength(int numBytes) {
	switch (numBytes) {
		case 128:
			return SEC_KEYTYPE_RSA_1024;
		case 256:
			return SEC_KEYTYPE_RSA_2048;
		case 384:
			return SEC_KEYTYPE_RSA_3072;
		default:
		  SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
		  return SEC_KEYTYPE_NUM;
	}
}

Sec_KeyType SecKey_GetRSAPubKeyTypeForByteLength(int numBytes) {
	switch (numBytes) {
		case 128:
			return SEC_KEYTYPE_RSA_1024_PUBLIC;
		case 256:
			return SEC_KEYTYPE_RSA_2048_PUBLIC;
		case 384:
			return SEC_KEYTYPE_RSA_3072_PUBLIC;
		default:
		  SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
		  return SEC_KEYTYPE_NUM;
	}
}

Sec_KeyContainer SecKey_GetRSAKCForByteLength(int numBytes) {
	switch (numBytes) {
		case 128:
			return SEC_KEYCONTAINER_RAW_RSA_1024;
		case 256:
			return SEC_KEYCONTAINER_RAW_RSA_2048;
		case 384:
			return SEC_KEYCONTAINER_RAW_RSA_3072;
		default:
		  SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
		  return SEC_KEYCONTAINER_NUM;
	}
}

Sec_KeyContainer SecKey_GetRSAPubKCForByteLength(int numBytes) {
	switch (numBytes) {
		case 128:
			return SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC;
		case 256:
			return SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC;
		case 384:
			return SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC;
		default:
		  SEC_LOG_ERROR("Invalid numBytes encountered: %d", numBytes);
		  return SEC_KEYCONTAINER_NUM;
	}
}

// Like SecSignature_SingleInput but with a Cert handle
// Used to validate a signature using the RSA or ECC public key from a specified certificate.
Sec_Result SecSignature_SingleInputCert(Sec_ProcessorHandle* secProcHandle,
		Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
		Sec_CertificateHandle* certHandle, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
		SEC_SIZE *signatureSize)
{
	Sec_Result res = SEC_RESULT_FAILURE;
	Sec_KeyHandle *key = NULL;
	Sec_RSARawPublicKey rsaPubKey;
    Sec_ECCRawPublicKey eccPubKey;
    Sec_KeyType keyType;

    if (mode == SEC_SIGNATUREMODE_SIGN) {   // Sanity check: This does not handle SIGN
        SEC_LOG_ERROR("SecSignature_SingleInputCert does not support SEC_SIGNATUREMODE_SIGN");
        goto done;
    }

	keyType = SecCertificate_GetKeyType(certHandle);

	switch (keyType) {
	case SEC_KEYTYPE_RSA_1024_PUBLIC:
	case SEC_KEYTYPE_RSA_2048_PUBLIC:
	case SEC_KEYTYPE_RSA_3072_PUBLIC:
	    if (SEC_RESULT_SUCCESS != SecCertificate_ExtractRSAPublicKey(certHandle, &rsaPubKey))
	    {
	        SEC_LOG_ERROR("SecCertificate_ExtractRSAPublicKey failed");
	        goto done;
	    }

	    if (SEC_RESULT_SUCCESS != SecKey_Provision(secProcHandle,
	            SEC_OBJECTID_SIG_FROM_CERT,
	            SEC_STORAGELOC_RAM_SOFT_WRAPPED,
	            SecKey_GetRSAPubKCForByteLength(Sec_BEBytesToUint32(rsaPubKey.modulus_len_be)),
                (SEC_BYTE *) &rsaPubKey, sizeof(rsaPubKey)))
	    {
	        SEC_LOG_ERROR("SecKey_Provision failed");
	        goto done;
	    }
	    break;

	case SEC_KEYTYPE_ECC_NISTP256:
	    if (SEC_RESULT_SUCCESS != SecCertificate_ExtractECCPublicKey(certHandle, &eccPubKey))
	    {
	        SEC_LOG_ERROR("SecCertificate_ExtractECCPublicKey failed");
	        goto done;
	    }

	    if (SEC_RESULT_SUCCESS != SecKey_Provision(secProcHandle,
	            SEC_OBJECTID_SIG_FROM_CERT,
	            SEC_STORAGELOC_RAM_SOFT_WRAPPED,
	            SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC,
	            (SEC_BYTE *) &eccPubKey, sizeof(eccPubKey)))
	    {
	        SEC_LOG_ERROR("SecKey_Provision failed");
	        goto done;
	    }
	    break;

	default:
	    SEC_LOG_ERROR("SecSignature_SingleInputCert: Unhandled keyType %d", (int)keyType);
	    goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(secProcHandle, SEC_OBJECTID_SIG_FROM_CERT, &key))
	{
		SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecSignature_SingleInput(secProcHandle,
			algorithm, mode, key, input, inputSize, signature, signatureSize))
	{
		SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

done:
	if (key != NULL)
	{
		SecKey_Release(key);
	}

	return res;
}

// Like SecSignature_SingleInput but with a Key OBJECT Id
Sec_Result SecSignature_SingleInputId(Sec_ProcessorHandle* secProcHandle,
		Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
		SEC_OBJECTID id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
		SEC_SIZE *signatureSize)
{
	Sec_KeyHandle *key = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(secProcHandle, id, &key))
	{
		SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecSignature_SingleInput(secProcHandle,
			algorithm, mode, key, input, inputSize, signature, signatureSize))
	{
		SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;
done:
	if (key != NULL)
	{
		SecKey_Release(key);
	}

	return res;
}

// Like SecSignature_SingleInputCert but with a Cert OBJECT Id
Sec_Result SecSignature_SingleInputCertId(Sec_ProcessorHandle* secProcHandle,
		Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
		SEC_OBJECTID cert_id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
		SEC_SIZE *signatureSize)
{
	Sec_CertificateHandle *certHandle = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

	if (SEC_RESULT_SUCCESS != SecCertificate_GetInstance(secProcHandle, cert_id, &certHandle))
	{
		SEC_LOG_ERROR("SecCertificate_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecSignature_SingleInputCert(secProcHandle,
			algorithm, mode, certHandle, input, inputSize, signature, signatureSize))
	{
		SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

  done:
	if (certHandle != NULL)
	{
		SecCertificate_Release(certHandle);
	}

	return res;
}

SEC_BOOL SecSignature_IsDigest(Sec_SignatureAlgorithm alg)
{
	return alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
			|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST
			|| alg == SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST
      || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
  		|| alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST;
}

Sec_Result SecMac_IsValidKey(Sec_KeyType key_type, Sec_MacAlgorithm alg)
{
	switch (alg)
	{
	case SEC_MACALGORITHM_HMAC_SHA1:
	case SEC_MACALGORITHM_HMAC_SHA256:
		if (key_type == SEC_KEYTYPE_HMAC_256
				|| key_type == SEC_KEYTYPE_HMAC_160
				|| key_type == SEC_KEYTYPE_HMAC_128)
		{
			return SEC_RESULT_SUCCESS;
		}
		else
		{
			return SEC_RESULT_FAILURE;
		}
		break;

	case SEC_MACALGORITHM_CMAC_AES_128:
		if (key_type == SEC_KEYTYPE_AES_128
				|| key_type == SEC_KEYTYPE_AES_256)
		{
			return SEC_RESULT_SUCCESS;
		}
		else
		{
			return SEC_RESULT_FAILURE;
		}
		break;

	default:
		break;
	}

	return SEC_RESULT_UNIMPLEMENTED_FEATURE;
}

Sec_DigestAlgorithm SecMac_GetDigestAlgorithm(Sec_MacAlgorithm alg)
{
	switch (alg)
	{
	case SEC_MACALGORITHM_HMAC_SHA1:
		return SEC_DIGESTALGORITHM_SHA1;
	case SEC_MACALGORITHM_HMAC_SHA256:
		return SEC_DIGESTALGORITHM_SHA256;
	case SEC_MACALGORITHM_CMAC_AES_128:
	default:
		break;
	}

	return SEC_DIGESTALGORITHM_NUM;
}

Sec_Result SecMac_SingleInput(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
		Sec_KeyHandle *key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
		SEC_SIZE *mac_len)
{
	Sec_Result res;
	Sec_MacHandle *mac_handle = NULL;

	res = SecMac_GetInstance(proc, alg, key, &mac_handle);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecMac_GetInstance failed");
		return res;
	}

	res = SecMac_Update(mac_handle, input, input_len);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecMac_Update failed");
		SecMac_Release(mac_handle, mac, mac_len);
		return res;
	}

	res = SecMac_Release(mac_handle, mac, mac_len);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecMac_Update failed");
		return res;
	}

	return res;
}

Sec_Result SecMac_SingleInputId(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
		SEC_OBJECTID key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
		SEC_SIZE *mac_len)
{
	Sec_Result res = SEC_RESULT_FAILURE;
	Sec_KeyHandle *key_handle = NULL;

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, key, &key_handle))
	{
		SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
	}

	res = SecMac_SingleInput(proc, alg, key_handle, input, input_len, mac, mac_len);

done:
	if (key_handle != NULL)
		SecKey_Release(key_handle);

	return res;
}

SEC_SIZE SecKey_GetKeyLenForKeyType(Sec_KeyType keyType)
{
	switch (keyType)
	{
	case SEC_KEYTYPE_AES_128:
		return 16;
	case SEC_KEYTYPE_AES_256:
		return 32;
	case SEC_KEYTYPE_HMAC_128:
		return 16;
	case SEC_KEYTYPE_HMAC_160:
		return 20;
	case SEC_KEYTYPE_HMAC_256:
		return 32;
	case SEC_KEYTYPE_RSA_1024:
	case SEC_KEYTYPE_RSA_1024_PUBLIC:
		return 128;
	case SEC_KEYTYPE_RSA_2048:
	case SEC_KEYTYPE_RSA_2048_PUBLIC:
		return 256;
	case SEC_KEYTYPE_RSA_3072:
	case SEC_KEYTYPE_RSA_3072_PUBLIC:
		return 384;
	case SEC_KEYTYPE_ECC_NISTP256:
	case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
		return SEC_ECC_NISTP256_KEY_LEN;

		/* NEW: add new key types here */
	default:
		break;
	}

	SEC_LOG_ERROR("Unknown key type encountered: %d", keyType);
	return 0;
}

SEC_BOOL SecKey_IsSymetric(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_AES_128:
	case SEC_KEYTYPE_AES_256:
	case SEC_KEYTYPE_HMAC_128:
	case SEC_KEYTYPE_HMAC_160:
	case SEC_KEYTYPE_HMAC_256:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsAES(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_AES_128:
	case SEC_KEYTYPE_AES_256:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsHMAC(Sec_KeyType type)
{
    switch (type)
    {
    case SEC_KEYTYPE_HMAC_128:
    case SEC_KEYTYPE_HMAC_160:
    case SEC_KEYTYPE_HMAC_256:
        return 1;

    default:
        break;
    }

    return 0;
}

SEC_BOOL SecKey_IsRsa(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_RSA_1024:
	case SEC_KEYTYPE_RSA_1024_PUBLIC:
	case SEC_KEYTYPE_RSA_2048:
	case SEC_KEYTYPE_RSA_2048_PUBLIC:
	case SEC_KEYTYPE_RSA_3072:
	case SEC_KEYTYPE_RSA_3072_PUBLIC:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsPubRsa(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_RSA_1024_PUBLIC:
	case SEC_KEYTYPE_RSA_2048_PUBLIC:
	case SEC_KEYTYPE_RSA_3072_PUBLIC:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsPrivRsa(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_RSA_1024:
	case SEC_KEYTYPE_RSA_2048:
	case SEC_KEYTYPE_RSA_3072:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsEcc(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_ECC_NISTP256:
	case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsPubEcc(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsPrivEcc(Sec_KeyType type)
{
	switch (type)
	{
	case SEC_KEYTYPE_ECC_NISTP256:
		return 1;

	default:
		break;
	}

	return 0;
}

SEC_BOOL SecKey_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
		SEC_OBJECTID object_id)
{
	Sec_KeyHandle *key;

    if (SEC_OBJECTID_INVALID == object_id) {
        return 0;
    }

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(secProcHandle, object_id, &key))
	{
		return 0;
	}

	SecKey_Release(key);
	return 1;
}

SEC_OBJECTID SecKey_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
		SEC_OBJECTID top)
{
	SEC_OBJECTID id;
	Sec_KeyHandle *key_handle;
	Sec_Result res;

	for (id = base; id < top; ++id)
	{
		res = SecKey_GetInstance(proc, id, &key_handle);
		if (SEC_RESULT_SUCCESS == res)
			SecKey_Release(key_handle);
		else
			return id;
	}

	return SEC_OBJECTID_INVALID;
}

SEC_BYTE SecKey_GetObjectType(SEC_OBJECTID object_id)
{
	return (SEC_BYTE) ((object_id & 0xff00000000000000ULL) >> 56);
}

Sec_Result SecKey_ComputeKeyDigest(Sec_ProcessorHandle *proc, SEC_OBJECTID key_id,
		Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len)
{
	Sec_KeyHandle *key_handle = NULL;
	Sec_DigestHandle *digest_handle = NULL;
	Sec_Result res;

	CHECK_EXACT(SecKey_GetInstance(proc, key_id, &key_handle),
			SEC_RESULT_SUCCESS, error);

	CHECK_EXACT( SecDigest_GetInstance(proc, alg, &digest_handle),
			SEC_RESULT_SUCCESS, error);

	CHECK_EXACT( SecDigest_UpdateWithKey(digest_handle, key_handle),
			SEC_RESULT_SUCCESS, error);

	SecKey_Release(key_handle);
	res = SecDigest_Release(digest_handle, digest, digest_len);
	digest_handle = NULL;

	return res;

	error:
	if (key_handle != NULL)
		SecKey_Release(key_handle);
	if (digest_handle != NULL )
		SecDigest_Release(digest_handle, digest, digest_len);

	return SEC_RESULT_FAILURE;
}

Sec_Result SecKey_ComputeBaseKeyLadderInputs(Sec_ProcessorHandle *secProcHandle,
		const char *inputDerivationStr, const char *cipherAlgorithmStr,
		SEC_BYTE *nonce, Sec_DigestAlgorithm digestAlgorithm, SEC_SIZE inputSize,
		SEC_BYTE *c1, SEC_BYTE *c2, SEC_BYTE *c3, SEC_BYTE *c4)
{
	int i;
	SEC_BYTE loop[] = { 0, 0, 0, 0 };
	SEC_BYTE digest[SEC_DIGEST_MAX_LEN];
	SEC_SIZE digest_len;
	Sec_Result res = SEC_RESULT_FAILURE;
	SEC_BYTE *c[4] = { c1, c2, c3, c4 };
	Sec_Buffer inputBuffer;
	SEC_SIZE bufferLen;

	if (inputSize > SecDigest_GetDigestLenForAlgorithm(digestAlgorithm))
	{
		SEC_LOG_ERROR("Invalid input size for specified digest algorithm");
		return SEC_RESULT_FAILURE;
	}

	bufferLen = SEC_NONCE_LEN + strlen(inputDerivationStr) + strlen(cipherAlgorithmStr) + sizeof(loop);
	SecBuffer_Init(&inputBuffer, malloc(bufferLen), bufferLen);
	if (NULL == inputBuffer.base)
	{
		SEC_LOG_ERROR("malloc failed");
		return SEC_RESULT_FAILURE;
	}

	for (i = 1; i <= 4; i++)
	{
		loop[3] = i;

		SecBuffer_Reset(&inputBuffer);

		CHECK_EXACT(
				SecBuffer_Write(&inputBuffer, nonce, SEC_NONCE_LEN),
                SEC_RESULT_SUCCESS, done);

		CHECK_EXACT(
				SecBuffer_Write(&inputBuffer, (SEC_BYTE *) inputDerivationStr, strlen(inputDerivationStr)),
                SEC_RESULT_SUCCESS, done);

		CHECK_EXACT(
				SecBuffer_Write(&inputBuffer, (SEC_BYTE *) cipherAlgorithmStr, strlen(cipherAlgorithmStr)),
                SEC_RESULT_SUCCESS, done);

		CHECK_EXACT(SecBuffer_Write(&inputBuffer, loop, sizeof(loop)),
                SEC_RESULT_SUCCESS, done);

		res = SecDigest_SingleInput(secProcHandle, digestAlgorithm, inputBuffer.base, inputBuffer.written,
				digest, &digest_len);
		if (SEC_RESULT_SUCCESS != res)
            goto done;

		memcpy(c[i-1], digest, inputSize);
	}

done:
	SEC_FREE(inputBuffer.base);
	return res;
}

SEC_BOOL SecKey_IsClearKeyContainer(Sec_KeyContainer kct)
{
	switch (kct)
	{
	case SEC_KEYCONTAINER_RAW_AES_128:
	case SEC_KEYCONTAINER_RAW_AES_256:
	case SEC_KEYCONTAINER_RAW_HMAC_128:
	case SEC_KEYCONTAINER_RAW_HMAC_160:
	case SEC_KEYCONTAINER_RAW_HMAC_256:
	case SEC_KEYCONTAINER_RAW_RSA_1024:
	case SEC_KEYCONTAINER_RAW_RSA_2048:
	case SEC_KEYCONTAINER_RAW_RSA_3072:
	case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
	case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
	case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
	case SEC_KEYCONTAINER_PEM_RSA_1024:
	case SEC_KEYCONTAINER_PEM_RSA_2048:
	case SEC_KEYCONTAINER_PEM_RSA_3072:
	case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
	case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
	case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
	case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
	case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
		return SEC_TRUE;
		break;

	default:
		break;
	}

	return SEC_FALSE;
}

Sec_KeyContainer SecKey_GetClearContainer(Sec_KeyType key_type)
{
	switch (key_type)
	{
	case SEC_KEYTYPE_AES_128:
		return SEC_KEYCONTAINER_RAW_AES_128;
	case SEC_KEYTYPE_AES_256:
		return SEC_KEYCONTAINER_RAW_AES_256;
	case SEC_KEYTYPE_HMAC_128:
		return SEC_KEYCONTAINER_RAW_HMAC_128;
	case SEC_KEYTYPE_HMAC_160:
		return SEC_KEYCONTAINER_RAW_HMAC_160;
	case SEC_KEYTYPE_HMAC_256:
		return SEC_KEYCONTAINER_RAW_HMAC_256;
	case SEC_KEYTYPE_RSA_1024:
		return SEC_KEYCONTAINER_RAW_RSA_1024;
	case SEC_KEYTYPE_RSA_2048:
		return SEC_KEYCONTAINER_RAW_RSA_2048;
	case SEC_KEYTYPE_RSA_3072:
		return SEC_KEYCONTAINER_RAW_RSA_3072;
	case SEC_KEYTYPE_RSA_1024_PUBLIC:
		return SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC;
	case SEC_KEYTYPE_RSA_2048_PUBLIC:
		return SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC;
	case SEC_KEYTYPE_RSA_3072_PUBLIC:
		return SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC;
	case SEC_KEYTYPE_ECC_NISTP256:
		return SEC_KEYCONTAINER_RAW_ECC_NISTP256;
	case SEC_KEYTYPE_ECC_NISTP256_PUBLIC:
		return SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC;
	default:
		break;
	}

	return SEC_KEYCONTAINER_NUM;
}

Sec_KeyType SecKey_GetKeyTypeForClearKeyContainer(Sec_KeyContainer kc)
{
	switch (kc) {
	case SEC_KEYCONTAINER_RAW_AES_128:
		return SEC_KEYTYPE_AES_128;

    case SEC_KEYCONTAINER_RAW_AES_256:
		return SEC_KEYTYPE_AES_256;

    case SEC_KEYCONTAINER_RAW_HMAC_128:
		return SEC_KEYTYPE_HMAC_128;

    case SEC_KEYCONTAINER_RAW_HMAC_160:
		return SEC_KEYTYPE_HMAC_160;

    case SEC_KEYCONTAINER_RAW_HMAC_256:
		return SEC_KEYTYPE_HMAC_256;

    case SEC_KEYCONTAINER_RAW_RSA_1024:
    case SEC_KEYCONTAINER_PEM_RSA_1024:
    case SEC_KEYCONTAINER_DER_RSA_1024:
		return SEC_KEYTYPE_RSA_1024;

    case SEC_KEYCONTAINER_RAW_RSA_2048:
    case SEC_KEYCONTAINER_PEM_RSA_2048:
    case SEC_KEYCONTAINER_DER_RSA_2048:
		return SEC_KEYTYPE_RSA_2048;

    case SEC_KEYCONTAINER_RAW_RSA_3072:
    case SEC_KEYCONTAINER_PEM_RSA_3072:
    case SEC_KEYCONTAINER_DER_RSA_3072:
		return SEC_KEYTYPE_RSA_3072;

    case SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC:
    case SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC:
    case SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC:
		return SEC_KEYTYPE_RSA_1024_PUBLIC;

    case SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC:
    case SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC:
    case SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC:
		return SEC_KEYTYPE_RSA_2048_PUBLIC;

    case SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC:
    case SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC:
    case SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC:
		return SEC_KEYTYPE_RSA_3072_PUBLIC;

    case SEC_KEYCONTAINER_PEM_ECC_NISTP256:
    case SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256:
    case SEC_KEYCONTAINER_RAW_ECC_NISTP256:
    case SEC_KEYCONTAINER_DER_ECC_NISTP256:
    	return SEC_KEYTYPE_ECC_NISTP256;

    case SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC:
    case SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC:
    case SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC:
    	return SEC_KEYTYPE_ECC_NISTP256_PUBLIC;

    default:
    	return SEC_KEYTYPE_NUM;
	}
}


SEC_BOOL SecCertificate_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
		SEC_OBJECTID object_id)
{
	Sec_CertificateHandle *certHandle;

	if (SEC_RESULT_SUCCESS != SecCertificate_GetInstance(secProcHandle, object_id, &certHandle))
	{
		return 0;
	}

	SecCertificate_Release(certHandle);
	return 1;
}

SEC_SIZE SecCertificate_GetSize(Sec_CertificateHandle* certHandle)
{
	SEC_BYTE buffer[SEC_CERT_MAX_DATA_LEN];
	SEC_SIZE written;

	if (SEC_RESULT_SUCCESS != SecCertificate_Export(certHandle, buffer, sizeof(buffer), &written))
	{
		SEC_LOG_ERROR("SecCertificate_Export failed");
		return 0;
	}

	return written;
}

SEC_OBJECTID SecCertificate_ObtainFreeObjectId(Sec_ProcessorHandle *proc,
		SEC_OBJECTID base, SEC_OBJECTID top)
{
	SEC_OBJECTID id;
	Sec_CertificateHandle *certHandle;
	Sec_Result res;

	for (id = base; id < top; ++id)
	{
		res = SecCertificate_GetInstance(proc, id, &certHandle);

		if (SEC_RESULT_SUCCESS == res)
			SecCertificate_Release(certHandle);
		else
			return id;
	}

	return SEC_OBJECTID_INVALID;
}

SEC_SIZE SecDigest_GetDigestLenForAlgorithm(Sec_DigestAlgorithm alg)
{
	switch (alg)
	{
	case SEC_DIGESTALGORITHM_SHA1:
		return 20;

	case SEC_DIGESTALGORITHM_SHA256:
		return 32;

	default:
		break;
	}

	return 0;
}

Sec_Result SecDigest_SingleInput(Sec_ProcessorHandle *proc,
		Sec_DigestAlgorithm alg, SEC_BYTE *input, SEC_SIZE input_len,
		SEC_BYTE *digest, SEC_SIZE *digest_len)
{
	Sec_Result res;
	Sec_DigestHandle *digest_handle = NULL;

	res = SecDigest_GetInstance(proc, alg, &digest_handle);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecDigest_GetInstance failed");
		SecDigest_Release(digest_handle, digest, digest_len);
		return res;
	}

	res = SecDigest_Update(digest_handle, input, input_len);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecDigest_Update failed");
		SecDigest_Release(digest_handle, digest, digest_len);
		return res;
	}

	return SecDigest_Release(digest_handle, digest, digest_len);
}

Sec_Result SecDigest_SingleInputWithKeyId(Sec_ProcessorHandle *proc, Sec_DigestAlgorithm alg, SEC_OBJECTID key_id, SEC_BYTE *digest, SEC_SIZE *digest_len)
{
	Sec_Result res = SEC_RESULT_FAILURE;

	Sec_DigestHandle *digest_handle = NULL;
	Sec_KeyHandle *key_handle = NULL;

	if (SEC_RESULT_SUCCESS != SecDigest_GetInstance(proc, alg, &digest_handle))
	{
		SEC_LOG_ERROR("SecDigest_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, key_id, &key_handle))
	{
		SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecDigest_UpdateWithKey(digest_handle, key_handle))
	{
		SEC_LOG_ERROR("SecDigest_Update failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;
done:
	if (digest_handle != NULL)
	{
		SecDigest_Release(digest_handle, digest, digest_len);
		digest_handle = NULL;
	}

	if (key_handle != NULL)
	{
		SecKey_Release(key_handle);
		key_handle = NULL;
	}
	return res;
}

Sec_Result SecRandom_SingleInput(Sec_ProcessorHandle *proc,
		Sec_RandomAlgorithm alg, SEC_BYTE *output, SEC_SIZE output_len)
{
	Sec_Result res;
	Sec_RandomHandle *random_handle = NULL;

	res = SecRandom_GetInstance(proc, alg, &random_handle);
	if (res != SEC_RESULT_SUCCESS)
		return res;

	res = SecRandom_Process(random_handle, output, output_len);
	if (res != SEC_RESULT_SUCCESS)
	{
		SEC_LOG_ERROR("SecRandom_Process failed");
		SecRandom_Release(random_handle);
		return res;
	}

	SecRandom_Release(random_handle);

	return res;
}

SEC_BOOL SecBundle_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
		SEC_OBJECTID object_id)
{
	Sec_BundleHandle *bundle;

	if (SEC_RESULT_SUCCESS != SecBundle_GetInstance(secProcHandle, object_id, &bundle))
	{
		return 0;
	}

	SecBundle_Release(bundle);
	return 1;
}

SEC_OBJECTID SecBundle_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
		SEC_OBJECTID top)
{
	SEC_OBJECTID id;
	Sec_BundleHandle *bundle_handle;
	Sec_Result res;

	for (id = base; id < top; ++id)
	{
		res = SecBundle_GetInstance(proc, id, &bundle_handle);
		if (SEC_RESULT_SUCCESS == res)
			SecBundle_Release(bundle_handle);
		else
			return id;
	}

	return SEC_OBJECTID_INVALID;
}

#ifndef SEC_COMMON_17
Sec_Result SecKey_GenerateWrappedKeyAsn1(SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, Sec_KeyType wrappedKeyType,
		SEC_OBJECTID wrappingKeyId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm,
		SEC_BYTE *output, SEC_SIZE output_len, SEC_SIZE *written)
{
	Sec_Asn1KC *asn1kc = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

	asn1kc = SecAsn1KC_Alloc();
	if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, wrappedKey, wrappedKeyLen))
	{
		SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType))
	{
		SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUint64(asn1kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingKeyId))
	{
		SEC_LOG_ERROR("SecAsn1KC_AddAttrUint64 failed");
        goto done;
	}

	if (wrappingIv != NULL && SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE))
	{
		SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm))
	{
		SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_Encode(asn1kc, output, output_len, written))
	{
		SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

done:
	if (asn1kc != NULL)
	{
		SecAsn1KC_Free(asn1kc);
		asn1kc = NULL;
	}

	return res;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1(Sec_Asn1KC *kc,
		SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, SEC_SIZE *written,
		Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg)
{
	unsigned long ulongVal;
	SEC_SIZE writtenIv;

	if (kc == NULL)
	{
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPEDKEY, wrappedKey, wrappedKeyLen, written))
	{
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, &ulongVal))
	{
		return SEC_RESULT_FAILURE;
	}
	*wrappedKeyType = (Sec_KeyType) ulongVal;

	if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUint64(kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingId))
	{
		return SEC_RESULT_FAILURE;
	}

	if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGIV) && SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE, &writtenIv))
	{
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPINGALGORITHMID, &ulongVal))
	{
		return SEC_RESULT_FAILURE;
	}
	*wrappingAlg = (Sec_CipherAlgorithm) ulongVal;

	return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1Buffer(SEC_BYTE *asn1, SEC_SIZE asn1_len,
		SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, SEC_SIZE *written,
		Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg)
{
	Sec_Asn1KC *asn1kc = NULL;
	Sec_Result res = SEC_RESULT_FAILURE;

	asn1kc = SecAsn1KC_Decode(asn1, asn1_len);
	if (asn1kc == NULL)
	{
		SEC_LOG_ERROR("SecAsn1KC_Decode failed");
        goto done;
	}

	if (SEC_RESULT_SUCCESS != SecKey_ExtractWrappedKeyParamsAsn1(asn1kc, wrappedKey, wrappedKeyLen, written,
			wrappedKeyType, wrappingId, wrappingIv, wrappingAlg))
	{
		SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1 failed");
        goto done;
	}

	res = SEC_RESULT_SUCCESS;

done:
	SecAsn1KC_Free(asn1kc);
	return res;
}

Sec_Result SecKey_GenerateWrappedKeyAsn1Off(SEC_BYTE *payload, SEC_SIZE payloadLen, Sec_KeyType wrappedKeyType,
                                         SEC_OBJECTID wrappingKeyId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm,
                                         SEC_BYTE *output, SEC_SIZE output_len, SEC_SIZE *written, SEC_SIZE key_offset)
{
    Sec_Asn1KC *asn1kc = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Alloc();
    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUint64(asn1kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingKeyId))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUint64 failed");
        goto done;
    }

    if (wrappingIv != NULL && SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
    }

    if ((key_offset + SecKey_GetKeyLenForKeyType(wrappedKeyType)) > payloadLen)
    {
        SEC_LOG_ERROR("Illegal key_offset %ld", (long)key_offset);
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, key_offset))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_Encode(asn1kc, output, output_len, written))
    {
        SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    if (asn1kc != NULL)
    {
        SecAsn1KC_Free(asn1kc);
        asn1kc = NULL;
    }

    return res;
}

Sec_Result SecKey_GenerateWrappedKeyAsn1V3(SEC_BYTE *payload, SEC_SIZE payloadLen, Sec_KeyType wrappedKeyType,
                                         SEC_BYTE *wrappingKey, SEC_SIZE wrappingKeyLen,
                                         SEC_BYTE *wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm,
                                         SEC_BYTE *output, SEC_SIZE output_len, SEC_SIZE *written, SEC_SIZE key_offset)
{
    Sec_Asn1KC *asn1kc = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Alloc();
    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, wrappedKeyType))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGKEY, wrappingKey, wrappingKeyLen))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
    }

    if (wrappingIv != NULL && SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrBuffer(asn1kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrBuffer failed");
        goto done;
    }

    if ((key_offset + SecKey_GetKeyLenForKeyType(wrappedKeyType)) > payloadLen)
    {
        SEC_LOG_ERROR("Illegal key_offset %ld", (long)key_offset);
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, key_offset))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttrUlong(asn1kc, SEC_ASN1KC_WRAPPINGALGORITHMID, wrappingAlgorithm))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttrUlong failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_Encode(asn1kc, output, output_len, written))
    {
        SEC_LOG_ERROR("SecAsn1KC_Encode failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    if (asn1kc != NULL)
    {
        SecAsn1KC_Free(asn1kc);
        asn1kc = NULL;
    }

    return res;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1Off(Sec_Asn1KC *kc,
                                              SEC_BYTE *payload, SEC_SIZE payloadLen, SEC_SIZE *written,
                                              Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv,
                                              Sec_CipherAlgorithm *wrappingAlg, SEC_SIZE *key_offset)
{
    unsigned long ulongVal;
    SEC_SIZE writtenIv;

    if (kc == NULL)
    {
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen, written))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEY failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, &ulongVal))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPEDKEYTYPEID failed");
        return SEC_RESULT_FAILURE;
    }
    *wrappedKeyType = (Sec_KeyType) ulongVal;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUint64(kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingId))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUint64 SEC_ASN1KC_WRAPPINGKEYID failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET))
    {
        if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, &ulongVal))
        {
	        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
            return SEC_RESULT_FAILURE;
        }
        *key_offset = (SEC_SIZE) ulongVal;
    }
    else
    {
        *key_offset = (SEC_SIZE) 0; // default value
    }

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGIV) && SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE, &writtenIv))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGIV failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPINGALGORITHMID, &ulongVal))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrUlong SEC_ASN1KC_WRAPPINGALGORITHMID failed");
        return SEC_RESULT_FAILURE;
    }
    *wrappingAlg = (Sec_CipherAlgorithm) ulongVal;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1BufferOff(SEC_BYTE *asn1, SEC_SIZE asn1_len,
                                                    SEC_BYTE *payload, SEC_SIZE payloadLen, SEC_SIZE *written,
                                                    Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg, SEC_SIZE *key_offset)
{
    Sec_Asn1KC *asn1kc = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Decode(asn1, asn1_len);
    if (asn1kc == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_Decode failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExtractWrappedKeyParamsAsn1Off(asn1kc, payload, payloadLen, written,
                                                                    wrappedKeyType, wrappingId, wrappingIv, wrappingAlg, key_offset))
    {
        SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1Off failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    SecAsn1KC_Free(asn1kc);
    return res;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1V3(Sec_Asn1KC *kc,
                                              SEC_BYTE *payload, SEC_SIZE payloadLen, SEC_SIZE *written,
                                              Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv,
                                              Sec_CipherAlgorithm *wrappingAlg, SEC_SIZE *key_offset,
                                              SEC_BYTE *wrappingKey, SEC_SIZE wrappingKeyLen, SEC_SIZE *writtenWrappingKey)
{
    unsigned long ulongVal;
    SEC_SIZE writtenIv;

	*writtenWrappingKey = 0;
	*wrappingId = 0;

    if (kc == NULL)
    {
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPEDKEY, payload, payloadLen, written))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEY failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYTYPEID, &ulongVal))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYTYPEID failed");
        return SEC_RESULT_FAILURE;
    }
    *wrappedKeyType = (Sec_KeyType) ulongVal;

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET))
    {
        if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPEDKEYOFFSET, &ulongVal))
        {
	        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
            return SEC_RESULT_FAILURE;
        }
        *key_offset = (SEC_SIZE) ulongVal;
    }
    else
    {
        *key_offset = (SEC_SIZE) 0; // default value
    }

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGIV) && SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGIV, wrappingIv, SEC_AES_BLOCK_SIZE, &writtenIv))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPEDKEYOFFSET failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUlong(kc, SEC_ASN1KC_WRAPPINGALGORITHMID, &ulongVal))
    {
        SEC_TRACE(SEC_TRACE_UNWRAP, "SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGALGORITHMID failed");
        return SEC_RESULT_FAILURE;
    }
    *wrappingAlg = (Sec_CipherAlgorithm) ulongVal;

    if (SecAsn1KC_HasAttr(kc, SEC_ASN1KC_WRAPPINGKEY))
    {
        if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrBuffer(kc, SEC_ASN1KC_WRAPPINGKEY, wrappingKey, wrappingKeyLen, writtenWrappingKey)) {
        	SEC_LOG_ERROR("SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGKEY failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
    	if (SEC_RESULT_SUCCESS != SecAsn1KC_GetAttrUint64(kc, SEC_ASN1KC_WRAPPINGKEYID, wrappingId)) {
        	SEC_LOG_ERROR("SecAsn1KC_GetAttrBuffer SEC_ASN1KC_WRAPPINGKEYID failed");
        	return SEC_RESULT_FAILURE;
    	}
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecKey_ExtractWrappedKeyParamsAsn1BufferV3(SEC_BYTE *asn1, SEC_SIZE asn1_len,
                                                    SEC_BYTE *payload, SEC_SIZE payloadLen, SEC_SIZE *written,
                                                    Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg, SEC_SIZE *key_offset,
                                                    SEC_BYTE *wrappingKey, SEC_SIZE wrappingKeySize, SEC_SIZE *writtenWrappingKey)
{
    Sec_Asn1KC *asn1kc = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    asn1kc = SecAsn1KC_Decode(asn1, asn1_len);
    if (asn1kc == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_Decode failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExtractWrappedKeyParamsAsn1V3(asn1kc, payload, payloadLen, written,
                                                                    wrappedKeyType, wrappingId, wrappingIv, wrappingAlg, key_offset,
                                                                    wrappingKey, wrappingKeySize, writtenWrappingKey))
    {
        SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1V3 failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    SecAsn1KC_Free(asn1kc);
    return res;
}

void SecKeyProperties_SetDefault(Sec_KeyProperties* props, Sec_KeyType type) {
    memset(props->keyId, 0, sizeof(props->keyId));
    memset(props->rights, SEC_KEYOUTPUTRIGHT_NOT_SET, sizeof(props->rights));
    memset(props->notBefore, 0, sizeof(props->notBefore));
    memset(props->notOnOrAfter, 0, sizeof(props->notOnOrAfter));
    props->keyLength = SecKey_GetKeyLenForKeyType(type);
    props->keyType = type;
    props->usage = SEC_KEYUSAGE_DATA_KEY;
    props->cacheable = 1;
}

#endif
