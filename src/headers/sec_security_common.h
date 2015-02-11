
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

/**
 * @file sec_security_common.h
 *
 * @brief Common functions used by all platform implementations
 *
 */

#ifndef SEC_SECURITY_COMMON_H_
#define SEC_SECURITY_COMMON_H_

#include "sec_security_datatype.h"
#ifndef SEC_COMMON_17
#include "sec_security_asn1kc.h"
#endif
#include <openssl/rsa.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Buffer information structure
 */
typedef struct
{
    SEC_BYTE* base;
    SEC_SIZE size;
    SEC_SIZE written;
} Sec_Buffer;

/**
 * @brief initialize the Sec_Buffer structure
 *
 * @param buffer Sec_Buffer structure to initialize
 * @param mem memory buffer to use
 * @param len size of the memory buffer
 */
void SecBuffer_Init(Sec_Buffer *buffer, void *mem, SEC_SIZE len);

/**
 * @brief reset the buffer
 *
 * @param buffer Sec_Buffer structure to initialize
 */
void SecBuffer_Reset(Sec_Buffer *buffer);

/**
 * @brief Write data to a buffer
 *
 * @param buffer pointer to a Sec_Buffer structure to use
 * @param data input data to write
 * @param len length of input data
 *
 * @return Status of the operation.  Error status will be returned if there
 * is not enough space left in the output buffer.
 */
Sec_Result SecBuffer_Write(Sec_Buffer *buffer, void *data, SEC_SIZE len);

typedef enum
{
    SEC_ENDIANESS_BIG,
    SEC_ENDIANESS_LITTLE,
    SEC_ENDIANESS_UNKNOWN
} Sec_Endianess;

/**
 * @brief Obtain chip endianess at runtime
 */
Sec_Endianess Sec_GetEndianess(void);

/**
 * @brief Convert big endian bytes to native uint32
 */
uint32_t Sec_BEBytesToUint32(SEC_BYTE *bytes);

/**
 * @brief Convert big endian bytes to native uint64
 */
uint64_t Sec_BEBytesToUint64(SEC_BYTE *bytes);

/**
 * @brief Convert native uint32 to big endian bytes
 */
void Sec_Uint32ToBEBytes(uint32_t val, SEC_BYTE *bytes);

/**
 * @brief Convert native uint64 to big endian bytes
 */
void Sec_Uint64ToBEBytes(uint64_t val, SEC_BYTE *bytes);

/**
 * @brief Endian swap
 */
uint16_t Sec_EndianSwap_uint16(uint16_t val);

/**
 * @brief Endian swap
 */
int16_t Sec_EndianSwap_int16(int16_t val);

/**
 * @brief Endian swap
 */
uint32_t Sec_EndianSwap_uint32(uint32_t val);

/**
 * @brief Endian swap
 */
int32_t Sec_EndianSwap_int32(int32_t val);

/**
 * @brief Endian swap
 */
int64_t Sec_EndianSwap_int64(int64_t val);

/**
 * @brief Endian swap
 */
uint64_t Sec_EndianSwap_uint64(uint64_t val);

/**
 * @brief memcmp replacement with constant time runtime
 */
int Sec_Memcmp(const void* ptr1, const void* ptr2, const size_t num);

/**
 * @brief memset replacement that cannot be optimized out
 */
void *Sec_Memset(void *ptr, int value, size_t num);

/**
 * @brief Check whether the supplied key and iv are valid for the chosen cipher algorithm
 *
 * @param key_type key type
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param iv initialization vector
 *
 * @return status of the call
 */
Sec_Result SecCipher_IsValidKey(Sec_KeyType key_type,
        Sec_CipherAlgorithm algorithm, Sec_CipherMode mode, SEC_BYTE *iv);

SEC_BOOL SecCipher_IsCBC(Sec_CipherAlgorithm alg);

/**
 * @brief get the required output buffer size for the specified combination of input parameters
 *
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param keyType key type
 * @param inputSize size of the input buffer
 * @param outputSize size of the output buffer
 * @param lastInput is this the last input to the cipher
 *
 * @return status of the call
 */
Sec_Result SecCipher_GetRequiredOutputSize(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
        SEC_SIZE *outputSize, SEC_BOOL lastInput);

/**
 * @brief get the required output buffer length for fragemnted encryption/decryption
 *
 * @param algorithm cipher algorithm
 * @param mode cipher mode
 * @param keyType key type
 * @param inputSize size of the input buffer
 * @param outputSize size of the output buffer
 * @param lastInput is this the last input to the cipher
 * @param framentOffset offset in bytes of the fragment data within larger packet
 * @param fragmentSize length in bytes of the data fragment
 * @param fragmentPeriod the length in bytes of the packet containing the fragment
 *
 * @return status of the call
 */
Sec_Result SecCipher_GetRequiredOutputSizeFragmented(Sec_CipherAlgorithm algorithm,
        Sec_CipherMode mode, Sec_KeyType keyType, SEC_SIZE inputSize,
        SEC_SIZE *outputSize, SEC_BOOL lastInput, SEC_SIZE fragmentOffset, SEC_SIZE fragmentSize, SEC_SIZE fragmentPeriod);

/**
 * @brief Apply PKCS7 padding to the AES input block
 *
 * @param inputBlock input data to pad
 * @param inputSize size of input data
 * @param outputBlock Output block.  Has to be the size of SEC_AES_BLOCKSIZE
 */
void SecCipher_PadAESPKCS7Block(SEC_BYTE *inputBlock, SEC_SIZE inputSize,
        SEC_BYTE *outputBlock);

/**
 * @brief Checks whether the specified cipher algorithm is AES
 */
SEC_BOOL SecCipher_IsAES(Sec_CipherAlgorithm alg);

/**
 * @brief Checks whether the specified cipher algorithm is RSA
 */
SEC_BOOL SecCipher_IsRsa(Sec_CipherAlgorithm alg);

Sec_Result SecCipher_SingleInput(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, Sec_KeyHandle *key,
        SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
        SEC_SIZE output_len, SEC_SIZE *written);

Sec_Result SecCipher_SingleInputId(Sec_ProcessorHandle *proc,
        Sec_CipherAlgorithm alg, Sec_CipherMode mode, SEC_OBJECTID key,
        SEC_BYTE *iv, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *output,
        SEC_SIZE output_len, SEC_SIZE *written);

SEC_BOOL SecCipher_IsPKCS7Padded(Sec_CipherAlgorithm algorithm);
SEC_BOOL SecCipher_IsDecrypt(Sec_CipherMode mode);

/**
 * @brief Checks whether the passed in key is valid for a chosen signing algorithm and mode
 *
 * @param key_type key type
 * @param algorithm signing algorithm
 * @param mode signing mode
 *
 * @return status of the operation
 */
Sec_Result SecSignature_IsValidKey(Sec_KeyType key_type,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode);

/**
 * @brief Obtain a digest algorithm used by a specific signing algorithm
 *
 * @param alg signing algorithm
 *
 * @return digest algorithm used
 */
Sec_DigestAlgorithm SecSignature_GetDigestAlgorithm(Sec_SignatureAlgorithm alg);

/**
 * @brief Signature util that handles Sec_SignatureHandle generation and release
 *
 * @param secProcHandle processor handle
 * @param algorithm signing algorithm
 * @param mode signing mode
 * @param key key used for signing operations
 * @param input pointer to the input buffer whose signature we are generating/verifying
 * @param inputSize the length of the input
 * @param signature buffer where signature is/will be stored
 * @param signatureSize output variable that will be set to the signature size
 *
 * @return The status of the operation
 */
Sec_Result SecSignature_SingleInput(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_KeyHandle* key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

Sec_Result SecSignature_SingleInputCert(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        Sec_CertificateHandle* cert, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

Sec_Result SecSignature_SingleInputId(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        SEC_OBJECTID id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

Sec_Result SecSignature_SingleInputCertId(Sec_ProcessorHandle* secProcHandle,
        Sec_SignatureAlgorithm algorithm, Sec_SignatureMode mode,
        SEC_OBJECTID cert_id, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* signature,
        SEC_SIZE *signatureSize);

/**
 * @brief Check whether the passed in key type is valid for a chosen MAC algorithm
 *
 * @param key_type key type
 * @param algorithm MAC algorithm
 *
 * @return status of the operation
 */
Sec_Result SecMac_IsValidKey(Sec_KeyType key_type, Sec_MacAlgorithm algorithm);

/**
 * @brief Obtain a digest algorithm used by a specified MAC algorithm
 *
 * @param alg MAC algorithm
 *
 * @return digest algorithm used
 */
Sec_DigestAlgorithm SecMac_GetDigestAlgorithm(Sec_MacAlgorithm alg);

Sec_Result SecMac_SingleInput(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
        Sec_KeyHandle *key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
        SEC_SIZE *mac_len);

Sec_Result SecMac_SingleInputId(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg,
        SEC_OBJECTID key, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac,
        SEC_SIZE *mac_len);

/**
 * @brief Checks if a passed in key type is symetric.
 *
 * @param type key type
 *
 * @return 1 if key type is symetric, 0 if asymetric
 */
SEC_BOOL SecKey_IsSymetric(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is an AES key.
 *
 * @param type key type
 *
 * @return 1 if key type is AES, 0 if not
 */
SEC_BOOL SecKey_IsAES(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsRsa(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is pub Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is pub rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsPubRsa(Sec_KeyType type);

/**
 * @brief Checks if a passed in key type is priv Rsa
 *
 * @param type key type
 *
 * @return 1 if key type is priv rsa, 0 otherwise
 */
SEC_BOOL SecKey_IsPrivRsa(Sec_KeyType type);

/**
 * @brief Obtain a key length in bytes for a specified key type.
 *
 * For symetric keys, the return value will be the actual key size.  For asymetric keys
 * the return value will be the modulus size.
 *
 * @param keyType key type
 *
 * @return key size
 */
SEC_SIZE SecKey_GetKeyLenForKeyType(Sec_KeyType keyType);

/**
 * @brief Is the specified container a raw (clear) container
 */
SEC_BOOL SecKey_IsClearKeyContainer(Sec_KeyContainer kct);

/**
 * @brief  Obtain a key container type for a specified key type
 *
 * @param key_type key type
 * @return key container type
 */
Sec_KeyContainer SecKey_GetClearContainer(Sec_KeyType key_type);

/**
 * @brief Find if the key with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecKey_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief finds the first available key id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecKey_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base, SEC_OBJECTID top);

/**
 * @brief Get the type (msd byte) of the object id
 */
uint8_t SecKey_GetObjectType(SEC_OBJECTID object_id);

/**
 * @brief Obtain a digest value computed over a specified key
 *
 * @param proc secure processor handle
 * @param key_id key id
 * @param alg digest algorithm to use
 * @param digest output digest value
 * @param digest_len size of the written digest value
 * @return
 */
Sec_Result SecKey_ComputeKeyDigest(Sec_ProcessorHandle *proc, SEC_OBJECTID key_id,
        Sec_DigestAlgorithm alg, SEC_BYTE *digest, SEC_SIZE *digest_len);


/**
 * @brief Obtain the size of the digest for a specified digest algorithm
 *
 * @param alg digest algorithm
 *
 * @return digest size in bytes
 */
SEC_SIZE SecDigest_GetDigestLenForAlgorithm(Sec_DigestAlgorithm alg);

/**
 * @brief compute inputs for the base key ladder
 */
Sec_Result SecKey_ComputeBaseKeyLadderInputs(Sec_ProcessorHandle *secProcHandle,
        const char *inputDerivationStr, const char *cipherAlgorithmStr,
        SEC_BYTE *nonce, Sec_DigestAlgorithm digestAlgorithm, SEC_SIZE inputSize,
        SEC_BYTE *c1, SEC_BYTE *c2, SEC_BYTE *c3, SEC_BYTE *c4);

/**
 * @brief Check if provided algorithm takes digest as an input
 */
SEC_BOOL SecSignature_IsDigest(Sec_SignatureAlgorithm alg);

/**
 * log callback function
 */
typedef void (*SecApiLogCallback)(const char *fmt, ...);

/**
 * @brief set log callback function
 *
 * @param cb pointer to the logger function
 */
void Sec_SetLogger(SecApiLogCallback cb);

/**
 * @brief get the log callback function
 *
 * @return pointer to the logger function
 */
SecApiLogCallback Sec_GetLogger(void);

/**
 * @brief default logger implementation (stdout)
 */
void Sec_DefaultLoggerCb(const char *fmt, ...);

/**
 * @brief NOP logger implementation
 */
void Sec_NOPLoggerCb(const char *fmt, ...);

/**
 * @brief Print a hexadecimal value
 */
void Sec_PrintHex(void* data, SEC_SIZE numBytes);

/**
 * Initialize all OpenSSL algorithms used by the Security API.  Register securityapi engine.
 */
void Sec_InitOpenSSL(void);

/**
 * Print OpenSSL version information
 */
void Sec_PrintOpenSSLVersion();

/**
 * @brief Obtain an OpenSSL RSA key from the Security API key handle.  This RSA
 * key will support performing RSA encrypt/decrypt/sign/verify operations in hardware
 * when used by OpenSSL functions such as PKCS7_sign, PKCS7_verify, etc.
 */
RSA* SecKey_ToEngineRSA(Sec_KeyHandle *key);

RSA* SecKey_ToEngineRSAWithCert(Sec_KeyHandle *key, Sec_CertificateHandle *cert);

/**
 * @brief Load an OpenSSL X509 object from a DER format
 */
X509 * SecCertificate_DerToX509(void *mem, SEC_SIZE len);

/**
 * @brief Obtain an OpenSSL X509 certificate from the Security API cert handle.
 */
X509* SecCertificate_ToX509(Sec_CertificateHandle *cert);

/**
 * @brief Find if the certificate with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecCertificate_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief Obtain the size of the certificate in DER format
 *
 * @param cert_handle certificate whose size we want to obtain
 */
SEC_SIZE SecCertificate_GetSize(Sec_CertificateHandle* cert_handle);

/**
 * @brief finds the first available certificate id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecCertificate_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base, SEC_OBJECTID top);

/**
 * @brief Utility function for calculating a digest value of a single input buffer
 *
 * @param proc secure processor handle
 * @param alg digest algorithm to use
 * @param input input data to calculate digest over
 * @param input_len size of input data in bytes
 * @param digest output buffer where the calculated digest value will be written
 * @param digest_len number of bytes written to the output digest buffer
 *
 * @return status of the operation
 */
Sec_Result SecDigest_SingleInput(Sec_ProcessorHandle *proc, Sec_DigestAlgorithm alg, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *digest, SEC_SIZE *digest_len);

/**
 * @brief Utility function for calculating a digest value of a single input buffer
 *
 * @param proc secure processor handle
 * @param alg digest algorithm to use
 * @param key_id id of the key over which the digest is being calculated
 * @param digest output buffer where the calculated digest value will be written
 * @param digest_len number of bytes written to the output digest buffer
 *
 * @return status of the operation
 */
Sec_Result SecDigest_SingleInputWithKeyId(Sec_ProcessorHandle *proc, Sec_DigestAlgorithm alg, SEC_OBJECTID key_id, SEC_BYTE *digest, SEC_SIZE *digest_len);

/**
 * @brief Utility function for filling out a random value
 *
 * @param proc secure processor handle
 * @param alg random algorithm to use
 * @param output output buffer where the random value will be written
 * @param output_len number of bytes written to the output buffer
 *
 * @return status of the operation
 */
Sec_Result SecRandom_SingleInput(Sec_ProcessorHandle *proc,
        Sec_RandomAlgorithm alg, SEC_BYTE *output, SEC_SIZE output_len);

/**
 * @brief Find if the bundle with a specific id has been provisioned
 *
 * @param secProcHandle secure processor handle
 * @param object_id id of the certificate
 *
 * @return 1 if an object has been provisioned, 0 if it has not been
 */
SEC_BOOL SecBundle_IsProvisioned(Sec_ProcessorHandle* secProcHandle,
        SEC_OBJECTID object_id);

/**
 * @brief finds the first available bundle id in the range passed in
 *
 * @param proc secure processor
 * @param base bottom of the range to search
 * @param top top of the range to search
 * @return
 */
SEC_OBJECTID SecBundle_ObtainFreeObjectId(Sec_ProcessorHandle *proc, SEC_OBJECTID base,
        SEC_OBJECTID top);

#ifndef SEC_COMMON_17

/**
 * @brief Generate an Asn1 key container for wrapped keys
 */
Sec_Result SecKey_GenerateWrappedKeyAsn1(SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, Sec_KeyType wrappedKeyType,
        SEC_OBJECTID wrappingKeyId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm wrappingAlgorithm,
        SEC_BYTE *output, SEC_SIZE output_len, SEC_SIZE *written);

/**
 * @brief Extract wrapped key params from ASN1KC
 */
Sec_Result SecKey_ExtractWrappedKeyParamsAsn1(Sec_Asn1KC *kc,
        SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, SEC_SIZE *written,
        Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg);

/**
 * @brief Extract wrapped key params from ASN1KC buffer
 */
Sec_Result SecKey_ExtractWrappedKeyParamsAsn1Buffer(SEC_BYTE *asn1, SEC_SIZE asn1_len,
        SEC_BYTE *wrappedKey, SEC_SIZE wrappedKeyLen, SEC_SIZE *written,
        Sec_KeyType *wrappedKeyType, SEC_OBJECTID *wrappingId, SEC_BYTE *wrappingIv, Sec_CipherAlgorithm *wrappingAlg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_COMMON_H_ */
