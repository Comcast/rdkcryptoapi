
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
 * @file sec_security_utils.h
 *
 * @brief Helper utilities for implementing the Security API
 *
 */

#ifndef SEC_SECURITY_UTILS_H_
#define SEC_SECURITY_UTILS_H_

#include "sec_security.h"
#include <openssl/rsa.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct
{
    uint8_t inner_kc_type;
    uint8_t reserved[7];

    uint8_t device_id[SEC_DEVICEID_LEN];
} SecUtils_KeyStoreHeader;

#define SEC_UTILS_KEYSTORE_MAGIC "KST0"

/* create a bit mask for a specified bit */
#define SEC_BIT_MASK(bit) (1 << bit)

/* read a specified bit */
#define SEC_BIT_READ(bit, input) ((input >> bit) & 1)

/* write a specified value at the specific bit position */
#define SEC_BIT_WRITE(bit, input, val) ((~SEC_BIT_MASK(bit) | input) | ((val & 1) << bit))

#define SEC_INVALID_EPOCH (SEC_SIZE)-1

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle *proc, SEC_BOOL require_mac, void* store, SEC_SIZE store_len);
Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle *proc, SecUtils_KeyStoreHeader *header, Sec_KeyContainer container);
SecUtils_KeyStoreHeader *SecUtils_GetKeyStoreUserHeader(void *store);

/**
 * @brief Read data from a file into a specified buffer
 *
 * @param path file path
 * @param data output data buffer where the file contents will be written
 * @param data_len length of the output buffer
 * @param data_read actual number of bytes written
 *
 * @return status of the operation
 */
Sec_Result SecUtils_ReadFile(const char *path, void *data, SEC_SIZE data_len, SEC_SIZE *data_read);

/**
 * @brief Write the input data into a specified file
 *
 * @param path output file path
 * @param data data to write
 * @param data_len length of input data
 *
 * @return status of the operation
 */
Sec_Result SecUtils_WriteFile(const char *path, void *data, SEC_SIZE data_len);

/**
 * @brief create a specified directory
 * @param path directory path
 */
Sec_Result SecUtils_MkDir(const char *path);

/**
 * @brief Remove a specified file
 *
 * @param path of the file to remove
 */
Sec_Result SecUtils_RmFile(const char *path);

/**
 * @brief Checks whether the specified file exists
 *
 * @param path file path
 *
 * @return 1 if the file exists, 0 if it does not
 */
SEC_BOOL SecUtils_FileExists(const char *path);

typedef struct
{
    char name[SEC_MAX_FILE_PATH_LEN];
    SEC_BYTE is_dir;
} Sec_LsDirEntry;

/**
 * @brief Obtain directory entries from a specified dir
 *
 * @param path path of the directory to list
 * @param entries pointer to the entry array.  If NULL, the entries info will not be filled in, but the number
 * of items will still be returned
 * @param maxNumEntries The maximun number of entries to fill.
 *
 * @return number of directory entries in a specified dir
 */
SEC_SIZE SecUtils_LsDir(const char *path, Sec_LsDirEntry *entries, SEC_SIZE maxNumEntries);

/**
 * @brief Write a BIGNUM value into the specified buffer
 */
Sec_Result SecUtils_BigNumToBuffer(const BIGNUM *bignum, SEC_BYTE *buffer,
        SEC_SIZE buffer_len);

/**
 * @brief Obtain an OpenSSL RSA object from the private key binary blob
 */
RSA *SecUtils_RSAFromPrivBinary(Sec_RSARawPrivateKey *binary);

/**
 * @brief Obtain an OpenSSL RSA object from the full private key binary blob
 */
RSA *SecUtils_RSAFromPrivFullBinary(Sec_RSARawPrivateFullKey *binary);

/**
 * @brief Obtain an OpenSSL RSA object from the public key binary blob
 */
RSA *SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey *binary);

/**
 * @brief Write OpenSSL RSA object into a private key binary blob
 */
void SecUtils_RSAToPrivBinary(RSA *rsa, Sec_RSARawPrivateKey *binary);

/**
 * @brief Write OpenSSL RSA object into a full private key binary blob
 */
void SecUtils_RSAToPrivFullBinary(RSA *rsa, Sec_RSARawPrivateFullKey *binary);

/**
 * @brief Write OpenSSL RSA object into a public key binary blob
 */
void SecUtils_RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary);

RSA *SecUtils_RSAFromDERPriv(SEC_BYTE *der, SEC_SIZE der_len);

Sec_Result SecUtils_PKEYToDERPriv(EVP_PKEY *evp_key, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_RSAToDERPriv(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_RSAToDERPrivKeyInfo(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);

RSA *SecUtils_RSAFromDERPub(SEC_BYTE *der, SEC_SIZE der_len);

Sec_Result SecUtils_RSAToDERPubKey(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);

RSA *SecUtils_RSAFromPEMPriv(SEC_BYTE *pem, SEC_SIZE pem_len);

RSA *SecUtils_RSAFromPEMPub(SEC_BYTE *pem, SEC_SIZE pem_len);

SEC_BOOL SecUtils_RSAIsClearKC(Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len);

RSA* SecUtils_RSAFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len);

SEC_BOOL SecUtils_RSAHasPriv(RSA *rsa);

SEC_BOOL SecUtils_ECCIsClearKC(Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len);

EC_KEY* SecUtils_ECCFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len);

SEC_BOOL SecUtils_ECCHasPriv(EC_KEY *ec_key);

/**
 * @brief Obtain an OpenSSL EC_KEY object from the private key binary blob
 */
EC_KEY *SecUtils_ECCFromOnlyPrivBinary(Sec_ECCRawOnlyPrivateKey *binary);

/**
 * @brief Obtain an OpenSSL EC_KEY object from the private key binary blob
 */
EC_KEY *SecUtils_ECCFromPrivBinary(Sec_ECCRawPrivateKey *binary);

/**
 * @brief Obtain an OpenSSL EC_KEY object from the public key binary blob
 */
EC_KEY *SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey *binary);

/**
 * @brief Write OpenSSL EC_KEY object into a private key binary blob
 *
 * The private key also contains the public key
 */
Sec_Result SecUtils_ECCToPrivBinary(EC_KEY *ec_key, Sec_ECCRawPrivateKey *binary);

/**
 * @brief Write OpenSSL EC_KEY object into a public key binary blob
 */
Sec_Result SecUtils_ECCToPubBinary(EC_KEY *ec_key, Sec_ECCRawPublicKey *binary);

EC_KEY *SecUtils_ECCFromDERPriv(SEC_BYTE *der, SEC_SIZE der_len);
EC_KEY *SecUtils_ECCFromPEMPriv(SEC_BYTE *pem, SEC_SIZE pem_len);
EC_KEY *SecUtils_ECCFromDERPub(SEC_BYTE *der, SEC_SIZE der_len);
EC_KEY *SecUtils_ECCFromPEMPub(SEC_BYTE *pem, SEC_SIZE pem_len);
Sec_Result SecUtils_ECCToDERPriv(EC_KEY *ec_key, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);
Sec_Result SecUtils_ECCToDERPrivKeyInfo(EC_KEY *ec_key, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);
Sec_Result SecUtils_ECCToDERPubKey(EC_KEY *ec_key, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written);

int SecUtils_ElGamal_Encrypt_Rand(EC_KEY *ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output, SEC_SIZE outputSize, BIGNUM *sender_rand);
int SecUtils_ElGamal_Encrypt(EC_KEY *ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output, SEC_SIZE outputSize);
int SecUtils_ElGamal_Decrypt(EC_KEY *ec_key, SEC_BYTE* input, SEC_SIZE inputSize, SEC_BYTE* output, SEC_SIZE outputSize);

/**
 * @brief Write an OpenSSL X509 object in DER format
 */
SEC_SIZE SecUtils_X509ToDer(X509 *x509, void *mem);

X509 * SecUtils_DerToX509(SEC_BYTE *der, SEC_SIZE der_len);
SEC_SIZE SecUtils_X509ToDerLen(X509 *x509, void *mem, SEC_SIZE mem_len);

/**
 * @brief Verify X509 certificate with public RSA key
 */
Sec_Result SecUtils_VerifyX509WithRawRSAPublicKey(
        X509 *x509, Sec_RSARawPublicKey* public_key);

/**
 * @brief Verify X509 certificate with public ECC key
 */
Sec_Result SecUtils_VerifyX509WithRawECCPublicKey(
        X509 *x509, Sec_ECCRawPublicKey* public_key);


/**
 * @brief Increment the AES 128-bit counter
 */
void SecUtils_AesCtrInc(SEC_BYTE *counter);

/*
 * @brief Create Digest Info structure for RSA signing from the digest
 */
Sec_Result SecUtils_DigestInfoForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE* padded_len, SEC_SIZE keySize);

/**
 * @brief Perform required padding for an RSA input data
 */
Sec_Result SecUtils_PadForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE keySize);

/**
 * @brief Checks whether the specified strings ends with the other string
 */
SEC_BYTE SecUtils_EndsWith(const char* str, const char* end);

/**
 * @brief obtain the index of the item in a list
 */
int SecUtils_ItemIndex(SEC_OBJECTID *items, SEC_SIZE numItems, SEC_OBJECTID item);

/**
 * @brief insert new item into the list if it does not exist.
 */
SEC_SIZE SecUtils_UpdateItemList(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, SEC_OBJECTID item_id);

/**
 * @brief insert new items into the list from the specified directory.
 */
SEC_SIZE SecUtils_UpdateItemListFromDir(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, const char* dir, const char* ext);

Sec_Result SecUtils_WrapRSAPriv(Sec_ProcessorHandle *proc, SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv, RSA *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);
Sec_Result SecUtils_WrapRSAPrivKeyInfo(Sec_ProcessorHandle *proc, SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv, RSA *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_WrapSymetric(Sec_ProcessorHandle *proc,
                                 SEC_OBJECTID wrappingKey,
                                 Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                 SEC_BYTE *payload, SEC_SIZE payloadLen,
                                 SEC_BYTE *out, SEC_SIZE out_len,
                                 SEC_SIZE *written);

Sec_Result SecUtils_WrapECCPriv(Sec_ProcessorHandle *proc,
                                SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_WrapECCPrivKeyInfo(Sec_ProcessorHandle *proc,
                                       SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                       EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_WrapRawECCPriv(Sec_ProcessorHandle *proc,
                                   SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                   const EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);

Sec_Result SecUtils_WrapRawECCPrivKeyInfo(Sec_ProcessorHandle *proc,
                                          SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                          const EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written);

/**
 * @brief Get the key type of the specified OpenSSL EC_GROUP
 *
 * @param EC_GROUP Group for which a key type is needed
 *
 * @return The key type or SEC_KEYTYPE_NUM if EC_GROUP is invalid
 */
Sec_KeyType SecKey_GroupToKeyType(const EC_GROUP *group);

/**
 * @brief Debugging functions
 */
void EC_POINT_dump(const EC_POINT *ec_point);
void EC_KEY_dump(const EC_KEY *ec_key);
void BN_dump(const BIGNUM *bn);

/**
 * @brief Extracts the X and Y coordinates from an EC_KEY
 *
 * @param ec_key The ec_key to extract from
 * @param xp Pointer to a Point to the X coordinate.  May not be NULL.
 * @param yp Pointer to a Point to the Y coordinate.  May be NULL if you don't
 *           need the Y coordinate.
 * @param keyTypep Optional pointer to the key type.  May be NULL.
 *
 * This calls BN_new() to allocate *xp and optionally *yp.
 * If this returns ok, then the caller is responsible to call BN_free() on *xp
 * and, if valid, *yp.
 *
 * @return status of the operation
 */
Sec_Result SecUtils_Extract_EC_KEY_X_Y(const EC_KEY *ec_key,
                                       BIGNUM **xp, BIGNUM **yp,
                                       Sec_KeyType *keyTypep);

/**
 * @brief Get the output length needed for encoding.
 */
SEC_SIZE SecUtils_Base64EncodeLength(SEC_SIZE size);

/**
 * @brief Get the output length needed for decoding.
 */
SEC_SIZE SecUtils_Base64DecodeLength(SEC_SIZE size);

/**
 * @brief Base64 url decode the input string
 */
Sec_Result SecUtils_Base64UrlDecode(const SEC_BYTE* input, SEC_SIZE in_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len);

/**
 * @brief Base64 url encode the input string
 */
Sec_Result SecUtils_Base64UrlEncode(const SEC_BYTE* input, SEC_SIZE in_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len);

/**
 * @brief base64 decode the input string.
 */
Sec_Result SecUtils_Base64Decode(const SEC_BYTE* input, SEC_SIZE in_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE* out_len);

/**
 * @brief Base64 encode the input string.
 */
Sec_Result SecUtils_Base64Encode(const SEC_BYTE* input, SEC_SIZE input_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len);

/**
 * @brief Convert the given epoch to iso formatted string.
 */
char* SecUtils_Epoch2IsoTime(SEC_SIZE epoch, char* iso_time, SEC_SIZE iso_time_size);

/**
 * @brief Convert the given iso time string to epoch value.
 */
SEC_SIZE SecUtils_IsoTime2Epoch(const char* iso_time, SEC_SIZE *epoch);

/**
 * @brief Get the current epoch value.
 */
SEC_SIZE SecUtils_GetUtcNow();


#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_UTILS_H_ */
