
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
#ifndef SEC_SECURITY_DATATYPE_H_
#define SEC_SECURITY_DATATYPE_H_

#include <stdint.h>
#include <sys/param.h>

#ifdef __cplusplus

extern "C"
{
#endif

#if !defined(_32_BIT_) && !defined(_64_BIT_)
    #if defined(_WIN32) || defined(_WIN64)
        #if defined(_WIN64)
            #define _64_BIT_
        #else
            #define _32_BIT_
        #endif
    #elif __GNUC__ || defined(__APPLE__)
        #if __x86_64__ || __ppc64__
            #define _64_BIT_
        #else
            #define _32_BIT_
        #endif
    #else
        #error "Could not determine whether compiling for 32 bit or 64 bit system"
    #endif
#endif

/* enables debug prints */
#define SEC_DEBUG

/* macro to string */
#define SEC_MTOS_(x) #x
#define SEC_MTOS(x) SEC_MTOS_(x)

/* min */
#ifndef SEC_MIN
#define SEC_MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* max */
#ifndef SEC_MAX
#define SEC_MAX(a,b) (((a)<(b))?(b):(a))
#endif

#define SEC_MAX_FILE_PATH_LEN MAXPATHLEN

/* maximum length of a digest value (in bytes) */
#define SEC_DIGEST_MAX_LEN 32

/* maximum length of a MAC value (in bytes) */
#define SEC_MAC_MAX_LEN 32

/* maximum length of a MAC key (in bytes) */
#define SEC_MAC_KEY_MAX_LEN 32

/* maximum length of an RSA key modulus (in bytes) */
#define SEC_RSA_KEY_MAX_LEN 256

/* length of an NIST_P256 ECC key */
#define SEC_ECC_NISTP256_KEY_LEN 32

/* maximum length of an ECC point coordinate (in bytes) */
#define SEC_EC_KEY_MAX_LEN 80

/* maximum length of a signature value (in bytes) */
#define SEC_SIGNATURE_MAX_LEN SEC_RSA_KEY_MAX_LEN

/* maximum length of an AES key (in bytes) */
#define SEC_AES_KEY_MAX_LEN 32

/* aes block size (in bytes) */
#define SEC_AES_BLOCK_SIZE 16

/* maximum length of a symetric key (AES or MAC) (in bytes) */
#define SEC_SYMETRIC_KEY_MAX_LEN SEC_MAX(SEC_AES_KEY_MAX_LEN, SEC_MAC_KEY_MAX_LEN)

/* maximum length of the IV value (in bytes) */
#define SEC_CIPHER_IV_MAX_LEN SEC_AES_KEY_MAX_LEN

/* the length of the device id (in bytes) */
#define SEC_DEVICEID_LEN 8

/* the length of client nonce (in bytes) */
#define SEC_NONCE_LEN 20

/* fixed reserved ids */
#define SEC_OBJECTID_INVALID 0xffffffffffffffffULL
#define SEC_OBJECTID_BASE_KEY_AES 0xfffffffffffffffeULL
#define SEC_OBJECTID_BASE_KEY_MAC 0xfffffffffffffffdULL
#define SEC_OBJECTID_STORE_MACKEYGEN_KEY 0xfffffffffffffffcULL
#define SEC_OBJECTID_CERTSTORE_KEY 0xfffffffffffffffbULL
#define SEC_OBJECTID_STORE_AES_KEY 0xfffffffffffffffaULL
#define SEC_OBJECTID_SIG_FROM_CERT 0xfffffffffffffff9ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_8 0xfffffffffffffff8ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_7 0xfffffffffffffff7ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_6 0xfffffffffffffff6ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_5 0xfffffffffffffff5ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_4 0xfffffffffffffff4ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_3 0xfffffffffffffff3ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_2 0xfffffffffffffff2ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_1 0xfffffffffffffff1ULL
#define SEC_OBJECTID_RESERVEDPLATFORM_0 0xfffffffffffffff0ULL

/* reserved key space */
#define SEC_OBJECTID_RESERVED_TOP  0xfffffffffffffff0ULL
#define SEC_OBJECTID_RESERVED_BASE 0xffffffffffffff00ULL

/* user key space */
#define SEC_OBJECTID_USER_TOP   0xffffffffffffff00ULL
#define SEC_OBJECTID_USER_BASE  0xfffffffffffff000ULL

#if defined(_64_BIT_) && !defined(__APPLE__)
    #define SEC_OBJECTID_PATTERN "%016lx"
    #define SEC_KEY_FILENAME_PATTERN "%016lx.key"
    #define SEC_KEYINFO_FILENAME_PATTERN "%016lx.keyinfo"
    #define SEC_CERT_FILENAME_PATTERN "%016lx.cert"
    #define SEC_CERTINFO_FILENAME_PATTERN "%016lx.certinfo"
    #define SEC_BUNDLE_FILENAME_PATTERN "%016lx.bin"
#else
    #define SEC_OBJECTID_PATTERN "%016llx"
    #define SEC_KEY_FILENAME_PATTERN "%016llx.key"
    #define SEC_KEYINFO_FILENAME_PATTERN "%016llx.keyinfo"
    #define SEC_CERT_FILENAME_PATTERN "%016llx.cert"
    #define SEC_CERTINFO_FILENAME_PATTERN "%016llx.certinfo"
    #define SEC_BUNDLE_FILENAME_PATTERN "%016llx.bin"
#endif

#define SEC_KEY_FILENAME_EXT ".key"
#define SEC_CERT_FILENAME_EXT ".cert"
#define SEC_BUNDLE_FILENAME_EXT ".bin"

#define SEC_KEYCONTAINER_MAX_LEN (1024 * 4)
#define SEC_BUNDLE_MAX_LEN (1024 * 128)
#define SEC_CERT_MAX_DATA_LEN (1024 * 64)

#define SEC_TRUE 1
#define SEC_FALSE 0

/* ASN1KC format defines */
#define SEC_ASN1KC_WRAPPEDKEY "WrappedKey"
#define SEC_ASN1KC_WRAPPEDKEYTYPEID "WrappedKeyTypeId"
#define SEC_ASN1KC_WRAPPINGKEYID "WrappingKeyId"
#define SEC_ASN1KC_WRAPPINGIV "WrappingIV"
#define SEC_ASN1KC_WRAPPINGALGORITHMID "WrappingAlgorithmId"
#define SEC_ASN1KC_WRAPPEDKEYOFFSET "WrappedKeyOffset"
#define SEC_ASN1KC_WRAPPINGKEY "WrappingKey"

/*****************************************************************************
 * EXPORTED TYPES
 *****************************************************************************/

typedef uint8_t SEC_BYTE;
typedef uint8_t SEC_BOOL;
typedef uint32_t SEC_SIZE;
typedef uint64_t SEC_OBJECTID;

// A general note for all the enums below:
// the ..._NUM value must be the last defined.  It is returned to indicate
// an invalid value

typedef enum
{
    SEC_KEYLADDERROOT_UNIQUE,
    SEC_KEYLADDERROOT_SHARED,
    SEC_KEYLADDERROOT_NUM
} Sec_KeyLadderRoot;

/**
 * @brief Cipher algorithms
 *
 */
typedef enum
{
    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING = 0,
    SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING,
    SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING,
    SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING,
    SEC_CIPHERALGORITHM_AES_CTR,
    SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING,
    SEC_CIPHERALGORITHM_RSA_OAEP_PADDING,
    SEC_CIPHERALGORITHM_ECC_ELGAMAL,
    SEC_CIPHERALGORITHM_NUM
} Sec_CipherAlgorithm;

/**
 * @brief Key types
 *
 */
typedef enum
{
    SEC_KEYTYPE_AES_128 = 0,
    SEC_KEYTYPE_AES_256,
    SEC_KEYTYPE_RSA_1024,
    SEC_KEYTYPE_RSA_2048,
    SEC_KEYTYPE_RSA_1024_PUBLIC,
    SEC_KEYTYPE_RSA_2048_PUBLIC,
    SEC_KEYTYPE_HMAC_128,
    SEC_KEYTYPE_HMAC_160,
    SEC_KEYTYPE_HMAC_256,
    SEC_KEYTYPE_ECC_NISTP256,
    SEC_KEYTYPE_ECC_NISTP256_PUBLIC,
    SEC_KEYTYPE_RSA_3072,
    SEC_KEYTYPE_RSA_3072_PUBLIC,
    SEC_KEYTYPE_NUM
} Sec_KeyType;

/**
 * @brief Key container types
 *
 */
typedef enum
{
    SEC_KEYCONTAINER_RAW_AES_128 = 0,
    SEC_KEYCONTAINER_RAW_AES_256,
    SEC_KEYCONTAINER_RAW_HMAC_128,
    SEC_KEYCONTAINER_RAW_HMAC_160,
    SEC_KEYCONTAINER_RAW_HMAC_256,
    SEC_KEYCONTAINER_RAW_RSA_1024,
    SEC_KEYCONTAINER_RAW_RSA_2048,
    SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC,
    SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC,
    SEC_KEYCONTAINER_PEM_RSA_1024,
    SEC_KEYCONTAINER_PEM_RSA_2048,
    SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC,
    SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC,
    SEC_KEYCONTAINER_SOC,
    SEC_KEYCONTAINER_SOC_INTERNAL_0,
    SEC_KEYCONTAINER_SOC_INTERNAL_1,
    SEC_KEYCONTAINER_SOC_INTERNAL_2,
    SEC_KEYCONTAINER_SOC_INTERNAL_3,
    SEC_KEYCONTAINER_SOC_INTERNAL_4,
    SEC_KEYCONTAINER_SOC_INTERNAL_5,
    SEC_KEYCONTAINER_SOC_INTERNAL_6,
    SEC_KEYCONTAINER_SOC_INTERNAL_7,
    SEC_KEYCONTAINER_STORE,
    SEC_KEYCONTAINER_DER_RSA_1024,
    SEC_KEYCONTAINER_DER_RSA_2048,
    SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC,
    SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC,
    SEC_KEYCONTAINER_ASN1,
    SEC_KEYCONTAINER_PEM_ECC_NISTP256,
    SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC,
    SEC_KEYCONTAINER_RAW_ECC_NISTP256,
    SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC,
    SEC_KEYCONTAINER_DER_ECC_NISTP256,
    SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC,
    SEC_KEYCONTAINER_SOC_INTERNAL_8,
    SEC_KEYCONTAINER_SOC_INTERNAL_9,
    SEC_KEYCONTAINER_SOC_INTERNAL_10,
    SEC_KEYCONTAINER_SOC_INTERNAL_11,
    SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256,
    SEC_KEYCONTAINER_RAW_RSA_3072,
    SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC,
    SEC_KEYCONTAINER_PEM_RSA_3072,
    SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC,
    SEC_KEYCONTAINER_DER_RSA_3072,
    SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC,
    SEC_KEYCONTAINER_JTYPE,
    SEC_KEYCONTAINER_COMCAST = SEC_KEYCONTAINER_JTYPE,
    SEC_KEYCONTAINER_EXPORTED,
    SEC_KEYCONTAINER_SOC_INTERNAL_12,
    SEC_KEYCONTAINER_SOC_INTERNAL_13,
    SEC_KEYCONTAINER_SOC_INTERNAL_14,
    SEC_KEYCONTAINER_SOC_INTERNAL_15,
    SEC_KEYCONTAINER_NUM
} Sec_KeyContainer;

/**
 * @brief Certificate container types
 *
 */
typedef enum
{
    SEC_CERTIFICATECONTAINER_X509_DER = 0,
    SEC_CERTIFICATECONTAINER_X509_PEM,
    SEC_CERTIFICATECONTAINER_SOC,
    SEC_CERTIFICATECONTAINER_NUM
} Sec_CertificateContainer;

/**
 * @brief Storage locations
 *
 */
typedef enum {
    SEC_STORAGELOC_RAM = 0,
    SEC_STORAGELOC_RAM_SOFT_WRAPPED,
    SEC_STORAGELOC_FILE,
    SEC_STORAGELOC_FILE_SOFT_WRAPPED,
    SEC_STORAGELOC_OEM,
    SEC_STORAGELOC_SOC = SEC_STORAGELOC_OEM,
    SEC_STORAGELOC_NUM
} Sec_StorageLoc;

/**
 * @brief Cipher modes
 *
 */
typedef enum
{
    SEC_CIPHERMODE_ENCRYPT = 0,
    SEC_CIPHERMODE_DECRYPT,
    SEC_CIPHERMODE_ENCRYPT_NATIVEMEM,
    SEC_CIPHERMODE_DECRYPT_NATIVEMEM,
    SEC_CIPHERMODE_NUM
} Sec_CipherMode;

/**
 * @brief Signature algorithms
 *
 */
typedef enum
{
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS = 0,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS,
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST,
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS,
    SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST,
    SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST,
    SEC_SIGNATUREALGORITHM_ECDSA_NISTP256,
    SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST,
    SEC_SIGNATUREALGORITHM_NUM
} Sec_SignatureAlgorithm;

/**
 * @brief Signature modes
 *
 */
typedef enum
{
    SEC_SIGNATUREMODE_SIGN = 0,
    SEC_SIGNATUREMODE_VERIFY,
    SEC_SIGNATUREMODE_NUM
} Sec_SignatureMode;

/**
 * @brief MAC algorithms
 *
 */
typedef enum
{
    SEC_MACALGORITHM_HMAC_SHA1 = 0,
    SEC_MACALGORITHM_HMAC_SHA256,
    SEC_MACALGORITHM_CMAC_AES_128,
    SEC_MACALGORITHM_NUM
} Sec_MacAlgorithm;

/**
 * @brief Digest algorithms
 *
 */
typedef enum
{
    SEC_DIGESTALGORITHM_SHA1 = 0,
    SEC_DIGESTALGORITHM_SHA256,
    SEC_DIGESTALGORITHM_NUM
} Sec_DigestAlgorithm;

/**
 * @brief Random algorithms
 *
 */
typedef enum
{
    SEC_RANDOMALGORITHM_TRUE = 0,
    SEC_RANDOMALGORITHM_PRNG,
    SEC_RANDOMALGORITHM_NUM
} Sec_RandomAlgorithm;

/**
 * @brief Function return codes
 *
 */
typedef enum
{
    SEC_RESULT_SUCCESS = 0,
    SEC_RESULT_FAILURE,
    SEC_RESULT_INVALID_PARAMETERS,
    SEC_RESULT_NO_SUCH_ITEM,
    SEC_RESULT_BUFFER_TOO_SMALL,
    SEC_RESULT_INVALID_INPUT_SIZE,
    SEC_RESULT_INVALID_HANDLE,
    SEC_RESULT_INVALID_PADDING,
    SEC_RESULT_UNIMPLEMENTED_FEATURE,
    SEC_RESULT_ITEM_ALREADY_PROVISIONED,
    SEC_RESULT_ITEM_NON_REMOVABLE,
    SEC_RESULT_VERIFICATION_FAILED,
    SEC_RESULT_NO_KEYSLOTS_AVAILABLE,
    SEC_RESULT_SVP_NOT_ENGAGED,
    SEC_RESULT_OPL_NOT_ENGAGED,
    SEC_RESULT_INVALID_SVP_DATA,
    SEC_RESULT_ALLOCATION_FAILED,
    SEC_RESULT_NUM
} Sec_Result;

/**
 * @brief Key output protection rights
 */
typedef enum
{
    SEC_KEYOUTPUTRIGHT_NOT_SET = 0x00,
    SEC_KEYOUTPUTRIGHT_SVP_REQUIRED = 0x01,
    SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED = 0x02,
    SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED = 0x03,
    SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED = 0x04,
    SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED = 0x05,
    SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED = 0x06,
    SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED = 0x07,
    SEC_KEYOUTPUTRIGHT_CGMSA_REQUIRED = 0x08,
    SEC_KEYOUTPUTRIGHT_RESERVED_10 = 0x09,
    SEC_KEYOUTPUTRIGHT_RESERVED_11 = 0x0a,
    SEC_KEYOUTPUTRIGHT_RESERVED_12 = 0x0b,
    SEC_KEYOUTPUTRIGHT_RESERVED_13 = 0x0c,
    SEC_KEYOUTPUTRIGHT_RESERVED_14 = 0x0d,
    SEC_KEYOUTPUTRIGHT_RESERVED_15 = 0x0e,
    SEC_KEYOUTPUTRIGHT_RESERVED_16 = 0x0f,
    SEC_KEYOUTPUTRIGHT_NUM
} Sec_KeyOutputRight;

/**
 * @brief Key usage values
 */
typedef enum
{
    SEC_KEYUSAGE_DATA_KEY = 0,
    SEC_KEYUSAGE_DATA,
    SEC_KEYUSAGE_KEY,
    SEC_KEYUSAGE_NUM
} Sec_KeyUsage;

typedef struct _Sec_KeyProperties
{
    char keyId[40];
    SEC_BYTE rights[SEC_KEYOUTPUTRIGHT_NUM];
    char notBefore[24];
    char notOnOrAfter[24];
    SEC_SIZE keyLength;
    Sec_KeyType keyType;
    Sec_KeyUsage usage;
    SEC_BYTE cacheable;
} Sec_KeyProperties;

/**
 * @brief Raw Private RSA key data
 *
 */
typedef struct
{
    SEC_BYTE n[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE d[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE e[4];
    SEC_BYTE modulus_len_be[4];
    uint32_t padding[2];
} Sec_RSARawPrivateKey;

/**
 * @brief Full Raw Private RSA key data
 *
 */
typedef struct
{
    SEC_BYTE n[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE d[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE e[4];
    SEC_BYTE modulus_len_be[4];
    uint32_t padding[2];
    SEC_BYTE p[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE q[SEC_RSA_KEY_MAX_LEN];
} Sec_RSARawPrivateFullKey;

/**
 * @brief Raw Public RSA key data
 *
 */
typedef struct
{
    SEC_BYTE n[SEC_RSA_KEY_MAX_LEN];
    SEC_BYTE e[4];
    SEC_BYTE modulus_len_be[4];
} Sec_RSARawPublicKey;

/**
 * @brief Raw Private EC key data
 *
 * Note: A prv value need not be on the curve. A prv value is simply
 * an integer multiplier k that tells how many times to add the
 * universal public point P (on the curve) to itself get the
 * corresponding private point. An ECC private key for the NIST
 * 256-curve would be 256-bits.  For that curve, prv is simply a
 * random 256-bit number. prv can be gotten by a call to a sound
 * random number generator, e.g. genrandom(256) and anything that
 * comes out is valid.
 *
 */
typedef struct
{
    Sec_KeyType type;        // curve parameters indicated by key type
    SEC_BYTE x[SEC_EC_KEY_MAX_LEN];
    SEC_BYTE y[SEC_EC_KEY_MAX_LEN];
    SEC_BYTE prv[SEC_EC_KEY_MAX_LEN];
    SEC_BYTE key_len[4];     // length in bytes of x (same as y and prv)
} Sec_ECCRawPrivateKey;

/**
 * @brief Raw Public EC key data
 *
 */
typedef struct
{
    Sec_KeyType type;        // curve parameters indicated by key type
    SEC_BYTE x[SEC_EC_KEY_MAX_LEN];
    SEC_BYTE y[SEC_EC_KEY_MAX_LEN];
    SEC_BYTE key_len[4];     // length in bytes of x (same as y and prv)
} Sec_ECCRawPublicKey;

/**
 * @brief Raw ONLY Private EC key data
 *
 * This contains just a 256-bit [32 byte] ECC private key.
 * $$$ If we add more ECC key types, will need to modify this.
 */
typedef struct {
    SEC_BYTE prv[SEC_ECC_NISTP256_KEY_LEN];
} Sec_ECCRawOnlyPrivateKey;

typedef struct {
    SEC_BYTE p[384];  // Prime p.  Big-endian format 
    SEC_SIZE pLen;  // Length of p in bytes.  Max value is 384. 
    SEC_BYTE g[384];  // Base g.  Big-endian format 
    SEC_SIZE gLen;  // Length of g in bytes 
} Sec_DHParameters;

typedef enum {
    NISTP256 = 0
} EC_PARAMETERS;

typedef struct {
    EC_PARAMETERS curve;
} Sec_ECDHParameters;

typedef enum {
    SEC_KEYEXCHANGE_DH = 0,
    SEC_KEYEXCHANGE_ECDH,
    SEC_KEYEXCHANGE_NUM
} Sec_KeyExchangeAlgorithm;

typedef enum {
    SEC_KDF_HKDF = 0,
    SEC_KDF_CONCAT,
    SEC_KDF_ANSI_X_9_63,
    SEC_KDF_NUM
} Sec_Kdf;

typedef struct {
    SEC_BYTE version[256];
} Sec_ProcessorInfo;

/**
 * @brief Opaque processor initialization parameters
 *
 */
typedef struct Sec_ProcessorInitParams_struct Sec_ProcessorInitParams;

/**
 * @brief Opaque processor handle
 *
 */
typedef struct Sec_ProcessorHandle_struct Sec_ProcessorHandle;

/**
 * @brief Opaque key handle
 *
 */
typedef struct Sec_KeyHandle_struct Sec_KeyHandle;

/**
 * @brief Opaque bundle handle
 *
 */
typedef struct Sec_BundleHandle_struct Sec_BundleHandle;

/**
 * @brief Opaque cipher handle
 *
 */
typedef struct Sec_CipherHandle_struct Sec_CipherHandle;

/**
 * @brief Opaque digest handle
 *
 */
typedef struct Sec_DigestHandle_struct Sec_DigestHandle;

/**
 * @brief Opaque mac handle
 *
 */
typedef struct Sec_MacHandle_struct Sec_MacHandle;

/**
 * @brief Opaque signature handle
 *
 */
typedef struct Sec_SignatureHandle_struct Sec_SignatureHandle;

/**
 * @brief Opaque random handle
 *
 */
typedef struct Sec_RandomHandle_struct Sec_RandomHandle;

/**
 * @brief Opaque certificate handle
 *
 */
typedef struct Sec_CertificateHandle_struct Sec_CertificateHandle;

/**
 * @brief Opaque key exchange handle
 *
 */
typedef struct Sec_KeyExchangeHandle_struct Sec_KeyExchangeHandle;

/**
 * @brief Opaque buffer handle
 */
typedef struct Sec_OpaqueBufferHandle_struct Sec_OpaqueBufferHandle;

typedef void Sec_ProtectedMemHandle;

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_DATATTYPE_H_ */
