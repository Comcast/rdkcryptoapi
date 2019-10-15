/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2014 - 2019 RDK Management
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

#ifndef SEC_SECURITY_OPENSSL_H_
#define SEC_SECURITY_OPENSSL_H_

#include "sec_security.h"
#include "sec_security_store.h"

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/cmac.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define SEC_OPENSSL_KEYCONTAINER_DERIVED SEC_KEYCONTAINER_SOC_INTERNAL_0

#define SEC_OBJECTID_OPENSSL_DERIVE_TMP SEC_OBJECTID_RESERVEDPLATFORM_0
#define SEC_OBJECTID_OPENSSL_EXPORT SEC_OBJECTID_RESERVEDPLATFORM_0
#define SEC_OBJECTID_OPENSSL_EXPORT_MAC SEC_OBJECTID_RESERVEDPLATFORM_1

typedef struct
{
    SEC_BYTE input1[16];
    SEC_BYTE input2[16];
} SecOpenSSL_DerivedInputs;

typedef union
{
    /* native containers */
    /* none for openssl impl */

    /* sec store based containers */
    SEC_BYTE buffer[SEC_KEYCONTAINER_MAX_LEN];
    SecStore_Header store;
} _Sec_KC;

#if (SEC_KEYCONTAINER_MAX_LEN%16 != 0)
#error "Invalid SEC_KEYCONTAINER_MAX_LEN"
#endif

typedef struct
{
    Sec_KeyType key_type;
    Sec_KeyContainer kc_type;
} _Sec_KeyInfo;

typedef struct
{
    _Sec_KeyInfo info;
    _Sec_KC kc;
    SEC_SIZE kc_len;
} _Sec_KeyData;

typedef struct
{
    SEC_BYTE mac[SEC_MAC_MAX_LEN];
    SEC_SIZE cert_len;
    SEC_BYTE cert[SEC_CERT_MAX_DATA_LEN];
} _Sec_CertificateData;


typedef struct
{
    SEC_BYTE bundle[SEC_BUNDLE_MAX_LEN];
    SEC_SIZE bundle_len;
} _Sec_BundleData;

struct Sec_BundleHandle_struct
{
    SEC_OBJECTID object_id;
    Sec_StorageLoc location;
    _Sec_BundleData bundle_data;
    struct Sec_ProcessorHandle_struct *proc;
};

struct Sec_KeyHandle_struct
{
    SEC_OBJECTID object_id;
    Sec_StorageLoc location;
    _Sec_KeyData key_data;
    struct Sec_ProcessorHandle_struct *proc;
};

typedef struct {
    SEC_BYTE nonce[8];
    uint64_t ctr;
    size_t sub_block_offset;
} AesCtrState;

struct Sec_CipherHandle_struct
{
    Sec_CipherAlgorithm algorithm;
    Sec_CipherMode mode;
    Sec_KeyHandle* key_handle;
    SEC_BOOL last;
    EVP_CIPHER_CTX *evp_ctx;
    AesCtrState ctr_state;
    SEC_BOOL svp_required;
};

struct Sec_DigestHandle_struct
{
    Sec_DigestAlgorithm algorithm;
    SHA_CTX sha1_ctx;
    SHA256_CTX sha256_ctx;
};

struct Sec_SignatureHandle_struct
{
    Sec_SignatureAlgorithm algorithm;
    Sec_SignatureMode mode;
    Sec_KeyHandle* key_handle;
};

struct Sec_MacHandle_struct
{
    Sec_MacAlgorithm algorithm;
    Sec_KeyHandle* key_handle;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX _hmac_ctx;
#endif
    HMAC_CTX *hmac_ctx;
    CMAC_CTX *cmac_ctx;
};

struct Sec_CertificateHandle_struct
{
    SEC_OBJECTID object_id;
    Sec_StorageLoc location;
    _Sec_CertificateData cert_data;
    struct Sec_ProcessorHandle_struct *proc;
};

struct Sec_RandomHandle_struct
{
    Sec_RandomAlgorithm algorithm;
};

struct Sec_ProcessorInitParams_struct
{
    const char *keystorage_file_dir;
    const char *certstorage_file_dir;
    const char *bundlestorage_file_dir;
};

typedef struct _Sec_RAMKeyData_struct
{
    SEC_OBJECTID object_id;
    _Sec_KeyData key_data;
    struct _Sec_RAMKeyData_struct *next;
} _Sec_RAMKeyData;

typedef struct _Sec_RAMCertificateData_struct
{
    SEC_OBJECTID object_id;
    _Sec_CertificateData cert_data;
    struct _Sec_RAMCertificateData_struct *next;
} _Sec_RAMCertificateData;

typedef struct _Sec_RAMBundleData_struct
{
    SEC_OBJECTID object_id;
    _Sec_BundleData bundle_data;
    struct _Sec_RAMBundleData_struct *next;
} _Sec_RAMBundleData;

struct Sec_ProcessorHandle_struct
{
    SEC_BYTE device_id[SEC_DEVICEID_LEN];
    SEC_BYTE root_key[16];
    _Sec_RAMKeyData *ram_keys;
    _Sec_RAMBundleData *ram_bundles;
    _Sec_RAMCertificateData *ram_certs;
    char *global_dir;
    char *app_dir;
    int device_settings_init_flag;
};

struct Sec_KeyExchangeHandle_struct
{
    Sec_ProcessorHandle *proc;
    Sec_KeyExchangeAlgorithm alg;
    DH *dh;
    EC_KEY *ecdh_priv;
};

struct Sec_OpaqueBufferHandle_struct
{
    SEC_BYTE *dataBuf;
    SEC_SIZE dataBufSize;
};

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_OPENSSL_H_ */
