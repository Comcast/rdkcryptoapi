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

#include "sec_security_utils.h"
#include "sec_security_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static SEC_BOOL g_sec_openssl_inited = 0;

static int _Sec_OpenSSLPrivSign(int type, const unsigned char *m, unsigned int m_len,
    unsigned char *sigret, unsigned int *siglen, const RSA *rsa)
{
    Sec_KeyHandle *key = NULL;
    Sec_SignatureAlgorithm alg;
    int ret = -1;

    switch (type)
    {
        case NID_sha1:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST;
            break;
        case NID_sha256:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST;
            break;
        default:
            SEC_LOG_ERROR("Unknown type %d", type);
            goto cleanup;
            break;
    }

    key = (Sec_KeyHandle *) RSA_get_app_data(rsa);
    if (NULL == key)
    {
        SEC_LOG_ERROR("NULL key encountered");
        goto cleanup;
    }

    if (SEC_RESULT_SUCCESS != SecSignature_SingleInput(SecKey_GetProcessor(key),
            alg, SEC_SIGNATUREMODE_SIGN, key, (SEC_BYTE*) m, m_len,
            (SEC_BYTE*) sigret, siglen))
    {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto cleanup;
    }

    ret = 1;
cleanup:
    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x00909000L
static int _Sec_OpenSSLPubVerify(int type, const unsigned char *m, unsigned int m_len,
    unsigned char *sigret, unsigned int siglen, const RSA *rsa)
#else
static int _Sec_OpenSSLPubVerify(int type, const unsigned char *m, unsigned int m_len,
    const unsigned char *sigret, unsigned int siglen, const RSA *rsa)
#endif
{
    Sec_KeyHandle *key = NULL;
    Sec_SignatureAlgorithm alg;
    int ret = -1;

    switch (type)
    {
        case NID_sha1:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST;
            break;
        case NID_sha256:
            alg = SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST;
            break;
        default:
            SEC_LOG_ERROR("Unknown type %d", type);
            goto cleanup;
            break;
    }

    key = (Sec_KeyHandle *) RSA_get_app_data(rsa);
    if (NULL == key)
    {
        SEC_LOG_ERROR("NULL key encountered");
        goto cleanup;
    }

    if (SEC_RESULT_SUCCESS != SecSignature_SingleInput(SecKey_GetProcessor(key),
            alg, SEC_SIGNATUREMODE_VERIFY, key, (SEC_BYTE*) m, m_len,
            (SEC_BYTE*) sigret, &siglen))
    {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto cleanup;
    }

    ret = 1;
cleanup:
    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x00909000L
static int _Sec_OpenSSLPubEncrypt(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
#else
static int _Sec_OpenSSLPubEncrypt(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
#endif
{
    Sec_KeyHandle *key = NULL;
    Sec_CipherAlgorithm alg;
    SEC_SIZE written;
    int ret = -1;

    switch (padding)
    {
        case RSA_PKCS1_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
            break;
        case RSA_PKCS1_OAEP_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_OAEP_PADDING;
            break;
        default:
            SEC_LOG_ERROR("Unknown padding %d", padding);
            goto cleanup;
            break;
    }

    key = (Sec_KeyHandle *) RSA_get_app_data(rsa);
    if (NULL == key)
    {
        SEC_LOG_ERROR("NULL key encountered");
        goto cleanup;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInput(SecKey_GetProcessor(key),
            alg, SEC_CIPHERMODE_ENCRYPT, key, NULL,
            (SEC_BYTE*) from, flen, (SEC_BYTE*) to, SecKey_GetKeyLen(key), &written))
    {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto cleanup;
    }

    ret = written;
cleanup:
    return ret;
}

#if OPENSSL_VERSION_NUMBER < 0x00909000L
static int _Sec_OpenSSLPrivDecrypt(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
#else
static int _Sec_OpenSSLPrivDecrypt(int flen, const unsigned char *from,
        unsigned char *to, RSA *rsa, int padding)
#endif
{
    Sec_KeyHandle *key = NULL;
    Sec_CipherAlgorithm alg;
    SEC_SIZE written;
    int ret = -1;

    switch (padding)
    {
        case RSA_PKCS1_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING;
            break;
        case RSA_PKCS1_OAEP_PADDING:
            alg = SEC_CIPHERALGORITHM_RSA_OAEP_PADDING;
            break;
        default:
            SEC_LOG_ERROR("Unknown padding %d", padding);
            goto cleanup;
            break;
    }

    key = (Sec_KeyHandle *) RSA_get_app_data(rsa);
    if (NULL == key)
    {
        SEC_LOG_ERROR("NULL key encountered");
        goto cleanup;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInput(SecKey_GetProcessor(key),
            alg, SEC_CIPHERMODE_DECRYPT, key, NULL,
            (SEC_BYTE*) from, flen, (SEC_BYTE*) to, SecKey_GetKeyLen(key), &written))
    {
        SEC_LOG_ERROR("SecSignature_SingleInput failed");
        goto cleanup;
    }

    ret = written;
cleanup:
    return ret;
}

static RSA_METHOD g_sec_openssl_rsamethod = {
        "securityapi RSA method",
        _Sec_OpenSSLPubEncrypt,  /* rsa_pub_enc */
        NULL,  /* rsa_pub_dec */
        NULL, /* rsa_priv_enc */
        _Sec_OpenSSLPrivDecrypt, /* rsa_priv_dec */
        NULL,  /* rsa_mod_exp */
        NULL,  /* bn_mod_exp */
        NULL,  /* init */
        NULL,  /* finish */
        RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY | RSA_FLAG_SIGN_VER,  /* flags */
        NULL,  /* app_data */
        _Sec_OpenSSLPrivSign,  /* rsa_sign */
        _Sec_OpenSSLPubVerify,  /* rsa_verify */
        NULL,  /* rsa_keygen */
};

void ENGINE_load_securityapi(void)
{
    ENGINE *engine = ENGINE_new();

    if (engine == NULL )
    {
        SEC_LOG_ERROR("ENGINE_new failed");
        return;
    }

    if (!ENGINE_set_id(engine, "securityapi")
            || !ENGINE_set_name(engine, "SecurityApi engine")
            || !ENGINE_set_RSA(engine, &g_sec_openssl_rsamethod)
            )
    {
        ENGINE_free(engine);
        return;
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
}

void SecUtils_InitOpenSSL(void)
{
    if (!g_sec_openssl_inited)
    {
        ERR_load_crypto_strings();
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();

        ENGINE_load_securityapi();

        g_sec_openssl_inited = 1;
    }
}

Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle *proc, SecUtils_KeyStoreHeader *header, Sec_KeyContainer container)
{
    SecUtils_Memset(header, 0, sizeof(SecUtils_KeyStoreHeader));

    if (SEC_RESULT_SUCCESS != SecProcessor_GetDeviceId(proc, header->device_id))
    {
        SEC_LOG_ERROR("SecProcessor_GetDeviceId failed");
        return SEC_RESULT_FAILURE;
    }

    header->inner_kc_type = container;

    return SEC_RESULT_SUCCESS;
}

SecUtils_KeyStoreHeader *SecUtils_GetKeyStoreUserHeader(void *store)
{
    return (SecUtils_KeyStoreHeader *) SecStore_GetUserHeader(store);
}

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle *proc, SEC_BOOL require_mac, void* store, SEC_SIZE store_len)
{
    SecUtils_KeyStoreHeader header;
    SEC_BYTE device_id[SEC_DEVICEID_LEN];

    SecUtils_Memset(&header, 0, sizeof(header));

    if (store_len < sizeof(SecStore_Header) || store_len < SecStore_GetStoreLen(store))
    {
        SEC_LOG_ERROR("Invalid store");
        return SEC_RESULT_FAILURE;
    }

    if (0 != memcmp(SEC_UTILS_KEYSTORE_MAGIC, SecStore_GetHeader(store)->user_header_magic, strlen(SEC_UTILS_KEYSTORE_MAGIC)))
    {
        SEC_LOG_ERROR("Invalid key store magic value");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecStore_RetrieveData(proc, require_mac, &header, sizeof(header), NULL, 0, store, store_len))
    {
        SEC_LOG_ERROR("SecStore_RetrieveData failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecProcessor_GetDeviceId(proc, device_id))
    {
        SEC_LOG_ERROR("SecProcessor_GetDeviceId failed");
        return SEC_RESULT_FAILURE;
    }

    if (0 != memcmp(device_id, header.device_id, SEC_DEVICEID_LEN))
    {
        SEC_LOG_ERROR("device_id does not match the key store");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

RSA* SecUtils_KeyToEngineRSA(Sec_KeyHandle *key)
{
    Sec_RSARawPublicKey pubKey;
    RSA *rsa = NULL;
    ENGINE* engine = NULL;

    engine = ENGINE_by_id("securityapi");
    if (NULL == engine)
    {
        SEC_LOG_ERROR("ENGINE_by_id failed");
        return NULL;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExtractPublicKey(key, &pubKey))
    {
        SEC_LOG_ERROR("SecKey_ExtractPublicKey failed");
        return NULL;
    }

    rsa = RSA_new_method(engine);
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new_method failed");
        return NULL;
    }

    rsa->n = BN_bin2bn(pubKey.n, SecUtils_BEBytesToUint32(pubKey.modulus_len_be), NULL);
    rsa->e = BN_bin2bn(pubKey.e, 4, NULL);

    RSA_set_app_data(rsa, key);

    return rsa;
}

X509* SecUtils_CertificateToX509(Sec_CertificateHandle *cert)
{
    SEC_BYTE exportedCert[1024*64];
    SEC_SIZE exportedCertLen;

    if (SEC_RESULT_SUCCESS != SecCertificate_Export(cert, exportedCert, sizeof(exportedCert), &exportedCertLen))
    {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return NULL;
    }

    return SecUtils_DerToX509(exportedCert, exportedCertLen);
}

int SecUtils_Memcmp(void* ptr1, void* ptr2, const size_t num)
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

void *SecUtils_Memset(void *ptr, int value, size_t num)
{
    volatile SEC_BYTE *p = ptr;
    while (num--)
        *p++ = value;
    return ptr;
}

void SecUtils_BufferInit(Sec_Buffer *buffer, void *mem, SEC_SIZE len)
{
    buffer->base = mem;
    buffer->size = len;
    buffer->written = 0;
}

void SecUtils_BufferReset(Sec_Buffer *buffer)
{
    buffer->written = 0;
}

Sec_Result SecUtils_BufferWrite(Sec_Buffer *buffer, void *data, SEC_SIZE len)
{
    int space_left = buffer->size - buffer->written;

    if (space_left < 0 || (SEC_SIZE) space_left < len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer->base + buffer->written, data, len);
    buffer->written += len;

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_ReadFile(const char *path, void *data, SEC_SIZE data_len,
        SEC_SIZE *data_read)
{
    FILE *f = NULL;
    Sec_Result sec_res = SEC_RESULT_SUCCESS;
    SEC_BYTE last_byte;

    *data_read = 0;

    f = fopen(path, "rb");
    if (NULL == f)
    {
        SEC_LOG_ERROR("Could not open file: %s", path);
        sec_res = SEC_RESULT_FAILURE;
        goto cleanup;
    }

    while (0 == ferror(f) && 0 == feof(f) && *data_read < data_len)
    {
        *data_read += fread(data, 1, data_len - *data_read, f);
    }

    if (0 != ferror(f))
    {
        SEC_LOG_ERROR("ferror encountered while reading file: %s", path);
        sec_res = SEC_RESULT_NO_SUCH_ITEM;
        goto cleanup;
    }

    fread(&last_byte, 1, 1, f);

    if (0 == feof(f))
    {
        SEC_LOG_ERROR("data_len is too small");
        sec_res = SEC_RESULT_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    sec_res = SEC_RESULT_SUCCESS;

    cleanup: if (f != NULL)
    {
        fclose(f);
        f = NULL;
    }

    return sec_res;
}

Sec_Result SecUtils_WriteFile(const char *path, void *data, SEC_SIZE data_len)
{
    FILE *f = NULL;
    Sec_Result sec_res = SEC_RESULT_SUCCESS;

    f = fopen(path, "wb");
    if (NULL == f)
    {
        SEC_LOG_ERROR("Could not open file: %s", path);
        sec_res = SEC_RESULT_FAILURE;
        goto cleanup;
    }

    if (data_len != fwrite(data, 1, data_len, f))
    {
        SEC_LOG_ERROR("could not write to file: %s", path);
        sec_res = SEC_RESULT_FAILURE;
        goto cleanup;
    }

    sec_res = SEC_RESULT_SUCCESS;

    cleanup: if (f != NULL)
    {
        fclose(f);
        f = NULL;
    }

    return sec_res;
}

Sec_Result SecUtils_MkDir(const char *path)
{
    char tmp[SEC_MAX_FILE_PATH_LEN];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (len == 0)
    {
        SEC_LOG_ERROR("Empty path string");
        return SEC_RESULT_FAILURE;
    }

    if(tmp[len - 1] == '/')
    {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p != 0; p++)
    {
        if(*p == '/')
        {
            *p = 0;
            if (0 != mkdir(tmp, S_IRWXU) && errno != EEXIST)
            {
                SEC_LOG_ERROR("mkdir %s failed", tmp);
                return SEC_RESULT_FAILURE;
            }
            *p = '/';
        }
    }

    if (0 != mkdir(tmp, S_IRWXU) && errno != EEXIST)
    {
        SEC_LOG_ERROR("mkdir %s failed", tmp);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_FAILURE;
}

Sec_Result SecUtils_RmFile(const char *path)
{
    if (0 != unlink(path))
    {
        SEC_LOG_ERROR("unlink %s failed", path);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecUtils_LsDir(const char *path, Sec_LsDirEntry *entries, SEC_SIZE maxNumEntries)
{
    struct dirent* dent;
    struct stat st;
    DIR* srcdir;
    SEC_SIZE found = 0;
    char file_path[SEC_MAX_FILE_PATH_LEN];

    srcdir = opendir(path);

    if (srcdir == NULL)
    {
        SEC_LOG_ERROR("opendir failed");
        return -1;
    }

    while((dent = readdir(srcdir)) != NULL)
    {
        snprintf(file_path, sizeof(file_path), "%s%s", path, dent->d_name);

        if (stat(file_path, &st) < 0)
        {
            SEC_LOG_ERROR("fstatat failed on: %s", dent->d_name);
            continue;
        }

        /* store found file */
        if (entries != NULL && found < maxNumEntries)
        {
            snprintf(entries[found].name, sizeof(entries[found].name), "%s", dent->d_name);
            entries[found].is_dir = S_ISDIR(st.st_mode);
        }
        ++found;
    }
    closedir(srcdir);

    return found;
}

SEC_BOOL SecUtils_FileExists(const char *path)
{
    FILE *f = NULL;

    f = fopen(path, "rb");
    if (NULL == f)
        return 0;

    fclose(f);

    return 1;
}

Sec_KeyContainer SecUtils_RawContainer(Sec_KeyType key_type)
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
        case SEC_KEYTYPE_RSA_1024_PUBLIC:
            return SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC;
        case SEC_KEYTYPE_RSA_2048_PUBLIC:
            return SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC;
        default:
            break;
    }

    return SEC_KEYCONTAINER_NUM;
}

void SecUtils_BigNumToBuffer(BIGNUM *bignum, SEC_BYTE *buffer,
        SEC_SIZE buffer_len)
{
    SEC_SIZE num_bytes;

    memset(buffer, 0, buffer_len);

    if (bignum == NULL)
        return;

    num_bytes = BN_num_bytes(bignum);

    BN_bn2bin(bignum, buffer + buffer_len - num_bytes);
}

RSA *SecUtils_RSAFromPrivBinary(Sec_RSARawPrivateKey *binary)
{
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }
    rsa->n = BN_bin2bn(binary->n, SecUtils_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
    rsa->d = BN_bin2bn(binary->d, SecUtils_BEBytesToUint32(binary->modulus_len_be), NULL);

    return rsa;
}

RSA *SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey *binary)
{
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }
    rsa->n = BN_bin2bn(binary->n, SecUtils_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);

    return rsa;
}

void SecUtils_RSAToPrivBinary(RSA *rsa, Sec_RSARawPrivateKey *binary)
{
    SecUtils_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, binary->n, SecUtils_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
    SecUtils_BigNumToBuffer(rsa->d, binary->d, SecUtils_BEBytesToUint32(binary->modulus_len_be));
}

void SecUtils_RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary)
{
    SecUtils_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, binary->n, SecUtils_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
}

SEC_SIZE SecUtils_X509ToDer(X509 *x509, void *mem)
{
    int written = 0;
    SEC_BYTE *ptr = (SEC_BYTE *) mem;
    written = i2d_X509(x509, &ptr);
    if (written < 0)
        return 0;
    return written;
}

X509 * SecUtils_DerToX509(void *mem, SEC_SIZE len)
{
    X509 *x509 = NULL;
    const SEC_BYTE *ptr = (const SEC_BYTE *) mem;
    x509 = d2i_X509(&x509, &ptr, len);
    return x509;
}

Sec_Result SecUtils_VerifyX509WithRawPublicKey(X509 *x509,
        Sec_RSARawPublicKey* public_key)
{
    RSA *rsa = NULL;
    EVP_PKEY *evp_key = NULL;
    int verify_res;

    rsa = SecUtils_RSAFromPubBinary(public_key);
    if (rsa == NULL)
    {
        SEC_LOG_ERROR("_Sec_ReadRSAPublic failed");
        goto error;
    }

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto error;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_RSA_FREE(rsa);
    SEC_EVPPKEY_FREE(evp_key);

    if (1 != verify_res)
    {
        SEC_LOG_ERROR("X509_verify failed, %s",
                ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;

    error: if (rsa != NULL)
        SEC_RSA_FREE(rsa);
    if (evp_key != NULL)
        SEC_EVPPKEY_FREE(evp_key);

    return SEC_RESULT_FAILURE;
}

uint32_t SecUtils_CRC(void *intput, SEC_SIZE input_len)
{
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, intput, input_len);
    return crc;
}

uint16_t SecUtils_EndianSwap_uint16(uint16_t val)
{
    return (val << 8) | (val >> 8);
}

int16_t SecUtils_EndianSwap_int16(int16_t val)
{
    return (val << 8) | ((val >> 8) & 0xFF);
}

uint32_t SecUtils_EndianSwap_uint32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

int32_t SecUtils_EndianSwap_int32(int32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | ((val >> 16) & 0xFFFF);
}

int64_t SecUtils_EndianSwap_int64(int64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
            | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
            | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}

uint64_t SecUtils_EndianSwap_uint64(uint64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
            | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
            | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

void SecUtils_PrintHex(void* data, SEC_SIZE numBytes)
{
    SEC_BYTE* data_ptr = (SEC_BYTE *) data;
    SEC_SIZE i;
    SEC_PRINT("0x");
    for (i = 0; i < numBytes; ++i)
        SEC_PRINT("%02x", data_ptr[i]);
}

#define GETU32(pt) (((uint32_t)(pt)[0] << 24) ^ ((uint32_t)(pt)[1] << 16) ^ ((uint32_t)(pt)[2] <<  8) ^ ((uint32_t)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (uint8_t)((st) >> 24); (ct)[1] = (uint8_t)((st) >> 16); (ct)[2] = (uint8_t)((st) >>  8); (ct)[3] = (uint8_t)(st); }

void SecUtils_AesCtrInc(SEC_BYTE *counter)
{
    unsigned long c;

    /* Grab bottom dword of counter and increment */
    c = GETU32(counter + 12);
    c++;
    c &= 0xFFFFFFFF;
    PUTU32(counter + 12, c);

    /* if no overflow, we're done */
    if (c)
        return;

    /* Grab 1st dword of counter and increment */
    c = GETU32(counter + 8);
    c++;
    c &= 0xFFFFFFFF;
    PUTU32(counter + 8, c);

    /* if no overflow, we're done */
    if (c)
        return;

    /* Grab 2nd dword of counter and increment */
    c = GETU32(counter + 4);
    c++;
    c &= 0xFFFFFFFF;
    PUTU32(counter + 4, c);

    /* if no overflow, we're done */
    if (c)
        return;

    /* Grab top dword of counter and increment */
    c = GETU32(counter + 0);
    c++;
    c &= 0xFFFFFFFF;
    PUTU32(counter + 0, c);
}

Sec_Result SecUtils_PadForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE keySize)
{
    X509_SIG sig;
    ASN1_TYPE parameter;
    int i, j;
    SEC_BYTE *p = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest_str;
    SEC_BYTE temp_padded[SEC_RSA_KEY_MAX_LEN+1];
    int type;

    if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
            || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST)
    {
        type = NID_sha1;
    }
    else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS
            || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST)
    {
        type = NID_sha256;
    }
    else
    {
        SEC_LOG_ERROR("Unknown signature algorithm");
        return SEC_RESULT_FAILURE;
    }

    sig.algor = &algor;
    sig.algor->algorithm = OBJ_nid2obj(type);

    if (sig.algor->algorithm == NULL)
    {
        SEC_LOG_ERROR("Unknown algorithm type");
        return SEC_RESULT_FAILURE;
    }

    if (sig.algor->algorithm->length == 0)
    {
        SEC_LOG_ERROR("Unknown object identifier");
        return SEC_RESULT_FAILURE;
    }

    parameter.type = V_ASN1_NULL;
    parameter.value.ptr = NULL;
    sig.algor->parameter = &parameter;

    sig.digest = &digest_str;
    sig.digest->data = (SEC_BYTE *) digest;
    sig.digest->length = digest_len;

    i = i2d_X509_SIG(&sig, NULL);

    j = keySize;
    if (i > (j - RSA_PKCS1_PADDING_SIZE))
    {
        SEC_LOG_ERROR("Digest is too large");
        return SEC_RESULT_FAILURE;
    }

    p = temp_padded;
    i2d_X509_SIG(&sig, &p);

    if (!RSA_padding_add_PKCS1_type_1((SEC_BYTE *) padded, keySize,
            (SEC_BYTE *) temp_padded, i))
    {
        SEC_LOG_ERROR("RSA_padding_add_PKCS1_type_1 failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SecUtils_Endianess SecUtils_GetEndianess(void)
{
    uint32_t u32Val = 0x03020100;
    uint8_t *u8ptr = (uint8_t*) &u32Val;

    if (u8ptr[0] == 0x03 && u8ptr[1] == 0x02 && u8ptr[2] == 0x01 && u8ptr[3] == 0x00)
        return SEC_ENDIANESS_BIG;

    if (u8ptr[0] == 0x00 && u8ptr[1] == 0x01 && u8ptr[2] == 0x02 && u8ptr[3] == 0x03)
        return SEC_ENDIANESS_LITTLE;

    return SEC_ENDIANESS_UNKNOWN;
}

uint32_t SecUtils_BEBytesToUint32(SEC_BYTE *bytes)
{
    uint32_t val;

    memcpy(&val, bytes, 4);

    switch (SecUtils_GetEndianess())
    {
        case SEC_ENDIANESS_BIG:
            return val;
        case SEC_ENDIANESS_LITTLE:
            return SecUtils_EndianSwap_uint32(val);
        default:
            break;
    }

    SEC_LOG_ERROR("Unknown endianess detected");
    return 0;
}

uint64_t SecUtils_BEBytesToUint64(SEC_BYTE *bytes)
{
    uint64_t val;

    memcpy(&val, bytes, 8);

    switch (SecUtils_GetEndianess())
    {
        case SEC_ENDIANESS_BIG:
            return val;
        case SEC_ENDIANESS_LITTLE:
            return SecUtils_EndianSwap_uint64(val);
        default:
            break;
    }

    SEC_LOG_ERROR("Unknown endianess detected");
    return 0;
}

void SecUtils_Uint32ToBEBytes(uint32_t val, SEC_BYTE *bytes)
{
    if (SecUtils_GetEndianess() == SEC_ENDIANESS_LITTLE)
    {
        val = SecUtils_EndianSwap_uint32(val);
    }

    memcpy(bytes, &val, 4);
}

void SecUtils_Uint64ToBEBytes(uint64_t val, SEC_BYTE *bytes)
{
    if (SecUtils_GetEndianess() == SEC_ENDIANESS_LITTLE)
    {
        val = SecUtils_EndianSwap_uint64(val);
    }

    memcpy(bytes, &val, 8);
}
SEC_BYTE SecUtils_EndsWith(const char* str, const char* end)
{
    SEC_SIZE lenstr;
    SEC_SIZE lenend;

    if (!str || !end)
        return 0;

    lenstr = strlen(str);
    lenend = strlen(end);
    if (lenend >  lenstr)
        return 0;

    return strncmp(str + lenstr - lenend, end, lenend) == 0;
}

int SecUtils_ItemIndex(SEC_OBJECTID *items, SEC_SIZE numItems, SEC_OBJECTID item)
{
    SEC_SIZE i;

    for (i=0; i<numItems; ++i)
    {
        if (items[i] == item)
            return i;
    }

    return -1;
}

SEC_SIZE SecUtils_UpdateItemList(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, SEC_OBJECTID item_id)
{
    /* if array is full, just return it */
    if (numItems >= maxNumItems)
        return numItems;

    /* if item already in the list, skip it */
    if (SecUtils_ItemIndex(items, numItems, item_id) != -1)
        return numItems;

    items[numItems] = item_id;
    ++numItems;

    return numItems;
}

SEC_SIZE SecUtils_UpdateItemListFromDir(SEC_OBJECTID *items, SEC_SIZE maxNumItems, SEC_SIZE numItems, const char* dir, const char* ext)
{
    SEC_SIZE numEntries = 0;
    SEC_SIZE i = 0;
    Sec_LsDirEntry entries[256];
    char pattern[256];
    SEC_OBJECTID item_id;

    snprintf(pattern, sizeof(pattern), "%s%s", SEC_OBJECTID_PATTERN, ext);

    numEntries = SecUtils_LsDir(dir, entries, 256);

    for (i=0; i<numEntries; ++i)
    {
        if (!entries[i].is_dir && SecUtils_EndsWith(entries[i].name, ext))
        {
            /* obtain 64-bit item id */
            if (sscanf(entries[i].name, pattern, &item_id) != 1)
            {
                SEC_LOG_ERROR("sscanf failed on: %s", entries[i].name);
                continue;
            }

            numItems = SecUtils_UpdateItemList(items, maxNumItems, numItems, item_id);
        }
    }

    return numItems;
}
