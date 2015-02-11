
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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>

Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle *proc, SecUtils_KeyStoreHeader *header, Sec_KeyContainer container)
{
    Sec_Memset(header, 0, sizeof(SecUtils_KeyStoreHeader));

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

    Sec_Memset(&header, 0, sizeof(header));

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

cleanup:
    if (f != NULL)
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

cleanup:
    if (f != NULL)
    {
        if (0 != fclose(f))
        {
            SEC_LOG_ERROR("fclose failed");
            sec_res = SEC_RESULT_FAILURE;
        }
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

    return SEC_RESULT_SUCCESS;
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
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
    rsa->d = BN_bin2bn(binary->d, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);

    return rsa;
}

RSA *SecUtils_RSAFromPrivFullBinary(Sec_RSARawPrivateFullKey *binary)
{
    RSA *rsa = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *tmp = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
    rsa->d = BN_bin2bn(binary->d, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->p = BN_bin2bn(binary->p, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->q = BN_bin2bn(binary->q, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);

    rsa->dmp1 = BN_new();
    rsa->dmq1 = BN_new();
    rsa->iqmp = BN_new();
    tmp = BN_new();

    ctx = BN_CTX_new();
    BN_sub(tmp, rsa->p, BN_value_one());
    BN_mod(rsa->dmp1, rsa->d, tmp, ctx);
    BN_sub(tmp, rsa->q, BN_value_one());
    BN_mod(rsa->dmq1, rsa->d, tmp, ctx);
    BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);

    BN_free(tmp);
    BN_CTX_free(ctx);

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
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);

    return rsa;
}

RSA *SecUtils_RSAFromDERPriv(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    EVP_PKEY *evp_key = NULL;
    RSA *rsa = NULL;

    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, der_len);
    if (p8 != NULL)
    {
        evp_key = EVP_PKCS82PKEY(p8);
        if (evp_key == NULL)
        {
            SEC_LOG_ERROR("EVP_PKCS82PKEY failed");
            goto done;
        }
    }
    else
    {
        evp_key = d2i_AutoPrivateKey(NULL, &p, der_len);
        if (evp_key == NULL)
        {
            SEC_LOG_ERROR("d2i_AutoPrivateKey failed");
            goto done;
        }
    }

    rsa = EVP_PKEY_get1_RSA(evp_key);
    if (rsa == NULL)
    {
        SEC_LOG_ERROR("EVP_PKEY_get1_RSA failed");
        goto done;
    }

done:
    SEC_EVPPKEY_FREE(evp_key);

    if (p8 != NULL)
    {
        PKCS8_PRIV_KEY_INFO_free(p8);
    }

    return rsa;
}

static int _Sec_DisablePassphrasePrompt(char *buf, int size, int rwflag, void *u)
{
    return 0;
}

RSA *SecUtils_RSAFromPEMPriv(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    RSA *rsa = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, _Sec_DisablePassphrasePrompt, NULL);

    if (rsa == NULL)
    {
        SEC_LOG_ERROR("Invalid RSA key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return rsa;
}

RSA *SecUtils_RSAFromDERPub(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    RSA *rsa = NULL;

    rsa = d2i_RSAPublicKey(&rsa, &p, der_len);

    if (!rsa)
    {
        p = (const unsigned char *) der;
        rsa = d2i_RSA_PUBKEY(&rsa, &p, der_len);
    }

    if (!rsa)
    {
        SEC_LOG_ERROR("Invalid RSA key container");
        goto done;
    }

done:
    return rsa;
}

RSA *SecUtils_RSAFromPEMPub(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    RSA *rsa = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    rsa = PEM_read_bio_RSA_PUBKEY(bio, &rsa, _Sec_DisablePassphrasePrompt, NULL);

    if (rsa == NULL)
    {
        SEC_LOG_ERROR("Invalid RSA key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return rsa;
}

void SecUtils_RSAToPrivBinary(RSA *rsa, Sec_RSARawPrivateKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
    SecUtils_BigNumToBuffer(rsa->d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
}

void SecUtils_RSAToPrivFullBinary(RSA *rsa, Sec_RSARawPrivateFullKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
    SecUtils_BigNumToBuffer(rsa->d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->p, binary->p, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->q, binary->q, Sec_BEBytesToUint32(binary->modulus_len_be));
}

void SecUtils_RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
}

Sec_Result SecUtils_PKEYToDERPriv(EVP_PKEY *evp_key, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written)
{
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        SEC_LOG_ERROR("BIO_new(BIO_s_mem()) failed");
        goto done;
    }

    if (!i2d_PrivateKey_bio(bio, evp_key))
    {
        SEC_LOG_ERROR("i2d_PrivateKey_bio failed");
        goto done;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *written = bptr->length;

    if (output != NULL)
    {
        if (out_len < bptr->length)
        {
            SEC_LOG_ERROR("output buffer is not large enough");
            goto done;
        }
        memcpy(output, bptr->data, bptr->length);
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_BIO_FREE(bio);

    return res;
}

Sec_Result SecUtils_RSAToDERPriv(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written)
{
    EVP_PKEY *evp_key = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecUtils_PKEYToDERPriv(evp_key, output, out_len, written))
    {
        SEC_LOG_ERROR("SecUtils_PKEYToDERPriv failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_EVPPKEY_FREE(evp_key);

    return res;
}

Sec_Result SecUtils_RSAToDERPrivKeyInfo(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written)
{
    BIO *bio = NULL;
    EVP_PKEY *evp_key = NULL;
    BUF_MEM *bptr = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto done;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        SEC_LOG_ERROR("BIO_new(BIO_s_mem()) failed");
        goto done;
    }

    if (!i2d_PKCS8PrivateKeyInfo_bio(bio, evp_key))
    {
        SEC_LOG_ERROR("i2d_PKCS8_PRIV_KEY_INFO_bio failed");
        goto done;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *written = bptr->length;

    if (output != NULL)
    {
        if (out_len < bptr->length)
        {
            SEC_LOG_ERROR("output buffer is not large enough");
            goto done;
        }
        memcpy(output, bptr->data, bptr->length);

//        SecUtils_WriteFile("/home/ccpuser/test.pkcs8", output, *written);
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_EVPPKEY_FREE(evp_key);
    SEC_BIO_FREE(bio);

    return res;
}

Sec_Result SecUtils_RSAToDERPubKey(RSA *rsa, SEC_BYTE *output, SEC_SIZE out_len, SEC_SIZE *written)
{
    BIO *bio = NULL;
    EVP_PKEY *evp_key = NULL;
    BUF_MEM *bptr = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_RSA(evp_key, rsa))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_RSA failed");
        goto done;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        SEC_LOG_ERROR("BIO_new(BIO_s_mem()) failed");
        goto done;
    }

    if (!i2d_PUBKEY_bio(bio, evp_key))
    {
        SEC_LOG_ERROR("i2d_PUBKEY_bio failed");
        goto done;
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    *written = bptr->length;

    if (output != NULL)
    {
        if (out_len < bptr->length)
        {
            SEC_LOG_ERROR("output buffer is not large enough");
            goto done;
        }
        memcpy(output, bptr->data, bptr->length);
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_EVPPKEY_FREE(evp_key);
    SEC_BIO_FREE(bio);

    return res;
}

SEC_BOOL SecUtils_RSAHasPriv(RSA *rsa)
{
    return rsa->d != NULL;
}

SEC_BOOL SecUtils_RSAIsClearKC(Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len)
{
    return kc == SEC_KEYCONTAINER_DER_RSA_1024
            || kc == SEC_KEYCONTAINER_DER_RSA_2048
            || kc == SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC
            || kc == SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC
            || kc == SEC_KEYCONTAINER_RAW_RSA_1024
            || kc == SEC_KEYCONTAINER_RAW_RSA_2048
            || kc == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC
            || kc == SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC
            || kc == SEC_KEYCONTAINER_PEM_RSA_1024
            || kc == SEC_KEYCONTAINER_PEM_RSA_2048
            || kc == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC
            || kc == SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC
            || (kc == SEC_KEYCONTAINER_STORE
                    && data_len >= sizeof(SecStore_Header)
                    && data_len >= (sizeof(SecStore_Header) + SecStore_GetUserHeaderLen(data))
                    && SecUtils_RSAIsClearKC(SecUtils_GetKeyStoreUserHeader(data)->inner_kc_type, data, data_len));
}

RSA* SecUtils_RSAFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len)
{
    RSA *rsa = NULL;
    SecUtils_KeyStoreHeader store_header;
    SEC_BYTE store_data[SEC_KEYCONTAINER_MAX_LEN];

    if (kc == SEC_KEYCONTAINER_DER_RSA_1024 || kc == SEC_KEYCONTAINER_DER_RSA_2048) {
        rsa = SecUtils_RSAFromDERPriv(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromDERPriv failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC) {
        rsa = SecUtils_RSAFromDERPub(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromDERPub failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_RAW_RSA_1024 || kc == SEC_KEYCONTAINER_RAW_RSA_2048) {
        if (data_len == sizeof(Sec_RSARawPrivateKey))
        {
            rsa = SecUtils_RSAFromPrivBinary((Sec_RSARawPrivateKey *) data);
            if (rsa == NULL)
            {
                SEC_LOG_ERROR("Sec_RSARawPrivateKey failed");
                goto done;
            }
        } else if (data_len == sizeof(Sec_RSARawPrivateFullKey)) {
            rsa = SecUtils_RSAFromPrivFullBinary((Sec_RSARawPrivateFullKey *) data);
            if (rsa == NULL)
            {
                SEC_LOG_ERROR("Sec_RSARawPrivateFullKey failed");
                goto done;
            }
        } else {
            SEC_LOG_ERROR("Invalid priv key structure size: %d", data_len);
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC) {
        if (data_len != sizeof(Sec_RSARawPublicKey))
        {
            SEC_LOG_ERROR("Invalid pub key structure size: %d", data_len);
            goto done;
        }

        rsa = SecUtils_RSAFromPubBinary((Sec_RSARawPublicKey *) data);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromPubBinary failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_PEM_RSA_1024 || kc == SEC_KEYCONTAINER_PEM_RSA_2048) {
        rsa = SecUtils_RSAFromPEMPriv(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromPEMPriv failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC) {
        rsa = SecUtils_RSAFromPEMPub(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromPEMPub failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_STORE) {
        if (SEC_RESULT_SUCCESS != SecStore_RetrieveData(proc, SEC_FALSE,
                &store_header, sizeof(store_header),
                store_data, sizeof(store_data),
                data, data_len))
        {
            SEC_LOG_ERROR("SecStore_RetrieveData failed");
            goto done;
        }

        rsa = SecUtils_RSAFromClearKC(proc, store_header.inner_kc_type, store_data, SecStore_GetDataLen(data));
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromKc failed");
            goto done;
        }
    } else {
        SEC_LOG_ERROR("Unknown container type");
        goto done;
    }

done:
    return rsa;
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

SEC_SIZE SecUtils_X509ToDerLen(X509 *x509, void *mem, SEC_SIZE mem_len)
{
    int written = 0;
    SEC_BYTE *ptr = (SEC_BYTE *) mem;

    if (i2d_X509(x509, NULL) >= mem_len)
    {
        SEC_LOG_ERROR("Buffer is too small");
        return 0;
    }

    written = i2d_X509(x509, &ptr);

    if (written < 0)
    {
        SEC_LOG_ERROR("i2d_X509 failed");
        return 0;
    }

    return written;
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

Sec_Result SecUtils_DigestInfoForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE* padded_len, SEC_SIZE keySize)
{
    X509_SIG sig;
    ASN1_TYPE parameter;
    SEC_BYTE *p = NULL;
    X509_ALGOR algor;
    ASN1_OCTET_STRING digest_str;
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

    *padded_len = i2d_X509_SIG(&sig, NULL);
    if (*padded_len > (keySize - RSA_PKCS1_PADDING_SIZE))
    {
        SEC_LOG_ERROR("Digest is too large");
        return SEC_RESULT_FAILURE;
    }
    p = padded;
    i2d_X509_SIG(&sig, &p);

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_PadForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE keySize)
{
    SEC_SIZE temp_padded_len;
    SEC_BYTE temp_padded[SEC_RSA_KEY_MAX_LEN+1];

    if (SEC_RESULT_SUCCESS != SecUtils_DigestInfoForRSASign(alg, digest, digest_len, temp_padded, &temp_padded_len, keySize))
    {
        SEC_LOG_ERROR("SecUtils_DigestInfoForRSASign failed");
        return SEC_RESULT_FAILURE;
    }

    if (!RSA_padding_add_PKCS1_type_1((SEC_BYTE *) padded, keySize,
            (SEC_BYTE *) temp_padded, temp_padded_len))
    {
        SEC_LOG_ERROR("RSA_padding_add_PKCS1_type_1 failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
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

SEC_BOOL SecUtils_BitmapGet(SEC_BYTE *bitmap, SEC_SIZE bitNo)
{
    return SEC_BIT_READ(bitmap[bitNo/8], bitNo%8) != 0;
}

void SecUtils_BitmapSet(SEC_BYTE *bitmap, SEC_SIZE bitNo, SEC_BOOL val)
{
    bitmap[bitNo/8] = SEC_BIT_WRITE(bitNo%8, bitmap[bitNo/8], val);
}

SEC_SIZE SecUtils_BitmapGetFirst(SEC_BYTE *bitmap, SEC_SIZE num_bytes, SEC_BOOL val)
{
    SEC_SIZE i;
    SEC_SIZE j;

    for (i=0; i<num_bytes; ++i)
    {
        if ((val && bitmap[i] != 0x00) || (!val && bitmap[i] != 0xff))
        {
            for (j=0; j<8; ++j)
            {
                if (SEC_BIT_READ(j, bitmap[i]) == val)
                {
                    return i*8 + j;
                }
            }
        }
    }

    return (SEC_SIZE) -1;
}

/*
Sec_Result SecUtils_PoolInit(pthread_mutex_t *mutex, SEC_BOOL shared, SEC_BYTE *bitmap, SEC_SIZE num_bytes, SEC_SIZE num_bits)
{
    Sec_MutexResult res;
    SEC_SIZE i;

    res = SecMutex_Init(mutex, shared);

    if (res == SEC_MUTEXRESULT_OK)
    {
        SEC_MUTEX_LOCK(mutex);

        Sec_Memset(bitmap, 0, num_bytes);
        for (i=num_bits; i<(num_bytes*8); ++i)
        {
            SecUtils_BitmapSet(bitmap, i, 1);
        }

        SEC_MUTEX_UNLOCK(mutex);
    }
    else if (res == SEC_MUTEXRESULT_ALREADY_INITIALIZED)
    {
        //only the thread/process that created the mutex will run the initialization code
    }
    else
    {
        SEC_LOG_ERROR("SEC_MUTEX_INIT failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecUtils_PoolAcquire(pthread_mutex_t *mutex, SEC_BYTE *bitmap, SEC_SIZE num_bytes)
{
    SEC_SIZE ret = (SEC_SIZE) -1;

    while (1)
    {
        SEC_MUTEX_LOCK(mutex);
        ret = SecUtils_BitmapGetFirst(bitmap, num_bytes, 0);
        if (ret != (SEC_SIZE) -1)
        {
            SecUtils_BitmapSet(bitmap, ret, 1);
            SEC_MUTEX_UNLOCK(mutex);
            break;
        }
        SEC_MUTEX_UNLOCK(mutex);

        // yield processing time to other threads/processes
        sleep(0);
    }

    return ret;
}

void SecUtils_PoolRelease(pthread_mutex_t *mutex, SEC_BYTE *bitmap, SEC_SIZE num_bytes, SEC_SIZE bitNo)
{
    SEC_MUTEX_LOCK(mutex);

    if (SecUtils_BitmapGet(bitmap, bitNo) != 1)
    {
        SEC_LOG_ERROR("Attempting to release an already released bit %d", bitNo);
    }
    else
    {
        SecUtils_BitmapSet(bitmap, bitNo, 0);
    }

    SEC_MUTEX_UNLOCK(mutex);
}
*/

Sec_Result SecUtils_WrapSymetric(Sec_ProcessorHandle *proc, SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv, Sec_KeyType wrappedType, SEC_BYTE *wrappedKey, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
            wrappingAlg, SEC_CIPHERMODE_ENCRYPT, wrappingKey,
            iv, wrappedKey, SecKey_GetKeyLenForKeyType(wrappedType), out,
            out_len, written)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_WrapRSAPriv(Sec_ProcessorHandle *proc, SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv, RSA *wrappedKey, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    SEC_BYTE pkcs8[SEC_KEYCONTAINER_MAX_LEN];
    SEC_SIZE pkcs8_len;

    if (SEC_RESULT_SUCCESS != SecUtils_RSAToDERPriv(wrappedKey, pkcs8, sizeof(pkcs8), &pkcs8_len))
    {
        SEC_LOG_ERROR("SecUtils_RSAToDERPriv failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
            wrappingAlg, SEC_CIPHERMODE_ENCRYPT, wrappingKey,
            iv, pkcs8, pkcs8_len, out,
            out_len, written)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecUtils_WrapRSAPrivKeyInfo(Sec_ProcessorHandle *proc, SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv, RSA *wrappedKey, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    SEC_BYTE pkcs8[SEC_KEYCONTAINER_MAX_LEN];
    SEC_SIZE pkcs8_len;

    if (SEC_RESULT_SUCCESS != SecUtils_RSAToDERPrivKeyInfo(wrappedKey, pkcs8, sizeof(pkcs8), &pkcs8_len))
    {
        SEC_LOG_ERROR("SecUtils_RSAToDERPriv failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
            wrappingAlg, SEC_CIPHERMODE_ENCRYPT, wrappingKey,
            iv, pkcs8, pkcs8_len, out,
            out_len, written)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

