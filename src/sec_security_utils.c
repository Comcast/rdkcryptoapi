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
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/aes.h>

Sec_Result SecUtils_FillKeyStoreUserHeader(Sec_ProcessorHandle *proc,
                                           SecUtils_KeyStoreHeader *header, Sec_KeyContainer container)
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

Sec_Result SecUtils_ValidateKeyStore(Sec_ProcessorHandle *proc,
                                     SEC_BOOL require_mac, void* store, SEC_SIZE store_len)
{
    SecUtils_KeyStoreHeader header;
    SEC_BYTE device_id[SEC_DEVICEID_LEN];

    Sec_Memset(&header, 0, sizeof(header));

    if (store_len < sizeof(SecStore_Header)
        || store_len < SecStore_GetStoreLen(store))
    {
        SEC_LOG_ERROR("Invalid store");
        return SEC_RESULT_FAILURE;
    }

    if (0
        != memcmp(SEC_UTILS_KEYSTORE_MAGIC,
                  SecStore_GetHeader(store)->user_header_magic,
                  strlen(SEC_UTILS_KEYSTORE_MAGIC)))
    {
        SEC_LOG_ERROR("Invalid key store magic value");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
        != SecStore_RetrieveData(proc, require_mac, &header, sizeof(header),
                                 NULL, 0, store, store_len))
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

static long SecUtils_GetFileLen(const char *path) {
    FILE *f = NULL;
    long len = -1;

    f = fopen(path, "rb");
    if (NULL == f)
    {
        SEC_LOG_ERROR("Could not open file: %s", path);
        goto cleanup;
    }

    fseek(f, 0L, SEEK_END);
    len = ftell(f);
    fseek(f, 0L, SEEK_SET);

cleanup:
    if (f != NULL) {
        if (0 != fclose(f)) {
            SEC_LOG_ERROR("fclose failed");
        }
    }

    return len;
}

static Sec_Result SecUtils_VerifyFile(const char *path, void *expected, SEC_SIZE expected_len) {
    SEC_BYTE *read = NULL;
    SEC_SIZE read_len;
    SEC_SIZE file_len;
    Sec_Result res = SEC_RESULT_FAILURE;

    //allocate memory for verification
    read = malloc(expected_len);
    if (read == NULL) {
        SEC_LOG_ERROR("malloc failed for file: %s", path);
        goto cleanup;
    }

    //make sure that the written file is of proper length
    file_len = SecUtils_GetFileLen(path);
    if (expected_len != file_len) {
        SEC_LOG_ERROR("File written out (%s) is %d bytes, but expected %d", path, file_len, expected_len);
        goto cleanup;
    }

    //read data back in
    if (SEC_RESULT_SUCCESS != SecUtils_ReadFile(path, read, expected_len, &read_len)) {
        SEC_LOG_ERROR("SecUtils_ReadFile failed for file: %s", path);
        goto cleanup;
    }

    //compare read data to input
    if (0 != memcmp(expected, read, expected_len)) {
        SEC_LOG_ERROR("Data read in does not match the data written out for file: %s", path);
        goto cleanup;
    }

    res = SEC_RESULT_SUCCESS;

cleanup:
    SEC_FREE(read);

    return res;
}

Sec_Result SecUtils_WriteFile(const char *path, void *data, SEC_SIZE data_len)
{
    Sec_Result sec_res = SEC_RESULT_FAILURE;
    FILE *f = NULL;
    int fdesc = -1;
    int dir_fdesc = -1;
    char *path_cpy = NULL;

    //make a copy of the path string since basedir will change it
    path_cpy = strdup(path);
    if (path_cpy == NULL) {
        SEC_LOG_ERROR("strdup failed for file: %s", path);
        goto cleanup;
    }

    //open file
    f = fopen(path, "wb");
    if (NULL == f) {
        SEC_LOG_ERROR("Could not open file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    //get file descriptor
    fdesc = fileno(f);
    if (fdesc < 0) {
        SEC_LOG_ERROR("fileno failed for file: %s, errno: %d", path, errno);
        goto cleanup;        
    }

    //write contents
    if (data_len != fwrite(data, 1, data_len, f)) {
        SEC_LOG_ERROR("could not write to file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    //flush
    if (0 != fflush(f)) {
        SEC_LOG_ERROR("fflush failed for file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    //force sync on written file
    if (0 != fsync(fdesc)) {
        SEC_LOG_ERROR("fsync failed for file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    //close file
    if (0 != fclose(f)) {
        SEC_LOG_ERROR("fclose failed for file: %s, errno: %d", path, errno);
        f = NULL;
        goto cleanup;
    }
    f = NULL;

    //sync parent directory
    dir_fdesc = open(dirname(path_cpy), O_RDONLY);
    if (dir_fdesc < 0) {
        SEC_LOG_ERROR("open parent failed for file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    if (0 != fsync(dir_fdesc)) {
        SEC_LOG_ERROR("fsync parent failed for file: %s, errno: %d", path, errno);
        goto cleanup;
    }

    if (0 != close(dir_fdesc)) {
        dir_fdesc = -1;
        SEC_LOG_ERROR("close parent failed for file: %s, errno: %d", path, errno);
        goto cleanup;
    }
    dir_fdesc = -1;

    //verify written file
    if (SEC_RESULT_SUCCESS != SecUtils_VerifyFile(path, data, data_len)) {
        SEC_LOG_ERROR("SecUtils_VerifyFile failed for file: %s", path);
        goto cleanup;
    }

    sec_res = SEC_RESULT_SUCCESS;

cleanup:
    if (f != NULL) {
        if (0 != fclose(f)) {
            SEC_LOG_ERROR("fclose failed for file: %s, errno: %d", path, errno);
        }
        f = NULL;
    }

    if (dir_fdesc >= 0) {
        if (0 != close(dir_fdesc)) {
            dir_fdesc = -1;
            SEC_LOG_ERROR("close parent failed for file: %s, errno: %d", path, errno);
        }
        dir_fdesc = -1;
    }

    SEC_FREE(path_cpy);

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

    if (tmp[len - 1] == '/')
    {
        tmp[len - 1] = 0;
    }

    for (p = tmp + 1; *p != 0; p++)
    {
        if (*p == '/')
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
	void *zeros = NULL;
	long len;

	len = SecUtils_GetFileLen(path);
	if (len > 0) {
		zeros = calloc(len, 1);
		if (zeros != NULL) {
			SecUtils_WriteFile(path, zeros, len);
			free(zeros);
		} else {
	        SEC_LOG_ERROR("calloc failed");
		}
	}

    if (0 != unlink(path))
    {
        SEC_LOG_ERROR("unlink %s failed", path);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

SEC_SIZE SecUtils_LsDir(const char *path, Sec_LsDirEntry *entries,
                        SEC_SIZE maxNumEntries)
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

    while ((dent = readdir(srcdir)) != NULL)
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
            snprintf(entries[found].name, sizeof(entries[found].name), "%s",
                     dent->d_name);
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


SEC_BOOL SecUtils_ECCHasPriv(EC_KEY *ec_key)
{
    return EC_KEY_get0_private_key(ec_key) != NULL;
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

done: return rsa;
}


SEC_BOOL SecUtils_ECCIsClearKC(Sec_KeyContainer kc,
                               SEC_BYTE *data, SEC_SIZE data_len)
{
    return kc == SEC_KEYCONTAINER_DER_ECC_NISTP256
    || kc == SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC
    || kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256
    || kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC
    || kc == SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256
    || kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256
    || kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC
    || (kc == SEC_KEYCONTAINER_STORE
        && data_len >= sizeof(SecStore_Header)
        && data_len >= (sizeof(SecStore_Header) + SecStore_GetUserHeaderLen(data))
        && SecUtils_ECCIsClearKC(SecUtils_GetKeyStoreUserHeader(data)->inner_kc_type,
                                 data, data_len));
}

EC_KEY* SecUtils_ECCFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc,
                                SEC_BYTE *data, SEC_SIZE data_len)
{ //$$$ could add SEC_KEYCONTAINER_RAW_ECC_PRIVONLY_NISTP256
    EC_KEY *ec_key = NULL;
    SecUtils_KeyStoreHeader store_header;
    SEC_BYTE store_data[SEC_KEYCONTAINER_MAX_LEN];

    if (kc == SEC_KEYCONTAINER_DER_ECC_NISTP256)
    {
        ec_key = SecUtils_ECCFromDERPriv(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromDERPriv failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_DER_ECC_NISTP256_PUBLIC)
    {
        ec_key = SecUtils_ECCFromDERPub(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromDERPub failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256)
    {
        if (data_len == sizeof(Sec_ECCRawPrivateKey))
        {
            ec_key = SecUtils_ECCFromPrivBinary((Sec_ECCRawPrivateKey *) data);
            if (ec_key == NULL)
            {
                SEC_LOG_ERROR("SecUtils_ECCFromPrivBinary failed");
                goto done;
            }
        }
        //$$$ no ecc equivalent: else if (data_len == sizeof(Sec_RSARawPrivateFullKey))
        //$$$ {
        //$$$     ec_key = SecUtils_ECCFromPrivFullBinary(
        //$$$                                          (Sec_RSARawPrivateFullKey *) data);
        //$$$     if (ec_key == NULL)
        //$$$     {
        //$$$         SEC_LOG_ERROR("Sec_ECCRawPrivateFullKey failed");
        //$$$         goto done;
        //$$$     }
        //$$$ }
        else
        {
            SEC_LOG_ERROR("Invalid priv key structure size: %d", data_len);
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_RAW_ECC_NISTP256_PUBLIC)
    {
        if (data_len != sizeof(Sec_ECCRawPublicKey))
        {
            SEC_LOG_ERROR("Invalid pub key structure size: %d", data_len);
            goto done;
        }

        ec_key = SecUtils_ECCFromPubBinary((Sec_ECCRawPublicKey *) data);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPubBinary failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256)
    {
        ec_key = SecUtils_ECCFromPEMPriv(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPEMPriv failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_PEM_ECC_NISTP256_PUBLIC)
    {
        ec_key = SecUtils_ECCFromPEMPub(data, data_len);
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromPEMPub failed");
            goto done;
        }
    }
    else if (kc == SEC_KEYCONTAINER_STORE)
    {
        if (SEC_RESULT_SUCCESS
            != SecStore_RetrieveData(proc, SEC_FALSE, &store_header,
                                     sizeof(store_header), store_data, sizeof(store_data),
                                     data, data_len))
        {
            SEC_LOG_ERROR("SecStore_RetrieveData failed");
            goto done;
        }

        ec_key = SecUtils_ECCFromClearKC(proc, store_header.inner_kc_type,
                                         store_data, SecStore_GetDataLen(data));
        if (ec_key == NULL)
        {
            SEC_LOG_ERROR("SecUtils_ECCFromClearKC failed");
            goto done;
        }
    }
    else
    {
        SEC_LOG_ERROR("Unknown container type");
        goto done;
    }

done: return ec_key;
}


// $$$ Expand for more support private key types (not public types, because
// $$$ they won't have a private key)
EC_KEY *SecUtils_ECCFromOnlyPrivBinary(Sec_ECCRawOnlyPrivateKey *binary)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;

    EC_KEY_set_private_key(ec_key,
                           BN_bin2bn(binary->prv, sizeof binary->prv, NULL));

    return ec_key;
}

// Precondition: binary->type must have been verified as a supported value.
// $$$ Expand for more support private key types (not public types, because
// $$$ they won't have a private key)
EC_KEY *SecUtils_ECCFromPrivBinary(Sec_ECCRawPrivateKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    // Note that SEC_KEYTYPE_ECC_NISTP256_PUBLIC is not acceptable,
    // because it won't have a private key value
    if (binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp, *prvp;
    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL)
        || ((prvp = BN_CTX_get(ctx)) == NULL))
        goto done;

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                                        BN_bin2bn(binary->x, Sec_BEBytesToUint32(binary->key_len), xp),
                                        BN_bin2bn(binary->y, Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

    EC_KEY_set_private_key(ec_key,
                           BN_bin2bn(binary->prv, Sec_BEBytesToUint32(binary->key_len), prvp));

done:
    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
}

// Precondition: binary->type must have been verified as a supported value
// $$$ expand for more support key types
EC_KEY *SecUtils_ECCFromPubBinary(Sec_ECCRawPublicKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    if (   binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC
        && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp;

    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL))
        goto done;

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                                        BN_bin2bn(binary->x, Sec_BEBytesToUint32(binary->key_len), xp),
                                        BN_bin2bn(binary->y, Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

done:
    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
}

Sec_Result SecUtils_ECCToPrivBinary(EC_KEY *ec_key, Sec_ECCRawPrivateKey *binary)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    Sec_KeyType keyType;

    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &keyType) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("SecUtils_ECCToPrivBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }
    else
    {
        binary->type = keyType;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
        SecUtils_BigNumToBuffer((BIGNUM *) EC_KEY_get0_private_key(ec_key), binary->prv, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}

Sec_Result SecUtils_ECCToPubBinary(EC_KEY *ec_key, Sec_ECCRawPublicKey *binary)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    Sec_KeyType keyType;

    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, &keyType) != SEC_RESULT_SUCCESS)
    {

        SEC_LOG_ERROR("SecUtils_ECCToPubBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }
    else
    {
        binary->type = keyType;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
        SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}

EC_KEY *SecUtils_ECCFromDERPriv(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    EVP_PKEY *evp_key = NULL;
    EC_KEY *ecc = NULL;

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

    ecc = EVP_PKEY_get1_EC_KEY(evp_key);
    if (ecc == NULL)
    {
        SEC_LOG_ERROR("EVP_PKEY_get1_EC_KEY failed");
        goto done;
    }

done:
    SEC_EVPPKEY_FREE(evp_key);

    if (p8 != NULL)
    {
        PKCS8_PRIV_KEY_INFO_free(p8);
    }

    return ecc;
}

EC_KEY *SecUtils_ECCFromPEMPriv(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    ec_key = PEM_read_bio_ECPrivateKey(bio, &ec_key, _Sec_DisablePassphrasePrompt, NULL);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return ec_key;
}

EC_KEY *SecUtils_ECCFromDERPub(SEC_BYTE *der, SEC_SIZE der_len)
{
    const unsigned char *p = (const unsigned char *) der;
    EC_KEY *ec_key = NULL;

    ec_key = d2i_EC_PUBKEY(&ec_key, &p, der_len);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    return ec_key;
}

EC_KEY *SecUtils_ECCFromPEMPub(SEC_BYTE *pem, SEC_SIZE pem_len)
{
    BIO *bio = NULL;
    EC_KEY *ec_key = NULL;

    bio = BIO_new_mem_buf(pem, pem_len);
    ec_key = PEM_read_bio_EC_PUBKEY(bio, &ec_key, _Sec_DisablePassphrasePrompt, NULL);

    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("Invalid ECC key container");
        goto done;
    }

done:
    SEC_BIO_FREE(bio);

    return ec_key;
}

Sec_Result SecUtils_ECCToDERPriv(EC_KEY *ec_key, SEC_BYTE *output,
                                 SEC_SIZE out_len, SEC_SIZE *written)
{
    EVP_PKEY *evp_key = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_EC_KEY(evp_key, ec_key))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS
        != SecUtils_PKEYToDERPriv(evp_key, output, out_len, written))
    {
        SEC_LOG_ERROR("SecUtils_PKEYToDERPriv failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;

done:
    SEC_EVPPKEY_FREE(evp_key);

    return res;
}

Sec_Result SecUtils_ECCToDERPrivKeyInfo(EC_KEY *ec_key, SEC_BYTE *output,
                                        SEC_SIZE out_len, SEC_SIZE *written)
{
    BIO *bio = NULL;
    EVP_PKEY *evp_key = NULL;
    BUF_MEM *bptr = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_EC_KEY(evp_key, ec_key))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
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

Sec_Result SecUtils_ECCToDERPubKey(EC_KEY *ec_key, SEC_BYTE *output, SEC_SIZE out_len,
                                   SEC_SIZE *written)
{
    BIO *bio = NULL;
    EVP_PKEY *evp_key = NULL;
    BUF_MEM *bptr = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_EC_KEY(evp_key, ec_key))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
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

SEC_SIZE SecUtils_X509ToDer(X509 *x509, void *mem)
{
    int written = 0;
    SEC_BYTE *ptr = (SEC_BYTE *) mem;
    written = i2d_X509(x509, &ptr);
    if (written < 0)
        return 0;
    return written;
}

X509 * SecUtils_DerToX509(SEC_BYTE *der, SEC_SIZE der_len) {
	BIO *bio = NULL;
	X509 *x509 = NULL;

    bio = BIO_new_mem_buf(der, der_len);
    x509 = d2i_X509_bio(bio, NULL );
    SEC_BIO_FREE(bio);

    if (x509 == NULL) {
    	SEC_LOG_ERROR("d2i_X509_bio failed");
    }

    return x509;
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

Sec_Result SecUtils_VerifyX509WithRawRSAPublicKey(X509 *x509,
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

Sec_Result SecUtils_VerifyX509WithRawECCPublicKey(X509 *x509,
                                                  Sec_ECCRawPublicKey* public_key)
{
    EC_KEY *ec_key = NULL;
    EVP_PKEY *evp_key = NULL;
    int verify_res;

    ec_key = SecUtils_ECCFromPubBinary(public_key);
    if (ec_key == NULL)
    {
        SEC_LOG_ERROR("SecUtils_ECCFromPubBinary failed");
        goto error;
    }

    evp_key = EVP_PKEY_new();
    if (0 == EVP_PKEY_set1_EC_KEY(evp_key, ec_key))
    {
        SEC_LOG_ERROR("EVP_PKEY_set1_EC_KEY failed");
        goto error;
    }

    verify_res = X509_verify(x509, evp_key);

    SEC_ECC_FREE(ec_key);
    SEC_EVPPKEY_FREE(evp_key);

    if (1 != verify_res)
    {
        SEC_LOG_ERROR("X509_verify failed, %s",
                      ERR_error_string(ERR_get_error(), NULL));
        return SEC_RESULT_VERIFICATION_FAILED;
    }

    return SEC_RESULT_SUCCESS;

error:
    SEC_ECC_FREE(ec_key);
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
    SEC_BYTE temp_padded[SEC_RSA_KEY_MAX_LEN + 1];

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
    if (lenend > lenstr)
        return 0;

    return strncmp(str + lenstr - lenend, end, lenend) == 0;
}

int SecUtils_ItemIndex(SEC_OBJECTID *items, SEC_SIZE numItems, SEC_OBJECTID item)
{
    SEC_SIZE i;

    for (i = 0; i < numItems; ++i)
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

    for (i = 0; i < numEntries; ++i)
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
    bitmap[bitNo / 8] = SEC_BIT_WRITE(bitNo % 8, bitmap[bitNo / 8], val);
}

SEC_SIZE SecUtils_BitmapGetFirst(SEC_BYTE *bitmap, SEC_SIZE num_bytes, SEC_BOOL val)
{
    SEC_SIZE i;
    SEC_SIZE j;

    for (i = 0; i < num_bytes; ++i)
    {
        if ((val && bitmap[i] != 0x00) || (!val && bitmap[i] != 0xff))
        {
            for (j = 0; j < 8; ++j)
            {
                if (SEC_BIT_READ(j, bitmap[i]) == val)
                {
                    return i * 8 + j;
                }
            }
        }
    }

    return (SEC_SIZE) -1;
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

Sec_Result SecUtils_WrapSymetric(Sec_ProcessorHandle *proc,
                                 SEC_OBJECTID wrappingKey,
                                 Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                 SEC_BYTE *payload, SEC_SIZE payloadLen,
                                 SEC_BYTE *out, SEC_SIZE out_len,
                                 SEC_SIZE *written)
{
    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc,
            wrappingAlg, SEC_CIPHERMODE_ENCRYPT, wrappingKey,
            iv, payload, payloadLen, out,
            out_len, written)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// Wrap an ECC key inside a PKCS#8 DER wrapper
// For some background, see
// http://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
//
Sec_Result SecUtils_WrapECCPriv(Sec_ProcessorHandle *proc,
                                SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    SEC_BYTE pkcs8[SEC_KEYCONTAINER_MAX_LEN];
    SEC_SIZE pkcs8_len;

    if (SEC_RESULT_SUCCESS
        != SecUtils_ECCToDERPriv(keyToWrap, pkcs8, sizeof(pkcs8),
                                 &pkcs8_len))
    {
        SEC_LOG_ERROR("SecUtils_ECCToDERPriv failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
        != SecCipher_SingleInputId(proc, wrappingAlg,
                                   SEC_CIPHERMODE_ENCRYPT, wrappingKey, iv, pkcs8, pkcs8_len,
                                   out, out_len, written))
    {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// Wrap an ECC key info inside a PKCS#8 DER wrapper
Sec_Result SecUtils_WrapECCPrivKeyInfo(Sec_ProcessorHandle *proc,
                                     SEC_OBJECTID wrappingKey, Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                     EC_KEY *keyToWrap, SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    SEC_BYTE pkcs8[SEC_KEYCONTAINER_MAX_LEN];
    SEC_SIZE pkcs8_len;

    if (SEC_RESULT_SUCCESS
        != SecUtils_ECCToDERPrivKeyInfo(keyToWrap, pkcs8, sizeof(pkcs8),
                                        &pkcs8_len))
    {
        SEC_LOG_ERROR("SecUtils_ECCToDERPrivKeyInfo failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
        != SecCipher_SingleInputId(proc, wrappingAlg,
                                   SEC_CIPHERMODE_ENCRYPT, wrappingKey, iv, pkcs8, pkcs8_len,
                                   out, out_len, written))
    {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// Wrap an raw ECC key
//
Sec_Result SecUtils_WrapRawECCPriv(Sec_ProcessorHandle *proc,
                                   SEC_OBJECTID wrappingKey,
                                   Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                   const EC_KEY *keyToWrap,
                                   SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    Sec_ECCRawOnlyPrivateKey onlyPrv;

    SecUtils_BigNumToBuffer((BIGNUM *) EC_KEY_get0_private_key(keyToWrap),
                            onlyPrv.prv, sizeof onlyPrv.prv);

    if (SEC_RESULT_SUCCESS
        != SecCipher_SingleInputId(proc, wrappingAlg,
                                   SEC_CIPHERMODE_ENCRYPT, wrappingKey, iv,
                                   (SEC_BYTE*)&onlyPrv, sizeof onlyPrv,
                                   out, out_len, written))
    {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// Wrap an ECC key inside a Sec_ECCRawPrivateKey
//$$$ Note that this is identical to SecUtils_WrapRawECCPriv
Sec_Result SecUtils_WrapRawECCPrivKeyInfo(Sec_ProcessorHandle *proc,
                                          SEC_OBJECTID wrappingKey,
                                          Sec_CipherAlgorithm wrappingAlg, SEC_BYTE *iv,
                                          const EC_KEY *keyToWrap,
                                          SEC_BYTE *out, SEC_SIZE out_len, SEC_SIZE *written)
{
    Sec_ECCRawOnlyPrivateKey onlyPrv;

    SecUtils_BigNumToBuffer((BIGNUM *) EC_KEY_get0_private_key(keyToWrap),
                            onlyPrv.prv, sizeof onlyPrv.prv);

    if (SEC_RESULT_SUCCESS
        != SecCipher_SingleInputId(proc, wrappingAlg,
                                   SEC_CIPHERMODE_ENCRYPT, wrappingKey, iv,
                                   (SEC_BYTE*)&onlyPrv, sizeof onlyPrv,
                                   out, out_len, written))
    {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}


/**
 * @brief Get the key type of the specified OpenSSL EC_GROUP
 *
 * $$$ If we handle more groups, then add more cases.
 *
 * Note that NID_secp256k1 is *not* SEC_KEYTYPE_ECC_NISTP256.
 *
 * @param EC_GROUP Group for which a key type is needed
 *
 * @return The key type or SEC_KEYTYPE_NUM if EC_GROUP is invalid
 */
Sec_KeyType SecKey_GroupToKeyType(const EC_GROUP *group)
{
    if (NULL == group)
        return SEC_KEYTYPE_NUM;
    switch (EC_GROUP_get_curve_name(group))
    {
        case NID_X9_62_prime256v1:
            return SEC_KEYTYPE_ECC_NISTP256;
        case 0:
        default:
            return SEC_KEYTYPE_NUM;
    }
}

// ec_key is the other side's public ECC key
//
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Encrypt_Rand(EC_KEY *ec_key,
                                  SEC_BYTE* input, SEC_SIZE inputSize,
                                  SEC_BYTE* output, SEC_SIZE outputSize,
                                  BIGNUM *sender_rand)
{
    int res = -1;
    BIGNUM *inputAsBN = NULL;
    const EC_GROUP *group = NULL;
    const EC_POINT *P = NULL;
    const EC_POINT *PK_recipient = NULL;
    EC_POINT *shared_secret = NULL;
    EC_POINT *key_2_wrap_point = NULL;
    EC_POINT *sender_share = NULL;
    EC_POINT *wrapped_key = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;

    if (inputSize != SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Input size needed != One BIGNUM");
        goto done;
    }

    if (outputSize < 4 * SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Output size needed < Four BIGNUMs");
        goto done;
    }

    /* Convert the input buffer to be encrypted to a BIGNUM */
    inputAsBN = BN_new();
    if (inputAsBN == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }
    if (BN_bin2bn(input, inputSize, inputAsBN) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed. Error: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto done;
    }

    group = EC_KEY_get0_group(ec_key);
    if (NULL == group)
    {
        SEC_LOG_ERROR("EC_KEY_get0_group failed");
        goto done;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        SEC_LOG_ERROR("BN_CTX_new failed");
        goto done;
    }

    // Convert the X coordinate to an EC Point.  This takes the desired Y value in 1 bit (to choose
    // which of the two possible Y values to use).  This *calculates* an actual Y value for the point.
    key_2_wrap_point = EC_POINT_new(group);
    if (key_2_wrap_point == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    if (!EC_POINT_set_compressed_coordinates_GFp(group, key_2_wrap_point, inputAsBN, 0, ctx)) //$$$ 1=>0 on 7/8/15
    {
        // Don't print an error message if the error is "point not on curve" 100A906E, but still fail
        if (ERR_get_error() != 0x100A906E) // i.e. error:100A906E:lib(16):func(169):reason(110)
        {
            SEC_LOG_ERROR("Set EC_POINT_set_compressed_coordinates_GFp failed. Error: %s",
                          ERR_error_string(ERR_get_error(), NULL));
        }
        goto done;
    }
//#define VERIFY_CREATED_EC_POINT
#ifdef VERIFY_CREATED_EC_POINT
    // debugging code
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    if (!EC_POINT_get_affine_coordinates_GF2m(group, key_2_wrap_point, x1, y1,
                                              ctx))
        SEC_LOG_ERROR("EC_POINT_get_affine_coordinates_GF2m failed");
    SEC_PRINT("inputAsBN: ");
    BN_dump(inputAsBN);
    SEC_PRINT("x1: ");
    BN_dump(x1);
    SEC_PRINT("y1: ");
    BN_dump(y1);
#endif

    /* Calc sender's shared point 'wP' => this gets sent back to receiver */
    sender_share = EC_POINT_new(group);
    if (sender_share == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    P = EC_GROUP_get0_generator(group);
    if (P == NULL)
    {
        SEC_LOG_ERROR("EC_GROUP_get0_generator failed");
        goto done;
    }
    EC_POINT_mul(group, sender_share, NULL, P, sender_rand, ctx);

    /******
     // Calling EC_POINT_is_on_curve is not necessary if we used
     // EC_POINT_set_compressed_coordinates_GFp to get the point,
     // so skipping the following call:
     if (!EC_POINT_is_on_curve(group, key_2_wrap_point, ctx)) {
         SEC_PRINT(" -EG-Error: key_2_wrap_point not in curve");
         ...
     }
     *******/

    ///* Calc sender's Shared Secret 'wRr'  => this hides the key I want to send */
    shared_secret = EC_POINT_new(group);
    if (shared_secret == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    PK_recipient = EC_KEY_get0_public_key(ec_key);
    if (PK_recipient == NULL)
    {
        SEC_LOG_ERROR("EC_KEY_get0_public_key failed");
        goto done;
    }
    EC_POINT_mul(group, shared_secret, NULL, PK_recipient, sender_rand, ctx);

    // key_2_wrap_point is a point on the curve, we add the shared_secret
    // to it and send the result, the wrapped_key, to the receiver.
    wrapped_key = EC_POINT_new(group);
    if (wrapped_key == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }
    EC_POINT_add(group, wrapped_key, key_2_wrap_point, shared_secret, ctx);

    // Dissect the wrapped point to get its coordinates
    x = BN_new();
    if (x == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }
    y = BN_new();
    if (y == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }

    // Clear output buffer to start, in case any of the bignums don't take all
    // their alloted space due to leading zero bytes not being stored by BN_bn2bin
    Sec_Memset(output, 0, 4 * SEC_ECC_NISTP256_KEY_LEN);

    // Copy/convert the two points into our output buffer
    // C1=g^x and C2=m'*s
    // BN_bn2bin does not write leading zero bytes, so the length of the
    // converted bignums is not guaranteed to be SEC_ECC_NISTP256_KEY_LEN.
    // We ignore the return value from BN_bn2bin, the number of bytes written.

    // Dissect shared_secret to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, sender_share, x, y, ctx);

    (void) BN_bn2bin(x, (unsigned char *) &output[0 * SEC_ECC_NISTP256_KEY_LEN]);
    (void) BN_bn2bin(y, (unsigned char *) &output[1 * SEC_ECC_NISTP256_KEY_LEN]);

#ifdef DEBUG_EC
    //$$$ debugging code -- Using x and y from sender_share
    SEC_PRINT("Plaintext: "); Sec_PrintHex(input, inputSize); SEC_PRINT("\n");
    SEC_PRINT("Random: "); BN_dump(sender_rand);
    SEC_PRINT("key_2_wrap_point: "); EC_POINT_dump(key_2_wrap_point); SEC_PRINT("\n");
    SEC_PRINT("EC key for Elgamal: "); EC_KEY_dump(ec_key);
    SEC_PRINT("sender_share X="); BN_dump(x);
    SEC_PRINT("   Y="); BN_dump(y);
#endif

    // Dissect wrapped_key to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, wrapped_key, x, y, ctx);

    (void) BN_bn2bin(x, (unsigned char *) &output[2 * SEC_ECC_NISTP256_KEY_LEN]);
    (void) BN_bn2bin(y, (unsigned char *) &output[3 * SEC_ECC_NISTP256_KEY_LEN]);

    res = 4 * SEC_ECC_NISTP256_KEY_LEN;

#ifdef DEBUG_EC
    //$$$ debugging code -- Using x and y from wrapped_key
    SEC_PRINT("wrapped_key X="); BN_dump(x);
    SEC_PRINT("   Y="); BN_dump(y);
    EC_POINT_dump(wrapped_key); SEC_PRINT("\n");
    // remember that res is the length of the output
    SEC_PRINT("Ciphertext:"); Sec_PrintHex(output, res); SEC_PRINT("\n");
#endif

done:
    if (NULL != x)
        BN_free(x);
    if (NULL != y)
        BN_free(y);
    if (NULL != inputAsBN)
        BN_free(inputAsBN);
    if (NULL != sender_rand)
        BN_free(sender_rand);
    if (NULL != shared_secret)
        EC_POINT_free(shared_secret);
    if (NULL != sender_share)
        EC_POINT_free(sender_share);
    if (NULL != key_2_wrap_point)
        EC_POINT_free(key_2_wrap_point);
    if (NULL != wrapped_key)
        EC_POINT_free(wrapped_key);
    BN_CTX_free(ctx);

    return res;
}

// ec_key is the other side's public ECC key
//
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Encrypt(EC_KEY *ec_key,
                             SEC_BYTE* input, SEC_SIZE inputSize,
                             SEC_BYTE* output, SEC_SIZE outputSize)
{
    /* Generate random number 'w' (multiplier) for the sender */
    BIGNUM *sender_rand = BN_new();

    if (sender_rand == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        return SEC_RESULT_FAILURE;
    }
    if (0 == BN_rand(sender_rand, 256, -1, 0))
    {
        SEC_LOG_ERROR("BN_rand failed");
        if (NULL != sender_rand)
            BN_free(sender_rand);
        return SEC_RESULT_FAILURE;
    }

    return SecUtils_ElGamal_Encrypt_Rand(ec_key,
                                         input, inputSize,
                                         output, outputSize,
                                         sender_rand);
}

// ec_key is our private ECC key
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Decrypt(EC_KEY *ec_key, SEC_BYTE* input,
                             SEC_SIZE inputSize, SEC_BYTE* output, SEC_SIZE outputSize)
{
    int res = -1;
    const EC_GROUP *group = NULL;
    const BIGNUM *our_priv_key = NULL;
    EC_POINT *shared_secret = NULL;
    EC_POINT *sender_share = NULL;
    EC_POINT *wrapped_key = NULL;
    EC_POINT *wrapped_point = NULL;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BN_CTX *ctx = NULL;

    if (inputSize != 4 * SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Input size needed != Four BIGNUMs");
        goto done;
    }

    if (outputSize < SEC_ECC_NISTP256_KEY_LEN)
    {
        SEC_LOG_ERROR("Output size needed > 1 BIGNUM");
        goto done;
    }

    group = EC_KEY_get0_group(ec_key);
    if (NULL == group)
    {
        SEC_LOG_ERROR("EC_KEY_get0_group failed");
        goto done;
    }

    our_priv_key = EC_KEY_get0_private_key(ec_key);
    if (our_priv_key == NULL)
    {
        SEC_LOG_ERROR("EC_KEY_get0_private_key failed");
        goto done;
    }

    shared_secret = EC_POINT_new(group);
    if (shared_secret == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    sender_share = EC_POINT_new(group);
    if (sender_share == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    wrapped_key = EC_POINT_new(group);
    if (wrapped_key == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    wrapped_point = EC_POINT_new(group);
    if (wrapped_point == NULL)
    {
        SEC_LOG_ERROR("EC_POINT_new failed");
        goto done;
    }

    x = BN_new();
    if (x == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }

    y = BN_new();
    if (y == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        goto done;
    }

    ctx = BN_CTX_new();
    if (ctx == NULL)
    {
        SEC_LOG_ERROR("BN_CTX_new failed");
        goto done;
    }

    // Convert the input buffer to 2 EC Points
    // C1=g^x and C2=m'*s

    // Get X and Y coords of EC Point wrapped_key and create the point 'C1'
    if (BN_bin2bn((unsigned char *) &input[2 * SEC_ECC_NISTP256_KEY_LEN],
                  SEC_ECC_NISTP256_KEY_LEN, x) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed converting wrapped_key X coord");
        goto done;
    }
    if (BN_bin2bn((unsigned char *) &input[3 * SEC_ECC_NISTP256_KEY_LEN],
                  SEC_ECC_NISTP256_KEY_LEN, y) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed converting wrapped_key Y coord");
        goto done;
    }
    if (EC_POINT_set_affine_coordinates_GFp(group, wrapped_key, x, y, ctx) != 1)
    {
        SEC_LOG_ERROR("Failed to make wrapped_key EC Point");
        goto done;
    }
#ifdef DEBUG_EC
    //$$$ debugging code
    SEC_PRINT("wrapped_key X="); BN_dump(x);
    SEC_PRINT("   Y="); BN_dump(y);
#endif
    // Note that BN_bin2bn can be safely called on a previously used BN

    // Get X and Y coords of EC Point sender_share and create the point 'C2'
    if (BN_bin2bn((unsigned char *) &input[0 * SEC_ECC_NISTP256_KEY_LEN],
                  SEC_ECC_NISTP256_KEY_LEN, x) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed converting sender_share X coord");
        goto done;
    }
    if (BN_bin2bn((unsigned char *) &input[1 * SEC_ECC_NISTP256_KEY_LEN],
                  SEC_ECC_NISTP256_KEY_LEN, y) == NULL)
    {
        SEC_LOG_ERROR("BN_bin2bn failed converting sender_share Y coord");
        goto done;
    }
    if (EC_POINT_set_affine_coordinates_GFp(group, sender_share, x, y, ctx)
        != 1)
    {
        SEC_LOG_ERROR("Failed to make sender_share EC Point");
        goto done;
    }

#ifdef DEBUG_EC
    //$$$ debugging code
    SEC_PRINT("Decrypting:");
    Sec_PrintHex(input, inputSize);
    SEC_PRINT("\n");
    SEC_PRINT("sender_share X="); BN_dump(x);
    SEC_PRINT("   Y="); BN_dump(y);
#endif

    // Calculate result shared_secret = our_private_key * C1
    EC_POINT_mul(group, shared_secret, NULL, sender_share, our_priv_key, ctx);

    // Calculate plain text wrapped_point = C2 - our_private_key * C1
    // aka wrapped_point = C2 + invert(shared_secret)
    EC_POINT_invert(group, shared_secret, ctx);
    EC_POINT_add(group, wrapped_point, wrapped_key, shared_secret, ctx);

    // Extract just the X coordinate from wrapped_point
    EC_POINT_get_affine_coordinates_GFp(group, wrapped_point, x, /*y=*/NULL,
                                        ctx);

    res = BN_bn2bin(x, (unsigned char *) output);
    if (res != BN_num_bytes(x))
    {
        SEC_LOG_ERROR("Output size needed != what BN_num_bytes said it would be");
        goto done;
    }

#ifdef DEBUG_EC
    //$$$ debugging code
    SEC_PRINT("Decrypted output:");
    Sec_PrintHex(output, outputSize);
    SEC_PRINT("\n");
#endif

    res = SEC_ECC_NISTP256_KEY_LEN;

done:
    if (NULL != x)
        BN_free(x);
    if (NULL != y)
        BN_free(y);
    if (NULL != wrapped_point)
        EC_POINT_free(wrapped_point);
    if (NULL != wrapped_key)
        EC_POINT_free(wrapped_key);
    if (NULL != shared_secret)
        EC_POINT_free(shared_secret);
    if (NULL != sender_share)
        EC_POINT_free(sender_share);
    BN_CTX_free(ctx);

    return res;
}

/*
 * The next steps a caller might take are:
 * SecUtils_BigNumToBuffer(x, public_key->x, Sec_BEBytesToUint32(public_key->key_len));
 * SecUtils_BigNumToBuffer(y, public_key->y, Sec_BEBytesToUint32(public_key->key_len));
 */
Sec_Result SecUtils_Extract_EC_KEY_X_Y(const EC_KEY *ec_key, BIGNUM **xp, BIGNUM **yp, Sec_KeyType *keyTypep)
{
    const EC_GROUP *group = NULL;
    const EC_POINT *ec_point = NULL;
    BN_CTX *ctx = NULL;
    Sec_Result res = SEC_RESULT_FAILURE;

    if (NULL == xp)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: X cannot be NULL");
        goto error;
    }

    group = EC_KEY_get0_group(ec_key);
    if (NULL == group)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_group: %s", ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    ec_point = EC_KEY_get0_public_key(ec_key);
    if (NULL == ec_point)
    {
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_KEY_get0_public_key: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    ctx = BN_CTX_new();
    if (NULL == ctx)
    {
        SEC_LOG_ERROR("BN_CTX_new() failed");
        goto error;
    }

    *xp = BN_new();
    if (NULL == *xp)
    {
        SEC_LOG_ERROR("BN_new() failed");
        goto error;
    }

    if (NULL != yp) { // if caller wants y coordinate returned
        *yp = BN_new();
        if (NULL == *yp)
        {
            SEC_LOG_ERROR("BN_new() failed");
            goto error;
        }
    }

    if (NULL != keyTypep) // if caller wants key type returned
    {
        *keyTypep = SecKey_GroupToKeyType(group);
    }

    // Get the X coordinate and optionally the Y coordinate
    if (EC_POINT_get_affine_coordinates_GFp(group, ec_point,
                                            *xp,
                                            yp != NULL ? *yp : NULL,
                                            ctx) != 1)
    {
        BN_clear_free(*xp);
        if (NULL != yp)
            BN_clear_free(*yp);
        SEC_LOG_ERROR("SecUtils_ExtractEcc_Key_X_Y: EC_POINT_get_affine_coordinates_GFp: %s",
                      ERR_error_string(ERR_get_error(), NULL));
        goto error;
    }

    res = SEC_RESULT_SUCCESS;
    // continue into "error"

error:
    if (NULL != ctx)
        BN_CTX_free(ctx);

    return res;
}

//$$$ bypass OpenSSL data structure hiding
struct my_ec_point_st {
    const EC_METHOD *meth;
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;
    int Z_is_one;
};

// Debugging function (useful from gdb)
void EC_POINT_dump(const EC_POINT *ec_point)
{
    struct my_ec_point_st *my = (struct my_ec_point_st *)ec_point;
    SEC_PRINT("EC_POINT:");
    SEC_PRINT(" X="); BN_print_fp(stdout, &my->X);
    SEC_PRINT(" Y="); BN_print_fp(stdout, &my->Y);
    SEC_PRINT(" Z="); BN_print_fp(stdout, &my->Z);
    SEC_PRINT(" z_is_one=%d ", my->Z_is_one ? 1 : 0);
}

// Debugging function (useful from gdb)
void EC_KEY_dump(const EC_KEY *ec_key)
{
    //$$$ bypass OpenSSL data structure hiding
    const struct my_ec_key_st {
        int version;
        EC_GROUP *group;
        struct my_ec_point_st *pub_key;
        BIGNUM *priv_key;
        unsigned int enc_flag;
        point_conversion_form_t conv_form;
        int references;
        int flags;
        void *method_data;
    } *e = (struct my_ec_key_st *)ec_key;

    //{version = 1, group = 0x6ae660, pub_key = 0x6b2250, priv_key = 0x0, enc_flag = 0, conv_form = POINT_CONVERSION_UNCOMPRESSED, references = 1,
    // flags = 0, method_data = 0x0}

    if (e->pub_key != NULL)
    {
        SEC_PRINT("pub_key (");
        EC_POINT_dump((const EC_POINT *)e->pub_key);
        SEC_PRINT(") ");
    }
    if (e->priv_key != NULL)
    {
        SEC_PRINT("priv_key="); BN_print_fp(stdout, e->priv_key);
    }
    SEC_PRINT("\n");
}

// Debugging function (useful from gdb)
void BN_dump(const BIGNUM *bn)
{
    BN_print_fp(stdout, bn);
    printf("\n");
}
