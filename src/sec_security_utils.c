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
#include <errno.h>

#if !defined(SEC_PUBOPS_TOMCRYPT)
#include  <openssl/pem.h>
#include  <openssl/err.h>
#endif

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
    SEC_SIZE read = 0;

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

    read= fread(&last_byte, 1, 1, f);

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
    read = (SEC_BYTE *) malloc(expected_len);
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
			if (SecUtils_WriteFile(path, zeros, len) != SEC_RESULT_SUCCESS)
				SEC_LOG_ERROR("Could not write zeros");
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

#if !defined(SEC_PUBOPS_TOMCRYPT)
Sec_Result SecUtils_BigNumToBuffer(const BIGNUM *bignum, SEC_BYTE *buffer, SEC_SIZE buffer_len)
{
    SEC_SIZE num_bytes;

    memset(buffer, 0, buffer_len);
    num_bytes = BN_num_bytes(bignum);

    if (num_bytes > buffer_len) {
        SEC_LOG_ERROR("buffer not large enough.  needed: %d, actual: %d", num_bytes, buffer_len);
        return SEC_RESULT_FAILURE;
    }

    BN_bn2bin(bignum, buffer + buffer_len - num_bytes);

    return SEC_RESULT_SUCCESS;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
RSA *SecUtils_RSAFromPrivBinary(Sec_RSARawPrivateKey *binary)
{
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
    rsa->d = BN_bin2bn(binary->d, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
#else
    RSA_set0_key(rsa,
        BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL),
        BN_bin2bn(binary->e, 4, NULL),
        BN_bin2bn(binary->d, Sec_BEBytesToUint32(binary->modulus_len_be), NULL));
#endif

    return rsa;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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

    tmp = BN_new();
    ctx = BN_CTX_new();

    BIGNUM *p = BN_bin2bn(binary->p, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    BIGNUM *q = BN_bin2bn(binary->q, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    BIGNUM *d = BN_bin2bn(binary->d, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
    rsa->d = d;
    rsa->p = p;
    rsa->q = q;

    rsa->dmp1 = BN_new();
    rsa->dmq1 = BN_new();
    rsa->iqmp = BN_new();

    BN_sub(tmp, rsa->p, BN_value_one());
    BN_mod(rsa->dmp1, rsa->d, tmp, ctx);
    BN_sub(tmp, rsa->q, BN_value_one());
    BN_mod(rsa->dmq1, rsa->d, tmp, ctx);
    BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx);

#else
    RSA_set0_key(rsa,
        BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL),
        BN_bin2bn(binary->e, 4, NULL),
        d);

    RSA_set0_factors(rsa,
        p,
        q);

    BIGNUM *dmp1 = BN_new();
    BIGNUM *dmq1 = BN_new();
    BIGNUM *iqmp = BN_new();

    BN_sub(tmp, p, BN_value_one());
    BN_mod(dmp1, d, tmp, ctx);
    BN_sub(tmp, q, BN_value_one());
    BN_mod(dmq1, d, tmp, ctx);
    BN_mod_inverse(iqmp, q, p, ctx);

    RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp);
#endif

    BN_free(tmp);
    BN_CTX_free(ctx);

    return rsa;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
RSA *SecUtils_RSAFromPubBinary(Sec_RSARawPublicKey *binary)
{
    RSA *rsa = NULL;

    rsa = RSA_new();
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL);
    rsa->e = BN_bin2bn(binary->e, 4, NULL);
#else
    RSA_set0_key(rsa,
        BN_bin2bn(binary->n, Sec_BEBytesToUint32(binary->modulus_len_be), NULL),
        BN_bin2bn(binary->e, 4, NULL),
        NULL);
#endif

    return rsa;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
static int _Sec_DisablePassphrasePrompt(char *buf, int size, int rwflag, void *u)
{
    return 0;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
void SecUtils_RSAToPrivBinary(RSA *rsa, Sec_RSARawPrivateKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
    SecUtils_BigNumToBuffer(rsa->d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
#else
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    SecUtils_BigNumToBuffer((BIGNUM *) n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer((BIGNUM *) e, binary->e, 4);
    SecUtils_BigNumToBuffer((BIGNUM *) d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
#endif
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
void SecUtils_RSAToPrivFullBinary(RSA *rsa, Sec_RSARawPrivateFullKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
    SecUtils_BigNumToBuffer(rsa->d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->p, binary->p, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->q, binary->q, Sec_BEBytesToUint32(binary->modulus_len_be));
#else
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    const BIGNUM *d = NULL;
    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    SecUtils_BigNumToBuffer((BIGNUM *) n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer((BIGNUM *) e, binary->e, 4);
    SecUtils_BigNumToBuffer((BIGNUM *) d, binary->d, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer((BIGNUM *) p, binary->p, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer((BIGNUM *) q, binary->q, Sec_BEBytesToUint32(binary->modulus_len_be));
#endif
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
void SecUtils_RSAToPubBinary(RSA *rsa, Sec_RSARawPublicKey *binary)
{
    Sec_Uint32ToBEBytes(RSA_size(rsa), binary->modulus_len_be);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SecUtils_BigNumToBuffer(rsa->n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer(rsa->e, binary->e, 4);
#else
    const BIGNUM *n = NULL;
    const BIGNUM *e = NULL;
    RSA_get0_key(rsa, &n, &e, NULL);
    SecUtils_BigNumToBuffer((BIGNUM *) n, binary->n, Sec_BEBytesToUint32(binary->modulus_len_be));
    SecUtils_BigNumToBuffer((BIGNUM *) e, binary->e, 4);
#endif
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
SEC_BOOL SecUtils_RSAHasPriv(RSA *rsa)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    return rsa->d != NULL;
#else
    const BIGNUM *d = NULL;
    RSA_get0_key(rsa, NULL, NULL, &d);

    return d != NULL;
#endif
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
SEC_BOOL SecUtils_ECCHasPriv(EC_KEY *ec_key)
{
    return EC_KEY_get0_private_key(ec_key) != NULL;
}
#endif

SEC_BOOL SecUtils_RSAIsClearKC(Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len)
{
    return kc == SEC_KEYCONTAINER_DER_RSA_1024
    || kc == SEC_KEYCONTAINER_DER_RSA_2048
    || kc == SEC_KEYCONTAINER_DER_RSA_3072
    || kc == SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC
    || kc == SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC
    || kc == SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC
    || kc == SEC_KEYCONTAINER_RAW_RSA_1024
    || kc == SEC_KEYCONTAINER_RAW_RSA_2048
    || kc == SEC_KEYCONTAINER_RAW_RSA_3072
    || kc == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC
    || kc == SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC
    || kc == SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC
    || kc == SEC_KEYCONTAINER_PEM_RSA_1024
    || kc == SEC_KEYCONTAINER_PEM_RSA_2048
    || kc == SEC_KEYCONTAINER_PEM_RSA_3072
    || kc == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC
    || kc == SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC
    || kc == SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC
    || (kc == SEC_KEYCONTAINER_STORE
        && data_len >= sizeof(SecStore_Header)
                    && data_len >= (sizeof(SecStore_Header) + SecStore_GetUserHeaderLen(data))
                    && SecUtils_RSAIsClearKC((Sec_KeyContainer) SecUtils_GetKeyStoreUserHeader(data)->inner_kc_type, data, data_len));
}

#if !defined(SEC_PUBOPS_TOMCRYPT)
RSA* SecUtils_RSAFromClearKC(Sec_ProcessorHandle *proc, Sec_KeyContainer kc, SEC_BYTE *data, SEC_SIZE data_len)
{
    RSA *rsa = NULL;
    SecUtils_KeyStoreHeader store_header;
    SEC_BYTE store_data[SEC_KEYCONTAINER_MAX_LEN];

    if (kc == SEC_KEYCONTAINER_DER_RSA_1024 || kc == SEC_KEYCONTAINER_DER_RSA_2048 || kc == SEC_KEYCONTAINER_DER_RSA_3072) {
        rsa = SecUtils_RSAFromDERPriv(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromDERPriv failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_DER_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_DER_RSA_2048_PUBLIC || kc == SEC_KEYCONTAINER_DER_RSA_3072_PUBLIC) {
        rsa = SecUtils_RSAFromDERPub(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromDERPub failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_RAW_RSA_1024 || kc == SEC_KEYCONTAINER_RAW_RSA_2048 || kc == SEC_KEYCONTAINER_RAW_RSA_3072) {
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
    } else if (kc == SEC_KEYCONTAINER_RAW_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_RAW_RSA_2048_PUBLIC || kc == SEC_KEYCONTAINER_RAW_RSA_3072_PUBLIC) {
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
    } else if (kc == SEC_KEYCONTAINER_PEM_RSA_1024 || kc == SEC_KEYCONTAINER_PEM_RSA_2048 || kc == SEC_KEYCONTAINER_PEM_RSA_3072) {
        rsa = SecUtils_RSAFromPEMPriv(data, data_len);
        if (rsa == NULL)
        {
            SEC_LOG_ERROR("SecUtils_RSAFromPEMPriv failed");
            goto done;
        }
    } else if (kc == SEC_KEYCONTAINER_PEM_RSA_1024_PUBLIC || kc == SEC_KEYCONTAINER_PEM_RSA_2048_PUBLIC || kc == SEC_KEYCONTAINER_PEM_RSA_3072_PUBLIC) {
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
#endif


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
        && SecUtils_ECCIsClearKC((Sec_KeyContainer) SecUtils_GetKeyStoreUserHeader(data)->inner_kc_type,
                                 data, data_len));
}

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif


#if !defined(SEC_PUBOPS_TOMCRYPT)
// $$$ Expand for more support private key types (not public types, because
// $$$ they won't have a private key)
EC_KEY *SecUtils_ECCFromOnlyPrivBinary(Sec_ECCRawOnlyPrivateKey *binary)
{
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (group == NULL) {
        SEC_LOG_ERROR("EC_GROUP_new_by_curve_name failed");
        return NULL;
    }

    EC_POINT *pub_key = EC_POINT_new(group);
    if (pub_key == NULL) {
        SEC_LOG_ERROR("EC_POINT_new failed");

        EC_GROUP_free(group);

        return NULL;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        SEC_LOG_ERROR("BN_CTX_new failed");

        EC_GROUP_free(group);
        EC_POINT_free(pub_key);

        return NULL;
    }

    if(!EC_POINT_mul(group, pub_key, BN_bin2bn(binary->prv, sizeof binary->prv, NULL), NULL, NULL, ctx)) {
        SEC_LOG_ERROR("EC_POINT_mul failed");

        EC_GROUP_free(group);
        EC_POINT_free(pub_key);
        BN_CTX_free(ctx);

        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;

    if (!EC_KEY_set_private_key(ec_key, BN_bin2bn(binary->prv, sizeof binary->prv, NULL))) {
        SEC_LOG_ERROR("EC_KEY_set_private_key failed");

        EC_GROUP_free(group);
        EC_POINT_free(pub_key);
        SEC_ECC_FREE(ec_key);
        BN_CTX_free(ctx);

        return NULL;
    }

    if (!EC_KEY_set_public_key(ec_key, pub_key)) {
        SEC_LOG_ERROR("EC_KEY_set_public_key failed");

        EC_GROUP_free(group);
        EC_POINT_free(pub_key);
        SEC_ECC_FREE(ec_key);
        BN_CTX_free(ctx);

        return NULL;
    }

    EC_GROUP_free(group);
    EC_POINT_free(pub_key);
    BN_CTX_free(ctx);

    return ec_key;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
// Precondition: binary->type must have been verified as a supported value.
// $$$ Expand for more support private key types (not public types, because
// $$$ they won't have a private key)
EC_KEY *SecUtils_ECCFromPrivBinary(Sec_ECCRawPrivateKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    // Note that SEC_KEYTYPE_ECC_NISTP256_PUBLIC is not acceptable,
    // because it won't have a private key value
    if (binary->type != SEC_KEYTYPE_ECC_NISTP256) {
        SEC_LOG_ERROR("invalid key type");
        return NULL;
    }

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp, *prvp;
    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL)
        || ((prvp = BN_CTX_get(ctx)) == NULL)) {

        SEC_LOG_ERROR("BN_CTX_get failed");
        goto done;
    }

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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
        if (keyType != SEC_KEYTYPE_ECC_NISTP256_PUBLIC) {
            SEC_LOG_ERROR("Unexpected key type encountered: %d", keyType);
            return SEC_RESULT_FAILURE;
        }
        binary->type = SEC_KEYTYPE_ECC_NISTP256;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(keyType), binary->key_len);
        SecUtils_BigNumToBuffer((BIGNUM *) EC_KEY_get0_private_key(ec_key), binary->prv, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
Sec_Result SecUtils_ECCToPubBinary(EC_KEY *ec_key, Sec_ECCRawPublicKey *binary)
{
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;

    if (SecUtils_Extract_EC_KEY_X_Y(ec_key, &x, &y, NULL) != SEC_RESULT_SUCCESS)
    {

        SEC_LOG_ERROR("SecUtils_ECCToPubBinary: SecUtils_Extract_EC_KEY_X_Y failed");
        return SEC_RESULT_FAILURE;
    }
    else
    {
        binary->type = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
        Sec_Uint32ToBEBytes(SecKey_GetKeyLenForKeyType(binary->type), binary->key_len);
        SecUtils_BigNumToBuffer(x, binary->x, Sec_BEBytesToUint32(binary->key_len));
        SecUtils_BigNumToBuffer(y, binary->y, Sec_BEBytesToUint32(binary->key_len));

        BN_free(y);
        BN_free(x);
        return SEC_RESULT_SUCCESS;
    }
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
SEC_SIZE SecUtils_X509ToDer(X509 *x509, void *mem)
{
    int written = 0;
    SEC_BYTE *ptr = (SEC_BYTE *) mem;
    written = i2d_X509(x509, &ptr);
    if (written < 0)
        return 0;
    return written;
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

Sec_Result SecUtils_DigestInfoForRSASign(Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *padded, SEC_SIZE* padded_len, SEC_SIZE keySize) {
    const SEC_BYTE SHA1_PREFIX[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    const SEC_BYTE SHA256_PREFIX[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

    if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST)
    {
        if (digest_len != 20) {
            SEC_LOG_ERROR("Invalid digest len");
            return SEC_RESULT_FAILURE;
        }

        memcpy(padded, SHA1_PREFIX, sizeof(SHA1_PREFIX));
        memcpy(padded + sizeof(SHA1_PREFIX), digest, digest_len);

        *padded_len = sizeof(SHA1_PREFIX) + digest_len;

        return SEC_RESULT_SUCCESS;
    }
    else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS
             || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST
             || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS
             || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST)
    {
        if (digest_len != 32) {
            SEC_LOG_ERROR("Invalid digest len");
            return SEC_RESULT_FAILURE;
        }

        memcpy(padded, SHA256_PREFIX, sizeof(SHA256_PREFIX));
        memcpy(padded + sizeof(SHA256_PREFIX), digest, digest_len);

        *padded_len = sizeof(SHA256_PREFIX) + digest_len;

        return SEC_RESULT_SUCCESS;
    }
    else
    {
        SEC_LOG_ERROR("Unknown signature algorithm");
        return SEC_RESULT_FAILURE;
    }
}

#define _RSA_PKCS1_PAD_SIZE   11
static Sec_Result _ApplyPKCS15Pad(SEC_BYTE *input, SEC_SIZE in_len, SEC_BYTE *output, SEC_SIZE out_len) {
    if (in_len > (out_len - _RSA_PKCS1_PAD_SIZE)) {
        SEC_LOG_ERROR("output is not large enough");
        return SEC_RESULT_FAILURE;
    }

    SEC_BYTE *p = input;
    *(p++) = 0;
    *(p++) = 1;  //block type

    SEC_SIZE i;
    for (i=0; i<(out_len - 3 - in_len); ++i) {
        *(p++) = 0xff;
    }
    *(p++) = 0;

    memcpy(p, input, in_len);

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

    if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST) {

        if (SEC_RESULT_SUCCESS != _ApplyPKCS15Pad(temp_padded, temp_padded_len, padded, keySize)) {
            SEC_LOG_ERROR("_ApplyPKCS15Pad failed");
            return SEC_RESULT_FAILURE;
        }
    } else if (alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST
        || alg == SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST) {

        SEC_LOG_ERROR("PSS padding cannot be applied without the key");
        return SEC_RESULT_FAILURE;
    } else {
        SEC_LOG_ERROR("Unknown signing algorithm detected: %d", alg);
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

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

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

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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

    // Convert the input buffer to be encrypted to a BIGNUM
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

    // Calc sender's shared point 'wP' => this gets sent back to receiver
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

    // Calc sender's Shared Secret 'wRr'  => this hides the key I want to send
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

    // Dissect shared_secret to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, sender_share, x, y, ctx);

    if (SEC_RESULT_SUCCESS != SecUtils_BigNumToBuffer(x, (unsigned char *) &output[0 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecUtils_BigNumToBuffer(y, (unsigned char *) &output[1 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
        goto done;
    }

    // Dissect wrapped_key to get its coordinates and output them
    EC_POINT_get_affine_coordinates_GFp(group, wrapped_key, x, y, ctx);

    if (SEC_RESULT_SUCCESS != SecUtils_BigNumToBuffer(x, (unsigned char *) &output[2 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecUtils_BigNumToBuffer(y, (unsigned char *) &output[3 * SEC_ECC_NISTP256_KEY_LEN], SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
        goto done;
    }

    res = 4 * SEC_ECC_NISTP256_KEY_LEN;

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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
// ec_key is the other side's public ECC key
//
// Returns the number of bytes in the encrypted output or
// -1 if there was an error
int SecUtils_ElGamal_Encrypt(EC_KEY *ec_key,
                             SEC_BYTE* input, SEC_SIZE inputSize,
                             SEC_BYTE* output, SEC_SIZE outputSize)
{
    // Generate random number 'w' (multiplier) for the sender
    BIGNUM *sender_rand = BN_new();

    if (sender_rand == NULL)
    {
        SEC_LOG_ERROR("BN_new failed");
        return -1;
    }
    if (0 == BN_rand(sender_rand, 256, -1, 0))
    {
        SEC_LOG_ERROR("BN_rand failed");
        if (NULL != sender_rand)
            BN_free(sender_rand);
        return -1;
    }

    return SecUtils_ElGamal_Encrypt_Rand(ec_key,
                                         input, inputSize,
                                         output, outputSize,
                                         sender_rand);
}
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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

    // Calculate result shared_secret = our_private_key * C1
    EC_POINT_mul(group, shared_secret, NULL, sender_share, our_priv_key, ctx);

    // Calculate plain text wrapped_point = C2 - our_private_key * C1
    // aka wrapped_point = C2 + invert(shared_secret)
    EC_POINT_invert(group, shared_secret, ctx);
    EC_POINT_add(group, wrapped_point, wrapped_key, shared_secret, ctx);

    // Extract just the X coordinate from wrapped_point
    EC_POINT_get_affine_coordinates_GFp(group, wrapped_point, x, NULL,
                                        ctx);

    if (SEC_RESULT_SUCCESS != SecUtils_BigNumToBuffer(x, output, SEC_ECC_NISTP256_KEY_LEN)) {
        SEC_LOG_ERROR("SecUtils_BigNumToBuffer failed");
        goto done;
    }

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
#endif

#if !defined(SEC_PUBOPS_TOMCRYPT)
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
        *keyTypep = SEC_KEYTYPE_ECC_NISTP256_PUBLIC;
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
#endif
