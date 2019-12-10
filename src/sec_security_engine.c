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

#if !defined(SEC_PUBOPS_TOMCRYPT)

#include "sec_security.h"
#include <pthread.h>
#include <openssl/engine.h>

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

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static RSA_METHOD g_sec_openssl_rsamethod = {
        "securityapi RSA method",
        _Sec_OpenSSLPubEncrypt,  // rsa_pub_enc
        NULL,  // rsa_pub_dec
        NULL, // rsa_priv_enc
        _Sec_OpenSSLPrivDecrypt, // rsa_priv_dec
        NULL,  // rsa_mod_exp
        NULL,  // bn_mod_exp
        NULL,  // init
        NULL,  // finish
        RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY | RSA_FLAG_SIGN_VER,  // flags
        NULL,  // app_data
        _Sec_OpenSSLPrivSign,  // rsa_sign
        _Sec_OpenSSLPubVerify,  // rsa_verify
        NULL,  // rsa_keygen
};

#else

RSA_METHOD * _GetRSAMethod() {
    static RSA_METHOD *s_method = NULL;

    if (s_method == NULL) {
        s_method = RSA_meth_new("securityapi RSA method", RSA_METHOD_FLAG_NO_CHECK | RSA_FLAG_EXT_PKEY);

        //rsa_pub_enc
        RSA_meth_set_pub_enc(s_method, _Sec_OpenSSLPubEncrypt);

        //rsa_priv_dec
        RSA_meth_set_priv_dec(s_method, _Sec_OpenSSLPrivDecrypt);

        //rsa_sign
        RSA_meth_set_sign(s_method, _Sec_OpenSSLPrivSign);

        //rsa_verify
        RSA_meth_set_verify(s_method, _Sec_OpenSSLPubVerify);
    }

    return s_method;
}

#endif

static void ENGINE_load_securityapi(void)
{
    ENGINE *engine = ENGINE_new();

    if (engine == NULL )
    {
        SEC_LOG_ERROR("ENGINE_new failed");
        return;
    }

    if (!ENGINE_set_id(engine, "securityapi")
            || !ENGINE_set_name(engine, "SecurityApi engine")
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            || !ENGINE_set_RSA(engine, &g_sec_openssl_rsamethod)
#else
#endif
            )
    {
        ENGINE_free(engine);
        return;
    }

    ENGINE_add(engine);
    ENGINE_free(engine);
    ERR_clear_error();
}

void Sec_InitOpenSSL(void)
{
    static pthread_mutex_t init_openssl_mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&init_openssl_mutex);

    if (!g_sec_openssl_inited)
    {
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_digests();

        ENGINE_load_openssl();
        ENGINE_set_default(ENGINE_by_id("openssl"), ENGINE_METHOD_ALL);
        ENGINE_load_securityapi();

        g_sec_openssl_inited = 1;
    }

    pthread_mutex_unlock(&init_openssl_mutex);
}

void Sec_PrintOpenSSLVersion()
{
    SEC_PRINT("Built against: %s\n", OPENSSL_VERSION_TEXT);
    SEC_PRINT("Running against: %s\n", SSLeay_version(SSLEAY_VERSION));
}

RSA* SecKey_ToEngineRSA(Sec_KeyHandle *key)
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

    if (SEC_RESULT_SUCCESS != SecKey_ExtractRSAPublicKey(key, &pubKey))
    {
        SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
        return NULL;
    }

    rsa = RSA_new_method(engine);
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new_method failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(pubKey.n, Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL);
    rsa->e = BN_bin2bn(pubKey.e, 4, NULL);
#else
    RSA_set0_key(rsa,
        BN_bin2bn(pubKey.n, Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL),
        BN_bin2bn(pubKey.e, 4, NULL),
        NULL);
#endif

    RSA_set_app_data(rsa, key);

    return rsa;
}

RSA* SecKey_ToEngineRSAWithCert(Sec_KeyHandle *key, Sec_CertificateHandle *cert)
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

    if (SEC_RESULT_SUCCESS != SecCertificate_ExtractRSAPublicKey(cert, &pubKey))
    {
        SEC_LOG_ERROR("SecKey_ExtractRSAPublicKey failed");
        return NULL;
    }

    rsa = RSA_new_method(engine);
    if (NULL == rsa)
    {
        SEC_LOG_ERROR("RSA_new_method failed");
        return NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    rsa->n = BN_bin2bn(pubKey.n, Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL);
    rsa->e = BN_bin2bn(pubKey.e, 4, NULL);
#else
    RSA_set0_key(rsa,
        BN_bin2bn(pubKey.n, Sec_BEBytesToUint32(pubKey.modulus_len_be), NULL),
        BN_bin2bn(pubKey.e, 4, NULL),
        NULL);
#endif

    RSA_set_app_data(rsa, key);

    return rsa;
}

EC_KEY* SecKey_ToEngineEcc(Sec_KeyHandle *key)
{
    SEC_LOG_ERROR("SecKey_ToEngineEcc is not implemented"); // support first appears in OpenSSL 1.0.2 and is not ready for us
    return NULL;
}

X509 * SecCertificate_DerToX509(void *mem, SEC_SIZE len)
{
    X509 *x509 = NULL;
    const SEC_BYTE *ptr = (const SEC_BYTE *) mem;
    x509 = d2i_X509(&x509, &ptr, len);
    return x509;
}

X509* SecCertificate_ToX509(Sec_CertificateHandle *cert)
{
    SEC_BYTE exportedCert[1024*64];
    SEC_SIZE exportedCertLen;

    if (SEC_RESULT_SUCCESS != SecCertificate_Export(cert, exportedCert, sizeof(exportedCert), &exportedCertLen))
    {
        SEC_LOG_ERROR("SecCertificate_Export failed");
        return NULL;
    }

    return SecCertificate_DerToX509(exportedCert, exportedCertLen);
}

#endif

