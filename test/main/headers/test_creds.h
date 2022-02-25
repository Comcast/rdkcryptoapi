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

#ifndef TEST_CREDS_H_
#define TEST_CREDS_H_

#include <vector>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include "sec_security.h"

enum TestKey {
    TESTKEY_AES128 = 0,
    TESTKEY_AES256,
    TESTKEY_HMAC128,
    TESTKEY_HMAC160,
    TESTKEY_HMAC256,
    TESTKEY_RSA1024_SGN_PRIV,
    TESTKEY_RSA1024_SGN_PUB,
    TESTKEY_RSA1024_ENC_PRIV,
    TESTKEY_RSA1024_ENC_PUB,
    TESTKEY_RSA1024_KEK_PRIV,
    TESTKEY_RSA1024_KEK_PUB,
    TESTKEY_RSA2048_SGN_PRIV,
    TESTKEY_RSA2048_SGN_PUB,
    TESTKEY_RSA2048_ENC_PRIV,
    TESTKEY_RSA2048_ENC_PUB,
    TESTKEY_RSA2048_KEK_PRIV,
    TESTKEY_RSA2048_KEK_PUB,
    TESTKEY_EC_PRIV,
    TESTKEY_EC_PUB,
    TESTKEY_NUM
};

enum TestKc {
    TESTKC_RAW,
    TESTKC_STORE,
    TESTKC_SOC,
    TESTKC_GENERATED,
    TESTKC_EXPORTED,
    TESTKC_NUM
};

enum TestCert {
    TESTCERT_RSA1024 = 0,
    TESTCERT_RSA2048,
    TESTCERT_EC,
    TESTCERT_NUM
};

enum WrappedKeyFormatVersion {
    WKFV_V2 = 2,    //with offset field
    WKFV_V3     //with embedded wrappedKey
};

enum Capability {
    CAPABILITY_AES256 = 0,
    CAPABILITY_HMAC_IN_HW,
    CAPABILITY_CMAC_IN_HW,
    CAPABILITY_DIGEST_OVER_HWKEY,
    CAPABILITY_HMAC_OVER_HWKEY,
    CAPABILITY_CMAC_OVER_HWKEY,
    CAPABILITY_HKDF_CMAC,
    CAPABILITY_EXTRACT_RSA_PUB,
    CAPABILITY_WRAPPED_KEY_FORMAT_V3,  //nested key containers
    CAPABILITY_RSA_AES_M2M,
    CAPABILITY_CLEAR_JTYPE_WRAPPING, // SOC only
    CAPABILITY_SVP,
    CAPABILITY_LOAD_SYM_SOC_KC,
    CAPABILITY_EXPORT_RSA,
    CAPABILITY_RSA_1024,
    CAPABILITY_RSA_AESCBC_AES,
    CAPABILITY_RSA_AESCTR_AES,
    CAPABILITY_RSA_AESCTR_RSA,
    CAPABILITY_NUM
};

class TestCtx;

class ProvKey {
public:
    ProvKey() {}

    ProvKey(std::vector<SEC_BYTE> _key, Sec_KeyContainer _kc) {
        key = _key;
        kc = _kc;
    }
    std::vector<SEC_BYTE> key;
    Sec_KeyContainer kc;
};

class ProvCert {
public:
    ProvCert(std::vector<SEC_BYTE> _cert, Sec_CertificateContainer _cc) {
        cert = _cert;
        cc = _cc;
    }
    std::vector<SEC_BYTE> cert;
    Sec_CertificateContainer cc;
};

class TestCreds {
public:
    static ProvKey* getKey(TestKey key, TestKc kc, SEC_OBJECTID id);
    static Sec_KeyType getKeyType(TestKey key);
    static ProvCert* getCert(TestCert cert);

    static std::vector<SEC_BYTE> asOpenSslAes(TestKey key);
    static RSA* asOpenSslRsa(TestKey key);
    static EC_KEY *asOpenSslEcKey(TestKey key);
    static EVP_PKEY *asOpenSslEvpPkey(TestKey key);

    //following stubs should be implemented by the SOC vendors in test_creds_soc.cpp
    static ProvKey* getSocKey(TestKey key, SEC_OBJECTID id);
    static Sec_Result preprovisionSoc(TestCtx *testCtx);
    static SEC_BOOL supports(Capability cap);
    static void init();
    static void shutdown();

    static std::vector<ProvKey> getWrappedContentKeyChainRsaAes(TestKey contentKey, TestKc kc, SEC_OBJECTID id, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg);
    static std::vector<ProvKey> getWrappedContentKeyChainRsaAesAes(TestKey contentKey, TestKc kc, SEC_OBJECTID id, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg);
    static std::vector<ProvKey> getWrappedContentKeyChainRsaAesRsaAesAes(TestKey contentKey, TestKc kc, SEC_OBJECTID id, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, Sec_CipherAlgorithm ckSymAlg);
    static std::vector<ProvKey> getWrappedContentKeyChainEcAes(TestKey contentKey, TestKc kc, SEC_OBJECTID id, Sec_CipherAlgorithm asymAlg);
    static std::vector<ProvKey> getWrappedContentKeyChainEcAesAes(TestKey contentKey, TestKc kc, SEC_OBJECTID base_id, Sec_KeyType aesType, Sec_CipherAlgorithm asymAlg, Sec_CipherAlgorithm symAlg);

    static ProvKey* wrapAesWithAes(const SEC_BYTE* clear, Sec_KeyType type, const SEC_BYTE* wrapping, Sec_KeyType wrappingType, SEC_OBJECTID wrappingId, Sec_CipherAlgorithm symAlg);
    static ProvKey* wrapAesWithEc(const SEC_BYTE* clear, Sec_KeyType type, EC_KEY *ec_key, SEC_OBJECTID wrappingId, Sec_CipherAlgorithm asymAlg);
    static ProvKey* wrapAesWithRsa(const SEC_BYTE* data, Sec_KeyType type, RSA *rsa_key, SEC_OBJECTID wrappingId, Sec_CipherAlgorithm asymAlg);
    static ProvKey* wrapRsaWithAes(RSA* rsa, const SEC_BYTE* wrapping, Sec_KeyType wrappingType, SEC_OBJECTID wrappingId, Sec_CipherAlgorithm symAlg);
};

#endif
