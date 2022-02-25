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

#include "sec_api_utest_main.h"
#include <stdio.h>
#include "sec_security.h"
#include "test_ctx.h"
#include "processor.h"
#include "key.h"
#include "cert.h"
#include "cipher.h"
#include "digest.h"
#include "mac.h"
#include "sign.h"
#include "bundle.h"
#include "random.h"
#include "wrapped.h"
#include "concurrent.h"
#include "jtype.h"
#include "svp.h"
#include "exchange.h"
#include "keyctrl.h"
#include "test_creds.h"
#include <vector>

#ifdef SEC_PLATFORM_OPENSSL
#include "sec_security_openssl.h"
#endif

void runProcessorTests(SuiteCtx *suite) {
    RUN_TEST(suite, testProcessorPrintInfo());
    RUN_TEST(suite, testProcessorGetInfo());
    RUN_TEST(suite, testProcessorGetDeviceId());
    RUN_TEST(suite, testProcessorGetKeyLadderMinMaxDepth(SEC_KEYLADDERROOT_UNIQUE));
    RUN_TEST(suite, testProcessorGetKeyLadderMinMaxDepth(SEC_KEYLADDERROOT_SHARED));
    RUN_TEST(suite, testProcessorNativeMallocFree());
}

void runBundleTests(SuiteCtx *suite) {
    RUN_TEST(suite, testBundleProvision(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, 256));
    RUN_TEST(suite, testBundleProvision(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_FILE, 256));
    RUN_TEST(suite, testBundleProvisionNoAppDir(SEC_OBJECTID_USER_BASE, 256));
}

#define CERT_TESTS_LOC(suite, cert, loc) do { \
    RUN_TEST(suite, testCertProvision(SEC_OBJECTID_USER_BASE, cert, loc)); \
    RUN_TEST(suite, testCertExport(SEC_OBJECTID_USER_BASE, cert, loc)); \
} while (0)

#define CERT_TESTS(suite, cert, pub_key) do { \
    CERT_TESTS_LOC(suite, cert, SEC_STORAGELOC_RAM); \
    CERT_TESTS_LOC(suite, cert, SEC_STORAGELOC_FILE); \
    RUN_TEST(suite, testCertVerify(SEC_OBJECTID_USER_BASE, cert, SEC_OBJECTID_USER_BASE+1, pub_key, SEC_STORAGELOC_RAM)); \
    RUN_TEST(suite, testCertVerify(SEC_OBJECTID_USER_BASE, cert, SEC_OBJECTID_USER_BASE+1, pub_key, SEC_STORAGELOC_RAM_SOFT_WRAPPED)); \
} while (0)

void runCertTests(SuiteCtx *suite) {
    if (TestCreds::supports(CAPABILITY_RSA_1024)) {
        CERT_TESTS(suite, TESTCERT_RSA1024, TESTKEY_RSA1024_SGN_PUB);
    }
    CERT_TESTS(suite, TESTCERT_RSA2048, TESTKEY_RSA2048_SGN_PUB);
    CERT_TESTS(suite, TESTCERT_EC, TESTKEY_EC_PUB);
}

#define KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, encKc, macKey, version, alg) do { \
    RUN_TEST(suite, testExportKey(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_CTR, 20, version, alg)); \
    RUN_TEST(suite, testExportKey(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, 32, version, alg)); \
    RUN_TEST(suite, testExportKey(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, 20, version, alg)); \
    RUN_TEST(suite, testExportKey(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 32, version, alg)); \
    RUN_TEST(suite, testExportKey(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, 20, version, alg)); \
} while (0)

#define JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, encKc, macKey, version, alg) do { \
    RUN_TEST(suite, testDecryptJType(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, 256, version, alg)); \
    RUN_TEST(suite, testDecryptJType(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_CTR, 256, version, alg)); \
    RUN_TEST(suite, testDecryptJType(contentKey, encryptionKey, encKc, macKey, TESTKC_RAW, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256, version, alg)); \
} while (0)

#define JTYPE_TESTS(suite, contentKey, encryptionKey, macKey, version) do { \
    if (version == 1) { \
        if (TestCreds::supports(CAPABILITY_LOAD_SYM_SOC_KC)) { \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_SOC, macKey, TESTKC_RAW, 1, "aesEcbNone")); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 1, "aesEcbNone"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 1, "aesEcbNone"); \
        } \
        if (TestCreds::supports(CAPABILITY_CLEAR_JTYPE_WRAPPING)) { \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_RAW, macKey, TESTKC_RAW, 1, "aesEcbNone")); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 1, "aesEcbNone"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 1, "aesEcbNone"); \
        } \
    } else if (version == 2) { \
        if (TestCreds::supports(CAPABILITY_LOAD_SYM_SOC_KC)) { \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_SOC, macKey, TESTKC_RAW, 2, "aesEcbNone")); \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_SOC, macKey, TESTKC_RAW, 2, "aesEcbPkcs5")); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 2, "aesEcbNone"); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 2, "aesEcbPkcs5"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 2, "aesEcbNone"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_SOC, macKey, 2, "aesEcbPkcs5"); \
        } \
        if (TestCreds::supports(CAPABILITY_CLEAR_JTYPE_WRAPPING)) { \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_RAW, macKey, TESTKC_RAW, 2, "aesEcbNone")); \
            RUN_TEST(suite, testProvisionJType(contentKey, encryptionKey, TESTKC_RAW, macKey, TESTKC_RAW, 2, "aesEcbPkcs5")); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 2, "aesEcbNone"); \
            KEY_EXPORT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 2, "aesEcbPkcs5"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 2, "aesEcbNone"); \
            JTYPE_DECRYPT_TESTS(suite, contentKey, encryptionKey, TESTKC_RAW, macKey, 2, "aesEcbPkcs5"); \
        } \
    } \
} while (0)

void runProvisionedKeyExportTest(SuiteCtx *suite) {
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES128, TESTKC_RAW));
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES256, TESTKC_RAW));
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC128, TESTKC_RAW));
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC160, TESTKC_RAW));
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC256, TESTKC_RAW));

    if (TestCreds::supports(CAPABILITY_LOAD_SYM_SOC_KC)) {
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES128, TESTKC_SOC));
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES256, TESTKC_SOC));
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC128, TESTKC_SOC));
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC160, TESTKC_SOC));
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_HMAC256, TESTKC_SOC));

        if (TestCreds::supports(CAPABILITY_EXPORT_RSA) && TestCreds::supports(CAPABILITY_RSA_1024)) {
            RUN_TEST(suite, testExportProvisionedKey(TESTKEY_RSA1024_SGN_PRIV, TESTKC_SOC));
        }
        if (TestCreds::supports(CAPABILITY_EXPORT_RSA)) {
            RUN_TEST(suite, testExportProvisionedKey(TESTKEY_RSA2048_SGN_PRIV, TESTKC_SOC));
        }
        RUN_TEST(suite, testExportProvisionedKey(TESTKEY_EC_PRIV, TESTKC_SOC));
    }

    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES128, TESTKC_GENERATED));
    RUN_TEST(suite, testExportProvisionedKey(TESTKEY_AES256, TESTKC_GENERATED));
}

void runKeyTests(SuiteCtx *suite) {
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_FILE));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_FILE_SOFT_WRAPPED));

    RUN_TEST(suite, testKeyProvisionDouble(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));

    JTYPE_TESTS(suite, TESTKEY_AES128, TESTKEY_AES128, TESTKEY_HMAC160, 1);
    JTYPE_TESTS(suite, TESTKEY_AES128, TESTKEY_AES128, TESTKEY_HMAC160, 2);
    JTYPE_TESTS(suite, TESTKEY_AES256, TESTKEY_AES128, TESTKEY_HMAC160, 2);

    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));

    RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE));
    RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_FALSE));
    RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_HMAC_160, SEC_STORAGELOC_RAM, SEC_FALSE));
    RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_FALSE));
    RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_ECC_NISTP256, SEC_STORAGELOC_RAM, SEC_FALSE));

    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_GENERATED, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA256, SEC_TRUE));
    if (TestCreds::supports(CAPABILITY_HKDF_CMAC)) {
        RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_CMAC_AES_128, SEC_TRUE));
    }
    RUN_TEST(suite, testKeyDeriveConcatKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_DIGESTALGORITHM_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveConcatKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_DIGESTALGORITHM_SHA256, SEC_TRUE));

    RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256, SEC_TRUE));
    if (TestCreds::supports(CAPABILITY_HKDF_CMAC)) {
        RUN_TEST(suite, testKeyDeriveHKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_CMAC_AES_128, SEC_TRUE));
    }
    RUN_TEST(suite, testKeyDeriveConcatKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveConcatKDF(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256, SEC_TRUE));

    RUN_TEST(suite, testKeyDeriveVendorAes128(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveVendorAes128(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256, SEC_TRUE));
    RUN_TEST(suite, testKeyDeriveKeyLadderAes128(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_KEYLADDERROOT_UNIQUE, SEC_TRUE));

    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 1, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 2, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 3, 512));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 4, 512));

    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_GENERATED, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 1, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_GENERATED, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 2, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_GENERATED, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 3, 512));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_GENERATED, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_TRUE, 4, 512));

    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_TRUE, 1, 256));
        RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_TRUE, 2, 512));
        RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_TRUE, 3, 512));
    }

    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_FALSE, 1, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_FALSE, 2, 256));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_FALSE, 3, 512));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_FALSE, 4, 512));

    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_FALSE, 1, 512));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_FALSE, 2, 512));
    RUN_TEST(suite, testKeyDeriveCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKC_SOC, SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_FALSE, 3, 512));

    RUN_TEST(suite, testKeyDeriveBaseKey(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1));
    }
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1));
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_160, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1));
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1));

    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256));
    }
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256));
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_160, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256));
    RUN_TEST(suite, testKeyDeriveHKDFBaseKey(SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256));

    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1));
    }
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1));
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_160, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1));
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1));

    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256));
    }
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256));
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_160, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256));
    RUN_TEST(suite, testKeyDeriveConcatKDFBaseKey(SEC_KEYTYPE_HMAC_256, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256));

    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM, SEC_TRUE));

        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyGenerate(SEC_OBJECTID_USER_BASE, SEC_KEYTYPE_AES_256, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_TRUE));
    }

    if (TestCreds::supports(CAPABILITY_RSA_1024)) {
        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
        RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA1024_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));
    }

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_RSA2048_SGN_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PUB, TESTKC_RAW, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_SOC, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyProvision(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_GENERATED, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyGetKeyInfo(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_GENERATED, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyExtractPublicKey(SEC_OBJECTID_USER_BASE, TESTKEY_EC_PRIV, TESTKC_GENERATED, SEC_STORAGELOC_RAM));

    RUN_TEST(suite, testKeyComputeBaseKeyDigest(SEC_OBJECTID_USER_BASE, SEC_DIGESTALGORITHM_SHA1));
    RUN_TEST(suite, testKeyComputeBaseKeyDigest(SEC_OBJECTID_USER_BASE, SEC_DIGESTALGORITHM_SHA256));

    RUN_TEST(suite, testKeyECDHKeyAgreementWithKDF(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKEY_EC_PRIV, TESTKC_SOC, TESTKEY_EC_PUB, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyECDHKeyAgreementWithKDF(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKEY_EC_PRIV, TESTKC_SOC, TESTKEY_EC_PUB, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256, SEC_TRUE));

    RUN_TEST(suite, testKeyECDHKeyAgreementWithKDF(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKEY_EC_PRIV, TESTKC_GENERATED, TESTKEY_EC_PUB, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA1, SEC_TRUE));
    RUN_TEST(suite, testKeyECDHKeyAgreementWithKDF(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, TESTKEY_EC_PRIV, TESTKC_GENERATED, TESTKEY_EC_PUB, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM, SEC_DIGESTALGORITHM_SHA256, SEC_TRUE));

    runProvisionedKeyExportTest(suite);
}

void runKeyCtrlTests(SuiteCtx *suite)
{
    RUN_TEST(suite, testKeyCtrlExportUnCachable(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlKeyOnlyUsage(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlKeyExpired(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlKeyNotYetAvail(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlExpectedJTypeProperties(1, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExpectedJTypeProperties(2, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExpectedJTypeProperties(2, "aesEcbNone", TESTKEY_AES256));
    RUN_TEST(suite, testKeyCtrlExpectedExportedProperties(1, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExpectedExportedProperties(2, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExpectedExportedProperties(2, "aesEcbNone", TESTKEY_AES256));
    RUN_TEST(suite, testKeyCtrlUnwrapWithKeyUsage(1, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlUnwrapWithKeyUsage(2, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlUnwrapWithKeyUsage(2, "aesEcbNone", TESTKEY_AES256));
    RUN_TEST(suite, testKeyCtrlUnwrapWithDataUsage(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlBadB64Jtype(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlExportDerived());
    RUN_TEST(suite, testKeyCtrlExportProvisionExport(1, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExportProvisionExport(2, "aesEcbNone", TESTKEY_AES128));
    RUN_TEST(suite, testKeyCtrlExportProvisionExport(2, "aesEcbNone", TESTKEY_AES256));
    RUN_TEST(suite, testKeyCtrlKeyExportGetSize(1, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlKeyExportGetSize(2, "aesEcbNone"));
    RUN_TEST(suite, testKeyCtrlExportAes(TESTKEY_AES128, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyCtrlExportAes(TESTKEY_AES256, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyCtrlExportAes(TESTKEY_AES128, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyCtrlExportAes(TESTKEY_AES256, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyCtrlKeyExportHmac(TESTKEY_HMAC128, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyCtrlKeyExportHmac(TESTKEY_HMAC160, SEC_STORAGELOC_RAM_SOFT_WRAPPED));
    RUN_TEST(suite, testKeyCtrlKeyExportHmac(TESTKEY_HMAC128, SEC_STORAGELOC_RAM));
    RUN_TEST(suite, testKeyCtrlKeyExportHmac(TESTKEY_HMAC160, SEC_STORAGELOC_RAM));
    if (TestCreds::supports(CAPABILITY_SVP)) {
        RUN_TEST(suite, testKeyCtrlCipherFailsSvpNonOpaque(1, "aesEcbNone"));
        RUN_TEST(suite, testKeyCtrlCipherSvpOpaque(1, "aesEcbNone", TESTKEY_AES128));
        RUN_TEST(suite, testKeyCtrlCipherSvpOpaque(2, "aesEcbNone", TESTKEY_AES128));
        RUN_TEST(suite, testKeyCtrlCipherSvpOpaque(2, "aesEcbNone", TESTKEY_AES256));
        RUN_TEST(suite, testKeyCtrlCipherSvpDataShiftOpaque(1, "aesEcbNone"));
        RUN_TEST(suite, testKeyCtrlSvpCheckOpaque(1, "aesEcbNone", TESTKEY_AES128));
        RUN_TEST(suite, testKeyCtrlSvpCheckOpaque(2, "aesEcbNone", TESTKEY_AES128));
        RUN_TEST(suite, testKeyCtrlSvpCheckOpaque(2, "aesEcbNone", TESTKEY_AES256));
        RUN_TEST(suite, testKeyCtrlProcessCtrDataShiftFailsSvpNonOpaque(1, "aesEcbNone"));
    }
    RUN_TEST(suite, testKeyCtrlExportEcc(TESTKC_SOC));
    RUN_TEST(suite, testKeyCtrlKeyExportSmallBuffer());
}

#define DIGEST_TESTS(suite, alg) do { \
    RUN_TEST(suite, testDigestSingle(alg, 0)); \
    RUN_TEST(suite, testDigestSingle(alg, 256)); \
    RUN_TEST(suite, testDigestSingle(alg, 259)); \
 \
    SEC_SIZE inputSizes[] = { 16, 16, 8, 0, 3, 16 }; \
    RUN_TEST(suite, testDigestMult(alg, std::vector<SEC_SIZE>(inputSizes, inputSizes+sizeof(inputSizes)/sizeof(SEC_SIZE)))); \
 \
    RUN_TEST(suite, testDigestOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, SEC_STORAGELOC_RAM)); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        RUN_TEST(suite, testDigestOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, SEC_STORAGELOC_RAM)); \
    } \
    RUN_TEST(suite, testDigestOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, SEC_STORAGELOC_RAM)); \
    RUN_TEST(suite, testDigestOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, SEC_STORAGELOC_RAM)); \
    RUN_TEST(suite, testDigestOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, SEC_STORAGELOC_RAM)); \
} while (0)

#define MAC_TESTS(suite, key, kc, loc, alg) do { \
    RUN_TEST(suite, testMacSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, alg, 256)); \
    RUN_TEST(suite, testMacSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, alg, 259)); \
 \
    SEC_SIZE inputSizes[] = { 16, 16, 8, 0, 3, 16 }; \
    RUN_TEST(suite, testMacMult(SEC_OBJECTID_USER_BASE, key, kc, loc, alg, std::vector<SEC_SIZE>(inputSizes, inputSizes+sizeof(inputSizes)/sizeof(SEC_SIZE)))); \
 \
    if (alg != SEC_MACALGORITHM_CMAC_AES_128) { \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES128, loc)); \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES256, loc)); \
        } \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC128, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC160, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC256, loc)); \
 \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES128, loc)); \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES256, loc)); \
        } \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC128, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC160, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC160, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC256, loc)); \
 \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES128, loc)); \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES256, loc)); \
        } \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC128, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC160, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_HMAC256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC256, loc)); \
    } else { \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES128, loc)); \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES256, loc)); \
        } \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC128, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC160, loc)); \
        RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC256, loc)); \
 \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES128, loc)); \
            if (TestCreds::supports(CAPABILITY_AES256)) { \
                RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_AES256, loc)); \
            } \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC128, loc)); \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC160, loc)); \
            RUN_TEST(suite, testMacOverKey(alg, SEC_OBJECTID_USER_BASE, TESTKEY_AES256, TESTKC_RAW, SEC_OBJECTID_USER_BASE + 1, TESTKEY_HMAC256, loc)); \
        } \
    } \
} while (0);

#define AESCTR_SPECIFIC_TESTS(suite, key, kc, loc, mode, inplace) do { \
    if (kc != TESTKC_GENERATED) { \
    RUN_TEST(suite, testProcessCtrWithDataShift(SEC_OBJECTID_USER_BASE, key, kc, loc, mode, inplace)); \
    RUN_TEST(suite, testCtrRollover(SEC_OBJECTID_USER_BASE, key, kc, loc, mode, 256, inplace)); \
    } \
} while (0)

#define AESCTR_INPLACE_TESTS(suite, key, kc, loc, mode) do { \
    AESCTR_SPECIFIC_TESTS(suite, key, kc, loc, mode, SEC_TRUE); \
    AESCTR_SPECIFIC_TESTS(suite, key, kc, loc, mode, SEC_FALSE); \
} while (0)

#define AESCTR_MODE_TESTS(suite, key, kc, loc) do { \
    AESCTR_INPLACE_TESTS(suite, key, kc, loc, SEC_CIPHERMODE_ENCRYPT); \
    AESCTR_INPLACE_TESTS(suite, key, kc, loc, SEC_CIPHERMODE_DECRYPT); \
} while (0)

#define AESCTR_LOC_TESTS(suite, key, kc) do { \
    AESCTR_MODE_TESTS(suite, key, kc, SEC_STORAGELOC_RAM); \
    if (kc == TESTKC_RAW) { \
        AESCTR_MODE_TESTS(suite, key, kc, SEC_STORAGELOC_RAM_SOFT_WRAPPED); \
    } \
} while (0)

#define AESCTR_KC_TESTS(suite, key) do { \
    AESCTR_LOC_TESTS(suite, key, TESTKC_RAW); \
    if (TestCreds::supports(CAPABILITY_LOAD_SYM_SOC_KC)) { \
        AESCTR_LOC_TESTS(suite, key, TESTKC_SOC); \
    } \
    AESCTR_LOC_TESTS(suite, key, TESTKC_GENERATED); \
} while (0)

#define AESCTR_TESTS(suite) do { \
    AESCTR_KC_TESTS(suite, TESTKEY_AES128); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        AESCTR_KC_TESTS(suite, TESTKEY_AES256); \
    } \
} while (0)

#define AES_TESTS(suite, key, kc, loc) do { \
    SEC_SIZE inputSizesBlock[] = { 0, 16, 32, 64, 128 }; \
    SEC_SIZE inputSizes[] = { 0, 16, 32, 64, 128, 5 }; \
    std::vector<SEC_SIZE> blocked(inputSizesBlock, inputSizesBlock + sizeof(inputSizesBlock)/sizeof(SEC_SIZE)); \
    std::vector<SEC_SIZE> unaligned(inputSizes, inputSizes + sizeof(inputSizes)/sizeof(SEC_SIZE)); \
 \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, blocked, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, blocked, SEC_TRUE)); \
    RUN_TEST(suite, testCipherUpdateIV(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2, SEC_FALSE)); \
    RUN_TEST(suite, testCipherUpdateIV(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2, SEC_FALSE)); \
 \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2+8)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2+8)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, unaligned, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, unaligned, SEC_TRUE)); \
 \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, blocked, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, blocked, SEC_TRUE)); \
 \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2+8)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2+8)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_ENCRYPT, unaligned, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_ECB_PKCS7_PADDING, SEC_CIPHERMODE_DECRYPT, unaligned, SEC_TRUE)); \
 \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE+1)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE+1, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE+1)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE+1, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, blocked)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, unaligned)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, blocked, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, unaligned, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, blocked, SEC_TRUE)); \
    RUN_TEST(suite, testCipherMult(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, unaligned, SEC_TRUE)); \
    RUN_TEST(suite, testCipherUpdateIV(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE*2, SEC_FALSE)); \
    RUN_TEST(suite, testCipherUpdateIV(SEC_OBJECTID_USER_BASE, key, kc, loc, SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE*2, SEC_FALSE)); \
} while(0)

#define RSA_ENCRYPT_TESTS(suite, pub, priv, kc) do { \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING, SEC_CIPHERMODE_ENCRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
} while(0)

#define RSA_DECRYPT_TESTS(suite, pub, priv, kc) do { \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE)); \
    RUN_TEST(suite, testCipherSingle(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_AES_BLOCK_SIZE, SEC_TRUE)); \
} while(0)

void runRandomTests(SuiteCtx *suite) {
    RUN_TEST(suite, testRandom(SEC_RANDOMALGORITHM_TRUE, 17));
    RUN_TEST(suite, testRandom(SEC_RANDOMALGORITHM_PRNG, 17));
}

void runSVPTests(SuiteCtx* suite) {
    if (TestCreds::supports(CAPABILITY_SVP)) {
        RUN_TEST(suite, testOpaqueMalloc());
        RUN_TEST(suite, testCopyOpaque());
        RUN_TEST(suite, testSecureBootEnabled());
        RUN_TEST(suite, testSetTime());
        RUN_TEST(suite, testKeycheckOpaque(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testProcessOpaque(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM));
        RUN_TEST(suite, testProcessDataShiftOpaque(SEC_OBJECTID_USER_BASE, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM));
    }
}

#define RSAAESRSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, ck_sym_alg, wkfv) do { \
    TestKey key = sym_type == SEC_KEYTYPE_AES_128 ? TESTKEY_AES128 : TESTKEY_AES256; \
    RUN_TEST(suite, testWrappedCipherSingleRsaAesRsaAesAes(key, TESTKC_SOC, rsa_type, rsa_alg, sym_type, sym_alg, ck_sym_alg, wkfv)); \
} while (0)

#define RSAAESRSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, ck_sym_alg) do { \
    RSAAESRSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, ck_sym_alg, WKFV_V2); \
    if (TestCreds::supports(CAPABILITY_WRAPPED_KEY_FORMAT_V3)) { \
        RSAAESRSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, ck_sym_alg, WKFV_V3); \
    } \
} while (0)

#define RSAAESRSAAESAES_CKSYMALG_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg) do { \
    if (TestCreds::supports(CAPABILITY_RSA_AESCBC_AES)) { \
        RSAAESRSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING); \
        RSAAESRSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING); \
    } \
    RSAAESRSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING); \
    if (TestCreds::supports(CAPABILITY_RSA_AESCTR_AES)) { \
        RSAAESRSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, SEC_CIPHERALGORITHM_AES_CTR); \
    } \
} while (0)

#define RSAAESRSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, sym_type) do { \
    RSAAESRSAAESAES_CKSYMALG_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING); \
    if (TestCreds::supports(CAPABILITY_RSA_AESCTR_RSA)) { \
        RSAAESRSAAESAES_CKSYMALG_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_CTR); \
    } \
} while (0)

#define RSAAESRSAAESAES_SYMTYPE_TESTS(suite, rsa_type, rsa_alg) do { \
    RSAAESRSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, SEC_KEYTYPE_AES_128); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        RSAAESRSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, SEC_KEYTYPE_AES_256); \
    } \
} while (0)

#define RSAAESRSAAESAES_ASYMALG_TESTS(suite, rsa_type) do { \
    RSAAESRSAAESAES_SYMTYPE_TESTS(suite, rsa_type, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING); \
    RSAAESRSAAESAES_SYMTYPE_TESTS(suite, rsa_type, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING); \
} while (0)

#define RSAAESRSAAESAES_ASYMTYPE_TESTS(suite) do { \
    if (TestCreds::supports(CAPABILITY_RSA_1024)) { \
        RSAAESRSAAESAES_ASYMALG_TESTS(suite, SEC_KEYTYPE_RSA_1024); \
    } \
    RSAAESRSAAESAES_ASYMALG_TESTS(suite, SEC_KEYTYPE_RSA_2048); \
} while (0)

#define RSAAES_SPECIFIC_TESTS(suite, con_key, rsa_type, rsa_alg, wkfv) do { \
    RUN_TEST(suite, testWrappedCipherSingleRsaAes(con_key, TESTKC_SOC, rsa_type, rsa_alg, wkfv)); \
} while (0)

#define RSAAES_WKFV_TESTS(suite, con_key, rsa_type, rsa_alg) do { \
    RSAAES_SPECIFIC_TESTS(suite, con_key, rsa_type, rsa_alg, WKFV_V2); \
    if (TestCreds::supports(CAPABILITY_WRAPPED_KEY_FORMAT_V3)) { \
        RSAAES_SPECIFIC_TESTS(suite, con_key, rsa_type, rsa_alg, WKFV_V3); \
    } \
} while (0)

#define RSAAES_ASYMALG_TESTS(suite, con_key, rsa_type) do { \
    RSAAES_WKFV_TESTS(suite, con_key, rsa_type, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING); \
    RSAAES_WKFV_TESTS(suite, con_key, rsa_type, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING); \
} while (0)

#define RSAAES_ASYTYPE_TESTS(suite, con_key) do { \
    if (TestCreds::supports(CAPABILITY_RSA_1024)) { \
        RSAAES_ASYMALG_TESTS(suite, con_key, SEC_KEYTYPE_RSA_1024); \
    } \
    RSAAES_ASYMALG_TESTS(suite, con_key, SEC_KEYTYPE_RSA_2048); \
} while (0)

#define RSAAES_TESTS(suite) do { \
    if (TestCreds::supports(CAPABILITY_RSA_AES_M2M)) { \
        RSAAES_ASYTYPE_TESTS(suite, TESTKEY_AES128); \
        if (TestCreds::supports(CAPABILITY_AES256)) { \
            RSAAES_ASYTYPE_TESTS(suite, TESTKEY_AES256); \
        } \
    } \
} while (0)

#define RSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, wkfv) do { \
    TestKey key = sym_type == SEC_KEYTYPE_AES_128 ? TESTKEY_AES128 : TESTKEY_AES256; \
    RUN_TEST(suite, testWrappedCipherSingleRsaAesAes(key, TESTKC_SOC, rsa_type, rsa_alg, sym_type, sym_alg, wkfv)); \
    RUN_TEST(suite, testExportWrappedRsaAesAes(key, TESTKC_SOC, rsa_type, rsa_alg, sym_type, sym_alg, wkfv)); \
} while (0)

#define RSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg) do { \
    RSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, WKFV_V2); \
    if (TestCreds::supports(CAPABILITY_WRAPPED_KEY_FORMAT_V3)) { \
        RSAAESAES_SPECIFIC_TESTS(suite, rsa_type, rsa_alg, sym_type, sym_alg, WKFV_V3); \
    } \
} while (0)

#define RSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, sym_type) do { \
    RSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING); \
    if (TestCreds::supports(CAPABILITY_RSA_AESCBC_AES)) { \
        RSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_CBC_NO_PADDING); \
        RSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING); \
    } \
    if (TestCreds::supports(CAPABILITY_RSA_AESCTR_AES)) { \
        RSAAESAES_WKFV_TESTS(suite, rsa_type, rsa_alg, sym_type, SEC_CIPHERALGORITHM_AES_CTR); \
    } \
} while (0)

#define RSAAESAES_SYMTYPE_TESTS(suite, rsa_type, rsa_alg) do { \
    RSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, SEC_KEYTYPE_AES_128); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        RSAAESAES_SYMALG_TESTS(suite, rsa_type, rsa_alg, SEC_KEYTYPE_AES_256); \
    } \
} while (0)

#define RSAAESAES_ASYMALG_TESTS(suite, rsa_type) do { \
    RSAAESAES_SYMTYPE_TESTS(suite, rsa_type, SEC_CIPHERALGORITHM_RSA_OAEP_PADDING); \
    RSAAESAES_SYMTYPE_TESTS(suite, rsa_type, SEC_CIPHERALGORITHM_RSA_PKCS1_PADDING); \
} while (0)

#define RSAAESAES_TESTS(suite) do { \
    if (TestCreds::supports(CAPABILITY_RSA_1024)) { \
        RSAAESAES_ASYMALG_TESTS(suite, SEC_KEYTYPE_RSA_1024); \
    } \
    RSAAESAES_ASYMALG_TESTS(suite, SEC_KEYTYPE_RSA_2048); \
} while (0)

#define ECAESAES_SPECIFIC_TESTS(suite, con_key, asym_alg, sym_alg, wkfv) do { \
    RUN_TEST(suite, testWrappedCipherSingleEcAesAes(con_key, TESTKC_SOC, SEC_KEYTYPE_AES_128, asym_alg, sym_alg, wkfv)); \
    RUN_TEST(suite, testExportWrappedEccAesAes(con_key, TESTKC_SOC, asym_alg, SEC_KEYTYPE_AES_128, sym_alg, wkfv)); \
    RUN_TEST(suite, testExportWrappedGeneratedEccAesAes(con_key, asym_alg, SEC_KEYTYPE_AES_128, sym_alg, wkfv)); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        RUN_TEST(suite, testWrappedCipherSingleEcAesAes(con_key, TESTKC_SOC, SEC_KEYTYPE_AES_256, asym_alg, sym_alg, wkfv)); \
        RUN_TEST(suite, testExportWrappedEccAesAes(con_key, TESTKC_SOC, asym_alg, SEC_KEYTYPE_AES_256, sym_alg, wkfv)); \
        RUN_TEST(suite, testExportWrappedGeneratedEccAesAes(con_key, asym_alg, SEC_KEYTYPE_AES_256, sym_alg, wkfv)); \
    } \
} while (0)

#define ECAES_SPECIFIC_TESTS(suite, con_key, asym_alg, wkfv) do { \
    RUN_TEST(suite, testWrappedCipherSingleEcAes(con_key, TESTKC_SOC, asym_alg, wkfv)); \
    RUN_TEST(suite, testExportWrappedEccAes(con_key, TESTKC_SOC, asym_alg, wkfv)); \
    RUN_TEST(suite, testExportWrappedGeneratedEccAes(con_key, asym_alg, wkfv)); \
} while (0)

#define ECAES_WKFV_TESTS(suite, con_key, asym_alg) do { \
    ECAES_SPECIFIC_TESTS(suite, con_key, asym_alg, WKFV_V2); \
    ECAESAES_SPECIFIC_TESTS(suite, con_key, asym_alg, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, WKFV_V2); \
    ECAESAES_SPECIFIC_TESTS(suite, con_key, asym_alg, SEC_CIPHERALGORITHM_AES_CTR, WKFV_V2); \
    if (TestCreds::supports(CAPABILITY_WRAPPED_KEY_FORMAT_V3)) { \
        ECAES_SPECIFIC_TESTS(suite, con_key, asym_alg, WKFV_V3); \
        ECAESAES_SPECIFIC_TESTS(suite, con_key, asym_alg, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, WKFV_V3); \
        ECAESAES_SPECIFIC_TESTS(suite, con_key, asym_alg, SEC_CIPHERALGORITHM_AES_CTR, WKFV_V3); \
    } \
} while (0)

#define ECAES_ASYMALG_TESTS(suite, con_key) do { \
    ECAES_WKFV_TESTS(suite, con_key, SEC_CIPHERALGORITHM_ECC_ELGAMAL); \
} while (0)

#define ECAES_TESTS(suite) do { \
    ECAES_ASYMALG_TESTS(suite, TESTKEY_AES128); \
    if (TestCreds::supports(CAPABILITY_AES256)) { \
        ECAES_ASYMALG_TESTS(suite, TESTKEY_AES256); \
    } \
} while (0)

void runWrappedTests(SuiteCtx *suite) {
    RSAAESRSAAESAES_ASYMTYPE_TESTS(suite);
    RSAAESAES_TESTS(suite);
    RSAAES_TESTS(suite);
    ECAES_TESTS(suite);

    RUN_TEST(suite, testWrappedKDFCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, SEC_OBJECTID_USER_BASE+2, SEC_KEYTYPE_AES_128, 1, 256));
    RUN_TEST(suite, testWrappedKDFCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, SEC_OBJECTID_USER_BASE+2, SEC_KEYTYPE_HMAC_128, 1, 256));
    RUN_TEST(suite, testExportedKDFCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, SEC_OBJECTID_USER_BASE+2, SEC_KEYTYPE_AES_128, 1, 256));
    RUN_TEST(suite, testExportedKDFCMACAES128(SEC_OBJECTID_USER_BASE, SEC_OBJECTID_USER_BASE+1, SEC_OBJECTID_USER_BASE+2, SEC_KEYTYPE_HMAC_128, 1, 256));
}

void runConcurrentTests(SuiteCtx *suite) {
    RUN_TEST(suite, testConcurrentVendor128(40));

    if (TestCreds::supports(CAPABILITY_RSA_1024)) { \
        RUN_TEST(suite, testConcurrentRsa(TESTKEY_RSA1024_ENC_PUB, TESTKEY_RSA1024_ENC_PRIV, TESTKC_SOC, 10)); \
    } \
    RUN_TEST(suite, testConcurrentRsa(TESTKEY_RSA2048_ENC_PUB, TESTKEY_RSA2048_ENC_PRIV, TESTKC_SOC, 10));
}

void runExchangeTests(SuiteCtx *suite) {
    RUN_TEST(suite, testKeyExchangeDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_AES_128));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyExchangeDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_AES_256));
    }
    RUN_TEST(suite, testKeyExchangeDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_HMAC_128));
    RUN_TEST(suite, testKeyExchangeDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_HMAC_160));

    RUN_TEST(suite, testKeyExchangeECDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_AES_128));
    if (TestCreds::supports(CAPABILITY_AES256)) {
        RUN_TEST(suite, testKeyExchangeECDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_AES_256));
    }
    RUN_TEST(suite, testKeyExchangeECDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_HMAC_128));
    RUN_TEST(suite, testKeyExchangeECDH(SEC_OBJECTID_USER_BASE, SEC_STORAGELOC_RAM, SEC_KEYTYPE_HMAC_160));
}

#define RSA_SIGNATURE_TESTS(suite, pub, priv, kc, keySize) do { \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST, SEC_SIGNATUREMODE_SIGN, 20)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS_DIGEST, SEC_SIGNATUREMODE_VERIFY, 20)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS, SEC_SIGNATUREMODE_SIGN, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PKCS, SEC_SIGNATUREMODE_VERIFY, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST, SEC_SIGNATUREMODE_SIGN, 32)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS_DIGEST, SEC_SIGNATUREMODE_VERIFY, 32)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS, SEC_SIGNATUREMODE_SIGN, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PKCS, SEC_SIGNATUREMODE_VERIFY, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST, SEC_SIGNATUREMODE_SIGN, 20)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS_DIGEST, SEC_SIGNATUREMODE_VERIFY, 20)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS, SEC_SIGNATUREMODE_SIGN, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA1_PSS, SEC_SIGNATUREMODE_VERIFY, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST, SEC_SIGNATUREMODE_SIGN, 32)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS_DIGEST, SEC_SIGNATUREMODE_VERIFY, 32)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS, SEC_SIGNATUREMODE_SIGN, 2049)); \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_RSA_SHA256_PSS, SEC_SIGNATUREMODE_VERIFY, 2049)); \
} while(0)

#define EC_SIGNATURE_TESTS(suite, pub, priv, kc, keySize) do { \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST, SEC_SIGNATUREMODE_SIGN, 32)); \
    if (kc != TESTKC_GENERATED) { \
        RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
                SEC_SIGNATUREALGORITHM_ECDSA_NISTP256_DIGEST, SEC_SIGNATUREMODE_VERIFY, 32)); \
    } \
 \
    RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, kc, SEC_STORAGELOC_RAM, \
            SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, SEC_SIGNATUREMODE_SIGN, 2049)); \
    if (kc != TESTKC_GENERATED) { \
        RUN_TEST(suite, testSignature(SEC_OBJECTID_USER_BASE, pub, priv, TESTKC_RAW, SEC_STORAGELOC_RAM, \
                SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, SEC_SIGNATUREMODE_VERIFY, 2049)); \
    } \
} while (0)

int testIt(int argc, char *argv[]) {
    int nParams = argc-1;
    std::vector<int> runParams;
    SEC_PRINT("Number of runParams: %d\n", nParams);
    for (int i=1; i<(nParams+1); ++i) {
        runParams.push_back(atoi(argv[i]));
    }

    SEC_PRINT("==============================================\n");

    //print SecApi info
    {
        TestCtx ctx;
        if (ctx.init() != SEC_RESULT_SUCCESS) {
            SEC_LOG_ERROR("TestCtx.init failed");
            return 1;
        }

        if (SEC_RESULT_SUCCESS != SecProcessor_PrintInfo(ctx.proc())) {
            SEC_LOG_ERROR("SecProcessor_PrintInfo failed");
            return 1;
        }
    }

    TestCreds::init();
    SuiteCtx suite;
    suite.setRunParams(runParams);

    SEC_PRINT("\n");
    SEC_PRINT("CAPABILITY_AES256: %d\n", TestCreds::supports(CAPABILITY_AES256));
    SEC_PRINT("CAPABILITY_HMAC_IN_HW: %d\n", TestCreds::supports(CAPABILITY_HMAC_IN_HW));
    SEC_PRINT("CAPABILITY_CMAC_IN_HW: %d\n", TestCreds::supports(CAPABILITY_CMAC_IN_HW));
    SEC_PRINT("CAPABILITY_DIGEST_OVER_HWKEY: %d\n", TestCreds::supports(CAPABILITY_DIGEST_OVER_HWKEY));
    SEC_PRINT("CAPABILITY_HMAC_OVER_HWKEY: %d\n", TestCreds::supports(CAPABILITY_HMAC_OVER_HWKEY));
    SEC_PRINT("CAPABILITY_CMAC_OVER_HWKEY: %d\n", TestCreds::supports(CAPABILITY_CMAC_OVER_HWKEY));
    SEC_PRINT("CAPABILITY_HKDF_CMAC: %d\n", TestCreds::supports(CAPABILITY_HKDF_CMAC));
    SEC_PRINT("CAPABILITY_EXTRACT_RSA_PUB: %d\n", TestCreds::supports(CAPABILITY_EXTRACT_RSA_PUB));
    SEC_PRINT("CAPABILITY_WRAPPED_KEY_FORMAT_V3: %d\n", TestCreds::supports(CAPABILITY_WRAPPED_KEY_FORMAT_V3));
    SEC_PRINT("CAPABILITY_RSA_AES_M2M: %d\n", TestCreds::supports(CAPABILITY_RSA_AES_M2M));
    SEC_PRINT("CAPABILITY_CLEAR_JTYPE_WRAPPING: %d\n", TestCreds::supports(CAPABILITY_CLEAR_JTYPE_WRAPPING));
    SEC_PRINT("CAPABILITY_SVP: %d\n", TestCreds::supports(CAPABILITY_SVP));
    SEC_PRINT("CAPABILITY_LOAD_SYM_SOC_KC: %d\n", TestCreds::supports(CAPABILITY_LOAD_SYM_SOC_KC));
    SEC_PRINT("CAPABILITY_EXPORT_RSA: %d\n", TestCreds::supports(CAPABILITY_EXPORT_RSA));
    SEC_PRINT("CAPABILITY_RSA_1024: %d\n", TestCreds::supports(CAPABILITY_RSA_1024));
    SEC_PRINT("CAPABILITY_RSA_AESCBC_AES: %d\n", TestCreds::supports(CAPABILITY_RSA_AESCBC_AES));
    SEC_PRINT("CAPABILITY_RSA_AESCTR_AES: %d\n", TestCreds::supports(CAPABILITY_RSA_AESCTR_AES));
    SEC_PRINT("CAPABILITY_RSA_AESCTR_RSA: %d\n", TestCreds::supports(CAPABILITY_RSA_AESCTR_RSA));
    SEC_PRINT("\n");

    runProcessorTests(&suite);

    runRandomTests(&suite);

    runBundleTests(&suite);

    runCertTests(&suite);

    runKeyTests(&suite);

    DIGEST_TESTS(&suite, SEC_DIGESTALGORITHM_SHA1);
    DIGEST_TESTS(&suite, SEC_DIGESTALGORITHM_SHA256);

    if (TestCreds::supports(CAPABILITY_HMAC_IN_HW)) {
        MAC_TESTS(&suite, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256);
        MAC_TESTS(&suite, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256);
        MAC_TESTS(&suite, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_HMAC_SHA256);
    } else {
        MAC_TESTS(&suite, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA1);
        MAC_TESTS(&suite, TESTKEY_HMAC128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA256);
        MAC_TESTS(&suite, TESTKEY_HMAC160, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA256);
        MAC_TESTS(&suite, TESTKEY_HMAC256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_HMAC_SHA256);
    }

    if (TestCreds::supports(CAPABILITY_CMAC_IN_HW)) {
        MAC_TESTS(&suite, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_CMAC_AES_128);
        if (TestCreds::supports(CAPABILITY_AES256)) {
            MAC_TESTS(&suite, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM, SEC_MACALGORITHM_CMAC_AES_128);
        }
    } else {
        MAC_TESTS(&suite, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_CMAC_AES_128);
        if (TestCreds::supports(CAPABILITY_AES256)) {
            MAC_TESTS(&suite, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED, SEC_MACALGORITHM_CMAC_AES_128);
        }
    }

    //aes
    AES_TESTS(&suite, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM);
    AES_TESTS(&suite, TESTKEY_AES128, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED);

    if (TestCreds::supports(CAPABILITY_AES256)) {
        AES_TESTS(&suite, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM);
        AES_TESTS(&suite, TESTKEY_AES256, TESTKC_RAW, SEC_STORAGELOC_RAM_SOFT_WRAPPED);
    }

    AESCTR_TESTS(&suite);

    //rsa
    if (TestCreds::supports(CAPABILITY_RSA_1024)) {
        RSA_ENCRYPT_TESTS(&suite, TESTKEY_RSA1024_ENC_PUB, TESTKEY_RSA1024_ENC_PRIV, TESTKC_RAW);
        RSA_DECRYPT_TESTS(&suite, TESTKEY_RSA1024_ENC_PUB, TESTKEY_RSA1024_ENC_PRIV, TESTKC_SOC);
    }

    RSA_ENCRYPT_TESTS(&suite, TESTKEY_RSA2048_ENC_PUB, TESTKEY_RSA2048_ENC_PRIV, TESTKC_RAW);
    RSA_DECRYPT_TESTS(&suite, TESTKEY_RSA2048_ENC_PUB, TESTKEY_RSA2048_ENC_PRIV, TESTKC_SOC);

    //sign
    if (TestCreds::supports(CAPABILITY_RSA_1024)) {
        RSA_SIGNATURE_TESTS(&suite, TESTKEY_RSA1024_SGN_PUB, TESTKEY_RSA1024_SGN_PRIV, TESTKC_SOC, 128);
    }
    RSA_SIGNATURE_TESTS(&suite, TESTKEY_RSA2048_SGN_PUB, TESTKEY_RSA2048_SGN_PRIV, TESTKC_SOC, 256);

    EC_SIGNATURE_TESTS(&suite, TESTKEY_EC_PUB, TESTKEY_EC_PRIV, TESTKC_SOC, 128);
    EC_SIGNATURE_TESTS(&suite, TESTKEY_EC_PUB, TESTKEY_EC_PRIV, TESTKC_GENERATED, 128);
    EC_SIGNATURE_TESTS(&suite, TESTKEY_EC_PUB, TESTKEY_EC_PRIV, TESTKC_EXPORTED, 128);

    runWrappedTests(&suite);

    runKeyCtrlTests(&suite);

    runSVPTests(&suite);

    runConcurrentTests(&suite);

    runExchangeTests(&suite);

    //todo: fragmented processing
    //todo: add pem containers, raw formats for keys, certs

    SEC_PRINT("==============================================\n");
    SEC_PRINT("Test summary: %d/%d succeeded, %d skipped\n", suite.getSucceeded().size(), suite.getAttempted().size(), suite.getSkipped().size());

    std::vector<int> failed = suite.getFailed();
    if (failed.size() > 0) {
        SEC_PRINT("\nFailed Tests: [%d]\n", failed.size());
        for (unsigned int i=0; i<failed.size(); ++i) {
            SEC_PRINT("%d ", failed[i]);
            if (i%16 == 15) {
                SEC_PRINT("\n");
            }
        }
        SEC_PRINT("\n-------------------\n");

        for (unsigned int i=0; i<failed.size(); ++i) {
            SEC_PRINT("%d: %s\n", failed[i], suite.getTestEntry(failed[i]).first);
        }
    }

    TestCreds::shutdown();

    return failed.size();
}

int main(int argc, char *argv[]) {
    return testIt(argc, argv);
}
