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

#include "keyctrl.h"
#include "jtype.h"
#include "mac.h"
#include "test_ctx.h"
#include "sec_security_comcastids.h"
#include "sec_security_utils.h"
#include "cipher.h"
#include "sign.h"
#include "jtype.h"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>

// default params for jtype key container
struct default_jtype_data_st
{
    TestKey contentKey;
    TestKey encryptionKey;
    TestKc encKc;
    TestKey macKey;
    TestKc macKc;
    SEC_OBJECTID provisionId;
}g_default_jtype_data = {
           .contentKey = TESTKEY_AES128,
        .encryptionKey = TESTKEY_AES128,
                .encKc = TESTKC_SOC,
               .macKey = TESTKEY_HMAC160,
                .macKc = TESTKC_RAW,
          .provisionId = SEC_OBJECTID_USER_BASE
};

#define RIGHTS_INIT(x) memset(x,0,SEC_KEYOUTPUTRIGHT_NUM)

std::string toB64(SEC_BYTE *data, SEC_SIZE len);

/* Convenience function to provision the jtype key and session keys using the default
 * settings.  Since the jtype is a wrapped key, a check is performed to test if the
 * platform supports wrapped keys in the clear.  if it doesn't, SOC key container
 * needs to be used.
 */
static Sec_KeyHandle* _provisionJTypeAndSession(TestCtx &ctx, std::string &jtypeKey)
{
    Sec_KeyHandle *keyHandle = NULL;

    if (SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY)
        && SecKey_IsProvisioned(ctx.proc(), SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY)) {
        SEC_PRINT("Session ENC and MAC keys are already provisioned.  Not provisioning again.\n");
    } else {
        SEC_PRINT("Provisioning session ENC and MAC.\n");

        //provision encryption key
        if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONENCKEY, SEC_STORAGELOC_RAM,
                g_default_jtype_data.encryptionKey, g_default_jtype_data.encKc)) {
            SEC_LOG_ERROR("provisionKey failed");
            goto done;
        }

        //provision maccing key
        if (NULL == ctx.provisionKey(SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY, SEC_STORAGELOC_RAM,
                g_default_jtype_data.macKey, g_default_jtype_data.macKc)) {
            SEC_LOG_ERROR("provisionKey failed");
            goto done;
        }
    }

    //provision jtype key
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), g_default_jtype_data.provisionId,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
            (SEC_BYTE *)&jtypeKey[0], jtypeKey.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), g_default_jtype_data.provisionId, &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for jtype key");
        goto done;
    }

done:

    return keyHandle;
}

/* SecCipher_GetInstance should fail with notBefore date in the future */
Sec_Result testKeyCtrlKeyNotYetAvail(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};
    const char *notBeforeTimeStr = "2022-12-09T19:53:06Z";


    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /*  key avail in one hour */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_FALSE, 1,
        notBeforeTimeStr,
        "2030-12-09T19:53:06Z",
        g_default_jtype_data.macKey,
        version, alg);
    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_FAILURE
            != SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR(
                "expected SeCcipher_GetInstance to fail for jtype key with notBefore [%s]", notBeforeTimeStr);

        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

/* Generate a jtype key with usage of key only.  SecCipher_GetInstance should fail. */
Sec_Result testKeyCtrlKeyOnlyUsage(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};


    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }


    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey, g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_FALSE, SEC_KEYUSAGE_KEY,
        "2010-12-09T19:53:06Z", "2025-12-09T01:02:03Z",
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS == SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR(
                "expected Seccipher_GetInstance to fail for key with usage flag for 'key' only");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (keyHandle)
        SecKey_Release(keyHandle);

    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    return result;
}

/* Generate a jtype key with usage of data only. */
Sec_Result testKeyCtrlUnwrapWithKeyUsage(int version, const char *alg, TestKey contentKey)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_KeyHandle *keyHandle = NULL;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        contentKey, g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
        SEC_FALSE, SEC_KEYUSAGE_KEY,
        "2010-12-09T19:53:06Z", "2025-12-09T01:02:03Z",
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    /* FIXME: actually encrypt the key bytes first */

    //create wrapped asn1 key
    std::vector<SEC_BYTE> wrapped = TestCtx::random(16);
    std::vector<SEC_BYTE> asn1;
    asn1.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE asn1_len;
    SEC_BYTE input[SEC_AES_BLOCK_SIZE];
    SEC_BYTE output[SEC_AES_BLOCK_SIZE];
    SEC_SIZE output_len;

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_GenerateWrappedKeyAsn1(&wrapped[0], wrapped.size(),
            SEC_KEYTYPE_AES_128,
            g_default_jtype_data.provisionId, NULL, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING,
            &asn1[0], asn1.size(), &asn1_len)) {
        SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1 failed");
        goto done;
    }
    asn1.resize(asn1_len);

    //provision wrapped
    SEC_PRINT("Provisioning wrapped\n");
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE+1,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1,
            (SEC_BYTE *) &asn1[0], asn1.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        goto done;
    }

    SEC_PRINT("Wielding wrapped\n");
    if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_OBJECTID_USER_BASE+1,
        NULL, input, sizeof(input), output,
        sizeof(output), &output_len)) {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlUnwrapWithDataUsage(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_KeyHandle *keyHandle = NULL;
    //create wrapped asn1 key
    std::vector<SEC_BYTE> wrapped = TestCtx::random(16);
    std::vector<SEC_BYTE> asn1;
    asn1.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE asn1_len;
    SEC_BYTE input[SEC_AES_BLOCK_SIZE];
    SEC_BYTE output[SEC_AES_BLOCK_SIZE];
    SEC_SIZE output_len;
    std::string jtype;
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key(SEC_KEYCONTAINER_MAX_LEN,0);
    SEC_SIZE exported_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        goto done;
    }

    jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey, g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_TRUE, SEC_KEYUSAGE_DATA,
        "2010-12-09T19:53:06Z", "2025-12-09T01:02:03Z",
        g_default_jtype_data.macKey,
        version, alg);
    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_GenerateWrappedKeyAsn1(&wrapped[0], wrapped.size(),
            SEC_KEYTYPE_AES_128,
            SEC_OBJECTID_USER_BASE, NULL, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING,
            &asn1[0], asn1.size(), &asn1_len)) {
        SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1 failed");
        goto done;
    }
    asn1.resize(asn1_len);

    //provision wrapped
    SEC_PRINT("Provisioning wrapped\n");
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE+1,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1,
            (SEC_BYTE *) &asn1[0], asn1.size()))
    {
        //this will fail on some platforms, others will fail when wielding cipher
        result = SEC_RESULT_SUCCESS;
        goto done;
    }


    SEC_PRINT("Wielding wrapped\n");
    if (SEC_RESULT_SUCCESS == SecCipher_SingleInputId(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_OBJECTID_USER_BASE+1,
        NULL, input, sizeof(input), output,
        sizeof(output), &output_len))
    {
        SEC_LOG_ERROR("Expected provisioning or wielding cipher to fail");
        goto done;
    }

    /* export the jtype and re-provision as exported to test exported logic as well */
    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_Export failed");
        goto done;
    }
    SecKey_Release(keyHandle);
    keyHandle = NULL;
    SecKey_Delete(ctx.proc(), g_default_jtype_data.provisionId);

    /* provision exported */
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), g_default_jtype_data.provisionId, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            &exported_key[0], exported_len))
    {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        goto done;
    }

    if (SEC_RESULT_SUCCESS == SecCipher_SingleInputId(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, SEC_OBJECTID_USER_BASE+1,
        NULL, input, sizeof(input), output,
        sizeof(output), &output_len))
    {
        SEC_LOG_ERROR("Expected provisioning or wielding cipher to fail");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

/* SecCipher_Getinstance should fail with notOnOrAfter date < now */
Sec_Result testKeyCtrlKeyExpired(int version, const char *alg)
{
    TestCtx ctx;

    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};
    const char *notOnOrAfter = "2015-12-09T19:53:06Z";
    Sec_Result result = SEC_RESULT_FAILURE;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey, g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_FALSE, 1,
        "2010-12-09T19:53:06Z", notOnOrAfter,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            == SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR(
                "expected Seccipher_GetInstance to fail for jtype key with expired notOnOrAfter [%s]",
                notOnOrAfter);
        goto done;
    }

    result = SEC_RESULT_SUCCESS;
done:
    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    if (keyHandle)
        SecKey_Release(keyHandle);


    return result;
}

/* test that export fails with a jtype key where is_cacheable is false */
Sec_Result testKeyCtrlExportUnCachable(int version, const char *alg)
{

    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_KeyHandle *keyHandle = NULL;
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key(SEC_KEYCONTAINER_MAX_LEN,0);
    SEC_SIZE exported_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey, g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_FALSE, 1,
        "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        return SEC_RESULT_FAILURE;
    }

    //get properties from j-type
    Sec_KeyProperties jtype_props;
    if (SEC_RESULT_SUCCESS != SecKey_GetProperties(keyHandle, &jtype_props)) {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        goto done;
    }

    //export j-type key
    if (SEC_RESULT_SUCCESS == SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("expected SecKey_ExportKey to fail with cachable flag set to false");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlExpectedJTypeProperties(int version, const char *alg, TestKey contentKey)
{
    TestCtx ctx;
    Sec_KeyHandle *keyHandle = NULL;
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_FALSE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        contentKey, g_default_jtype_data.encryptionKey, keyId,
        createDefaultRights(TestCreds::getKeyType(contentKey)).c_str(),
        cacheable, keyUsage,
        notBefore, notOnOrAfter,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);

    if (0!=strcmp(keyId,keyProps.keyId))
    {
        SEC_LOG_ERROR("keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notOnOrAfter,keyProps.notOnOrAfter))
    {
        SEC_LOG_ERROR("notOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notBefore,keyProps.notBefore))
    {
        SEC_LOG_ERROR("notBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType)
    {
        SEC_LOG_ERROR("keyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength)
    {
        SEC_LOG_ERROR("keyLength mismatch  expecting %d, received %d", SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable)
    {
        SEC_LOG_ERROR("cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage)
    {
        SEC_LOG_ERROR("usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlBadB64Jtype(int version, const char *alg)
{
    TestCtx ctx;
    TestKey contentKey = TESTKEY_AES128;
    TestKey encryptionKey = TESTKEY_AES128;
    TestKey macKey = TESTKEY_HMAC160;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    std::string jtype = "B" + createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        contentKey, encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        createDefaultRights(SEC_KEYTYPE_AES_128).c_str(),
        SEC_FALSE, 1,
        "2010-12-09T19:53:06Z", "2037-12-09T19:53:06Z",
        macKey,
        version, alg);
    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    //provision jtype key
    if (SEC_RESULT_FAILURE != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_JTYPE,
            (SEC_BYTE *) &jtype[0], jtype.size())) {
        SEC_LOG_ERROR("expected provisionKey to failed with bad base64");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlExportEcc(TestKc kc)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    SEC_OBJECTID priv_id = SEC_OBJECTID_USER_BASE +1;
    Sec_KeyHandle *priv_key_handle = NULL;
    TestKey pub = TESTKEY_EC_PUB;
    TestKey priv = TESTKEY_EC_PRIV;
	std::vector<SEC_BYTE> clear = TestCtx::random(32);
	std::vector<SEC_BYTE> derivation_input = TestCtx::random(16);
	SEC_BYTE exported_buffer[1024];
	std::vector<SEC_BYTE> signature;
    signature.resize(512);
	SEC_SIZE exported_size = 0, signature_size = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (priv_key_handle = ctx.provisionKey(priv_id, SEC_STORAGELOC_RAM, priv, kc)))
    {
        SEC_LOG_ERROR("provision priv key failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
            != SecSignature_SingleInputId(ctx.proc(),
                    SEC_SIGNATUREALGORITHM_ECDSA_NISTP256,
                    SEC_SIGNATUREMODE_SIGN, priv_id, &clear[0], clear.size(),
                    &signature[0], &signature_size))
    {

        SEC_LOG_ERROR("SecSignature_SingleInputId failed on signing with priv ecc key");
        return SEC_RESULT_FAILURE;
    }
    signature.resize(signature_size);

    //verify
    if (!verifyOpenSSL(SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, pub, clear, signature)) {
        SEC_LOG_ERROR("verifyOpenSSL failed");
        return SEC_RESULT_FAILURE;
    }

    /* export priv key */
    if ( SEC_RESULT_SUCCESS != SecKey_ExportKey(priv_key_handle,
            &derivation_input[0], exported_buffer, sizeof(exported_buffer), &exported_size))
    {
        SEC_LOG_ERROR("SecKey_Export failed for private ecc");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Delete(ctx.proc(), priv_id);

    if (SEC_RESULT_SUCCESS
            != SecKey_Provision(ctx.proc(), priv_id, SEC_STORAGELOC_RAM,
                    SEC_KEYCONTAINER_EXPORTED, exported_buffer, exported_size))
    {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    signature.resize(512);
    if (SEC_RESULT_SUCCESS
            != SecSignature_SingleInputId(ctx.proc(),
                    SEC_SIGNATUREALGORITHM_ECDSA_NISTP256,
                    SEC_SIGNATUREMODE_VERIFY, priv_id, &clear[0], clear.size(),
                    &signature[0], &signature_size))
    {

        SEC_LOG_ERROR("SecSignature_SingleInputId failed on verification with priv ecc key");
        return SEC_RESULT_FAILURE;
    }
    signature.resize(signature_size);

    //verify
    if (!verifyOpenSSL(SEC_SIGNATUREALGORITHM_ECDSA_NISTP256, pub, clear, signature)) {
        SEC_LOG_ERROR("verifyOpenSSL failed");
        return SEC_RESULT_FAILURE;
    }

    result = SEC_RESULT_SUCCESS;

    return result;
}

Sec_Result testKeyCtrlExportAes(TestKey aesKey, Sec_StorageLoc location)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_KeyHandle *key_handle = NULL;

    TestCtx ctx;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;
    Sec_CipherAlgorithm alg = SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING;
    Sec_KeyProperties keyProps;
    std::vector<SEC_BYTE> encrypted(16);
    std::vector<SEC_BYTE> decrypted(16);
    SEC_SIZE enc_len = 0;

    memset(&keyProps,0, sizeof(Sec_KeyProperties));

    if (key_handle != NULL) {
        SecKey_Release(key_handle);
    }
    key_handle = NULL;

    // input to export function
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    //gen iv
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);

    //gen clear input
    std::vector<SEC_BYTE> clear = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (ctx.init() != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_PRINT("SEC_KEYCONTAINER_RAW_AES_128\n");
    ProvKey *p = TestCreds::getKey(aesKey, TESTKC_RAW, id);
    SEC_PRINT("provisioning " SEC_OBJECTID_PATTERN "\n", id);

    if (SEC_RESULT_SUCCESS
            != SecKey_Provision(ctx.proc(), id, location,
                    aesKey == TESTKEY_AES128 ? SEC_KEYCONTAINER_RAW_AES_128 : SEC_KEYCONTAINER_RAW_AES_256,
                            &p->key[0],
                    p->key.size()))
    {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    //encrypt
    if (SEC_RESULT_SUCCESS
            != SecCipher_SingleInputId(ctx.proc(), alg,
                    SEC_CIPHERMODE_ENCRYPT, id,
                    NULL, &clear[0], clear.size(), &encrypted[0],
                    encrypted.size(), &enc_len))
    {

        SEC_LOG_ERROR("Encrypt failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecKey_GetInstance(ctx.proc(), id, &key_handle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }
    // get size
    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(key_handle, &derivation_input[0],
                    NULL, 0, &exported_key_len2))
    {
        SEC_LOG_ERROR("SecKey_ExportKey failed for key size");
        goto done;
    }
    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(key_handle, &derivation_input[0],
                    exported_key, sizeof(exported_key), &exported_key_len))
    {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        goto done;
    }
    SecKey_Release(key_handle);
    key_handle = NULL;

    if (exported_key_len2 != exported_key_len)
    {
        SEC_LOG_ERROR("exported key length mismatch, expected %d, received %d",
                exported_key_len2, exported_key_len);
        goto done;
    }

    // NOTE: on intel, exported keys MUST be provisioned with the same object_id as when
    //       they were originally provisioned.
    SEC_PRINT("provisioning exported " SEC_OBJECTID_PATTERN "\n", id);
    if (SEC_RESULT_SUCCESS
            != SecKey_Provision(ctx.proc(), id, SEC_STORAGELOC_RAM,
                    SEC_KEYCONTAINER_EXPORTED, exported_key,
                    exported_key_len))
    {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    // test decrypt with exported key
    if (SEC_RESULT_SUCCESS
            != SecCipher_SingleInputId(ctx.proc(), alg,
                    SEC_CIPHERMODE_DECRYPT, id,
                    NULL, &encrypted[0], encrypted.size(), &decrypted[0],
                    decrypted.size(), &enc_len))
    {

        SEC_LOG_ERROR("Decrypt failed");
        goto done;
    }
    TestCtx::printHex("derivation input", derivation_input);
    TestCtx::printHex("       encrypted", encrypted);
    TestCtx::printHex("       decrypted", decrypted);
    TestCtx::printHex("           clear", clear);
    if (clear != decrypted)
    {
        SEC_LOG_ERROR("decrypted vector mismatch");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (key_handle != NULL)
        SecKey_Release(key_handle);

    return result;
}

Sec_Result testKeyCtrlExportDerived()
{
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;
    Sec_KeyHandle *key_handle = NULL;
    TestCtx ctx;
    SEC_BYTE enc_output[256];
    SEC_SIZE enc_output_len = 0;
    SEC_BYTE enc_output2[256];
    SEC_SIZE enc_output_len2 = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    std::vector<SEC_BYTE> input = TestCtx::random(25);
    TestCtx::printHex("input", input);

    if (SEC_RESULT_SUCCESS != SecKey_Derive_VendorAes128(ctx.proc(),
            id, SEC_STORAGELOC_RAM, &input[0], input.size())) {
        SEC_LOG_ERROR("SecKey_Derive_VendorAes128 failed");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id, &key_handle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecCipher_SingleInputId(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING,
                    SEC_CIPHERMODE_ENCRYPT, id,
                    NULL, &derivation_input[0], derivation_input.size(),
                    enc_output, sizeof(enc_output), &enc_output_len))
    {

        SEC_LOG_ERROR("Encrypt failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(key_handle, &derivation_input[0], exported_key, sizeof(exported_key), &exported_key_len))
    {
        SEC_LOG_ERROR("SecKey_ExportKey failed for derived key type");
        goto done;
    }
    SecKey_Release(key_handle);
    key_handle = NULL;
    SecKey_Delete(ctx.proc(),id);

    /* import exported derived key */
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            exported_key, exported_key_len)) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id, &key_handle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }
    if (SEC_RESULT_SUCCESS
            != SecCipher_SingleInputId(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING,
                    SEC_CIPHERMODE_DECRYPT, id,
                    NULL, enc_output, enc_output_len,
                    enc_output2, sizeof(enc_output2), &enc_output_len2))
    {

        SEC_LOG_ERROR("Decrypt failed");
        goto done;
    }
    if (derivation_input.size() != enc_output_len2)
    {
        SEC_LOG_ERROR("enc output size mismatch, expected %d, %d", derivation_input.size(),
                enc_output_len2);
        goto done;
    }
    Sec_PrintHex(&derivation_input[0], derivation_input.size());
    SEC_PRINT("\n");
    Sec_PrintHex(enc_output2, enc_output_len2);
    SEC_PRINT("\n");
    if (0!=memcmp(&derivation_input[0], enc_output2, enc_output_len2))
    {
        SEC_LOG_ERROR("enc output mismatch");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (key_handle)
        SecKey_Release(key_handle);

    return result;
}

Sec_Result testKeyCtrlExpectedExportedProperties(int version, const char *alg, TestKey contentKey)
{
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle *keyHandle = NULL;
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        contentKey, g_default_jtype_data.encryptionKey, keyId,
        b64rights.c_str(), cacheable, keyUsage,
        notBefore, notOnOrAfter,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }

    SecKey_Release(keyHandle);
    keyHandle = NULL;
    SecKey_Delete(ctx.proc(),SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            exported_key, exported_key_len)) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    if (0!=strcmp(keyId,keyProps.keyId))
    {
        SEC_LOG_ERROR("keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notOnOrAfter,keyProps.notOnOrAfter))
    {
        SEC_LOG_ERROR("notOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notBefore,keyProps.notBefore))
    {
        SEC_LOG_ERROR("notBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType)
    {
        SEC_LOG_ERROR("keyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength)
    {
        SEC_LOG_ERROR("keyLength mismatch  expecting %d, received %d", SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable)
    {
        SEC_LOG_ERROR("cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage)
    {
        SEC_LOG_ERROR("usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    if (0!= memcmp(keyProps.rights, jtypeRights, 8))
    {
        SEC_LOG_ERROR("keyrights mismatch");
        return SEC_RESULT_FAILURE;
    }


    return SEC_RESULT_SUCCESS;
}

/* export a key, re-provision it, then export it again
 */
Sec_Result testKeyCtrlExportProvisionExport(int version, const char *alg, TestKey contentKey)
{
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle *keyHandle = NULL;
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    Sec_KeyProperties keyProps;
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        contentKey, g_default_jtype_data.encryptionKey, keyId,
        b64rights.c_str(), cacheable, keyUsage,
        notBefore, notOnOrAfter,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }

    SecKey_Release(keyHandle);
    keyHandle = NULL;
    SecKey_Delete(ctx.proc(),SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            exported_key, exported_key_len)) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    // export it again
    derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Release(keyHandle);
    keyHandle = NULL;
    SecKey_Delete(ctx.proc(),SEC_OBJECTID_USER_BASE);

    // reprovision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), SEC_OBJECTID_USER_BASE,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            exported_key, exported_key_len)) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported key");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), SEC_OBJECTID_USER_BASE, &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for exported key");
        return SEC_RESULT_FAILURE;
    }

    SecKey_GetProperties(keyHandle, &keyProps);
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    if (0!=strcmp(keyId,keyProps.keyId))
    {
        SEC_LOG_ERROR("keyid mismatch  expecting '%s', received '%s'", keyId, keyProps.keyId);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notOnOrAfter,keyProps.notOnOrAfter))
    {
        SEC_LOG_ERROR("notOnOrAfter mismatch  expecting '%s', received '%s'", notOnOrAfter, keyProps.notOnOrAfter);
        return SEC_RESULT_FAILURE;
    }
    if (0!=strcmp(notBefore,keyProps.notBefore))
    {
        SEC_LOG_ERROR("notBefore mismatch  expecting '%s', received '%s'", notBefore, keyProps.notBefore);
        return SEC_RESULT_FAILURE;
    }
    if (TestCreds::getKeyType(contentKey) != keyProps.keyType)
    {
        SEC_LOG_ERROR("keyType mismatch.  got %d, expected %d", keyProps.keyType, TestCreds::getKeyType(contentKey));
        return SEC_RESULT_FAILURE;
    }
    if (SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)) != keyProps.keyLength)
    {
        SEC_LOG_ERROR("keyLength mismatch  expecting %d, received %d", SecKey_GetKeyLenForKeyType(TestCreds::getKeyType(contentKey)), keyProps.keyLength);
        return SEC_RESULT_FAILURE;
    }
    if (cacheable != keyProps.cacheable)
    {
        SEC_LOG_ERROR("cacheable mismatch, expecting %d", cacheable);
        return SEC_RESULT_FAILURE;
    }
    if (keyUsage != keyProps.usage)
    {
        SEC_LOG_ERROR("usage mismatch, expecting %d, received %d", keyUsage, keyProps.usage);
        return SEC_RESULT_FAILURE;
    }

    if (0!= memcmp(keyProps.rights, jtypeRights, 8))
    {
        SEC_LOG_ERROR("keyrights mismatch");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

// get just size needed for key by passing NULL out buffer to KeyExport call
Sec_Result testKeyCtrlKeyExportGetSize(int version, const char *alg)
{
    TestCtx ctx;

    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    Sec_KeyHandle *keyHandle = NULL;
    const char* notOnOrAfter = "2025-12-09T19:53:06Z";
    const char* notBefore = "2010-12-09T19:53:06Z";
    const char* keyId = "9c621060-3a17-4813-8dcb-2e9187aaa903";
    SEC_BOOL cacheable = SEC_TRUE;
    Sec_KeyUsage keyUsage = SEC_KEYUSAGE_KEY;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /* expired key */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER", "HS256",
        g_default_jtype_data.contentKey, g_default_jtype_data.encryptionKey, keyId,
        b64rights.c_str(), cacheable, keyUsage,
        notBefore, notOnOrAfter,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    // get size
    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], NULL, 0, &exported_key_len2))
    {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed while getting key length");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SecKey_Release(keyHandle);
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        return SEC_RESULT_FAILURE;
    }
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    if (exported_key_len != exported_key_len2)
    {
        SEC_LOG_ERROR("exported key length mismatch, expected %d, received %d",
                exported_key_len2, exported_key_len);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeyCtrlKeyExportHmac(TestKey macKey, Sec_StorageLoc location)
{
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_KeyHandle *keyHandle = NULL;
    TestKc macKc = TESTKC_RAW;
    SEC_BYTE exported_key[4096];
    SEC_SIZE exported_key_len = 0;
    SEC_SIZE exported_key_len2 = 0;
    Sec_MacHandle *macHandle = NULL;
    SEC_BYTE mac_output[256];
    SEC_SIZE mac_output_len = 0;
    SEC_BYTE mac_output2[256];
    SEC_SIZE mac_output_len2 = 0;
    SEC_OBJECTID id = SEC_OBJECTID_COMCAST_XCALSESSIONMACKEY ;

    memset(mac_output, 0, sizeof(mac_output));
    memset(mac_output2, 0, sizeof(mac_output2));

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        goto done;
    }

    //provision maccing key
    if (NULL == ctx.provisionKey(id, location, macKey, macKc)) {
        SEC_LOG_ERROR("provisionKey failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id,
            &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for session mac key");
        goto done;
    }

    if(SEC_RESULT_SUCCESS != SecMac_GetInstance(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA1,
            keyHandle, &macHandle))
    {
        SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecMac_Update(macHandle, (SEC_BYTE*)&derivation_input[0], derivation_input.size()))
    {
        SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
        goto done;
    }

    SecMac_Release(macHandle, mac_output, &mac_output_len);
    macHandle = NULL;

    // get size
    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], NULL, 0, &exported_key_len2))
    {
        SEC_LOG_ERROR("SecKey_ExportKey failed while getting key length");
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SEC_LOG_ERROR("SecKey_ExportKey failedi for mac key");
        goto done;
    }
    SecKey_Release(keyHandle);
    keyHandle = NULL;

    SecKey_Delete(ctx.proc(),id);

    if (exported_key_len != exported_key_len2)
    {
        SEC_LOG_ERROR("exported key length mismatch, expected %d, received %d",
                exported_key_len2, exported_key_len);
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED,
            exported_key, exported_key_len)) {
        SEC_LOG_ERROR("SecKey_Provision failed for exported hmac key");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id,
            &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed for session mac key");
        goto done;
    }
    if(SEC_RESULT_SUCCESS != SecMac_GetInstance(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA1,
            keyHandle, &macHandle))
    {
        SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecMac_Update(macHandle, (SEC_BYTE*)&derivation_input[0], derivation_input.size()))
    {
        SEC_LOG_ERROR("SecMac_GetInstance failed for hmac key");
        goto done;
    }

    SecMac_Release(macHandle, mac_output2, &mac_output_len2);
    macHandle = NULL;

    if (mac_output_len != mac_output_len2)
    {
        SEC_LOG_ERROR("mac output size mismatch, %d, %d", mac_output_len, mac_output_len2);
        goto done;
    }
    Sec_PrintHex(mac_output, mac_output_len);
    SEC_PRINT("\n");
    Sec_PrintHex(mac_output2, mac_output_len2);
    SEC_PRINT("\n");
    if (0!=memcmp(mac_output, mac_output2, mac_output_len2))
    {
        SEC_LOG_ERROR("mac output mismatch");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (macHandle)
        SecMac_Release(macHandle,mac_output, &mac_output_len);
    if (keyHandle)
        SecKey_Release(keyHandle);


    return result;
}

/* Only Opaque buffers can be used when SVP is required */
Sec_Result testKeyCtrlCipherFailsSvpNonOpaque(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};
    SEC_BYTE clear_text[16] = {0x01};
    SEC_BYTE cipher_text[16];
    SEC_SIZE bytesWritten = 0;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2022-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /*  key avail in one hour */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        g_default_jtype_data.contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);
    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR( "SeCcipher_GetInstance failed" );
        goto done;
    }

    if (SEC_RESULT_SUCCESS ==
            SecCipher_Process(cipherHandle, clear_text, sizeof(clear_text), SEC_TRUE, cipher_text, sizeof(cipher_text), &bytesWritten))
    {
        SEC_LOG_ERROR(
                "expected SeCcipher_Process to fail when processing non-opaque buffer with SVP required");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

/* cipher process succeeds with svp required and opaque buffer */
Sec_Result testKeyCtrlCipherSvpOpaque(int version, const char *alg, TestKey contentKey)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};
    Sec_OpaqueBufferHandle *opaque_clear_text = NULL;
    Sec_OpaqueBufferHandle *opaque_cipher_text = NULL;
    SEC_SIZE bytesWritten = 0;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2022-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    SEC_BYTE clear_data[16] = { 0x01 };

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);


    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    /* init opaque buffers */
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(16, &opaque_clear_text))
    {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(16, &opaque_cipher_text))
    {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Write(opaque_clear_text,0, clear_data, 16))
    {
        SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR( "SeCcipher_GetInstance failed" );
        goto done;
    }

    if (SEC_RESULT_SUCCESS !=
            SecCipher_ProcessOpaque(cipherHandle, opaque_clear_text, opaque_cipher_text, 16, SEC_TRUE, &bytesWritten))
    {
        SEC_LOG_ERROR(
                "SeCcipher_ProcessOpaque failed");
        goto done;
    }
    if (bytesWritten != 16)
    {
        SEC_LOG_ERROR("expected output size to be 16, received %d", (int)bytesWritten);
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    if (keyHandle)
        SecKey_Release(keyHandle);

    if (opaque_clear_text)
        SecOpaqueBuffer_Free(opaque_clear_text);

    if (opaque_cipher_text)
        SecOpaqueBuffer_Free(opaque_cipher_text);

    return result;
}

Sec_Result testKeyCtrlCipherSvpDataShiftOpaque(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2022-12-09T19:53:06Z";
    TestCtx ctx;
    Sec_OpaqueBufferHandle *inputHandle1 = NULL;
    Sec_OpaqueBufferHandle *inputHandle2 = NULL;
    Sec_OpaqueBufferHandle *outputHandle = NULL;
    SEC_SIZE written = 0;
    Sec_CipherHandle* cipherHandle = NULL;
    Sec_KeyHandle *handle = NULL;
    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        g_default_jtype_data.contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == (handle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, handle,
        &iv[0], &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(8, &inputHandle1)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256-8, &inputHandle2)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &outputHandle)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_ProcessOpaque(cipherHandle,
        inputHandle1, outputHandle, 8, SEC_FALSE,
        &written)) {
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_ProcessCtrWithOpaqueDataShift(cipherHandle, inputHandle2, outputHandle, 256-8, &written, 8)) {
        SEC_LOG_ERROR("SecCipher_ProcessCtrWithOpaqueDataShift failed");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);
    if (handle)
        SecKey_Release(handle);
    if (outputHandle)
        SecOpaqueBuffer_Free(outputHandle);
    if (inputHandle1)
        SecOpaqueBuffer_Free(inputHandle1);
    if (inputHandle2)
        SecOpaqueBuffer_Free(inputHandle2);

    return result;
}

Sec_Result testKeyCtrlSvpCheckOpaque(int version, const char *alg, TestKey contentKey)
{
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2022-12-09T19:53:06Z";
    Sec_CipherHandle* cipherHandle = NULL;
    Sec_KeyHandle *handle = NULL, *handle2 = NULL;
    std::vector<SEC_BYTE> input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> expected(SEC_AES_BLOCK_SIZE,0);
    SEC_SIZE bytesWritten = 0;
    Sec_OpaqueBufferHandle *inputHandle = NULL;

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);

    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }
    if (NULL == (handle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    /* provision key setup expected test data */
    handle2=ctx.provisionKey(SEC_OBJECTID_USER_BASE +1, SEC_STORAGELOC_RAM, contentKey, TESTKC_RAW, SEC_FALSE);
    if( handle2 == NULL )
    {
        SEC_LOG_ERROR("provision failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_SingleInput(ctx.proc(), SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT,
            handle2, NULL, &input[0], input.size(), &expected[0], expected.size(),
            &bytesWritten))
    {
        SEC_LOG_ERROR("SecCipher_SingleInputId failed");
        goto done;
    }

    /* cipher handle using jtype key */
    if (SEC_RESULT_SUCCESS != SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, handle,
        NULL, &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    TestCtx::printHex("   input", input);
    TestCtx::printHex("expected", expected);

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(input.size(), &inputHandle)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Malloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Write(inputHandle, 0, &input[0], input.size())) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_KeyCheckOpaque(cipherHandle, inputHandle, SEC_AES_BLOCK_SIZE, &expected[0])) {
        SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
        return SEC_RESULT_FAILURE;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);
    if (inputHandle)
        SecOpaqueBuffer_Free(inputHandle);
    if (handle)
        SecKey_Release(handle);

    return result;
}



/* Only Opaque buffers can be used when SVP is required */
Sec_Result testKeyCtrlProcessCtrDataShiftFailsSvpNonOpaque(int version, const char *alg)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    TestCtx ctx;
    Sec_CipherHandle *cipherHandle = NULL;
    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE iv[16] = {0x01};
    SEC_BYTE clear_text[16] = {0x01};
    SEC_BYTE cipher_text[16];
    SEC_SIZE bytesWritten = 0;
    const char *notBeforeTimeStr = "2010-12-09T19:53:06Z";
    const char *notOnOrAfterTimeStr = "2022-12-09T19:53:06Z";
    SEC_BYTE jtypeRights[SEC_KEYOUTPUTRIGHT_NUM];
    std::string b64rights;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    RIGHTS_INIT(jtypeRights);
    jtypeRights[0]= SEC_KEYOUTPUTRIGHT_SVP_REQUIRED;
    jtypeRights[1]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
    jtypeRights[2]= SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
    b64rights = toB64(jtypeRights, SEC_KEYOUTPUTRIGHT_NUM);

    /*  key avail in one hour */
    std::string jtype = createJTypeContainer("1WXQ46EYW65SENER",
        "HS256",
        g_default_jtype_data.contentKey,
        g_default_jtype_data.encryptionKey,
        "9c621060-3a17-4813-8dcb-2e9187aaa903",
        b64rights.c_str(), SEC_TRUE, 1,
        notBeforeTimeStr,
        notOnOrAfterTimeStr,
        g_default_jtype_data.macKey,
        version, alg);
    if (jtype.size() == 0) {
        SEC_LOG_ERROR("createJTypeContainer failed");
        goto done;
    }

    if (NULL == (keyHandle = _provisionJTypeAndSession(ctx, jtype)))
    {
        goto done;
    }

    if (SEC_RESULT_SUCCESS
            != SecCipher_GetInstance(ctx.proc(),
                    SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_ENCRYPT,
                    keyHandle, iv, &cipherHandle))
    {
        SEC_LOG_ERROR( "SeCcipher_GetInstance failed" );
        goto done;
    }

    if (SEC_RESULT_SUCCESS ==
            SecCipher_ProcessCtrWithDataShift(cipherHandle, clear_text, sizeof(clear_text), cipher_text, sizeof(cipher_text), &bytesWritten, 8))
    {
        SEC_LOG_ERROR(
                "expected SeCcipher_ProcessCtrWithDataShift to fail when processing non-opaque buffer with SVP required");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}

Sec_Result testKeyCtrlKeyExportSmallBuffer()
{
    Sec_Result result = SEC_RESULT_FAILURE;

    Sec_KeyHandle *keyHandle = NULL;
    SEC_BYTE exported_key[8];
    SEC_SIZE exported_key_len = 0;
    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE + 50;
    Sec_StorageLoc location = SEC_STORAGELOC_RAM;
    TestCtx ctx;

    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> aesKey = TestCtx::random(SEC_AES_BLOCK_SIZE);

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id, location, SEC_KEYCONTAINER_RAW_AES_128,
            (SEC_BYTE*)&aesKey[0], aesKey.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), id, &keyHandle))
    {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS == SecKey_ExportKey(keyHandle, (SEC_BYTE*)&derivation_input[0], exported_key,
                    sizeof(exported_key), &exported_key_len))
    {
        SEC_LOG_ERROR("Expected SecKey_ExportKey to fail with under-sized output buffer");
        goto done;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    if (keyHandle)
        SecKey_Release(keyHandle);

    return result;
}
