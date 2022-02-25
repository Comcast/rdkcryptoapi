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

#include "svp.h"
#include "cipher.h"
#include "test_ctx.h"

Sec_Result testOpaqueMalloc() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle* handle = NULL;
    SEC_BYTE input[64*1024];

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(sizeof(input), &handle)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Write(handle, 0, input, sizeof(input))) {
        SEC_LOG_ERROR("Sec_OpaqueBufferWrite failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Free(handle)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferFree failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testSecureBootEnabled() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecCodeIntegrity_SecureBootEnabled()) {
        SEC_LOG_ERROR("SecCodeIntegrity_SecureBootEnabled failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testSetTime() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecSVP_SetTime(time(NULL))) {
        SEC_LOG_ERROR("SecSVP_SetTime failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testKeycheckOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *handle = NULL;
    if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
        SEC_LOG_ERROR("TestCtx.provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CipherHandle* cipherHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_ENCRYPT, handle,
        NULL, &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> expected = opensslAesEcb(key, SEC_CIPHERMODE_ENCRYPT, SEC_FALSE, NULL, input);

    TestCtx::printHex("input", input);
    TestCtx::printHex("expected", expected);

    Sec_OpaqueBufferHandle *inputHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &inputHandle)) {
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Write(inputHandle, 0, &input[0], input.size())) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferWrite failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_KeyCheckOpaque(cipherHandle, inputHandle, SEC_AES_BLOCK_SIZE, &expected[0])) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
        return SEC_RESULT_FAILURE;
    }

    /* 2.2 checks for 'checkLength' arg */
    if (SEC_RESULT_SUCCESS != SecCipher_KeyCheckOpaque(cipherHandle, inputHandle, 8, &expected[0])) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_KeyCheckOpaque failed");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS == SecCipher_KeyCheckOpaque(cipherHandle, inputHandle, 7, &expected[0])) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("expected SecCipher_KeyCheckOpaque to fail with checkLength < 8");
        return SEC_RESULT_FAILURE;
    }
    if (SEC_RESULT_SUCCESS == SecCipher_KeyCheckOpaque(cipherHandle, inputHandle, 17, &expected[0])) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("expected SecCipher_KeyCheckOpaque to fail with checkLength > 16");
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(inputHandle);
    SecCipher_Release(cipherHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *handle = NULL;
    if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
        SEC_LOG_ERROR("TestCtx.provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_CipherHandle* cipherHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, SEC_CIPHERMODE_DECRYPT, handle,
        NULL, &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle *inputHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &inputHandle)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        SecCipher_Release(cipherHandle);
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle *outputHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &outputHandle)) {
        SecOpaqueBuffer_Free(inputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_SIZE written = 0;

    if (SEC_RESULT_SUCCESS != SecCipher_ProcessOpaque(cipherHandle,
        inputHandle, outputHandle, 256, SEC_TRUE, &written)) {
        SecOpaqueBuffer_Free(inputHandle);
        SecOpaqueBuffer_Free(outputHandle);
        SecCipher_Release(cipherHandle);
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(inputHandle);
    SecOpaqueBuffer_Free(outputHandle);
    SecCipher_Release(cipherHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testCopyOpaque() {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle *inputHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &inputHandle)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_OpaqueBufferHandle *outputHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &outputHandle)) {
        SecOpaqueBuffer_Free(inputHandle);
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_BYTE tmp[128];
    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Write(inputHandle, 128, tmp, 128)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Write failed");
        SecOpaqueBuffer_Free(inputHandle);
        SecOpaqueBuffer_Free(outputHandle);
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Copy(outputHandle, 0, inputHandle, 128, 128)) {
        SEC_LOG_ERROR("SecOpaqueBuffer_Copy failed");
        SecOpaqueBuffer_Free(inputHandle);
        SecOpaqueBuffer_Free(outputHandle);
        return SEC_RESULT_FAILURE;
    }

    SecOpaqueBuffer_Free(inputHandle);
    SecOpaqueBuffer_Free(outputHandle);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessDataShiftOpaque(SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc) {
    TestCtx ctx;
    Sec_Result result = SEC_RESULT_FAILURE;
    Sec_OpaqueBufferHandle *inputHandle1 = NULL;
    Sec_OpaqueBufferHandle *inputHandle2 = NULL;
    Sec_OpaqueBufferHandle *outputHandle = NULL;
    SEC_SIZE written = 0;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyHandle *handle = NULL;
    if (NULL == (handle = ctx.provisionKey(id, loc, key, kc))) {
        SEC_LOG_ERROR("TestCtx.provision failed");
        return SEC_RESULT_FAILURE;
    }

    std::vector<SEC_BYTE> iv = TestCtx::random(SEC_AES_BLOCK_SIZE);
    Sec_CipherHandle* cipherHandle = NULL;
    if (SEC_RESULT_SUCCESS != SecCipher_GetInstance(ctx.proc(),
        SEC_CIPHERALGORITHM_AES_CTR, SEC_CIPHERMODE_DECRYPT, handle,
        &iv[0], &cipherHandle)) {
        SEC_LOG_ERROR("SecCipher_GetInstance failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(8, &inputHandle1)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256-8, &inputHandle2)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecOpaqueBuffer_Malloc(256, &outputHandle)) {
        SEC_LOG_ERROR("Sec_OpaqueBufferMalloc failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_ProcessOpaque(cipherHandle,
        inputHandle1, outputHandle, 8, SEC_FALSE, &written)) {
        SEC_LOG_ERROR("SecCipher_ProcessOpaque failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecCipher_ProcessCtrWithOpaqueDataShift(cipherHandle, inputHandle2, outputHandle, 256-8, &written, 8)) {
        SEC_LOG_ERROR("SecCipher_ProcessCtrWithOpaqueDataShift failed");
        goto done;
    }


    result = SEC_RESULT_SUCCESS;

    done:

    if (inputHandle1)
        SecOpaqueBuffer_Free(inputHandle1);
    if (inputHandle2)
        SecOpaqueBuffer_Free(inputHandle2);
    if (outputHandle)
        SecOpaqueBuffer_Free(outputHandle);
    if (cipherHandle)
        SecCipher_Release(cipherHandle);

    return result;
}
