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

#include "processor.h"
#include "test_ctx.h"

Sec_Result testProcessorPrintInfo() {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecProcessor_PrintInfo(ctx.proc())) {
		SEC_LOG_ERROR("SecProcessor_PrintInfo failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessorGetInfo() {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_ProcessorInfo info;

	if (SEC_RESULT_SUCCESS != SecProcessor_GetInfo(ctx.proc(), &info)) {
		SEC_LOG_ERROR("SecProcessor_GetInfo failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_PRINT("version: %s\n", (const char *) info.version);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessorGetDeviceId() {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> deviceId(SEC_DEVICEID_LEN);
	std::vector<SEC_BYTE> zeros(SEC_DEVICEID_LEN);

	if (SEC_RESULT_SUCCESS != SecProcessor_GetDeviceId(ctx.proc(), &deviceId[0])) {
		SEC_LOG_ERROR("SecProcessor_GetDeviceId failed");
		return SEC_RESULT_FAILURE;
	}

	TestCtx::printHex("deviceid", deviceId);

	if (deviceId == zeros) {
		SEC_LOG_ERROR("deviceId is all zeros");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessorGetKeyLadderMinMaxDepth(Sec_KeyLadderRoot root) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_SIZE depthMin = SecProcessor_GetKeyLadderMinDepth(ctx.proc(), root);
	SEC_SIZE depthMax = SecProcessor_GetKeyLadderMaxDepth(ctx.proc(), root);

	SEC_PRINT("min:%d\nmax:%d\n", depthMin, depthMax);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testProcessorNativeMallocFree() {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	void *mem = Sec_NativeMalloc(ctx.proc(), 256);
	memset(mem, 0, 256);

	if (mem == NULL) {
		SEC_LOG_ERROR("Sec_NativeMalloc failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_NativeFree(ctx.proc(), mem);

	return SEC_RESULT_SUCCESS;
}
