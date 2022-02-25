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

#include "random.h"
#include "test_ctx.h"

Sec_Result testRandom(Sec_RandomAlgorithm alg, SEC_SIZE size) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_RandomHandle *handle = NULL;
	if (NULL == (handle = ctx.acquireRandom(alg))) {
		SEC_LOG_ERROR("TestCtx::acquireRandom failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> out;
	out.resize(size);

	if (SEC_RESULT_SUCCESS != SecRandom_Process(handle, &out[0], out.size())) {
		SEC_LOG_ERROR("SecRandom_Process failed");
		return SEC_RESULT_FAILURE;
	}

	TestCtx::printHex("out", out);

	return SEC_RESULT_SUCCESS;
}
