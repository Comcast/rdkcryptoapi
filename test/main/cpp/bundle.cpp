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

#include "bundle.h"
#include "test_ctx.h"

Sec_Result testBundleProvision(SEC_OBJECTID id, Sec_StorageLoc loc, SEC_SIZE size) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> bundle = TestCtx::random(size);

	Sec_BundleHandle *handle;
	if (NULL == (handle = ctx.provisionBundle(id, loc, bundle))) {
		SEC_LOG_ERROR("TestCtx.provisionBundle failed");
		return SEC_RESULT_FAILURE;
	}

	//get bundle size
	SEC_SIZE written;
	if (SEC_RESULT_SUCCESS != SecBundle_Export(handle, NULL, 0, &written)) {
		SEC_LOG_ERROR("SecBundle_Export failed");
		return SEC_RESULT_FAILURE;
	}

	//export bundle
	std::vector<SEC_BYTE> out;
	out.resize(written);
	if (SEC_RESULT_SUCCESS != SecBundle_Export(handle,
	        &out[0], size, &written)) {
		SEC_LOG_ERROR("SecBundle_Export failed");
		return SEC_RESULT_FAILURE;
	}

	out.resize(written);

	if (out != bundle) {
		SEC_LOG_ERROR("Exported bundle does not match");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testBundleProvisionNoAppDir(SEC_OBJECTID id, SEC_SIZE size) {
	TestCtx ctx;
	if (ctx.init("/tmp", NULL) != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> bundle = TestCtx::random(size);


	if (SEC_RESULT_SUCCESS == SecBundle_Provision(
			ctx.proc(), id, SEC_STORAGELOC_FILE, (SEC_BYTE *) &bundle[0], bundle.size())) {
		SEC_LOG_ERROR("SecBundle_Provision succeeded, but expected to fail");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
