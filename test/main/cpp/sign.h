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

#ifndef TEST_SIGN_H_
#define TEST_SIGN_H_

#include "sec_security.h"
#include <vector>
#include "test_creds.h"

std::vector<SEC_BYTE> signOpenSSL(Sec_SignatureAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input);

SEC_BOOL verifyOpenSSL(Sec_SignatureAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input, const std::vector<SEC_BYTE>& sig);

Sec_Result testSignature(
		SEC_OBJECTID id, TestKey pub, TestKey priv, TestKc kc, Sec_StorageLoc loc,
		Sec_SignatureAlgorithm alg, Sec_SignatureMode mode, SEC_SIZE inputSize);

#endif
