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

#ifndef TEST_MAC_H_
#define TEST_MAC_H_

#include "sec_security.h"
#include <vector>
#include "test_creds.h"

Sec_Result testMacOverKey(Sec_MacAlgorithm alg, SEC_OBJECTID id_mac, TestKey keyMac, TestKc kc, SEC_OBJECTID id_payload, TestKey keyPayload, Sec_StorageLoc loc);

Sec_Result testMacSingle(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_MacAlgorithm alg, SEC_SIZE inputSize);

Sec_Result testMacMult(
		SEC_OBJECTID id, TestKey key, TestKc kc, Sec_StorageLoc loc,
		Sec_MacAlgorithm alg, const std::vector<SEC_SIZE>& inputSizes);

std::vector<SEC_BYTE> macOpenSSL(Sec_MacAlgorithm alg, TestKey key, const std::vector<SEC_BYTE>& input);

Sec_Result macCheck(Sec_ProcessorHandle *proc, Sec_MacAlgorithm alg, SEC_OBJECTID id, SEC_BYTE *key, SEC_SIZE key_len);

#endif
