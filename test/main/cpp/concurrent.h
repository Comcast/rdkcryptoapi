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

#ifndef TEST_CONCURRENT_H_
#define TEST_CONCURRENT_H_

#include "sec_security.h"
#include "test_creds.h"

Sec_Result testConcurrentVendor128(SEC_SIZE numThreads);
Sec_Result testConcurrentRsa(TestKey pub, TestKey priv, TestKc kc, SEC_SIZE numThreads);

#endif
