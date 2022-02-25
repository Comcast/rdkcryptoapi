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

#ifndef TEST_WRAPPED_H_
#define TEST_WRAPPED_H_

#include "sec_security.h"
#include "test_creds.h"

Sec_Result testWrappedCipherSingleRsaAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testWrappedCipherSingleRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testWrappedCipherSingleRsaAesRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, Sec_CipherAlgorithm ckSymAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testWrappedCipherSingleEcAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testWrappedCipherSingleEcAesAes(TestKey key, TestKc kc, Sec_KeyType aesType, Sec_CipherAlgorithm asymAlg, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testExportWrappedRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testWrappedKDFCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, SEC_OBJECTID idWrapped, Sec_KeyType keyType, SEC_BYTE counter, uint32_t L);
Sec_Result testExportedKDFCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, SEC_OBJECTID idWrapped, Sec_KeyType keyType, SEC_BYTE counter, uint32_t L);
Sec_Result testExportWrappedEccAesAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testExportWrappedEccAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testExportWrappedGeneratedEccAesAes(TestKey key, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv);
Sec_Result testExportWrappedGeneratedEccAes(TestKey key, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv);

#endif
