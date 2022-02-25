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

#ifndef TEST_KEYCTRL_H_
#define TEST_KEYCTRL_H_

#include "sec_security.h"
#include "test_creds.h"
#include <string>

Sec_Result testKeyCtrlDefaultProperties(int version, const char *alg);

Sec_Result testKeyCtrlFalseDefaultProperties(int version, const char *alg);

/* test expected platform default rights */
Sec_Result testKeyCtrlRightsFromPlatformDefault(int version, const char *alg);

/* gets output rights from either default (hard-coded) values or devicesettings
 * depending on compile directive -DSEC_KEYCTRL_ENABLE_DEVICE_SETTINGS
 */
Sec_Result testKeyCtrlGetOutputRights(int version, const char *alg);

/* Sec_GetCipherInstance fails with request right that is not allowed on device */
Sec_Result testKeyCtrlUnSupportedOutputRight(int version, const char *alg);

/* En/Decrypt successful with key requesting a right that is allowed on the device */
Sec_Result testKeyCtrlDecryptSupportedOutputRight(int version, const char *alg);

/* SecKey_Export fails if cacheable flag == 0 */
Sec_Result testKeyCtrlExportUnCachable(int version, const char *alg);

/* general rights combinations */
Sec_Result testKeyCtrlAllowedRights(int version, const char *alg);

/* SecCipher_GetInstance fails for key with usage for 'key' only */
Sec_Result testKeyCtrlKeyOnlyUsage(int version, const char *alg);

/* SecCipher_Getinstance should fail with notOnOrAfter date < now */
Sec_Result testKeyCtrlKeyExpired(int version, const char *alg);

/* SecCipher_GetInstance should fail with notBefore date in the future */
Sec_Result testKeyCtrlKeyNotYetAvail(int version, const char *alg);

/* key properties vaidation */
Sec_Result testKeyCtrlValidatePropertiesBadNotBefore(int version, const char *alg);
Sec_Result testKeyCtrlValidatePropertiesBadNotOnOrAfter(int version, const char *alg);
Sec_Result testKeyCtrlValidatePropertiesDefaults(int version, const char *alg);
Sec_Result testKeyCtrlUtilsTime(int version, const char *alg);
Sec_Result testKeyCtrlUnwrapWithKeyUsage(int version, const char *alg, TestKey key);
Sec_Result testKeyCtrlUnwrapWithDataUsage(int version, const char *alg);
Sec_Result testKeyCtrlBadB64Jtype(int version, const char *alg);
Sec_Result testKeyCtrlExportDerived();
Sec_Result testKeyCtrlExpectedJTypeProperties(int version, const char *alg, TestKey key);
Sec_Result testKeyCtrlExpectedExportedProperties(int version, const char *alg, TestKey key);
Sec_Result testKeyCtrlExportProvisionExport(int version, const char *alg, TestKey contentKey);
Sec_Result testKeyCtrlKeyExportGetSize(int version, const char *alg);
Sec_Result testKeyCtrlExportAes(TestKey aesKey, Sec_StorageLoc location);
Sec_Result testKeyCtrlKeyExportHmac(TestKey macKey, Sec_StorageLoc location);
Sec_Result testKeyCtrlCipherFailsSvpNonOpaque(int version, const char *alg);
Sec_Result testKeyCtrlCipherSvpOpaque(int version, const char *alg, TestKey contentKey);
Sec_Result testKeyCtrlCipherSvpDataShiftOpaque(int version, const char *alg);
Sec_Result testKeyCtrlSvpCheckOpaque(int version, const char *alg, TestKey contentKey);
Sec_Result testKeyCtrlProcessCtrDataShiftFailsSvpNonOpaque(int version, const char *alg);
Sec_Result testKeyCtrlExportEcc(TestKc kc);
Sec_Result testKeyCtrlKeyExportSmallBuffer();

#endif
