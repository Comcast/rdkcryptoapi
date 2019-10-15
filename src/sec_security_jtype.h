
/**
 * Copyright 2014 Comcast Cable Communications Management, LLC
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

#ifndef SEC_SECURITY_JTYPE_H_
#define SEC_SECURITY_JTYPE_H_

#include <stdarg.h>
#include "sec_security.h"

#ifdef __cplusplus
extern "C" {
#endif

Sec_Result SecJType_ProcessKey(Sec_ProcessorHandle *proc,
        SEC_OBJECTID macingKid, const void *jwtToken,
        SEC_SIZE jwtTokenLen, SEC_BYTE *out_wrappedKey, SEC_SIZE wrappedKeyBufSize,
        SEC_SIZE *out_wrappedKeyWritten, Sec_KeyProperties *out_keyProps,
        Sec_CipherAlgorithm *wrappingAlg, SEC_BYTE* iv);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_JTYPE_H_ */
