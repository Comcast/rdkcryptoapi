/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2014 - 2019 RDK Management
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

#ifndef SEC_SECURITY_JSON_H_
#define SEC_SECURITY_JSON_H_

#include <stdarg.h>
#include "sec_security.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Sec_JsonVal_struct Sec_JsonVal;
typedef struct Sec_JsonGenCtx_struct Sec_JsonGenCtx;
typedef struct Sec_JsonParseCtx_struct Sec_JsonParseCtx;

Sec_Result SecJson_Gen(char *json, SEC_SIZE json_len, ...);
Sec_JsonGenCtx* SecJson_GenInit();
Sec_Result SecJson_GenClose(Sec_JsonGenCtx *ctx, char *result, SEC_SIZE max_len);
Sec_Result SecJson_GenAdd(Sec_JsonGenCtx *ctx, const char* field, const char* value);

Sec_JsonVal * SecJson_Parse(const char *json);
void SecJson_ValFree(Sec_JsonVal *res);
Sec_JsonVal * SecJson_GetObjEntry(Sec_JsonVal *val, const char *key);
SEC_SIZE SecJson_GetObjNumKeys(Sec_JsonVal *val);
const char * SecJson_GetObjKey(Sec_JsonVal *val, SEC_SIZE idx);
Sec_JsonVal * SecJson_GetArrayEntry(Sec_JsonVal *val, SEC_SIZE idx);
SEC_SIZE SecJson_GetArraySize(Sec_JsonVal *val);
const char *SecJson_GetValue(Sec_JsonVal *val);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_JSON_H_ */
