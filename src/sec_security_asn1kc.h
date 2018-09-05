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

#ifndef SEC_COMMON_17

#ifndef SEC_SECURITY_ASN1KC_H_
#define SEC_SECURITY_ASN1KC_H_

#include "sec_security_datatype.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief Opaque certificate handle
 *
 */
typedef struct Asn1KC Sec_Asn1KC;

Sec_Asn1KC *SecAsn1KC_Alloc();
void SecAsn1KC_Free(Sec_Asn1KC *kc);
Sec_Result SecAsn1KC_Encode(Sec_Asn1KC *kc, SEC_BYTE *buf, SEC_SIZE buf_len, SEC_SIZE *written);
Sec_Asn1KC *SecAsn1KC_Decode(SEC_BYTE *buf, SEC_SIZE buf_len);
SEC_BOOL SecAsn1KC_HasAttr(Sec_Asn1KC *kc, const char *key);
Sec_Result SecAsn1KC_AddAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long val);
Sec_Result SecAsn1KC_AddAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t val);
Sec_Result SecAsn1KC_AddAttrLong(Sec_Asn1KC *kc, const char *key, long val);
Sec_Result SecAsn1KC_AddAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t val);
Sec_Result SecAsn1KC_AddAttrString(Sec_Asn1KC *kc, const char *key, const char *val);
Sec_Result SecAsn1KC_AddAttrBuffer(Sec_Asn1KC *kc, const char *key, void *buf, SEC_SIZE buf_len);
Sec_Result SecAsn1KC_GetAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long *val);
Sec_Result SecAsn1KC_GetAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t *val);
Sec_Result SecAsn1KC_GetAttrLong(Sec_Asn1KC *kc, const char *key, long *val);
Sec_Result SecAsn1KC_GetAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t *val);
Sec_Result SecAsn1KC_GetAttrBuffer(Sec_Asn1KC *kc, const char *key, SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written);
Sec_Result SecAsn1KC_GetAttrString(Sec_Asn1KC *kc, const char *key, char *buffer, SEC_SIZE buffer_len, SEC_SIZE *written);

#ifdef __cplusplus
}
#endif

#endif

#endif
