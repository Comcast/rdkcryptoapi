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

#ifndef SEC_PUBOPS_H_
#define SEC_PUBOPS_H_

#include "sec_security.h"

#ifdef __cplusplus
extern "C"
{
#endif

Sec_Result _Pubops_VerifyWithPubRsa(Sec_RSARawPublicKey *pub_key, Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *sig, SEC_SIZE sig_len, int salt_len);
Sec_Result _Pubops_VerifyWithPubEcc(Sec_ECCRawPublicKey *pub_key, Sec_SignatureAlgorithm alg, SEC_BYTE *digest, SEC_SIZE digest_len, SEC_BYTE *sig, SEC_SIZE sig_len);
Sec_Result _Pubops_EncryptWithPubRsa(Sec_RSARawPublicKey *pub_key, Sec_CipherAlgorithm alg, SEC_BYTE *in, SEC_SIZE in_len, SEC_BYTE *out, SEC_SIZE out_len);
Sec_Result _Pubops_EncryptWithPubEcc(Sec_ECCRawPublicKey *pub_key, Sec_CipherAlgorithm alg, SEC_BYTE *in, SEC_SIZE in_len, SEC_BYTE *out, SEC_SIZE out_len);
Sec_Result _Pubops_VerifyX509WithPubRsa(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub);
Sec_Result _Pubops_VerifyX509WithPubEcc(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub);
Sec_Result _Pubops_ExtractRSAPubFromX509Der(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub);
Sec_Result _Pubops_ExtractECCPubFromX509Der(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub);
Sec_Result _Pubops_ExtractRSAPubFromPUBKEYDer(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_RSARawPublicKey *pub);
Sec_Result _Pubops_ExtractECCPubFromPUBKEYDer(SEC_BYTE *cert, SEC_SIZE cert_len, Sec_ECCRawPublicKey *pub);
Sec_Result _Pubops_Random(SEC_BYTE* out, SEC_SIZE out_len);
Sec_Result _Pubops_RandomPrng(SEC_BYTE* out, SEC_SIZE out_len);
Sec_Result _Pubops_HMAC(Sec_MacAlgorithm alg, SEC_BYTE *key, SEC_SIZE key_len, SEC_BYTE *input, SEC_SIZE input_len, SEC_BYTE *mac, SEC_SIZE mac_len);

typedef struct _Pubops_DH_struct _Pubops_DH;
_Pubops_DH* _Pubops_DH_create(SEC_BYTE *p, SEC_SIZE p_len, SEC_BYTE *g, SEC_SIZE g_len);
void _Pubops_DH_free(_Pubops_DH *dh);
Sec_Result _Pubops_DH_generate_key(_Pubops_DH* dh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize);
Sec_Result _Pubops_DH_compute(_Pubops_DH* dh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len, SEC_SIZE* written);

typedef struct _Pubops_ECDH_struct _Pubops_ECDH;
_Pubops_ECDH* _Pubops_ECDH_create();
void _Pubops_ECDH_free(_Pubops_ECDH *ecdh);
Sec_Result _Pubops_ECDH_generate_key(_Pubops_ECDH *ecdh, SEC_BYTE* publicKey, SEC_SIZE pubKeySize);
Sec_Result _Pubops_ECDH_compute(_Pubops_ECDH *ecdh, SEC_BYTE* pub_key, SEC_SIZE pub_key_len, SEC_BYTE* key, SEC_SIZE key_len, SEC_SIZE* written);

#ifdef __cplusplus
}
#endif

#endif /* SEC_PUBOPS_H_ */
