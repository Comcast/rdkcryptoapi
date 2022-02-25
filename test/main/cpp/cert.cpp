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

#include "cert.h"
#include "test_ctx.h"
#include "test_creds.h"
#include "sec_security_utils.h"
#include <openssl/x509.h>

X509 * _DerToX509(SEC_BYTE *der, SEC_SIZE der_len) {
	BIO *bio = NULL;
	X509 *x509 = NULL;

    bio = BIO_new_mem_buf(der, der_len);
    x509 = d2i_X509_bio(bio, NULL );
    SEC_BIO_FREE(bio);

    if (x509 == NULL) {
    	SEC_LOG_ERROR("d2i_X509_bio failed");
    }

    return x509;
}

Sec_Result testCertProvision(SEC_OBJECTID id, TestCert cert, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_CertificateHandle *handle;
	if (NULL == (handle = ctx.provisionCert(id, loc, cert))) {
		SEC_LOG_ERROR("TestCtx.provisionCert failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCertExport(SEC_OBJECTID id, TestCert cert, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_CertificateHandle *handle;
	if (NULL == (handle = ctx.provisionCert(id, loc, cert))) {
		SEC_LOG_ERROR("TestCtx.provisionCert failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_SIZE written;
	if (SEC_RESULT_SUCCESS != SecCertificate_Export(handle, NULL, 0, &written)) {
		SEC_LOG_ERROR("SecBundle_Export failed");
		return SEC_RESULT_FAILURE;
	}

	std::vector<SEC_BYTE> out;
	out.resize(written);
	if (SEC_RESULT_SUCCESS != SecCertificate_Export(handle,
	        &out[0], out.size(), &written)) {
		SEC_LOG_ERROR("SecBundle_Export failed");
		return SEC_RESULT_FAILURE;
	}

	X509 *x509 = _DerToX509(&out[0], out.size());
	if (x509 == NULL) {
		SEC_LOG_ERROR("_DerToX509 failed");
		return SEC_RESULT_FAILURE;
	}
	SEC_X509_FREE(x509);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testCertVerify(SEC_OBJECTID id_cert, TestCert cert, SEC_OBJECTID id_key, TestKey key, Sec_StorageLoc loc) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_CertificateHandle *handle;
	if (NULL == (handle = ctx.provisionCert(id_cert, SEC_STORAGELOC_RAM, cert))) {
		SEC_LOG_ERROR("TestCtx.provisionCert failed");
		return SEC_RESULT_FAILURE;
	}

	Sec_KeyHandle *key_handle;
	if (NULL == (key_handle = ctx.provisionKey(id_key, loc, key, TESTKC_RAW))) {
		SEC_LOG_ERROR("TestCtx.provisionKey failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsEcc(TestCreds::getKeyType(key))) {
		Sec_ECCRawPublicKey pub_key;
		if (SEC_RESULT_SUCCESS != SecCertificate_ExtractECCPublicKey(handle, &pub_key)) {
			SEC_LOG_ERROR("SecCertificate_ExtractECCPublicKey failed");
			return SEC_RESULT_FAILURE;
		}

		if (SEC_RESULT_SUCCESS != SecCertificate_VerifyWithRawECCPublicKey(handle, &pub_key)) {
			SEC_LOG_ERROR("SecCertificate_VerifyWithRawECCPublicKey failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		Sec_RSARawPublicKey pub_key;
		if (SEC_RESULT_SUCCESS != SecCertificate_ExtractRSAPublicKey(handle, &pub_key)) {
			SEC_LOG_ERROR("SecCertificate_ExtractRSAPublicKey failed");
			return SEC_RESULT_FAILURE;
		}

		if (SEC_RESULT_SUCCESS != SecCertificate_VerifyWithRawRSAPublicKey(handle, &pub_key)) {
			SEC_LOG_ERROR("SecCertificate_VerifyWithRawRSAPublicKey failed");
			return SEC_RESULT_FAILURE;
		}
	}

	if (SEC_RESULT_SUCCESS != SecCertificate_Verify(handle, key_handle)) {
		SEC_LOG_ERROR("SecCertificate_Verify failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}
