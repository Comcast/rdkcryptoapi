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

#include "test_creds.h"
#include "test_ctx.h"
#include "sec_security_utils.h"
#include "openssl/rand.h"
#include <memory>

#define SEC_OBJECTID_OPENSSL_KPK SEC_OBJECTID_RESERVEDPLATFORM_7

static std::vector<SEC_BYTE> random(SEC_SIZE len) {
    std::vector<SEC_BYTE> res;
    res.resize(len);

    if (1 != RAND_bytes(&res[0], len))
    {
        SEC_LOG_ERROR("RAND_bytes failed");
        return std::vector<SEC_BYTE>();
    }

    return res;
}

static std::vector<SEC_BYTE> asn1(const std::vector<SEC_BYTE>& wrapped, const std::vector<SEC_BYTE>& iv, Sec_KeyType type) {
    std::vector<SEC_BYTE> res;
    SEC_SIZE written;

    res.resize(SEC_KEYCONTAINER_MAX_LEN);

    if (SEC_RESULT_SUCCESS != SecKey_GenerateWrappedKeyAsn1Off(
            (SEC_BYTE *) &wrapped[0],
            wrapped.size(),
            type,
            SEC_OBJECTID_OPENSSL_KPK,
            (SEC_BYTE *) &iv[0],
            SEC_CIPHERALGORITHM_AES_CBC_PKCS7_PADDING,
            &res[0],
            res.size(),
            &written,
            0)) {
        SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1Off failed");
        return std::vector<SEC_BYTE>();
    }

    res.resize(written);

    return res;
}

static std::vector<SEC_BYTE> wrap(const std::vector<SEC_BYTE>& input, const std::vector<SEC_BYTE>& iv) {
    std::vector<SEC_BYTE> output;
    std::vector<SEC_BYTE> openssl_key = TestCreds::asOpenSslAes(TESTKEY_AES128);

  const EVP_CIPHER *evp_cipher;

  if (openssl_key.size() == 16) {
      evp_cipher = (EVP_CIPHER *) EVP_aes_128_cbc();
  } else {
      evp_cipher = (EVP_CIPHER *) EVP_aes_256_cbc();
  }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX evp_ctx;
    EVP_CIPHER_CTX_init(&evp_ctx);
    EVP_CIPHER_CTX *p_evp_ctx = &evp_ctx;
#else
    EVP_CIPHER_CTX *p_evp_ctx = EVP_CIPHER_CTX_new();
#endif

  if (1 != EVP_CipherInit_ex(p_evp_ctx, evp_cipher, NULL, NULL, NULL, 1))
  {
      SEC_LOG_ERROR("EVP_CipherInit failed");
      return std::vector<SEC_BYTE>();
  }

  if (1 != EVP_CIPHER_CTX_set_padding(p_evp_ctx, 1))
  {
      SEC_LOG_ERROR("EVP_CIPHER_CTX_set_padding failed");
      return std::vector<SEC_BYTE>();
  }

  if (1 != EVP_CipherInit_ex(p_evp_ctx, NULL, NULL, &openssl_key[0], &iv[0], 1))
  {
      SEC_LOG_ERROR("EVP_CipherInit failed");
      return std::vector<SEC_BYTE>();
  }

  output.resize(input.size() + SEC_AES_BLOCK_SIZE);

  SEC_SIZE written = 0;
  int outlen = 0;
  if (1 != EVP_CipherUpdate(p_evp_ctx, &output[0], &outlen, &input[0], input.size()))
  {
      SEC_LOG_ERROR("EVP_CipherUpdate failed");
      return std::vector<SEC_BYTE>();
  }
  written += outlen;
  outlen = 0;

  if (1 != EVP_CipherFinal_ex(p_evp_ctx, &output[written], &outlen))
  {
      SEC_LOG_ERROR("EVP_CipherFinal failed");
      return std::vector<SEC_BYTE>();
  }
  written += outlen;

  output.resize(written);

  return output;
}

ProvKey* TestCreds::getSocKey(TestKey key, SEC_OBJECTID id) {
    //Here the soc vendors should add code that returns the same key material as
    //getClearKey(key), but packaged in the secure format that is specific to the
    //chipset.
    //
    //This result can either be computed live or be pre-generated.
    //
    //The kc_type field should be set to the SEC_KEYCONTAINER_SOC.

    ProvKey *pk = TestCreds::getKey(key, TESTKC_RAW, id);
    if (pk == NULL) {
        return NULL;
    }

    std::vector<SEC_BYTE> toWrap;

    switch (pk->kc) {
    case SEC_KEYCONTAINER_DER_RSA_1024:
    case SEC_KEYCONTAINER_DER_RSA_2048: {
        RSA *rsa = SecUtils_RSAFromDERPriv(&pk->key[0], pk->key.size());
        if (rsa == NULL) {
            SEC_LOG_ERROR("SecUtils_RSAFromDERPriv failed ");
            delete pk;
            return NULL;
        }

        SEC_SIZE written;
        toWrap.resize(SEC_KEYCONTAINER_MAX_LEN);
        if (SEC_RESULT_SUCCESS
                != SecUtils_RSAToDERPrivKeyInfo(rsa, &toWrap[0], toWrap.size(),
                        &written)) {
            SEC_LOG_ERROR("SecUtils_RSAToDERPrivKeyInfo failed");
            SEC_RSA_FREE(rsa);
            return NULL;
        }

        toWrap.resize(written);
        SEC_RSA_FREE(rsa);
    }
        break;

    case SEC_KEYCONTAINER_DER_ECC_NISTP256: {
        EC_KEY *ec_key = SecUtils_ECCFromDERPriv(&pk->key[0], pk->key.size());
        if (ec_key == NULL) {
            SEC_LOG_ERROR("SecUtils_ECCFromDERPriv failed ");
            delete pk;
            return NULL;
        }

        Sec_ECCRawPrivateKey ec_bin;
        if (SEC_RESULT_SUCCESS != SecUtils_ECCToPrivBinary(ec_key, &ec_bin)) {
            SEC_LOG_ERROR("SecUtils_ECCToPrivBinary failed");
            SEC_ECC_FREE(ec_key);
            delete pk;
            return NULL;
        }

        SEC_ECC_FREE(ec_key);

        toWrap.resize(32);
        memcpy(&toWrap[0], &ec_bin.prv[0], 32);
    }
        break;

    case SEC_KEYCONTAINER_RAW_AES_128:
    case SEC_KEYCONTAINER_RAW_AES_256:
    case SEC_KEYCONTAINER_RAW_HMAC_128:
    case SEC_KEYCONTAINER_RAW_HMAC_160:
    case SEC_KEYCONTAINER_RAW_HMAC_256: {
        toWrap.resize(pk->key.size());
        memcpy(&toWrap[0], &pk->key[0], pk->key.size());
    }
        break;

    default:
        SEC_LOG_ERROR("Unexpected kc encountered");
        return NULL;
    }

    std::vector<SEC_BYTE> iv = random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> wrapped = wrap(toWrap, iv);
    if (wrapped.empty()) {
        SEC_LOG_ERROR("wrap failed");
        delete pk;
        return NULL;
    }

    std::vector<SEC_BYTE> a1 = asn1(wrapped, iv, TestCreds::getKeyType(key));
    if (a1.empty()) {
        SEC_LOG_ERROR("ans1 failed");
        return NULL;
    }

    delete pk;

    return new ProvKey(a1, SEC_KEYCONTAINER_SOC);
}

Sec_Result TestCreds::preprovisionSoc(TestCtx *ctx) {
    //Here the soc vendors should add code to preprovision any credentials that
    //are required for the rest of the system to operate properly.

    //For most platforms this can stay a NOP

    //provision kpk
    ctx->provisionKey(SEC_OBJECTID_OPENSSL_KPK, SEC_STORAGELOC_RAM, TESTKEY_AES128, TESTKC_RAW, SEC_TRUE);

    return SEC_RESULT_SUCCESS;
}

SEC_BOOL TestCreds::supports(Capability cap) {
    //return whether a specific capability is supported in the target soc
    return cap != CAPABILITY_HKDF_CMAC
        && cap != CAPABILITY_SVP;
}

void TestCreds::init() {
}

void TestCreds::shutdown() {
}
