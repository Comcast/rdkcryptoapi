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

#include "wrapped.h"
#include "test_ctx.h"
#include "cipher.h"
#include "mac.h"
#include <memory>

static ProvKey convertV2ToV3(const std::vector<ProvKey>& v2) {
	ProvKey lastKey;

	for (unsigned int i=0; i<v2.size(); ++i) {
		const ProvKey& key = v2[i];

		if (key.kc == SEC_KEYCONTAINER_ASN1) {
			SEC_BYTE payload[SEC_KEYCONTAINER_MAX_LEN];
			SEC_SIZE payloadLen;
			Sec_KeyType wrappedKeyType;
			SEC_OBJECTID wrappingId;
			SEC_BYTE wrappingIv[16];
			Sec_CipherAlgorithm wrappingAlg;
			SEC_SIZE key_offset;

            memset(wrappingIv, 0, SEC_AES_BLOCK_SIZE);

			if (SEC_RESULT_SUCCESS != SecKey_ExtractWrappedKeyParamsAsn1BufferOff((SEC_BYTE *) &key.key[0], key.key.size(),
                payload, sizeof(payload), &payloadLen,
                &wrappedKeyType, &wrappingId, wrappingIv,
                &wrappingAlg, &key_offset)) {

				SEC_LOG_ERROR("SecKey_ExtractWrappedKeyParamsAsn1BufferOff failed");
				return ProvKey();
			}

            SEC_PRINT("%d: wrappingId=" SEC_OBJECTID_PATTERN "\n", i, wrappingId);

			//special case for wrapping root key
			if (wrappingId == 0) {
				lastKey = key;
				continue;
			}

			std::vector<SEC_BYTE> v3Key;
			v3Key.resize(SEC_KEYCONTAINER_MAX_LEN);
			SEC_SIZE v3KeyLen;

            if (i == 0) {
                lastKey = key;
            } else {
    			if (SEC_RESULT_SUCCESS != SecKey_GenerateWrappedKeyAsn1V3(
    				payload, payloadLen, wrappedKeyType,
                    &lastKey.key[0], lastKey.key.size(),
                    wrappingIv, wrappingAlg,
                    &v3Key[0], v3Key.size(), &v3KeyLen, key_offset)) {

    				SEC_LOG_ERROR("SecKey_GenerateWrappedKeyAsn1V3 failed");
    				return ProvKey();
    			}

    			v3Key.resize(v3KeyLen);

    			lastKey = ProvKey(v3Key, SEC_KEYCONTAINER_ASN1);
            }
		} else {
			lastKey = key;
		}
	}

	return lastKey;
}

Sec_Result testWrappedCipherSingleRsaAesRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, Sec_CipherAlgorithm ckSymAlg, WrappedKeyFormatVersion wkfv) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

	std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainRsaAesRsaAesAes(key, kc, id, rsaType, asymAlg, aesType, symAlg, ckSymAlg);
	if (keys.size() == 0) {
		SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
		return SEC_RESULT_FAILURE;
	}

	switch (wkfv) {
		case WKFV_V2: {
			for (unsigned int i=0; i<keys.size(); ++i) {
				if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
						&keys[i].key[0], keys[i].key.size())) {
					SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
					return SEC_RESULT_FAILURE;
				}
			}
		}
		break;

		case WKFV_V3: {
			ProvKey v3Key = convertV2ToV3(keys);
			if (v3Key.key.size() == 0) {
				SEC_LOG_ERROR("convertV2ToV3 failed");
				return SEC_RESULT_FAILURE;
			}

			if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
					&v3Key.key[0], v3Key.key.size())) {
				SEC_LOG_ERROR("SecKey_Provision failed");
				return SEC_RESULT_FAILURE;
			}
		}
		break;

		default:
			SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
			return SEC_RESULT_FAILURE;
			break;
	}

	Sec_KeyType keyType = TestCreds::getKeyType(key);
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id-1, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsAES(keyType)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), id-1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, id-1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("macCheck failed");
		return SEC_RESULT_FAILURE;
		}
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testWrappedCipherSingleRsaAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

	std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainRsaAes(key, kc, id, rsaType, asymAlg);
	if (keys.size() == 0) {
		SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
		return SEC_RESULT_FAILURE;
	}

	switch (wkfv) {
		case WKFV_V2: {
			for (unsigned int i=0; i<keys.size(); ++i) {
				if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
						&keys[i].key[0], keys[i].key.size())) {
					SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
					return SEC_RESULT_FAILURE;
				}
			}
		}
		break;

		case WKFV_V3: {
			ProvKey v3Key = convertV2ToV3(keys);
			if (v3Key.key.size() == 0) {
				SEC_LOG_ERROR("convertV2ToV3 failed");
				return SEC_RESULT_FAILURE;
			}

			if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
					&v3Key.key[0], v3Key.key.size())) {
				SEC_LOG_ERROR("SecKey_Provision failed");
				return SEC_RESULT_FAILURE;
			}
		}
		break;

		default:
			SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
			return SEC_RESULT_FAILURE;
			break;
	}

	Sec_KeyType keyType = TestCreds::getKeyType(key);
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id-1, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsAES(keyType)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), id-1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, id-1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("macCheck failed");
		return SEC_RESULT_FAILURE;
		}
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testWrappedCipherSingleEcAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

	std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainEcAes(key, kc, id, asymAlg);
	if (keys.size() == 0) {
		SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
		return SEC_RESULT_FAILURE;
	}

	switch (wkfv) {
		case WKFV_V2: {
			for (unsigned int i=0; i<keys.size(); ++i) {
				if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
						&keys[i].key[0], keys[i].key.size())) {
					SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
					return SEC_RESULT_FAILURE;
				}
			}
		}
		break;

		case WKFV_V3: {
			ProvKey v3Key = convertV2ToV3(keys);
			if (v3Key.key.size() == 0) {
				SEC_LOG_ERROR("convertV2ToV3 failed");
				return SEC_RESULT_FAILURE;
			}

			if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
					&v3Key.key[0], v3Key.key.size())) {
				SEC_LOG_ERROR("SecKey_Provision failed");
				return SEC_RESULT_FAILURE;
			}
		}
		break;

		default:
			SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
			return SEC_RESULT_FAILURE;
			break;
	}

	Sec_KeyType keyType = TestCreds::getKeyType(key);
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

	if (SecKey_IsAES(keyType)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), id - 1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, id - 1, &clear[0], clear.size())) {
			SEC_LOG_ERROR("macCheck failed");
		return SEC_RESULT_FAILURE;
		}
	}

	//check enc/dec
	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id-1, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testWrappedCipherSingleEcAesAes(TestKey key, TestKc kc, Sec_KeyType aesType, Sec_CipherAlgorithm asymAlg, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainEcAesAes(key, kc, id, aesType, asymAlg, symAlg);
    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), id - 1, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, id - 1, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    //check enc/dec
    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id-1, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testExportWrappedRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv) {
	TestCtx ctx;

	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

	std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainRsaAesAes(key, kc, id, rsaType, asymAlg, aesType, symAlg);
	if (keys.size() == 0) {
		SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
		return SEC_RESULT_FAILURE;
	}

	switch (wkfv) {
		case WKFV_V2: {
			for (unsigned int i=0; i<keys.size(); ++i) {
				if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
						&keys[i].key[0], keys[i].key.size())) {
					SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
					return SEC_RESULT_FAILURE;
				}
			}
		}
		break;

		case WKFV_V3: {
			ProvKey v3Key = convertV2ToV3(keys);
			if (v3Key.key.size() == 0) {
				SEC_LOG_ERROR("convertV2ToV3 failed");
				return SEC_RESULT_FAILURE;
			}

			if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
					&v3Key.key[0], v3Key.key.size())) {
				SEC_LOG_ERROR("SecKey_Provision failed");
				return SEC_RESULT_FAILURE;
			}
		}
		break;

		default:
			SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
			return SEC_RESULT_FAILURE;
			break;
	}

    SEC_OBJECTID idContentKey = id-1;

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idContentKey, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idContentKey,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

	Sec_KeyType keyType = TestCreds::getKeyType(key);
	std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

	if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idContentKey, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
		SEC_LOG_ERROR("cipherEncDecSingle failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsAES(keyType)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idContentKey, &clear[0], clear.size())) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idContentKey, &clear[0], clear.size())) {
			SEC_LOG_ERROR("macCheck failed");
		return SEC_RESULT_FAILURE;
		}
	}

	return SEC_RESULT_SUCCESS;
}

Sec_Result testWrappedCipherSingleRsaAesAes(TestKey key, TestKc kc, Sec_KeyType rsaType, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainRsaAesAes(key, kc, id, rsaType, asymAlg, aesType, symAlg);
    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, id-1, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), id-1, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, id-1, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

static std::vector<SEC_BYTE> asn1(Sec_ProcessorHandle *proc, const std::vector<SEC_BYTE>& clear, Sec_KeyType type, SEC_OBJECTID wrappingId, Sec_CipherAlgorithm algorithm) {
	std::vector<SEC_BYTE> wrapped;
	wrapped.resize(SEC_KEYCONTAINER_MAX_LEN);
	SEC_SIZE wrapped_len;

	std::vector<SEC_BYTE> iv = TestCtx::random(16);

	if (SEC_RESULT_SUCCESS != SecCipher_SingleInputId(proc, algorithm, SEC_CIPHERMODE_ENCRYPT, wrappingId, &iv[0], (SEC_BYTE *) &clear[0], clear.size(), &wrapped[0], wrapped.size(), &wrapped_len)) {
		SEC_LOG_ERROR("SecCipher_SingleInputId failed");
		return std::vector<SEC_BYTE>();
	}
	wrapped.resize(wrapped_len);

	std::vector<SEC_BYTE> res;
	SEC_SIZE written;
	res.resize(SEC_KEYCONTAINER_MAX_LEN);

	if (SEC_RESULT_SUCCESS != SecKey_GenerateWrappedKeyAsn1Off(
			(SEC_BYTE *) &wrapped[0],
			wrapped.size(),
			type,
			wrappingId,
			(SEC_BYTE *) &iv[0],
			algorithm,
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

Sec_Result testWrappedKDFCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, SEC_OBJECTID idWrapped, Sec_KeyType keyType, SEC_BYTE counter, uint32_t L) {
	TestCtx ctx;
	if (ctx.init() != SEC_RESULT_SUCCESS) {
		SEC_LOG_ERROR("TestCtx.init failed");
		return SEC_RESULT_FAILURE;
	}

	if (NULL == ctx.provisionKey(idBase, SEC_STORAGELOC_RAM, TESTKEY_AES128, TESTKC_SOC)) {
		SEC_LOG_ERROR("TestCtx.provision failed");
		return SEC_RESULT_FAILURE;
	}

	//base key
	TestCtx::printHex("baseKey", TestCreds::asOpenSslAes(TESTKEY_AES128));

	//label
	std::vector<SEC_BYTE> otherData = TestCtx::random(10);
	//separator
	otherData.push_back(0);
	//ctx
	std::vector<SEC_BYTE> ctx2 = TestCtx::random(32);
	otherData.insert(otherData.end(), ctx2.begin(), ctx2.end());

	otherData.push_back(0); otherData.push_back(0); otherData.push_back(0); otherData.push_back(0);
	Sec_Uint32ToBEBytes(L, &otherData[otherData.size() - 4]);

	TestCtx::printHex("otherData", otherData);

	if (SEC_RESULT_SUCCESS != SecKey_Derive_CMAC_AES128(ctx.proc(),
	        idDerived, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM,
	        idBase,
	        &otherData[0], otherData.size(),
	        &counter, 1)) {
		SEC_LOG_ERROR("SecKey_Derive_CMAC_AES128 failed");
		return SEC_RESULT_FAILURE;
	}

	//create wrapped key protected by CMAC_AES128 derived key
	std::vector<SEC_BYTE> clear = TestCtx::random(SecKey_GetKeyLenForKeyType(keyType));
	TestCtx::printHex("key", clear);

	std::vector<SEC_BYTE> wrapped = asn1(ctx.proc(), clear, keyType, idDerived, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING);
	if (wrapped.size() == 0) {
		SEC_LOG_ERROR("asn1 failed");
		return SEC_RESULT_FAILURE;
	}

	if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idWrapped, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1, &wrapped[0], wrapped.size())) {
		SEC_LOG_ERROR("SecKey_Provision failed");
		return SEC_RESULT_FAILURE;
	}

	if (SecKey_IsAES(keyType)) {
		if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idWrapped, &clear[0], clear.size())) {
			SEC_LOG_ERROR("aesKeyCheck failed");
			return SEC_RESULT_FAILURE;
		}
	} else {
		if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idWrapped, &clear[0], clear.size())) {
			SEC_LOG_ERROR("macCheck failed");
		return SEC_RESULT_FAILURE;
		}
	}


	SecKey_Delete(ctx.proc(), idDerived);

	return SEC_RESULT_SUCCESS;
}

Sec_Result testExportedKDFCMACAES128(SEC_OBJECTID idDerived, SEC_OBJECTID idBase, SEC_OBJECTID idWrapped, Sec_KeyType keyType, SEC_BYTE counter, uint32_t L) {
    TestCtx ctx;
    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    if (NULL == ctx.provisionKey(idBase, SEC_STORAGELOC_RAM, TESTKEY_AES128, TESTKC_SOC)) {
        SEC_LOG_ERROR("TestCtx.provision failed");
        return SEC_RESULT_FAILURE;
    }

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idBase, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idBase,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    //base key
    TestCtx::printHex("baseKey", TestCreds::asOpenSslAes(TESTKEY_AES128));

    //label
    std::vector<SEC_BYTE> otherData = TestCtx::random(10);
    //separator
    otherData.push_back(0);
    //ctx
    std::vector<SEC_BYTE> ctx2 = TestCtx::random(32);
    otherData.insert(otherData.end(), ctx2.begin(), ctx2.end());

    otherData.push_back(0); otherData.push_back(0); otherData.push_back(0); otherData.push_back(0);
    Sec_Uint32ToBEBytes(L, &otherData[otherData.size() - 4]);

    TestCtx::printHex("otherData", otherData);

    if (SEC_RESULT_SUCCESS != SecKey_Derive_CMAC_AES128(ctx.proc(),
            idDerived, SEC_KEYTYPE_AES_128, SEC_STORAGELOC_RAM,
            idBase,
            &otherData[0], otherData.size(),
            &counter, 1)) {
        SEC_LOG_ERROR("SecKey_Derive_CMAC_AES128 failed");
        return SEC_RESULT_FAILURE;
    }

    //create wrapped key protected by CMAC_AES128 derived key
    std::vector<SEC_BYTE> clear = TestCtx::random(SecKey_GetKeyLenForKeyType(keyType));
    TestCtx::printHex("key", clear);

    std::vector<SEC_BYTE> wrapped = asn1(ctx.proc(), clear, keyType, idDerived, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING);
    if (wrapped.size() == 0) {
        SEC_LOG_ERROR("asn1 failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idWrapped, SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_ASN1, &wrapped[0], wrapped.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idWrapped, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idWrapped, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }


    SecKey_Delete(ctx.proc(), idDerived);

    return SEC_RESULT_SUCCESS;
}

Sec_Result testExportWrappedEccAesAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainEcAesAes(key, kc, id, aesType, asymAlg, symAlg);
    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    SEC_OBJECTID idContentKey = id-1;

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idContentKey, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idContentKey,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idContentKey, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testExportWrappedEccAes(TestKey key, TestKc kc, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    std::vector<ProvKey> keys = TestCreds::getWrappedContentKeyChainEcAes(key, kc, id, asymAlg);
    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    SEC_OBJECTID idContentKey = id-1;

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idContentKey, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idContentKey,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idContentKey, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

static std::vector<ProvKey> getWrappedContentKeyChainGeneratedEcAes(TestKey contentKey, EC_KEY* ec_key, SEC_OBJECTID base_id, Sec_CipherAlgorithm asymAlg) {
  std::vector<ProvKey> res;

  //generate key1
  std::shared_ptr<ProvKey> wrappedKey1(TestCreds::wrapAesWithEc(TestCreds::asOpenSslAes(contentKey).data(), TestCreds::getKeyType(contentKey), ec_key, base_id, asymAlg));
  res.push_back(*wrappedKey1);

  return res;
}

static bool _Is_Valid_Point(EC_KEY* ec_key, const std::vector<SEC_BYTE> data)
{
    if (data.size() != SEC_ECC_NISTP256_KEY_LEN) {
        SEC_LOG_ERROR("Input size needed != One BIGNUM");
        return false;
    }

    // Convert the input buffer to be encrypted to a BIGNUM
    std::shared_ptr<BIGNUM> inputAsBN(BN_new(), BN_free);
    if (inputAsBN.get() == NULL) {
        SEC_LOG_ERROR("BN_new failed");
        return false;
    }

    if (BN_bin2bn(&data[0], data.size(), inputAsBN.get()) == NULL) {
        SEC_LOG_ERROR("BN_bin2bn failed.");
        return false;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (NULL == group) {
        SEC_LOG_ERROR("EC_KEY_get0_group failed");
        return false;
    }

    std::shared_ptr<BN_CTX> ctx(BN_CTX_new(), BN_CTX_free);
    if (ctx.get() == NULL) {
        SEC_LOG_ERROR("BN_CTX_new failed");
        return false;
    }

    std::shared_ptr<EC_POINT> pt(EC_POINT_new(group), EC_POINT_free);
    if (pt.get() == NULL) {
        SEC_LOG_ERROR("EC_POINT_new failed");
        return false;
    }

    if (!EC_POINT_set_compressed_coordinates_GFp(group, pt.get(), inputAsBN.get(), 0, ctx.get())) {
        SEC_LOG_ERROR("EC_POINT_set_compressed_coordinates_GFp failed");
        return false;
    }

    return true;
}

template <typename T> std::vector<T> concat(std::vector<T> &a, std::vector<T> &b) {
    std::vector<T> ret = std::vector<T>();
    std::copy(a.begin(), a.end(), std::back_inserter(ret));
    std::copy(b.begin(), b.end(), std::back_inserter(ret));
    return ret;
}

static std::vector<ProvKey> getWrappedContentKeyChainGeneratedEcAesAes(TestKey contentKey, EC_KEY* ec_key, SEC_OBJECTID base_id, Sec_KeyType aesType, Sec_CipherAlgorithm asymAlg, Sec_CipherAlgorithm symAlg) {
  std::vector<ProvKey> res;

  //generate key1
  std::vector<SEC_BYTE> key1 = TestCtx::random(SecKey_GetKeyLenForKeyType(aesType));
  while (!_Is_Valid_Point(ec_key, (SecKey_GetKeyLenForKeyType(aesType) == 16) ? concat(key1, key1) : key1)) {
      SEC_PRINT("Not a valid point.  Regenerating.\n");
      key1 = TestCtx::random(SecKey_GetKeyLenForKeyType(aesType));
  }

  std::shared_ptr<ProvKey> wrappedKey1(TestCreds::wrapAesWithEc(&key1[0], aesType, ec_key, base_id, asymAlg));
  res.push_back(*wrappedKey1);

  //generate key2
  std::shared_ptr<ProvKey> wrappedKey2(TestCreds::wrapAesWithAes(TestCreds::asOpenSslAes(contentKey).data(), TestCreds::getKeyType(contentKey), &key1[0], aesType, base_id+1, symAlg));
  res.push_back(*wrappedKey2);

  return res;
}

static EC_KEY *_ECCFromPubBinary(Sec_ECCRawPublicKey *binary)
{
    BN_CTX *ctx = BN_CTX_new();

    if (   binary->type != SEC_KEYTYPE_ECC_NISTP256_PUBLIC
        && binary->type != SEC_KEYTYPE_ECC_NISTP256)
        return NULL;

    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //create ec_key structure with NIST p256 curve;
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    BN_CTX_start(ctx);
    BIGNUM *xp, *yp;

    if (((xp = BN_CTX_get(ctx)) == NULL) || ((yp = BN_CTX_get(ctx)) == NULL))
        goto done;

    EC_POINT_set_affine_coordinates_GFp(group, ec_point,
                                        BN_bin2bn(binary->x, Sec_BEBytesToUint32(binary->key_len), xp),
                                        BN_bin2bn(binary->y, Sec_BEBytesToUint32(binary->key_len), yp), ctx);
    EC_KEY_set_public_key(ec_key, ec_point);

done:
    EC_POINT_free(ec_point);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);

    return ec_key;
}

static EC_KEY* generateEcAndGetPublic(TestCtx& ctx, SEC_OBJECTID id) {
    Sec_KeyHandle *ecKey = ctx.provisionKey(id, SEC_STORAGELOC_RAM, TESTKEY_EC_PRIV, TESTKC_GENERATED, SEC_FALSE);
    if (ecKey == NULL) {
        SEC_LOG_ERROR("provisionKey failed");
        return NULL;
    }

    Sec_ECCRawPublicKey public_key;
    memset(&public_key, 0, sizeof(public_key));
    if (SEC_RESULT_SUCCESS != SecKey_ExtractECCPublicKey(ecKey, &public_key)) {
        SEC_LOG_ERROR("SecKey_ExtractECCPublicKey failed");
        return NULL;
    }

    EC_KEY* openssl_key = _ECCFromPubBinary(&public_key);
    if (openssl_key == NULL) {
        SEC_LOG_ERROR("_ECCFromPubBinary failed");
        return NULL;
    }

    return openssl_key;
}

Sec_Result testExportWrappedGeneratedEccAesAes(TestKey key, Sec_CipherAlgorithm asymAlg, Sec_KeyType aesType, Sec_CipherAlgorithm symAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    EC_KEY* pub_ec = generateEcAndGetPublic(ctx, id);
    std::vector<ProvKey> keys = getWrappedContentKeyChainGeneratedEcAesAes(key, pub_ec, id, aesType, asymAlg, symAlg);

    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    //generated key is alreay provisioned
    id++;

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    SEC_OBJECTID idContentKey = id-1;

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idContentKey, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idContentKey,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idContentKey, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result testExportWrappedGeneratedEccAes(TestKey key, Sec_CipherAlgorithm asymAlg, WrappedKeyFormatVersion wkfv) {
    TestCtx ctx;

    if (ctx.init() != SEC_RESULT_SUCCESS) {
        SEC_LOG_ERROR("TestCtx.init failed");
        return SEC_RESULT_FAILURE;
    }

    SEC_OBJECTID id = SEC_OBJECTID_USER_BASE;

    EC_KEY* pub_ec = generateEcAndGetPublic(ctx, id);
    std::vector<ProvKey> keys = getWrappedContentKeyChainGeneratedEcAes(key, pub_ec, id, asymAlg);

    if (keys.size() == 0) {
        SEC_LOG_ERROR("TestCreds::getWrappedContentKeyChain failed");
        return SEC_RESULT_FAILURE;
    }

    //generated key is alreay provisioned
    id++;

    switch (wkfv) {
        case WKFV_V2: {
            for (unsigned int i=0; i<keys.size(); ++i) {
                if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, keys[i].kc,
                        &keys[i].key[0], keys[i].key.size())) {
                    SEC_LOG_ERROR("SecKey_Provision[%d] failed", i);
                    return SEC_RESULT_FAILURE;
                }
            }
        }
        break;

        case WKFV_V3: {
            ProvKey v3Key = convertV2ToV3(keys);
            if (v3Key.key.size() == 0) {
                SEC_LOG_ERROR("convertV2ToV3 failed");
                return SEC_RESULT_FAILURE;
            }

            if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), id++, SEC_STORAGELOC_RAM, v3Key.kc,
                    &v3Key.key[0], v3Key.key.size())) {
                SEC_LOG_ERROR("SecKey_Provision failed");
                return SEC_RESULT_FAILURE;
            }
        }
        break;

        default:
            SEC_LOG_ERROR("Unknown WKFT encountered: %d", wkfv);
            return SEC_RESULT_FAILURE;
            break;
    }

    SEC_OBJECTID idContentKey = id-1;

    //export content key
    std::vector<SEC_BYTE> derivation_input = TestCtx::random(SEC_AES_BLOCK_SIZE);
    std::vector<SEC_BYTE> exported_key;
    exported_key.resize(SEC_KEYCONTAINER_MAX_LEN);
    SEC_SIZE exported_len;

    Sec_KeyHandle *keyHandle;
    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(ctx.proc(), idContentKey, &keyHandle)) {
        SEC_LOG_ERROR("SecKey_GetInstance failed");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKey_ExportKey(keyHandle, &derivation_input[0], &exported_key[0], exported_key.size(), &exported_len)) {
        SEC_LOG_ERROR("SecKey_ExportKey failed");
        SecKey_Release(keyHandle);
        return SEC_RESULT_FAILURE;
    }
    exported_key.resize(exported_len);
    SecKey_Release(keyHandle);

    //provision exported
    if (SEC_RESULT_SUCCESS != SecKey_Provision(ctx.proc(), idContentKey,
            SEC_STORAGELOC_RAM, SEC_KEYCONTAINER_EXPORTED, &exported_key[0], exported_key.size())) {
        SEC_LOG_ERROR("SecKey_Provision failed");
        return SEC_RESULT_FAILURE;
    }

    Sec_KeyType keyType = TestCreds::getKeyType(key);
    std::vector<SEC_BYTE> clear = TestCreds::asOpenSslAes(key);

    if (SEC_RESULT_SUCCESS != cipherEncDecSingle(&ctx, idContentKey, SEC_CIPHERALGORITHM_AES_ECB_NO_PADDING, 256)) {
        SEC_LOG_ERROR("cipherEncDecSingle failed");
        return SEC_RESULT_FAILURE;
    }

    if (SecKey_IsAES(keyType)) {
        if (SEC_RESULT_SUCCESS != aesKeyCheck(ctx.proc(), idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("aesKeyCheck failed");
            return SEC_RESULT_FAILURE;
        }
    } else {
        if (SEC_RESULT_SUCCESS != macCheck(ctx.proc(), SEC_MACALGORITHM_HMAC_SHA256, idContentKey, &clear[0], clear.size())) {
            SEC_LOG_ERROR("macCheck failed");
        return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}
