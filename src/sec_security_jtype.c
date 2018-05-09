#include "sec_security.h"
#include "sec_security_utils.h"
#include "sec_security_json.h"
#include <string.h>

typedef struct _HeaderClaims
{
    char alg[32];
    char kid[32]; /* device auth session id */
}HeaderClaims;

void DumpKeyProps(Sec_KeyProperties *p)
{
    int i;
    SEC_PRINT("KeyProperties:\n");
    SEC_PRINT("    keyid        : %s\n", p->keyId);
    SEC_PRINT("    notBefore    : %s\n", p->notBefore);
    SEC_PRINT("    notOnOrAfter : %s\n", p->notOnOrAfter);
    SEC_PRINT("    cacheable    : %s\n", p->cacheable == 0x01 ? "true" : "false");
    SEC_PRINT("    keyType      : %d\n", p->keyType);
    SEC_PRINT("    keyLen       : %d\n", p->keyLength);
    SEC_PRINT("    usage        : %d\n", p->usage);
    SEC_PRINT("    rights       : ");
    for (i=0;i<8;i++)
        SEC_PRINT("0x%02x, ", p->rights[i]);
    SEC_PRINT("\n");
}

static Sec_Result _load_json_char_value(Sec_JsonVal *json_parsed, const char *json_key_name, char *out_buffer, SEC_SIZE out_buffer_size)
{
    Sec_Result ret = SEC_RESULT_FAILURE;
    Sec_JsonVal *tmp_json_value = NULL;
    const char *value = NULL;
    size_t val_len = 0;

    if ( NULL == (tmp_json_value = SecJson_GetObjEntry(json_parsed, json_key_name)))
    {
        SEC_LOG_ERROR("SecJson_GetObjEntry '%s' failed", json_key_name);
        goto done;
    }
    value = SecJson_GetValue(tmp_json_value);
    if ( NULL == value || strlen(value) == 0 )
    {
        SEC_LOG_ERROR("SecJson_GetValue '%s' failed", json_key_name);
        goto done;
    }
    val_len = strlen(value);
    if ( out_buffer_size <= val_len )
    {
        SEC_LOG_ERROR("json output buffer too small for '%s' value", json_key_name);
        goto done;
    }
    strncpy(out_buffer, value, val_len);
    out_buffer[val_len] = '\0';
    ret = SEC_RESULT_SUCCESS;
done:
    return ret;
}


static Sec_Result SecJwt_Verify(Sec_ProcessorHandle *proc,
        SEC_OBJECTID mac_kid, const HeaderClaims *headerClaims,
        const SEC_BYTE *sigdata, SEC_SIZE sigdataLen, const SEC_BYTE *signature,
        SEC_SIZE signatureLen)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    Sec_KeyHandle *macKeyHandle = NULL;
    Sec_MacHandle *macHandle = NULL;
    SEC_BYTE mac_buf[64];
    SEC_SIZE mac_buf_size = 64;
    Sec_MacAlgorithm secMacAlg;
    SEC_BYTE *decodedSig = NULL;
    SEC_SIZE decodedSigLen = 0;
    SEC_BYTE *tmpSigdata = NULL;

    /* decode sig data */
    decodedSigLen = SecUtils_Base64DecodeLength(signatureLen);
    decodedSig = calloc(1,decodedSigLen);
    if (SEC_RESULT_SUCCESS
            != SecUtils_Base64UrlDecode(signature, signatureLen, decodedSig, decodedSigLen,
                    &decodedSigLen))
    {
        SEC_LOG_ERROR("failed to b64 decode signature");
        goto done;
    }

    if (!strcmp("HS256", headerClaims->alg))
    {
        if (decodedSigLen != 32)
        {
            SEC_LOG_ERROR("Signature data does not match expected size. expected=%lu, received=%lu",
                    32, decodedSigLen);
            goto done;
        }
        secMacAlg = SEC_MACALGORITHM_HMAC_SHA256;
    }
    else
    {
        SEC_LOG_ERROR("Unsupported header alg `%s`", headerClaims->alg);
        goto done;
    }

    /* get around const for mac update */
    tmpSigdata = calloc(1, sigdataLen);
    memcpy(tmpSigdata,sigdata,sigdataLen);


    if (SEC_RESULT_SUCCESS != SecKey_GetInstance(proc, mac_kid, &macKeyHandle))
    {
        SEC_LOG_ERROR("Could not get key handle for session mac key. `" SEC_OBJECTID_PATTERN "'", mac_kid );
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecMac_GetInstance(proc,secMacAlg, macKeyHandle, &macHandle))
    {
        SEC_LOG_ERROR("Could not get mac handle for JWT key");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecMac_Update(macHandle, tmpSigdata, sigdataLen))
    {
        SEC_LOG_ERROR("SecMac_Update failed");
        goto done;
    }
    if (SEC_RESULT_SUCCESS != SecMac_Release(macHandle, mac_buf, &mac_buf_size))
    {
        SEC_LOG_ERROR("SecMac_Release failed.");
        goto done;
    }
    macHandle = NULL;

    if (decodedSigLen != mac_buf_size)
    {
            SEC_LOG_ERROR("Computed signature data does not match expected size. expected=%lu, received=%lu",
                    decodedSigLen, mac_buf_size);
        goto done;
    }
    if ( 0!= memcmp(mac_buf, decodedSig, mac_buf_size) )
    {
        SEC_LOG_ERROR("Mac bytes mismatch, jtype key auth failure.");
        SEC_PRINT("computed: ");
        Sec_PrintHex(mac_buf, mac_buf_size);
        SEC_PRINT("\nexpected: ");
        Sec_PrintHex(decodedSig, mac_buf_size);
        SEC_PRINT("\n");
        goto done;
    }

    status = SEC_RESULT_SUCCESS;

    done:

    if (NULL != decodedSig)
        free(decodedSig);

    if (NULL != tmpSigdata)
        free(tmpSigdata);

    if (NULL != macKeyHandle)
        SecKey_Release(macKeyHandle);

    if (NULL != macHandle)
        SecMac_Release(macHandle, mac_buf, &mac_buf_size);

    return status;
}

static Sec_Result SecJwt_DecodeHeader(const char* jsonHeader, HeaderClaims *headerClaims)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    Sec_JsonVal *jsonParsedVal = NULL;

    if ( NULL == (jsonParsedVal = SecJson_Parse(jsonHeader)))
    {
        SEC_LOG_ERROR("json parse failed");
        goto done;
    }
    if ( SEC_RESULT_SUCCESS != _load_json_char_value(jsonParsedVal, "alg", headerClaims->alg, sizeof(headerClaims->alg)))
    {
        SEC_LOG_ERROR("Json parse object name 'alg'");
        goto done;
    }
    if ( SEC_RESULT_SUCCESS != _load_json_char_value(jsonParsedVal, "kid", headerClaims->kid, sizeof(headerClaims->kid)))
    {
        SEC_LOG_ERROR("Json parse object name 'kid'");
        goto done;
    }

    status = SEC_RESULT_SUCCESS;

    done:

    if (NULL != jsonParsedVal)
        SecJson_ValFree(jsonParsedVal);

    return status;
}

/* 1. Parse the jwt token into header/payload and signature
 * 2. Verify the header+payload using macingKid
 * 3. B64Decode the payload into out_jsonPayload buffer
 */
static Sec_Result SecJwt_ProcessToken(Sec_ProcessorHandle *proc,
        const SEC_BYTE *jwtBytes, SEC_SIZE jwtLen, SEC_OBJECTID macingKid,
        char **out_jsonPayload)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    const SEC_BYTE *header = jwtBytes;
    const SEC_BYTE *payload = jwtBytes;
    const SEC_BYTE *signature = jwtBytes;
    const SEC_BYTE *tokenIdx = jwtBytes;
    SEC_SIZE headerLen = 0, payloadLen = 0, signatureLen = 0;
    char *jsonHeader = NULL;
    SEC_SIZE jsonLen = 0;
    int tokenCount = 0;
    HeaderClaims headerClaims;


    if (NULL == jwtBytes || jwtLen == 0)
    {
        SEC_LOG_ERROR("empty token");
        goto done;
    }

    for (; tokenIdx < (jwtBytes + jwtLen) && tokenCount < 3; tokenIdx++)
    {
        if (*tokenIdx == '.')
        {
            tokenCount++;
            if (tokenCount == 1)
            {
                // Found the first .
                headerLen = (tokenIdx - jwtBytes);
                payload = (tokenIdx + 1);
            }
            if (tokenCount == 2)
            {
                // Found the 2nd .
                payloadLen = (tokenIdx - payload);
                signatureLen = jwtLen - (tokenIdx - jwtBytes) - 1;
                signature = tokenIdx + 1;
            }
        }
    }

    if (tokenCount != 2)
    {
        SEC_LOG_ERROR("Invalid token count in jtype key container");
        goto done;
    }

    /* decode header */
    jsonLen = SecUtils_Base64DecodeLength(headerLen);
    jsonHeader = (char*)calloc(1, jsonLen+1);
    if (SEC_RESULT_SUCCESS != SecUtils_Base64UrlDecode(header,headerLen, (SEC_BYTE*)jsonHeader, jsonLen+1,  &jsonLen))
    {
        SEC_LOG_ERROR("base64url decode header failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecJwt_DecodeHeader(jsonHeader,&headerClaims))
    {
        SEC_LOG_ERROR("json decode header failed");
        goto done;
    }
//    SEC_LOG("header: alg=%s, kid=%s", headerClaims.alg, headerClaims.kid);

    if (SEC_RESULT_SUCCESS != SecJwt_Verify(proc, macingKid, &headerClaims, header, headerLen + payloadLen +1, signature, signatureLen))
    {
        SEC_LOG_ERROR("SVP verification failed");
        goto done;
    }

    jsonLen = SecUtils_Base64DecodeLength(payloadLen);
    *out_jsonPayload = (char*)calloc(1, jsonLen + 1);
    if (SEC_RESULT_SUCCESS != SecUtils_Base64UrlDecode(payload, payloadLen, (SEC_BYTE*)*out_jsonPayload, jsonLen+1, &jsonLen))
    {
        free(*out_jsonPayload);
        SEC_LOG_ERROR("base64url decode payload claims failed");
        goto done;
    }

    status = SEC_RESULT_SUCCESS;

    done:

    if (NULL!= jsonHeader)
        free(jsonHeader);

    return status;
}


static Sec_Result SecJType_DecodePayload(const char* jsonPayload,
        Sec_KeyProperties *out_keyProps, SEC_BYTE *wrappedKeyBuf,
        SEC_SIZE wrappedKeyBufSize, SEC_SIZE *keyBytesWritten)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    Sec_JsonVal *jsonParsedVal = NULL;
    char tmpchars[1024];
    SEC_BYTE tmpbytes[1024];
    SEC_SIZE tmpsize = 0;
    int i;
    SEC_SIZE epoch = 0;

    memset(out_keyProps, 0, sizeof(Sec_KeyProperties));

    /* For now, only aes-128 keys are provisioned in jtype container */
    out_keyProps->keyType = SEC_KEYTYPE_AES_128;
    out_keyProps->keyLength = SecKey_GetKeyLenForKeyType(out_keyProps->keyType);

    if ( NULL == (jsonParsedVal = SecJson_Parse(jsonPayload)))
    {
        SEC_LOG_ERROR("json parse failed");
        goto done;
    }

    /* contnetKeyId */
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyId", out_keyProps->keyId,
                    sizeof(out_keyProps->keyId)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyId'");
        goto done;
    }

    /* notBefore */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyNotBefore", out_keyProps->notBefore, sizeof(out_keyProps->notBefore)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyNotBefore'");
        goto done;
    }
    if (SEC_INVALID_EPOCH == SecUtils_IsoTime2Epoch(out_keyProps->notBefore, &epoch))
    {
        SEC_LOG_ERROR("contentKeyNotBefore time conversion failed, %s", out_keyProps->notBefore);
        goto done;
    }

    /* notAfter */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyNotOnOrAfter", out_keyProps->notOnOrAfter, sizeof(out_keyProps->notOnOrAfter)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyNotOnOrAfter'");
        goto done;
    }
    if (SEC_INVALID_EPOCH == SecUtils_IsoTime2Epoch(out_keyProps->notOnOrAfter, &epoch))
    {
        SEC_LOG_ERROR("contentKeyNotOnOrAfter time conversion failed, %s", out_keyProps->notOnOrAfter);
        goto done;
    }

    /* key output rights */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyRights", tmpchars, sizeof(tmpchars)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyRights'");
        goto done;
    }
    if (SecUtils_Base64Decode((SEC_BYTE*)tmpchars, strlen(tmpchars), tmpbytes, sizeof(tmpbytes), &tmpsize))
    {
        SEC_LOG_ERROR("base64 decode failed for key rights");
        goto done;
    }
    if (tmpsize > sizeof(out_keyProps->rights))
    {
        SEC_LOG_ERROR("key rights buffer too small, decoded=%u, max=%u",
                tmpsize, sizeof(out_keyProps->rights));
        goto done;
    }
    memset(out_keyProps->rights, 0, sizeof(out_keyProps->rights));
    memcpy(out_keyProps->rights, tmpbytes, tmpsize);

    /* validate rights */
    for(i=0;i<sizeof(out_keyProps->rights);i++)
    {
        switch(out_keyProps->rights[i])
        {
            case SEC_KEYOUTPUTRIGHT_NOT_SET:
            case SEC_KEYOUTPUTRIGHT_SVP_REQUIRED:
            case SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED:
            case SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED:
            case SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED:
            case SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED:
            case SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED:
            case SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED:
                break;
            default:
                SEC_LOG_ERROR("Invalid output right '%02X'", out_keyProps->rights[i]);
                goto done;
        }
    }

    /* key usage */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyUsage", tmpchars, sizeof(tmpchars)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyUsage'");
        goto done;
    }
    out_keyProps->usage = atoi(tmpchars);
    switch(out_keyProps->usage)
    {
        case SEC_KEYUSAGE_DATA_KEY:
        case SEC_KEYUSAGE_DATA:
        case SEC_KEYUSAGE_KEY:
            break;
        default:
            SEC_LOG_ERROR("Invalid key usage value '%d'",
                    out_keyProps->usage);
            goto done;
    }


    /* key cacheable */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKeyCacheable", tmpchars, sizeof(tmpchars)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKeyCacheable'");
        goto done;
    }
    out_keyProps->cacheable = 0==strcmp("true",tmpchars) ? 1 : 0;


    /* wrapped key */
    memset(tmpchars,0,sizeof(tmpchars));
    if (SEC_RESULT_SUCCESS
            != _load_json_char_value(jsonParsedVal, "contentKey", tmpchars, sizeof(tmpchars)))
    {
        SEC_LOG_ERROR("Json parse object 'contentKey'");
        goto done;
    }
    if (SecUtils_Base64Decode((SEC_BYTE*)tmpchars, strlen(tmpchars), wrappedKeyBuf, wrappedKeyBufSize, keyBytesWritten))
    {
        SEC_LOG_ERROR("base64 decode failed for encrypted key");
        goto done;
    }

    status = SEC_RESULT_SUCCESS;

    done:

    if (NULL != jsonParsedVal)
        SecJson_ValFree(jsonParsedVal);

    return status;
}

/* 1. Decode and verify the JWT key to get the paload claims.
 * 2. Decode the payload claims to get the key properties and wrapped key
 */
Sec_Result SecJType_ProcessKey(Sec_ProcessorHandle *proc,
        SEC_OBJECTID macingKid, const void *jwtToken,
        SEC_SIZE jwtTokenLen, SEC_BYTE *out_wrappedKey, SEC_SIZE wrappedKeyBufSize,
        SEC_SIZE *out_wrappedKeyWritten, Sec_KeyProperties *out_keyProps)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    char *payloadClaims = NULL;

    if (SEC_RESULT_SUCCESS != SecJwt_ProcessToken(proc, jwtToken, jwtTokenLen, macingKid, &payloadClaims))
    {
        SEC_LOG_ERROR("SecJType failed");
        goto done;
    }

    /* parse payload */
    if (SEC_RESULT_SUCCESS != SecJType_DecodePayload(payloadClaims, out_keyProps, out_wrappedKey, wrappedKeyBufSize, out_wrappedKeyWritten))
    {
        SEC_LOG_ERROR("SecJType failed.");
        goto done;
    }

    status = SEC_RESULT_SUCCESS;

    done:

    if (NULL != payloadClaims)
        free(payloadClaims);

    return status;
}

