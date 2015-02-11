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

#include "sec_security.h"
#include "sec_security_asn1kc.h"
#include "Asn1KC.h"
#include <errno.h>

int asn_INTEGER2int64(const INTEGER_t *iptr, int64_t *lptr) {
    uint8_t *b, *end;
    size_t size;
    int64_t l;

    /* Sanity checking */
    if(!iptr || !iptr->buf || !lptr) {
        errno = EINVAL;
        return -1;
    }

    /* Cache the begin/end of the buffer */
    b = iptr->buf;    /* Start of the INTEGER buffer */
    size = iptr->size;
    end = b + size;    /* Where to stop */

    if(size > sizeof(int64_t)) {
        uint8_t *end1 = end - 1;
        /*
         * Slightly more advanced processing,
         * able to >sizeof(int64_t) bytes,
         * when the actual value is small
         * (0x0000000000abcdef would yield a fine 0x00abcdef)
         */
        /* Skip out the insignificant leading bytes */
        for(; b < end1; b++) {
            switch(*b) {
            case 0x00: if((b[1] & 0x80) == 0) continue; break;
            case 0xff: if((b[1] & 0x80) != 0) continue; break;
            }
            break;
        }

        size = end - b;
        if(size > sizeof(int64_t)) {
            /* Still cannot fit the int64_t */
            errno = ERANGE;
            return -1;
        }
    }

    /* Shortcut processing of a corner case */
    if(end == b) {
        *lptr = 0;
        return 0;
    }

    /* Perform the sign initialization */
    /* Actually l = -(*b >> 7); gains nothing, yet unreadable! */
    if((*b >> 7)) l = -1; else l = 0;

    /* Conversion engine */
    for(; b < end; b++)
        l = (l << 8) | *b;

    *lptr = l;

    return 0;
}

int asn_INTEGER2uint64(const INTEGER_t *iptr, uint64_t *lptr) {
    uint8_t *b, *end;
    uint64_t l;
    size_t size;

    if(!iptr || !iptr->buf || !lptr) {
        errno = EINVAL;
        return -1;
    }

    b = iptr->buf;
    size = iptr->size;
    end = b + size;

    /* If all extra leading bytes are zeroes, ignore them */
    for(; size > sizeof(uint64_t); b++, size--) {
        if(*b) {
            /* Value won't fit uint64_t */
            errno = ERANGE;
            return -1;
        }
    }

    /* Conversion engine */
    for(l = 0; b < end; b++)
        l = (l << 8) | *b;

    *lptr = l;

    return 0;
}
int asn_int642INTEGER(INTEGER_t *st, int64_t value) {
    uint8_t *buf, *bp;
    uint8_t *p;
    uint8_t *pstart;
    uint8_t *pend1;
    int littleEndian = 1;    /* Run-time detection */
    int add;

    if(!st) {
        errno = EINVAL;
        return -1;
    }

    buf = (uint8_t *)MALLOC(sizeof(value));
    if(!buf) return -1;

    if(*(char *)&littleEndian) {
        pstart = (uint8_t *)&value + sizeof(value) - 1;
        pend1 = (uint8_t *)&value;
        add = -1;
    } else {
        pstart = (uint8_t *)&value;
        pend1 = pstart + sizeof(value) - 1;
        add = 1;
    }

    /*
     * If the contents octet consists of more than one octet,
     * then bits of the first octet and bit 8 of the second octet:
     * a) shall not all be ones; and
     * b) shall not all be zero.
     */
    for(p = pstart; p != pend1; p += add) {
        switch(*p) {
        case 0x00: if((*(p+add) & 0x80) == 0)
                continue;
            break;
        case 0xff: if((*(p+add) & 0x80))
                continue;
            break;
        }
        break;
    }
    /* Copy the integer body */
    for(pstart = p, bp = buf, pend1 += add; p != pend1; p += add)
        *bp++ = *p;

    if(st->buf) FREEMEM(st->buf);
    st->buf = buf;
    st->size = bp - buf;

    return 0;
}

int asn_uint642INTEGER(INTEGER_t *st, uint64_t value) {
    uint8_t *buf;
    uint8_t *end;
    uint8_t *b;
    int shr;

    if(value <= INT64_MAX)
        return asn_int642INTEGER(st, value);

    buf = (uint8_t *)MALLOC(1 + sizeof(value));
    if(!buf) return -1;

    end = buf + (sizeof(value) + 1);
    buf[0] = 0;
    for(b = buf + 1, shr = (sizeof(int64_t)-1)*8; b < end; shr -= 8, b++)
        *b = (uint8_t)(value >> shr);

    if(st->buf) FREEMEM(st->buf);
    st->buf = buf;
    st->size = 1 + sizeof(value);

    return 0;
}

static Asn1KCAttribute_t *SecAsn1KC_AllocAttr()
{
    Asn1KCAttribute_t *ptr = NULL;

    ptr = (Asn1KCAttribute_t *) calloc(1, sizeof(Asn1KCAttribute_t));
    if (ptr == NULL)
    {
        SEC_LOG_ERROR("calloc failed");
        return ptr;
    }

    return ptr;
}

static Sec_Result SecAsn1KC_AddAttr(Sec_Asn1KC *kc, Asn1KCAttribute_t *attribute)
{
    if (asn_set_add(&kc->list, attribute) != 0)
    {
        SEC_LOG_ERROR("asn_set_add failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Asn1KCAttribute_t *SecAsn1KC_GetAttr(Sec_Asn1KC *kc, const char *key)
{
    SEC_SIZE i;

    for (i=0; i<kc->list.count; ++i)
    {
        if (strlen(key) == kc->list.array[i]->key.size &&
            0 == Sec_Memcmp(key, kc->list.array[i]->key.buf, kc->list.array[i]->key.size))
        {
            return kc->list.array[i];
        }
    }

    return NULL;
}

SEC_BOOL SecAsn1KC_HasAttr(Sec_Asn1KC *kc, const char *key)
{
    return SecAsn1KC_GetAttr(kc, key) != NULL;
}

Sec_Result SecAsn1KC_GetAttrLong(Sec_Asn1KC *kc, const char *key, long *val)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_integer)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    if (0 != asn_INTEGER2long(&attr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_INTEGER2long failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t *val)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_integer)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    if (0 != asn_INTEGER2int64(&attr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_INTEGER2long failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long *val)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_integer)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    if (0 != asn_INTEGER2ulong(&attr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_INTEGER2long failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t *val)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_integer)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    if (0 != asn_INTEGER2uint64(&attr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_INTEGER2long failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrBuffer(Sec_Asn1KC *kc, const char *key, SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_octetstring)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    *written = attr->value.choice.octetstring.size;
    if (buffer != NULL)
    {
        if (*written > buffer_len)
        {
            SEC_LOG_ERROR("output buffer is too small.  Needed %d", *written);
            return SEC_RESULT_FAILURE;
        }

        memcpy(buffer, attr->value.choice.octetstring.buf, *written);
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrString(Sec_Asn1KC *kc, const char *key, char *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    Asn1KCAttribute_t *attr = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1cKC_GetAttrInteger failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value.present != value_PR_ia5string)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value.present);
        return SEC_RESULT_FAILURE;
    }

    *written = attr->value.choice.ia5string.size;
    if (buffer != NULL)
    {
        if (*written >= buffer_len)
        {
            SEC_LOG_ERROR("output buffer is too small.  Needed %d", *written);
            return SEC_RESULT_FAILURE;
        }

        memcpy(buffer, attr->value.choice.octetstring.buf, *written);
        buffer[*written] = '\0';
    }

    *written += 1;

    return SEC_RESULT_SUCCESS;
}

Sec_Asn1KC *SecAsn1KC_Alloc()
{
    Sec_Asn1KC *ptr = NULL;

    ptr = (Sec_Asn1KC *) calloc(1, sizeof(Sec_Asn1KC));
    if (ptr == NULL)
    {
        SEC_LOG_ERROR("calloc failed");
        return ptr;
    }

    return ptr;
}

void SecAsn1KC_Free(Sec_Asn1KC *kc)
{
    if (kc != NULL)
    {
        ASN_STRUCT_FREE(asn_DEF_Asn1KC, kc);
    }
}

Sec_Result SecAsn1KC_AddAttrLong(Sec_Asn1KC *kc, const char *key, long val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != asn_long2INTEGER(&ptr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_long2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_integer;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != asn_int642INTEGER(&ptr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_long2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_integer;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != asn_ulong2INTEGER(&ptr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_long2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_integer;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != asn_uint642INTEGER(&ptr->value.choice.integer, val))
    {
        SEC_LOG_ERROR("asn_long2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_integer;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrString(Sec_Asn1KC *kc, const char *key, const char *val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->value.choice.ia5string, val))
    {
        SEC_LOG_ERROR("asn_ulong2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_ia5string;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrBuffer(Sec_Asn1KC *kc, const char *key, void *buf, SEC_SIZE buf_len)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr();

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromString(&ptr->key, key))
    {
        SEC_LOG_ERROR("OCTET_STRING_fromString failed");
        goto done;
    }

    if (0 != OCTET_STRING_fromBuf(&ptr->value.choice.octetstring, buf, buf_len))
    {
        SEC_LOG_ERROR("asn_ulong2INTEGER failed");
        goto done;
    }
    ptr->value.present = value_PR_octetstring;

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_Encode(Sec_Asn1KC *kc, SEC_BYTE *buf, SEC_SIZE buf_len, SEC_SIZE *written)
{
    asn_enc_rval_t rval;

    if (buf == NULL)
    {
        rval = der_encode(&asn_DEF_Asn1KC, kc, 0, 0);
    }
    else
    {
        rval = der_encode_to_buffer(&asn_DEF_Asn1KC, kc, buf, buf_len);
    }
    if (rval.encoded == -1)
    {
        SEC_LOG_ERROR("der_encode_to_buffer failed");
        return SEC_RESULT_FAILURE;
    }

    *written = rval.encoded;

    return SEC_RESULT_SUCCESS;
}

Sec_Asn1KC *SecAsn1KC_Decode(SEC_BYTE *buf, SEC_SIZE buf_len)
{
    asn_dec_rval_t rval;
    Sec_Asn1KC *ret = NULL;

    rval = ber_decode(0, &asn_DEF_Asn1KC, (void **) &ret, buf, buf_len);
    if (rval.code != RC_OK)
    {
        ASN_STRUCT_FREE(asn_DEF_Asn1KC, ret);
        SEC_LOG_ERROR("ber_decode failed");
        return NULL;
    }

    return ret;
}

#endif
