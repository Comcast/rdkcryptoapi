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

#ifndef SEC_COMMON_17

#include "sec_security.h"
#include "sec_security_asn1kc.h"
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

ASN1_CHOICE(Asn1KCAttribute_t_c) = {
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.integer,     ASN1_INTEGER),
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.bitstring,   ASN1_BIT_STRING),
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.octetstring, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.null,        ASN1_NULL),
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.ia5string,   ASN1_IA5STRING),
    ASN1_SIMPLE(Asn1KCAttribute_t_c, c.utctime,     ASN1_UTCTIME),
} ASN1_CHOICE_END(Asn1KCAttribute_t_c)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(Asn1KCAttribute_t_c)
//Implements Asn1KCAttribute_t_c_new and Asn1KCAttribute_t_c_free

ASN1_SEQUENCE(Asn1KCAttribute_t) = {
    ASN1_SIMPLE(Asn1KCAttribute_t, name, ASN1_IA5STRING),
    ASN1_OPT(Asn1KCAttribute_t, value, Asn1KCAttribute_t_c),
} ASN1_SEQUENCE_END(Asn1KCAttribute_t)
IMPLEMENT_ASN1_ALLOC_FUNCTIONS(Asn1KCAttribute_t)
//Implements Asn1KCAttribute_t_new and Asn1KCAttribute_t_free

ASN1_ITEM_TEMPLATE(Sec_Asn1KC) =
ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SET_OF, 0, Sec_Asn1KC, Asn1KCAttribute_t)
ASN1_ITEM_TEMPLATE_END(Sec_Asn1KC)
IMPLEMENT_ASN1_FUNCTIONS(Sec_Asn1KC)
IMPLEMENT_ASN1_PRINT_FUNCTION(Sec_Asn1KC)  //PRINTF
//Implements Sec_Asn1KC_new, Sec_Asn1KC_free, d2i_Sec_Asn1KC i2d_Sec_Asn1KC

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static Sec_Result getBE_ASN1_INTEGER(SEC_BYTE* res, const ASN1_INTEGER *ai, SEC_SIZE size, SEC_BOOL signd)
{
    BIGNUM *bn = NULL;
    int bn_size = 0;

    if(ai == NULL || res == NULL) {
        SEC_LOG_ERROR("failed invalid input");
        return SEC_RESULT_FAILURE;
    }

    bn = ASN1_INTEGER_to_BN(ai, NULL);
    if(bn == NULL) {
        SEC_LOG_ERROR("failed ASN1_INTEGER_to_BN");
        return SEC_RESULT_FAILURE;
    }

    bn_size = BN_num_bytes(bn);
    memset(res, 0, size);
    if(bn_size == 0)
    {
        //Special case size == 0 means the integer value is 0;
        BN_free(bn);
        return SEC_RESULT_SUCCESS;
    }

    SEC_SIZE offset = size - bn_size;
    if (!BN_bn2bin(bn, (res + offset))) {
        BN_free(bn);
        SEC_LOG_ERROR("BN_bn2bin failed offset = %d, res = %p, size = %d", offset, res, size);
        return SEC_RESULT_FAILURE;
    }

    // If needed extend sign bits
    if(signd == SEC_TRUE)
    {
        if((res[offset] & 0x80) == 0x80)
            memset(res, 0xFF, offset);
    }

    BN_free(bn);
    return SEC_RESULT_SUCCESS;
}
#endif


static Sec_Result setBE_ASN1_INTEGER(ASN1_INTEGER *st, SEC_BYTE* be_value, SEC_SIZE size)
{
    BIGNUM *bn = BN_bin2bn(be_value, size, NULL);
    if(bn == NULL) {
        SEC_LOG_ERROR("failed BN_bin2bn");
        return SEC_RESULT_FAILURE;
    }

    if(!BN_to_ASN1_INTEGER(bn, st))
    {
        SEC_LOG_ERROR("failed BN_to_ASN1_INTEGER");
        if(bn != NULL) BN_free(bn);
        return SEC_RESULT_FAILURE;
    }

    BN_free(bn);

    return SEC_RESULT_SUCCESS;
}

typedef enum att_choic_e
{
    asn1_integer,
    asn1_bit_string,
    asn1_octet_string,
    asn1_null,
    asn1_ia5string,
    asn1_utctime
} att_choice;

static Asn1KCAttribute_t *SecAsn1KC_AllocAttr(att_choice c)
{
    Asn1KCAttribute_t *ptr = NULL;

    ptr = Asn1KCAttribute_t_new();
    if(ptr == NULL)
    {
        return NULL;
    }

    ptr->value = Asn1KCAttribute_t_c_new();
    if(ptr->value == NULL)
    {
        Asn1KCAttribute_t_free(ptr);
        return NULL;
    }

    switch (c) {
        case asn1_integer:
            ptr->value->c.integer = ASN1_INTEGER_new();
            if(ptr->value->c.integer == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_INTEGER_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_INTEGER;
            break;
        case asn1_bit_string:
            ptr->value->c.bitstring = ASN1_BIT_STRING_new();
            if(ptr->value->c.bitstring == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_BIT_STRING_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_BITSTRING;
            break;
        case asn1_octet_string:
            ptr->value->c.octetstring = ASN1_OCTET_STRING_new();
            if(ptr->value->c.octetstring == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_OCTET_STRING_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_OCTETSTRING;
            break;
        case asn1_null:
            ptr->value->c.null = ASN1_NULL_new();
            if(ptr->value->c.null == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_NULL_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_NULL;
            break;
        case asn1_ia5string:
            ptr->value->c.ia5string = ASN1_IA5STRING_new();
            if(ptr->value->c.ia5string == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_IA5STRING_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_IA5STRING;
            break;
        case asn1_utctime:
            ptr->value->c.utctime = ASN1_UTCTIME_new();
            if(ptr->value->c.utctime == NULL)
            {
                SEC_LOG_ERROR("failed ASN1_UTCTIME_new");
                Asn1KCAttribute_t_free(ptr);
                return NULL;
            }
            ptr->value->type = ASN1KCATTRIBUTE_T_CHOICE_UTCTIME;
            break;
        default:
            Asn1KCAttribute_t_free(ptr);
            return NULL;
            break;
    }

    return ptr;
}

static Sec_Result SecAsn1KC_AddAttr(Sec_Asn1KC *kc, Asn1KCAttribute_t *attribute)
{
    if (sk_Asn1KCAttribute_t_push(kc, attribute) == 0)
    {
        SEC_LOG_ERROR("sk_Asn1KCAttribute_t_push failed");
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

static Asn1KCAttribute_t *SecAsn1KC_GetAttr(Sec_Asn1KC *kc, const char *key)
{
    SEC_SIZE i = 0;
    Asn1KCAttribute_t *at = NULL;

    for(i = 0; i < sk_Asn1KCAttribute_t_num(kc); ++i)
    {
        at = sk_Asn1KCAttribute_t_value(kc, i);
        if (at != NULL &&
            strlen(key) == ASN1_STRING_length(at->name) &&
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            ASN1_STRING_data(at->name) != NULL &&
            0 == Sec_Memcmp(key, ASN1_STRING_data(at->name), ASN1_STRING_length(at->name)))
#else
            ASN1_STRING_get0_data(at->name) != NULL &&
            0 == Sec_Memcmp(key, ASN1_STRING_get0_data(at->name), ASN1_STRING_length(at->name)))
#endif
        {
            return at;
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
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_INTEGER)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d",
                attr->value->c);
        return SEC_RESULT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    // Openssl 1.0.9 has support for signed long types
    // With Openssl 1.1.x new applications should use ASN1_INTEGER_get_int64()
    // instead
    *val = (long)ASN1_INTEGER_get(attr->value->c.integer);
#else
    if(ASN1_INTEGER_get_int64((int64_t*)val, attr->value->c.integer) != 1)
    {
        SEC_LOG_ERROR("failed to get Long value from asn1 struct");
        return SEC_RESULT_FAILURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t *val)
{
    Asn1KCAttribute_t *attr = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SEC_BYTE val_buf[sizeof(int64_t)];
#endif

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed invalid key");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_INTEGER)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d",
                attr->value->type);
        return SEC_RESULT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    //With openssl 1.1.x support you can use ASN1_INTEGER_get_int64() in place
    //of getBE_ASN1_INTEGER()
    if(getBE_ASN1_INTEGER(val_buf, attr->value->c.integer, sizeof(val),
                SEC_TRUE) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("getBE_ASN1_INTEGER failed");
        return SEC_RESULT_FAILURE;
    }

    //val_buf is an 8 byte buffer that has sign bits extended if needed.
    *val = (int64_t)Sec_BEBytesToUint64(val_buf);
#else
    if(ASN1_INTEGER_get_int64(val, attr->value->c.integer) != 1)
    {
        SEC_LOG_ERROR("failed to get Long value from asn1 struct");
        return SEC_RESULT_FAILURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long *val)
{
    Asn1KCAttribute_t *attr = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SEC_BYTE val_buf[sizeof(unsigned long)];
#endif

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed invalid key");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_INTEGER)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value->c);
        return SEC_RESULT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    //With openssl 1.1.x support you can use ASN1_INTEGER_get_uint64() in place
    //of getBE_ASN1_INTEGER()
    if(getBE_ASN1_INTEGER(val_buf, attr->value->c.integer, sizeof(val),
                SEC_FALSE) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("getBE_ASN1_INTEGER failed");
        return SEC_RESULT_FAILURE;
    }

    if(sizeof(unsigned long) < sizeof(uint64_t))
    {
        *val = (unsigned long)Sec_BEBytesToUint32(val_buf);
    }
    else
    {
        *val = (unsigned long)Sec_BEBytesToUint64(val_buf);
    }

#else
    if(ASN1_INTEGER_get_uint64((uint64_t*)val, attr->value->c.integer) != 1)
    {
        SEC_LOG_ERROR("failed to get Long value from asn1 struct");
        return SEC_RESULT_FAILURE;
    }
#endif
    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t *val)
{
    Asn1KCAttribute_t *attr = NULL;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SEC_BYTE val_buf[sizeof(uint64_t)];
#endif

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed invalid key");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_INTEGER)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value->c);
        return SEC_RESULT_FAILURE;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    //With openssl 1.1.x support you can use ASN1_INTEGER_get_uint64() in place
    //of getBE_ASN1_INTEGER()
    if(getBE_ASN1_INTEGER(val_buf, attr->value->c.integer, sizeof(uint64_t),
                SEC_FALSE) != SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("getBE_ASN1_INTEGER failed");
        return SEC_RESULT_FAILURE;
    }

    *val = Sec_BEBytesToUint64(val_buf);
#else
    if(ASN1_INTEGER_get_uint64(val, attr->value->c.integer) != 1)
    {
        SEC_LOG_ERROR("failed to get Long value from asn1 struct");
        return SEC_RESULT_FAILURE;
    }
#endif

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrBuffer(Sec_Asn1KC *kc, const char *key, SEC_BYTE *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    Asn1KCAttribute_t *attr = NULL;
    const unsigned char *str_data = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed.");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_OCTETSTRING)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d",
                attr->value->type);
        return SEC_RESULT_FAILURE;
    }

    *written = ASN1_STRING_length(attr->value->c.octetstring);
    if (buffer != NULL)
    {
        if (*written > buffer_len)
        {
            SEC_LOG_ERROR("output buffer is too small.  Needed %d", *written);
            return SEC_RESULT_FAILURE;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        str_data = ASN1_STRING_data(attr->value->c.octetstring);
#else
        str_data = ASN1_STRING_get0_data(attr->value->c.octetstring);
#endif
        if(str_data == NULL)
        {
            SEC_LOG_ERROR("Call to ASN1_STRING_data failed");
            return SEC_RESULT_FAILURE;
        }

        memcpy(buffer, str_data, *written);
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecAsn1KC_GetAttrString(Sec_Asn1KC *kc, const char *key, char *buffer, SEC_SIZE buffer_len, SEC_SIZE *written)
{
    Asn1KCAttribute_t *attr = NULL;
    const unsigned char *str_data = NULL;

    attr = SecAsn1KC_GetAttr(kc, key);
    if (attr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_GetAttr failed");
        return SEC_RESULT_FAILURE;
    }

    if (attr->value->type != ASN1KCATTRIBUTE_T_CHOICE_IA5STRING)
    {
        SEC_LOG_ERROR("invalid value type contained in the attribute: %d", attr->value->type);
        return SEC_RESULT_FAILURE;
    }

    *written = ASN1_STRING_length(attr->value->c.ia5string);
    if (buffer != NULL)
    {
        if (*written >= buffer_len)
        {
            SEC_LOG_ERROR("output buffer is too small.  Needed %d", *written);
            return SEC_RESULT_FAILURE;
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        str_data = ASN1_STRING_data(attr->value->c.octetstring);
#else
        str_data = ASN1_STRING_get0_data(attr->value->c.octetstring);
#endif
        if(str_data == NULL)
        {
            SEC_LOG_ERROR("Call to ASN1_STRING_data failed");
            return SEC_RESULT_FAILURE;
        }

        memcpy(buffer, str_data, *written);
        buffer[*written] = '\0';
    }

    *written += 1;

    return SEC_RESULT_SUCCESS;
}

Sec_Asn1KC *SecAsn1KC_Alloc()
{
    Sec_Asn1KC *ptr = NULL;

    ptr = Sec_Asn1KC_new();
    if (ptr == NULL)
    {
        SEC_LOG_ERROR("Sec_Asn1KC_new failed");
        return ptr;
    }

    return ptr;
}

void SecAsn1KC_Free(Sec_Asn1KC *kc)
{
    if (kc != NULL)
    {
        Sec_Asn1KC_free(kc);
    }
}

Sec_Result SecAsn1KC_AddAttrLong(Sec_Asn1KC *kc, const char *key, long val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t   *ptr = SecAsn1KC_AllocAttr(asn1_integer);

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("ASN1_STRING_set failed");
        goto done;
    }

    if (0 == ASN1_INTEGER_set(ptr->value->c.integer, val))
    {
        SEC_LOG_ERROR("ASN1_INTEGER_set failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        if (ptr != NULL) Asn1KCAttribute_t_free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrInt64(Sec_Asn1KC *kc, const char *key, int64_t val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr(asn1_integer);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SEC_BYTE be_val[sizeof(val)];
#endif

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("ASN1_STRING_set failed");
        goto done;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    Sec_Uint64ToBEBytes((uint64_t)val, be_val);
    if(setBE_ASN1_INTEGER(ptr->value->c.integer, be_val, sizeof(val)) !=
            SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("setBE_ASN1_INTEGER failed");
        goto done;
    }
#else
    if (0 == ASN1_INTEGER_set_int64(ptr->value->c.integer, val))
    {
        SEC_LOG_ERROR("ASN1_INTEGER_set_int64 failed");
        goto done;
    }
#endif

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        if (ptr != NULL) Asn1KCAttribute_t_free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrUlong(Sec_Asn1KC *kc, const char *key, unsigned long val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr(asn1_integer);
    SEC_BYTE be_val[sizeof(val)];

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("ASN1_STRING_set failed");
        goto done;
    }

    if(sizeof(unsigned long) < sizeof(uint64_t))
    {
        Sec_Uint32ToBEBytes((uint32_t)val, be_val);
    }
    else
    {
        Sec_Uint64ToBEBytes((uint32_t)val, be_val);
    }
    if(setBE_ASN1_INTEGER(ptr->value->c.integer, be_val, sizeof(val)) !=
            SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("setBE_ASN1_INTEGER failed");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        if (ptr != NULL) Asn1KCAttribute_t_free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrUint64(Sec_Asn1KC *kc, const char *key, uint64_t val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr(asn1_integer);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SEC_BYTE be_val[sizeof(val)];
#endif

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("ASN1_STRING_set failed");
        goto done;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    Sec_Uint64ToBEBytes(val, be_val);
    if(setBE_ASN1_INTEGER(ptr->value->c.integer, be_val, sizeof(val)) !=
            SEC_RESULT_SUCCESS)
    {
        SEC_LOG_ERROR("setBE_ASN1_INTEGER failed");
        goto done;
    }
#else
    if (0 == ASN1_INTEGER_set_uint64(ptr->value->c.integer, val))
    {
        SEC_LOG_ERROR("ASN1_INTEGER_set_uint64 failed");
        goto done;
    }
#endif

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        if (ptr != NULL) Asn1KCAttribute_t_free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrString(Sec_Asn1KC *kc, const char *key, const char *val)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr(asn1_ia5string);

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("failed to set attribute name");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->value->c.ia5string, val, strlen(val)))
    {
        SEC_LOG_ERROR("failed to set ia5string");
        goto done;
    }

    if (SEC_RESULT_SUCCESS != SecAsn1KC_AddAttr(kc, ptr))
    {
        SEC_LOG_ERROR("SecAsn1KC_AddAttr failed");
        goto done;
    }

    res = SEC_RESULT_SUCCESS;
done:
    if (res != SEC_RESULT_SUCCESS)
    {
        if(ptr != NULL) Asn1KCAttribute_t_free(ptr);
    }
    return res;
}

Sec_Result SecAsn1KC_AddAttrBuffer(Sec_Asn1KC *kc, const char *key, void *buf, SEC_SIZE buf_len)
{
    Sec_Result res = SEC_RESULT_FAILURE;
    Asn1KCAttribute_t *ptr = SecAsn1KC_AllocAttr(asn1_octet_string);

    if (ptr == NULL)
    {
        SEC_LOG_ERROR("SecAsn1KC_AllocAttr failed");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->name, key, -1))
    {
        SEC_LOG_ERROR("failed to set attribute name");
        goto done;
    }

    if (!ASN1_STRING_set(ptr->value->c.octetstring, buf, buf_len))
    {
        SEC_LOG_ERROR("failed to set octetstring");
        goto done;
    }

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
    int der_len = i2d_Sec_Asn1KC(kc, NULL);

    if (buf == NULL)
    {
        *written = der_len;
    }
    else if (der_len < 0)
    {
        SEC_LOG_ERROR("der_encode_to_buffer failed");
        return SEC_RESULT_FAILURE;
    }
    else if (der_len > buf_len)
    {
        SEC_LOG_ERROR("der_encode_to_buffer invalide buffer length, der_len = %d, buf_len = %d", der_len, buf_len);
        return SEC_RESULT_FAILURE;
    }
    else
    {
      *written = i2d_Sec_Asn1KC(kc, &buf);
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Asn1KC *SecAsn1KC_Decode(SEC_BYTE *buf, SEC_SIZE buf_len)
{
    const unsigned char *c_buf = buf;
    Sec_Asn1KC *ret = NULL;

    if (buf_len > INT_MAX)
    {
        if (buf_len > LONG_MAX)
        {
             SEC_LOG_ERROR("buf length rollover");
             return NULL;
        }
    }

    ret = d2i_Sec_Asn1KC(NULL, &c_buf, (long)buf_len);
    return ret;
}

#endif
