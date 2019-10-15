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

#include "sec_security.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


/* Each char represents 6 bits. 4 chars are used to represent 4 * 6 = 24 bits = 3 bytes
 * so.... 4*(n/3) rounded to multiple of 4 is size needed. */
SEC_SIZE SecUtils_Base64EncodeLength(SEC_SIZE size)
{
    return ((((4*size)/3)+3) & ~0x3);
}
SEC_SIZE SecUtils_Base64DecodeLength(SEC_SIZE size)
{
    return 3 * size /4;
}

/* for url lengths just use same calc */
SEC_SIZE SecUtils_Base64UrlDecodeLength(SEC_SIZE data_len)
{
    return SecUtils_Base64DecodeLength(data_len);
}
SEC_SIZE SecUtils_Base64UrlEncodeLength(SEC_SIZE data_len)
{
    return SecUtils_Base64EncodeLength(data_len);
}

static int is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}


Sec_Result SecUtils_Base64Encode(const SEC_BYTE* input, SEC_SIZE input_len, SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    int i = 0;
    int j = 0;
    SEC_BYTE arr3[3];
    SEC_BYTE arr4[4];
    SEC_SIZE ret_len = 0;

    *out_len = 0;
    memset(arr3,0,3);
    memset(arr4,0,4);
    while (input_len--)
    {
        arr3[i++] = *(input++);
        if (i == 3)
        {
            arr4[0] = (arr3[0] & 0xfc) >> 2;
            arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
            arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
            arr4[3] = arr3[2] & 0x3f;

            for (i = 0; i < 4 ; i++)
            {
                if (ret_len >= max_output)
                {
                    SEC_LOG_ERROR("Output buffer too small");
                    goto done;
                }
                output[ret_len++] = base64_chars[arr4[i]];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
        {
            arr3[j] = '\0';
        }

        arr4[0] = (arr3[0] & 0xfc) >> 2;
        arr4[1] = ((arr3[0] & 0x03) << 4) + ((arr3[1] & 0xf0) >> 4);
        arr4[2] = ((arr3[1] & 0x0f) << 2) + ((arr3[2] & 0xc0) >> 6);
        arr4[3] = arr3[2] & 0x3f;

        for (j = 0; j < (i + 1); j++)
        {
            if (ret_len >= max_output)
            {
                SEC_LOG_ERROR("Output buffer too small");
                goto done;
            }
            output[ret_len++] = base64_chars[arr4[j]];
        }

        while (i++ < 3)
        {
            if (ret_len >= max_output)
            {
                SEC_LOG_ERROR("Output buffer too small");
                goto done;
            }
            output[ret_len++] = '=';
        }
    }

    *out_len = ret_len;
    status = SEC_RESULT_SUCCESS;

    done:

    return status;
}

Sec_Result SecUtils_Base64Decode(const SEC_BYTE* input, SEC_SIZE in_len, SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE* out_len)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    SEC_SIZE i = 0;
    SEC_SIZE j = 0;
    SEC_SIZE z = 0;
    SEC_SIZE ret_len = 0;
    SEC_SIZE curPos = 0;
    SEC_BYTE arr3[3];
    SEC_BYTE arr4[4];

    *out_len = 0;

    if (in_len <=1)
    {
        SEC_LOG_ERROR("Illegal base64 string");
        return SEC_RESULT_FAILURE;
    }

    memset(arr3,0,3);
    memset(arr4,0,4);
    while (in_len-- && (input[curPos] != '=') && is_base64(input[curPos]))
    {
        arr4[i++] = input[curPos]; curPos++;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
            {
                for (z=0;z<64;z++)
                {
                    if ( base64_chars[z] == arr4[i] )
                    {
                        arr4[i] = (SEC_BYTE)z;
                        break;
                    }
                }
            }

            arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
            arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
            arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

            for (i = 0; i < 3; i++)
            {
                if (ret_len >= max_output)
                {
                    SEC_LOG_ERROR("Output buffer too small");
                    goto done;
                }
                output[ret_len++] = arr3[i];
            }
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
        {
            arr4[j] = 0;
        }

        for (j = 0; j < 4; j++)
        {
            for (z=0;z<64;z++)
            {
                if ( base64_chars[z] == arr4[j] )
                {
                    arr4[j] = z;
                    break;
                }
            }
        }

        arr3[0] = (arr4[0] << 2) + ((arr4[1] & 0x30) >> 4);
        arr3[1] = ((arr4[1] & 0xf) << 4) + ((arr4[2] & 0x3c) >> 2);
        arr3[2] = ((arr4[2] & 0x3) << 6) + arr4[3];

        for (j = 0; (j < i - 1); j++)
        {
            if (ret_len >= max_output)
            {
                SEC_LOG_ERROR("Output buffer too small");
                goto done;
            }
            output[ret_len++] = arr3[j];
        }
    }
    *out_len = ret_len;
    status = SEC_RESULT_SUCCESS;

    done:

    return status;
}



Sec_Result SecUtils_Base64UrlEncode(const SEC_BYTE* input, SEC_SIZE in_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    SEC_SIZE i = 0;

    if (SEC_RESULT_SUCCESS != (status = SecUtils_Base64Encode(input,in_len, output, max_output, out_len)))
    {
        return status;
    }

    for(i=0;i<*out_len;i++)
        switch(output[i])
        {
            case '+':
                output[i] = '-';
                break;
            case '/':
                output[i] = '_';
                break;
        }
    /* remove trailing '=' */
    while (output[--i] == '=')
    {
        output[i] = '\0';
        (*out_len)--;
    }

    status = SEC_RESULT_SUCCESS;
    return status;

}

Sec_Result SecUtils_Base64UrlDecode(const SEC_BYTE* input, SEC_SIZE in_len,
        SEC_BYTE *output, SEC_SIZE max_output, SEC_SIZE *out_len)
{
    Sec_Result status = SEC_RESULT_FAILURE;
    SEC_BYTE *tmp = NULL;
    SEC_SIZE tmp_size = in_len;
    SEC_SIZE i = 0;

    if (in_len <=1)
    {
        SEC_LOG_ERROR("Illegal base64 string");
        goto done;
    }

    tmp = calloc(1,in_len+4);
    memcpy(tmp, input, in_len);

    for(i=0;i<in_len;i++)
        switch(tmp[i])
        {
            case '-':
                tmp[i] = '+';
                break;
            case '_':
                tmp[i] = '/';
                break;
        }

    switch(in_len%4)
    {
        case 0: /* no padding */
            break;
        case 2:
            tmp[tmp_size++] = '=';
            tmp[tmp_size++] = '=';
            break;
        case 3:
            tmp[tmp_size++] = '=';
            break;
        default:
            SEC_LOG_ERROR("Illegal base64 string");
            goto done;
    }
    status = SecUtils_Base64Decode(tmp, tmp_size, output, max_output, out_len);

    done:

    if (NULL!=tmp)
        free(tmp);

    return status;
}
