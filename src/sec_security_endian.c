
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

Sec_Endianess Sec_GetEndianess(void)
{
    uint32_t u32Val = 0x03020100;
    uint8_t *u8ptr = (uint8_t*) &u32Val;

    if (u8ptr[0] == 0x03 && u8ptr[1] == 0x02 && u8ptr[2] == 0x01 && u8ptr[3] == 0x00)
        return SEC_ENDIANESS_BIG;

    if (u8ptr[0] == 0x00 && u8ptr[1] == 0x01 && u8ptr[2] == 0x02 && u8ptr[3] == 0x03)
        return SEC_ENDIANESS_LITTLE;

    return SEC_ENDIANESS_UNKNOWN;
}

uint32_t Sec_BEBytesToUint32(SEC_BYTE *bytes)
{
    uint32_t val;

    memcpy(&val, bytes, 4);

    switch (Sec_GetEndianess())
    {
        case SEC_ENDIANESS_BIG:
            return val;
        case SEC_ENDIANESS_LITTLE:
            return Sec_EndianSwap_uint32(val);
        default:
            break;
    }

    SEC_LOG_ERROR("Unknown endianess detected");
    return 0;
}

uint64_t Sec_BEBytesToUint64(SEC_BYTE *bytes)
{
    uint64_t val;

    memcpy(&val, bytes, 8);

    switch (Sec_GetEndianess())
    {
        case SEC_ENDIANESS_BIG:
            return val;
        case SEC_ENDIANESS_LITTLE:
            return Sec_EndianSwap_uint64(val);
        default:
            break;
    }

    SEC_LOG_ERROR("Unknown endianess detected");
    return 0;
}

void Sec_Uint32ToBEBytes(uint32_t val, SEC_BYTE *bytes)
{
    if (Sec_GetEndianess() == SEC_ENDIANESS_LITTLE)
    {
        val = Sec_EndianSwap_uint32(val);
    }

    memcpy(bytes, &val, 4);
}

void Sec_Uint64ToBEBytes(uint64_t val, SEC_BYTE *bytes)
{
    if (Sec_GetEndianess() == SEC_ENDIANESS_LITTLE)
    {
        val = Sec_EndianSwap_uint64(val);
    }

    memcpy(bytes, &val, 8);
}

uint16_t Sec_EndianSwap_uint16(uint16_t val)
{
    return (val << 8) | (val >> 8);
}

int16_t Sec_EndianSwap_int16(int16_t val)
{
    return (val << 8) | ((val >> 8) & 0xFF);
}

uint32_t Sec_EndianSwap_uint32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

int32_t Sec_EndianSwap_int32(int32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | ((val >> 16) & 0xFFFF);
}

int64_t Sec_EndianSwap_int64(int64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
            | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
            | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | ((val >> 32) & 0xFFFFFFFFULL);
}

uint64_t Sec_EndianSwap_uint64(uint64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
            | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
            | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}
