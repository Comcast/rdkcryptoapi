
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

void SecBuffer_Init(Sec_Buffer *buffer, void *mem, SEC_SIZE len)
{
    buffer->base = mem;
    buffer->size = len;
    buffer->written = 0;
}

void SecBuffer_Reset(Sec_Buffer *buffer)
{
    buffer->written = 0;
}

Sec_Result SecBuffer_Write(Sec_Buffer *buffer, void *data, SEC_SIZE len)
{
    int space_left = buffer->size - buffer->written;

    if (space_left < 0 || (SEC_SIZE) space_left < len)
        return SEC_RESULT_BUFFER_TOO_SMALL;

    memcpy(buffer->base + buffer->written, data, len);
    buffer->written += len;

    return SEC_RESULT_SUCCESS;
}

