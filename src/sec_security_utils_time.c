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

#include "sec_security_utils.h"
#include <string.h>
#include <time.h>

#define SEC_ISO_TIME_FORMAT "%Y-%m-%dT%H:%M:%S"

SEC_SIZE SecUtils_GetUtcNow()
{
    time_t now = time(NULL);
    return (SEC_SIZE)now;
}

char * SecUtils_Epoch2IsoTime(SEC_SIZE epoch, char* iso_time, SEC_SIZE iso_time_size)
{
    time_t in_time = (time_t)epoch;
    struct tm ts = {0};
    memset(iso_time, 0, iso_time_size);
    if (0 == strftime(iso_time, iso_time_size, SEC_ISO_TIME_FORMAT "Z", gmtime_r(&in_time, &ts)))
    {
        memset(iso_time, 0, iso_time_size);
    }
    return iso_time;
}

SEC_SIZE SecUtils_IsoTime2Epoch(const char* iso_time)
{
    struct tm _tm = {0};
    char *strptimeResult = NULL;
    SEC_SIZE epoch = SEC_INVALID_EPOCH;

    strptimeResult = SecUtils_strptime(iso_time, SEC_ISO_TIME_FORMAT ,&_tm);
    if (NULL == strptimeResult || *strptimeResult != 'Z')
    {
        SEC_LOG_ERROR("parse error for iso time '%s'", iso_time);
        goto done;
    }
    epoch = (SEC_SIZE) (mktime(&_tm));

done:
    return epoch;
}
