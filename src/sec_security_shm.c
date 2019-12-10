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

#include "sec_security_shm.h"
#include <errno.h>

#ifndef _POSIX_THREAD_PROCESS_SHARED
    #error This system does not support process shared mutex
#endif

key_t SecShm_GenKey(const char *path, int id)
{
    key_t key = ftok(path, id);

    if (key == ((key_t) -1))
    {
        SEC_LOG_ERROR("ftok failed with errno %d", errno);
    }

    return key;
}

void *SecShm_InitSegment(key_t shmKey, SEC_SIZE shmSize, SEC_BOOL *created) {
    int shmId = -1;
    void *ptr = (void *) -1;

    if (created != NULL)
    {
        *created = SEC_FALSE;
    }

    //try to obtain a pre-existing shared memory segment
    if ((shmId = shmget(shmKey, shmSize, 0666)) < 0) {
        if (errno != ENOENT)
        {
            SEC_LOG_ERROR("shmget failed with unexpected errno %d", errno);
            return NULL;
        }

        //failed... lets try to create a new segment
        if ((shmId = shmget(shmKey, shmSize, IPC_CREAT | 0666)) < 0) {
            SEC_LOG_ERROR("shmget IPC_CREAT failed, errno=%d", errno);
            return NULL;
        }

        if (created != NULL)
        {
            *created = SEC_TRUE;
        }
    }

    /* attach memory segment */
    if ((ptr = shmat(shmId, NULL, 0)) == (void *) -1) {
        SEC_LOG_ERROR("shmat failed");
        return NULL;
    }

    return ptr;
}
