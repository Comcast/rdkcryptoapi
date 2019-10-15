/**
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2014 - 2019 RDK Management
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

#include "sec_security_mutex.h"
#include <errno.h>

#if SEC_TRACE_MUTEX
#pragma message "SEC_TRACE_MUTEX is enabled.  Please disable in production builds."
#endif

#if !defined(__APPLE__) && !defined(__ANDROID__)
    #define SEC_USE_ROBUST_MUTEX
#endif

Sec_MutexResult SecMutex_Init(pthread_mutex_t *mutex, SEC_BOOL shared)
{
    pthread_mutexattr_t mutex_attr;
    int ret;

    if ((ret = pthread_mutexattr_init(&mutex_attr)) != 0) {
        SEC_LOG_ERROR("pthread_mutexattr_init failed with error code %d", ret);
        return SEC_MUTEXRESULT_FAILED;
    }

    if (shared && (ret = pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED)) != 0) {
        SEC_LOG_ERROR("pthread_mutexattr_setpshared failed with error code %d", ret);
        return SEC_MUTEXRESULT_FAILED;
    }

#ifdef SEC_USE_ROBUST_MUTEX
    if ((ret = pthread_mutexattr_setrobust(&mutex_attr, PTHREAD_MUTEX_ROBUST)) != 0) {
        SEC_LOG_ERROR("pthread_mutexattr_setrobust failed with error code %d", ret);
        return SEC_MUTEXRESULT_FAILED;
    }
#endif

    ret = pthread_mutex_init(mutex, &mutex_attr);
    if (ret == EBUSY)
    {
        return SEC_MUTEXRESULT_ALREADY_INITIALIZED;
    }

    if (ret != 0)
    {
        SEC_LOG_ERROR("pthread_mutex_init failed with error code %d", ret);
        return SEC_MUTEXRESULT_FAILED;
    }

    return SEC_MUTEXRESULT_OK;
}

void SecMutex_Destroy(pthread_mutex_t *mutex)
{
    int ret;

    ret = pthread_mutex_destroy(mutex);
    if (ret != 0) {
        SEC_LOG_ERROR("pthread_mutex_destroy failed with error code %d", ret);
    }
}

SEC_BOOL SecMutex_TryLock(pthread_mutex_t *mutex)
{
    int ret;

    SEC_TRACE(SEC_TRACE_MUTEX, "TRYLOCK %p", mutex);
    ret = pthread_mutex_trylock(mutex);

#ifdef SEC_USE_ROBUST_MUTEX
    if (ret == EOWNERDEAD) {
        SEC_LOG_ERROR("Dead mutex owner detected.  Attempting to recover.");

        ret = pthread_mutex_consistent(mutex);
        if (0 != ret)
        {
            SEC_LOG_ERROR("pthread_mutex_consistent failed with error code %d", ret);
            goto done;
        }

        SEC_LOG_ERROR("mutex recovered.");
    }
#endif

    if (ret == 0) {
        SEC_TRACE(SEC_TRACE_MUTEX, "LOCKED %p", mutex);
    }

#ifdef SEC_USE_ROBUST_MUTEX
done:
#endif
    return ret == 0;
}

void SecMutex_Lock(pthread_mutex_t *mutex)
{
    int ret;

    ret = pthread_mutex_lock(mutex);

#ifdef SEC_USE_ROBUST_MUTEX
    if (ret == EOWNERDEAD) {
        SEC_LOG_ERROR("Dead mutex owner detected.  Attempting to recover.");

        ret = pthread_mutex_consistent(mutex);
        if (0 != ret)
        {
            SEC_LOG_ERROR("pthread_mutex_consistent failed with error code %d", ret);
            return;
        }

        SEC_LOG_ERROR("mutex recovered.");
    }
#endif
}

void SecMutex_Unlock(pthread_mutex_t *mutex)
{
    int ret;

    ret = pthread_mutex_unlock(mutex);

    if (EPERM == ret) {
        SEC_LOG_ERROR("pthread_mutex_unlock failed.  Not the mutex owner.");
    } else if (0 != ret) {
        SEC_LOG_ERROR("pthread_mutex_unlock failed with unknown error code %d", ret);
    }
}

