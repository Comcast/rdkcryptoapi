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

#ifndef SEC_SECURITY_MUTEX_H_
#define SEC_SECURITY_MUTEX_H_

#include "sec_security.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef SEC_TRACE_MUTEX
    #define SEC_TRACE_MUTEX 0
#endif

#define SEC_MUTEX_LOCK(mutex) do { SEC_TRACE(SEC_TRACE_MUTEX, "LOCK %p", mutex); SecMutex_Lock(mutex); SEC_TRACE(SEC_TRACE_MUTEX, "LOCKED %p", mutex);} while (0)
#define SEC_MUTEX_TRYLOCK(mutex) SecMutex_TryLock(mutex)
#define SEC_MUTEX_UNLOCK(mutex)  do { SEC_TRACE(SEC_TRACE_MUTEX, "UNLOCK %p", mutex); SecMutex_Unlock(mutex); } while (0)

#define SEC_MUTEX_SIZE sizeof(pthread_mutex_t)

typedef enum
{
    SEC_MUTEXRESULT_FAILED,
    SEC_MUTEXRESULT_OK,
    SEC_MUTEXRESULT_ALREADY_INITIALIZED
} Sec_MutexResult;

Sec_MutexResult SecMutex_Init(pthread_mutex_t *mutex, SEC_BOOL shared);
void SecMutex_Destroy(pthread_mutex_t *mutex);
SEC_BOOL SecMutex_TryLock(pthread_mutex_t *mutex);
void SecMutex_Lock(pthread_mutex_t *mutex);
void SecMutex_Unlock(pthread_mutex_t *mutex);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_DATATTYPE_H_ */
