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

#ifndef SEC_SECURITY_SHM_H_
#define SEC_SECURITY_SHM_H_

#include "sec_security.h"
#include <sys/shm.h>

#ifdef __cplusplus
extern "C"
{
#endif

key_t SecShm_GenKey(const char *path, int id);
void *SecShm_InitSegment(key_t shmKey, SEC_SIZE shmSize, SEC_BOOL *created);

#ifdef __cplusplus
}
#endif

#endif /* SEC_SECURITY_DATATTYPE_H_ */
