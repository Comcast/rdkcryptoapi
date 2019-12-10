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

#include "outprot.h"
#include <pthread.h>
#include <string.h>

pthread_mutex_t g_outprot_mock_mutex = PTHREAD_MUTEX_INITIALIZER;

//default to analog enabled - no protection, digital enabled with hdcp14
outprot_state g_outprot_mockstate = { 1, 0, 1, 0, 1, 0 };

static outprot_state* outprot_mock_lock_state() {
    pthread_mutex_lock(&g_outprot_mock_mutex);
    return &g_outprot_mockstate;
}

static void outprot_mock_unlock_state(outprot_state *state) {
    pthread_mutex_unlock(&g_outprot_mock_mutex);
}

void outprot_mock_set_state(outprot_state *state) {
    outprot_state *mock_state = outprot_mock_lock_state();
    memcpy(mock_state, state, sizeof(outprot_state));
    outprot_mock_unlock_state(mock_state);
}

int outprot_poll_state(outprot_state *state) {
    outprot_state *mock_state = outprot_mock_lock_state();
    memcpy(state, mock_state, sizeof(outprot_state));
    outprot_mock_unlock_state(mock_state);

    return 1;
}
