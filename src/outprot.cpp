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

#include "sec_security.h"
#include "outprot.h"
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <cstring>

#define OUTPROT_POLL_INTERVAL_SEC 1

pthread_mutex_t g_outprot_mutex = PTHREAD_MUTEX_INITIALIZER;
outprot_state g_outprot_state = { 1, 0, 1, 0, 0, 0 };

outprot_state* outprot_lock_state() {
    pthread_mutex_lock(&g_outprot_mutex);
    return &g_outprot_state;
}

void outprot_unlock_state(outprot_state *state) {
    pthread_mutex_unlock(&g_outprot_mutex);
}

int outprot_are_all_enabled_digital_outputs_protected(int dtcpallowed, int hdcp14allowed, int hdcp22allowed) {
    outprot_state *state = outprot_lock_state();

    int enabled = state->digitalEnabled;

    int protectd = 0;

    protectd += (dtcpallowed ? state->digitalWithDtcp : 0);
    protectd += (hdcp14allowed ? state->digitalWithHdcp14 : 0);
    protectd += (hdcp22allowed ? state->digitalWithHdcp22 : 0);

    int unprotected = enabled - protectd;

    if (unprotected > 0) {
        SEC_LOG_ERROR("Some digital outputs are in a disallowed state, digitalEnabled: %d, digitalWithDtcp: %d, digitalWithHdcp14: %d, digitalWithHdcp22: %d",
            state->digitalEnabled, state->digitalWithDtcp, state->digitalWithHdcp14, state->digitalWithHdcp22);
    }

    outprot_unlock_state(state);

    return unprotected == 0;
}

int outprot_are_any_analog_outputs_enabled() {
    outprot_state *state = outprot_lock_state();

    int res = state->analogEnabled;

    outprot_unlock_state(state);

    return res != 0;
}

int outprot_are_all_enabled_analog_outputs_protected(int cgmswithcopyneverallowed) {
    outprot_state *state = outprot_lock_state();

    int enabled = state->analogEnabled;

    int protectd = 0;
    protectd += (cgmswithcopyneverallowed ? state->analogWithCgmsa : 0);

    int unprotected = enabled - protectd;

    outprot_unlock_state(state);

    return unprotected == 0;
}

void *outprot_polling_thread(void *arg) {
    while (true) {
        outprot_state new_state;

        if (!outprot_poll_state(&new_state)) {
            //obtaining the state of the outputs has failed
            //assume the worst scenario of both analog and digital outputs being enabled without any protection
            new_state.analogEnabled = 1;
            new_state.analogWithCgmsa = 0;
            new_state.digitalEnabled = 1;
            new_state.digitalWithDtcp = 0;
            new_state.digitalWithHdcp14 = 0;
            new_state.digitalWithHdcp22 = 0;
        }

        //update the master state data
        outprot_state *global_state = outprot_lock_state();
        memcpy(global_state, &new_state, sizeof(outprot_state));

        /*
        printf("*** analogEnabled: %d, analogWithCgmsa: %d, digitalEnabled: %d, digitalWithDtcp: %d, digitalWithHdcp14: %d, digitalWithHdcp22: %d\n",
            new_state.analogEnabled, new_state.analogWithCgmsa, new_state.digitalEnabled, new_state.digitalWithDtcp, new_state.digitalWithHdcp14, new_state.digitalWithHdcp22);
        */

        outprot_unlock_state(global_state);

        //sleep for a while
        sleep(OUTPROT_POLL_INTERVAL_SEC);
    }

    return NULL;
}

int outprot_init() {
    static pthread_mutex_t _init_mutex = PTHREAD_MUTEX_INITIALIZER;
    static int inited = 0;
    static pthread_t thread;

    pthread_mutex_lock(&_init_mutex);

    if (!inited) {
        if (0 != pthread_create(&thread, NULL, outprot_polling_thread, NULL)) {
            pthread_mutex_unlock(&_init_mutex);
            return 0;
        }

        inited = 1;
    }

    pthread_mutex_unlock(&_init_mutex);

    return 1;
}
