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

#ifndef OUTPROT_H_
#define OUTPROT_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define OUTPROT_VERSION "1.0.0"

typedef struct {
    int analogEnabled;
    int analogWithCgmsa;
    int digitalEnabled;
    int digitalWithDtcp;
    int digitalWithHdcp14;
    int digitalWithHdcp22;
} outprot_state;

int outprot_init();

int outprot_poll_state(outprot_state *state);
outprot_state* outprot_lock_state();
void outprot_unlock_state(outprot_state *state);

int outprot_are_all_enabled_digital_outputs_protected(int dtcpallowed, int hdcp14allowed, int hdcp22allowed);
int outprot_are_any_analog_outputs_enabled();
int outprot_are_all_enabled_analog_outputs_protected(int cgmswithcopyneverallowed);

#ifdef __cplusplus
}
#endif

#endif /* OUTPROT_H_ */
