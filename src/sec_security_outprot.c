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

#include "sec_security_outprot.h"
#include "sec_security_utils.h"
#include "outprot.h"
#include <string.h>

#define _XOPEN_SOURCE
#include <time.h>

static Sec_Result _CheckUsage(Sec_KeyProperties *props, Sec_KeyUsage use) {
    switch (use) {
        case SEC_KEYUSAGE_DATA:
            if (props->usage != SEC_KEYUSAGE_DATA && props->usage != SEC_KEYUSAGE_DATA_KEY) {
                SEC_LOG_ERROR("Attempted usage %d of the key is not allowed by key properties usage %d.", use, props->usage);
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_KEYUSAGE_KEY:
            if (props->usage != SEC_KEYUSAGE_KEY && props->usage != SEC_KEYUSAGE_DATA_KEY) {
                SEC_LOG_ERROR("Attempted usage %d of the key is not allowed by key properties usage %d.", use, props->usage);
                return SEC_RESULT_FAILURE;
            }
            break;

        case SEC_KEYUSAGE_DATA_KEY:
            if (props->usage != SEC_KEYUSAGE_DATA_KEY) {
                SEC_LOG_ERROR("Attempted usage %d of the key is not allowed by key properties usage %d.", use, props->usage);
                return SEC_RESULT_FAILURE;
            }
            break;

        default:
            SEC_LOG_ERROR("Unexpected usage encountered: %d", use);
            return SEC_RESULT_FAILURE;
            break;
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result _CheckTime(Sec_KeyProperties *props) {
    SEC_SIZE now = time(NULL);

    if (strlen(props->notBefore) > 0) {
        SEC_SIZE epochNotBefore = SecUtils_IsoTime2Epoch(props->notBefore);
        if (epochNotBefore == SEC_INVALID_EPOCH) {
            SEC_LOG_ERROR("SecUtils_IsoTime2Epoch failed");
            return SEC_RESULT_FAILURE;
        }

        if (epochNotBefore > now) {
            SEC_LOG_ERROR("Key notBefore %d is greater then current time %d", epochNotBefore, now);
            return SEC_RESULT_FAILURE;
        }
    }

    if (strlen(props->notOnOrAfter) > 0) {
        SEC_SIZE epochNotOnOrAfter = SecUtils_IsoTime2Epoch(props->notOnOrAfter);
        if (epochNotOnOrAfter == SEC_INVALID_EPOCH) {
            SEC_LOG_ERROR("SecUtils_IsoTime2Epoch failed");
            return SEC_RESULT_FAILURE;
        }

        if (epochNotOnOrAfter <= now) {
            SEC_LOG_ERROR("Key notOnOrAfter %d is less then current time %d", epochNotOnOrAfter, now);
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}

static Sec_Result _CheckOPL(Sec_KeyProperties *props) {
    SEC_SIZE i;

    SEC_BYTE rights[SEC_KEYOUTPUTRIGHT_NUM];
    memset(rights, 0, sizeof(rights));

    //collapse rights
    SEC_BOOL anySet = SEC_FALSE;
    for (i=0; i<SEC_KEYOUTPUTRIGHT_NUM; ++i) {
        SEC_BYTE right = props->rights[i];

        if (right >= SEC_KEYOUTPUTRIGHT_NUM) {
            SEC_LOG_ERROR("Unexpected right encountered: %d", right);
            return SEC_RESULT_FAILURE;
        }

        if (right != SEC_KEYOUTPUTRIGHT_NOT_SET) {
            anySet = SEC_TRUE;
        }

        rights[right] = 1;
    }

    //by spec, if no rights are set, it means allow all
    if (!anySet) {
        return SEC_RESULT_SUCCESS;
    }

    //check output protections against the security profile in the key properties
    if (!rights[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED] && outprot_are_any_analog_outputs_enabled()) {
        SEC_LOG_ERROR("Analog output is not allowed but is enabled");
        return SEC_RESULT_FAILURE;
    }

    if (rights[SEC_KEYOUTPUTRIGHT_CGMSA_REQUIRED] && !outprot_are_all_enabled_analog_outputs_protected(1)) {
        SEC_LOG_ERROR("CGMS-A is required on all analog outputs, but is not enabled");
        return SEC_RESULT_FAILURE;
    }

    if (!outprot_are_all_enabled_digital_outputs_protected(
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED],
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED],
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED])) {
        SEC_LOG_ERROR("Some digital outputs are not set to the minimum security level: dtcp allowed %d, hdcp12 allowed %d, hdcp22 allowed %d",
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED],
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED],
            rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED]);
        return SEC_RESULT_FAILURE;
    }

    return SEC_RESULT_SUCCESS;
}

Sec_Result SecOutprot_IsKeyAllowed(Sec_KeyProperties *props, Sec_KeyUsage use) {
    //check usage
    if (SEC_RESULT_SUCCESS != _CheckUsage(props, use)) {
        SEC_LOG_ERROR("_CheckUsage failed");
        return SEC_RESULT_FAILURE;
    }

    //check validity time
    if (SEC_RESULT_SUCCESS != _CheckTime(props)) {
        SEC_LOG_ERROR("_CheckTime failed");
        return SEC_RESULT_FAILURE;
    }

    //check output protections
    if (use == SEC_KEYUSAGE_DATA || use == SEC_KEYUSAGE_DATA_KEY) {
        if (SEC_RESULT_SUCCESS != _CheckOPL(props)) {
            SEC_LOG_ERROR("_CheckOPL failed");
            return SEC_RESULT_OPL_NOT_ENGAGED;
        }
    }

    return SEC_RESULT_SUCCESS;
}

SEC_BOOL SecOutprot_IsSVPRequired(Sec_KeyProperties *props) {
    int i=0;

    for (i=0; i<SEC_KEYOUTPUTRIGHT_NUM; ++i) {
        if (props->rights[i] == SEC_KEYOUTPUTRIGHT_SVP_REQUIRED) {
            return SEC_TRUE;
        }
    }

    return SEC_FALSE;
}
