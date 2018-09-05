#include "sec_security_keyctrl.h"
#include "sec_security_utils.h"
#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdio.h>
#include <string.h>
#ifdef SEC_KEYCTRL_ENABLE_DS
#include <host.hpp>
#include <videoOutputPort.hpp>
#include <videoOutputPortType.hpp>
#include <videoResolution.hpp>
#include <manager.hpp>
#include <libIBus.h>
#endif


#if defined(SEC_KEYCTRL_ENABLE_ENV) && defined(SEC_KEYCTRL_ENABLE_DS)
#error "SEC_KEYCTRL_ENABLE_ENV and SEC_KEYCTRL_ENABLE_DS are both defined."
#endif

#if defined(SEC_KEYCTRL_ENABLE_ENV)
#pragma message "SEC_KEYCTRL_ENABLE_ENV is enabled.  Please disable in production builds."
#endif

#if defined(SEC_TRACE_KEYCTRL)
#pragma message "SEC_TRACE_KEYCTRL is enabled.  Please disable in production builds."
#endif

#if !defined(SEC_TRACE_KEYCTRL)
#define SEC_TRACE_KEYCTRL 0
#endif

static char _opr_str[8][64] = {
    "Not-set",
    "SVP",
    "DTCP",
    "HDCP-1.4",
    "HDCP-2.2",
    "Analog",
    "Transcription-copy",
    "Unrestricted-copy"
};

#define RIGHTS_STRING_MAX 128

/**
 * rights are passed in as a vector with each position either set to 0 or 1.  NOT
 * an array of rights.
 */
static char* _SecKeyCtrl_RightsVectorToString(const SEC_BYTE *rights, char *str, SEC_SIZE strSize)
{
    str[0] = '\0';
    int p=0;

    for (int i=0;i<SEC_KEYRIGHTS_LEN;i++)
    {
        if(rights[i])
        {
            if ( (strlen(str) + strlen(_opr_str[i])) < strSize-2 )
            {
                if (p++) strcat(str, ", ");
                strcat(str, _opr_str[i]);
            }
        }
    }

    return str;
}

static SEC_BOOL _SecKeyCtrl_IsKeyTypeCacheable(Sec_KeyType keyType)
{
    return SecKey_IsSymetric(keyType) || keyType == SEC_KEYTYPE_ECC_NISTP256;
}

static SEC_BOOL _SeckeyCtrl_VectorHasUniversalRights(SEC_BYTE *rights)
{
    return rights[SEC_KEYOUTPUTRIGHT_SVP_REQUIRED] == 0
            && rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED]
            && rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED]
            && rights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED]
            && rights[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED]
            && rights[SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED]
            && rights[SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED] ? SEC_TRUE : SEC_FALSE;
}

static SEC_BOOL _SecKeyCtrl_KeyRightsAreUniversal(SEC_BYTE *keyrights)
{
    SEC_BYTE rights_vector[SEC_KEYRIGHTS_LEN];
    memset(rights_vector,0,sizeof(rights_vector));

    for (int i=0;i<SEC_KEYRIGHTS_LEN;i++)
        if (keyrights[i] != SEC_KEYOUTPUTRIGHT_NOT_SET)
        {
            rights_vector[keyrights[i]] = 1;
        }

    return _SeckeyCtrl_VectorHasUniversalRights(rights_vector);
}

/**
 * Used when SecKey_GetProperties needs to return properties for a non-jtype/exported key.
 */
void SecKeyCtrl_SetDefaultKeyProperties(Sec_KeyProperties *keyProperties, Sec_KeyType keyType, SEC_SIZE keyLength)
{
        keyProperties->keyType = keyType;
        keyProperties->keyLength = keyLength;
        keyProperties->cacheable = _SecKeyCtrl_IsKeyTypeCacheable(keyType) ? 0x01 : 0x00;
        keyProperties->usage = SEC_KEYUSAGE_DATA_KEY;
        memset(keyProperties->keyId, '\0', sizeof(keyProperties->keyId));
        memset(keyProperties->notBefore, '\0', sizeof(keyProperties->notBefore));
        memset(keyProperties->notOnOrAfter, '\0', sizeof(keyProperties->notOnOrAfter));
        memset(keyProperties->rights, SEC_KEYOUTPUTRIGHT_NOT_SET, SEC_KEYRIGHTS_LEN);
        /* universal allowance for default properties */
        keyProperties->rights[0] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED;
        keyProperties->rights[1] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED;
        keyProperties->rights[2] = SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED;
        keyProperties->rights[3] = SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED;
        keyProperties->rights[4] = SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED;
        keyProperties->rights[5] = SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED;
}

SEC_BOOL SecKeyCtrl_KeyPropertiesContainOutputRight(Sec_KeyProperties *keyProps, Sec_KeyOutputRight right)
{
   for(int i=0;i<SEC_KEYRIGHTS_LEN;i++)
   {
       if (keyProps->rights[i] == right)
           return SEC_TRUE;
   }
   return SEC_FALSE;
}

SEC_BOOL SecKeyCtrl_IsDefaultKeyProperties(Sec_KeyProperties *keyProps)
{
    return (!strlen(keyProps->keyId)
            && !strlen(keyProps->notBefore)
            && !strlen(keyProps->notOnOrAfter)
            && keyProps->cacheable ==
                    (_SecKeyCtrl_IsKeyTypeCacheable(keyProps->keyType) ? 0x01 : 0x00)
            && keyProps->usage == SEC_KEYUSAGE_DATA_KEY
            && SEC_TRUE == _SecKeyCtrl_KeyRightsAreUniversal(keyProps->rights)) ? SEC_TRUE : SEC_FALSE;
}

#ifdef SEC_KEYCTRL_ENABLE_DS
#pragma message "SEC_KEYCTRL_ENABLE_DS is defined.  SecApi will connect to IARMBus for video port output rights."
/**
 * Use the RDK interface to connect to the IARMBus
 * The procHandle maintains a boolean flag that is set if the bus connection is
 * successful.
 *
 */
Sec_Result SecKeyCtrl_DeviceSettingsInit(int* device_settings_init_flag)
{
    Sec_Result result = SEC_RESULT_FAILURE;

    if (SEC_FALSE == *device_settings_init_flag)
    {
        if (IARM_Bus_Init("secapi") != IARM_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("initializing IARM Bus failed");
            goto done;
        }

        if (IARM_Bus_Connect() != IARM_RESULT_SUCCESS)
        {
            SEC_LOG_ERROR("error connecting to IARM Bus");
            goto done;
        }
        try
        {
            SEC_TRACE(SEC_TRACE_KEYCTRL, "initializing Device Manager...");
            ::device::Manager::Initialize();

        } catch (const std::exception &e)
        {
            SEC_LOG_ERROR("exception while initializing device manager %s",
                    e.what());
            goto done;
        }
        *device_settings_init_flag = SEC_TRUE;
    }

    result = SEC_RESULT_SUCCESS;

    done:

    return result;
}

/**
 *  Disconnect from the IARM bus
 *
 *  Called from SecProcessor_Release if SEC_KEYCTRL_ENABLE_DS is defined
 */
void SecKeyCtrl_DeviceSettingsShutdown(int* device_settings_init_flag)
{
    if ( SEC_TRUE == *device_settings_init_flag )
    {
        SEC_TRACE(SEC_TRACE_KEYCTRL, "deinitializing device manager...");
        try
        {
            ::device::Manager::DeInitialize();
        } catch (const std::exception &e)
        {
            SEC_LOG_ERROR(
                    "exception while shutting down device manager and iarm bus! %s",
                    e.what());
        }

        SEC_TRACE(SEC_TRACE_KEYCTRL, "disconnecting from IARM Bus...");
        IARM_Bus_Disconnect();
        IARM_Bus_Term();

        *device_settings_init_flag = SEC_FALSE;
    }
}

/**
 * Use the RDK devicesettings interface (videoPorts) to set the passed in
 * byte vector of device settings.
 */
Sec_Result SecKeyCtrl_GetRightsFromDeviceSettings(int* device_settings_init_flag, SEC_BYTE *deviceRights)
{

    if (NULL  == deviceRights)
    {
        SEC_LOG_ERROR("Argument `deviceRights` is null");
        return SEC_RESULT_FAILURE;
    }

    if (SEC_RESULT_SUCCESS != SecKeyCtrl_DeviceSettingsInit(device_settings_init_flag))
    {
        SEC_LOG_ERROR("SecKeyCtrl_DeviceSettingsInit failed");
        return SEC_RESULT_FAILURE;
    }

    // list of avail ports
    device::List<device::VideoOutputPort> vPorts = device::Host::getInstance().getVideoOutputPorts();
    for (size_t i = 0; i < vPorts.size(); i++)
    {
        device::VideoOutputPort &vPort = vPorts.at(i);

        SEC_TRACE(SEC_TRACE_KEYCTRL, "checking port: %s", vPort.getName().c_str());

        try
        {
            const device::VideoOutputPortType &portType = vPort.getType();

            if (vPort.isDisplayConnected())
            {
                if (portType.isDTCPSupported())
                {

#ifndef SEC_TARGET_PACEXG1
                    deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED] = 0x01;
                    SEC_TRACE(SEC_TRACE_KEYCTRL, "%s supports DTCP", vPort.getName().c_str());
#endif
                }

                if (vPort.getName() == "HDMI0")
                {
                    // vPort.isContentProtected() is true for either DTCP or HDCP
                    // if (vPort.getHDCPStatus() == dsHDCP_STATUS_AUTHENTICATED)
                    if (vPort.isContentProtected())
                    {
                        if (dsHDCP_VERSION_2X == (dsHdcpProtocolVersion_t) vPort.getHDCPCurrentProtocol())
                        {
                            SEC_TRACE(SEC_TRACE_KEYCTRL, "%s supports HDCP-2.2", vPort.getName().c_str());
                            deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED] =0x01;
                        }
                        else if (dsHDCP_VERSION_1X == (dsHdcpProtocolVersion_t) vPort.getHDCPCurrentProtocol())
                        {
                            SEC_TRACE(SEC_TRACE_KEYCTRL, "%s supports HDCP-1.4", vPort.getName().c_str());
                            deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] = 0x01;
                        }
                        else
                        {
                            SEC_LOG_ERROR("Unable to determine HDCP protocol");
                        }
                    }
                }
                else  if (vPort.getName() == "Component0")
                {
                    if (vPort.isEnabled())
                    {
                        SEC_TRACE(SEC_TRACE_KEYCTRL, "%s supports Analog", vPort.getName().c_str());
                        deviceRights[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED] = 0x01;
                    }
                }
            }
            else
            {
                SEC_TRACE(SEC_TRACE_KEYCTRL, "%s is not connected", vPort.getName().c_str());
            }
        }
        catch (const std::exception &e)
        {
            SEC_LOG_ERROR("caught exception trying to access device info. `%s'",
                    e.what());
            return SEC_RESULT_FAILURE;
        }
    }

    return SEC_RESULT_SUCCESS;
}
#endif // SEC_KEYCTRL_ENABLE_DS

#if defined(SEC_KEYCTRL_ENABLE_ENV)
Sec_Result SecKeyCtrl_GetRightsFromEnvSettings(SEC_BYTE *deviceRights)
{
    const char* envrights = NULL;

    if (NULL == (envrights=getenv("SEC_KEYCTRL_RIGHTS")))
    {
        SEC_LOG_ERROR("Environment variable `SEC_KEYCTRL_RIGHTS` is not set.");
        return SEC_RESULT_FAILURE;
    }

    std::string envString = envrights;
    std::istringstream ss(envString);
    std::string right;

    while (std::getline(ss, right, ','))
    {
        // remove spaces
        right.erase(std::remove_if(right.begin(), right.end(), ::isspace),
                right.end());
        // lower case
        std::transform(right.begin(), right.end(), right.begin(), ::tolower);

        if ("svp" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_SVP_REQUIRED] = 0x01;
        }
        else if ("dtcp" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED] = 0x01;
        }
        else if ("hdcp-1.4" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] =
                    0x01;
        }
        else if ("hdcp-2.2" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED] =
                    0x01;
        }
        else if ("analog" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED] = 0x01;
        }
        else if ("transcription-copy" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_TRANSCRIPTION_COPY_ALLOWED] = 0x01;
        }
        else if ("unrestricted-copy" == right)
        {
            deviceRights[SEC_KEYOUTPUTRIGHT_UNRESTRICTED_COPY_ALLOWED] = 0x01;
        }
        else
        {
            SEC_LOG("unknown right found: '%s'", right.c_str());
        }
    }

    return SEC_RESULT_SUCCESS;
}
#endif

/**
 * hard-coded output rights based on platform
 */
Sec_Result SecKeyCtrl_GetRightsFromPlatformDefault(SEC_BYTE *dsettings_arr)
{
    memset(dsettings_arr, 0, SEC_KEYRIGHTS_LEN);

#if defined(SEC_PLATFORM_OPENSSL)
    dsettings_arr[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] = 0x01;
    dsettings_arr[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED] = 0x01;
#elif defined(SEC_TARGET_PACEXG1)
    dsettings_arr[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] = 0x01;
    dsettings_arr[SEC_KEYOUTPUTRIGHT_ANALOG_OUTPUT_ALLOWED] = 0x01;
    /* ignoring DTCP on pacexg1 */
#endif

    return SEC_RESULT_SUCCESS;
}

/**
 * Interface to get the allowed device rights/settings based on the compile directive.
 */
Sec_Result SecKeyCtrl_GetDeviceOutputRights(int* device_settings_init_flag, SEC_BYTE *deviceRights)
{
    Sec_Result result = SEC_RESULT_FAILURE;
    memset(deviceRights, 0, SEC_KEYRIGHTS_LEN);

#if defined(SEC_KEYCTRL_ENABLE_DS)
    SEC_TRACE(SEC_TRACE_KEYCTRL, "getting output rights from devicesettings");
    result = SecKeyCtrl_GetRightsFromDeviceSettings(device_settings_init_flag, deviceRights);
#elif defined(SEC_KEYCTRL_ENABLE_ENV)
    SEC_TRACE(SEC_TRACE_KEYCTRL, "getting output rights from environment");
    result = SecKeyCtrl_GetRightsFromEnvSettings(deviceRights);
#else
    SEC_TRACE(SEC_TRACE_KEYCTRL, "getting output rights from default");
    result = SecKeyCtrl_GetRightsFromPlatformDefault(deviceRights);
#endif
    return result;
}

/**
 *  Check the passed in byte array of requested rights against the byte vector of
 *  enabled device rights.
 *
 * keyRights (rights coming from jtype container) is an array of
 * Sec_KeyOutputRight values.  Each element of the array may contain a
 * Sec_KeyOoutputRight value.
 *
 * deviceRights are set using the Sec_KeyOutputRight as an index into the vector to
 * either allow or disable the right.  Each element will either be 0x00 || 0x01
 *
 *  deviceRights[0][1][2][3][4][5][6][7]
 *               |  |  |  |  |  |  |  |
 *               |  |  |  |  |  |  |  unrestricted-copy
 *               |  |  |  |  |  |  transcription-copy
 *               |  |  |  |  |  analog-output
 *               |  |  |  |  hdcp-2.2
 *               |  |  |  hdcp-1.4
 *               |  |  dtcp
 *               |  svp
 *               not-set
 */
Sec_Result SecKeyCtrl_ComputeAllowedRights(const SEC_BYTE *keyRights, const SEC_BYTE *deviceEnabledRights)
{
    SEC_BYTE krv[SEC_KEYRIGHTS_LEN];
    int allowed = 0;
    SEC_BOOL keyHasRights = SEC_FALSE;
    SEC_BOOL deviceHasEnabled = SEC_FALSE;
    char keyStr[RIGHTS_STRING_MAX];
    char devStr[RIGHTS_STRING_MAX];

    memset(krv,0,sizeof(krv));

    // convert keyrights to vector
    for(int i=0;i<SEC_KEYRIGHTS_LEN;i++)
    {
        if (keyRights[i]!=SEC_KEYOUTPUTRIGHT_NOT_SET)
        {
            krv[keyRights[i]] = 1;
            keyHasRights = SEC_TRUE;
        }
        if (deviceEnabledRights[i])
            deviceHasEnabled = SEC_TRUE;
    }

    if (deviceHasEnabled == SEC_FALSE)
    {
        SEC_LOG_ERROR(
                "error-code=%d Device does not have any enabled output rights.  key-rights=[%s], enabled=[%s]",
                SEC_RESULT_OPL_NOT_ENGAGED,
                _SecKeyCtrl_RightsVectorToString(krv, keyStr, sizeof(keyStr)),
                _SecKeyCtrl_RightsVectorToString(deviceEnabledRights, devStr,
                        sizeof(devStr)));
        return SEC_RESULT_OPL_NOT_ENGAGED;
    }

    // for some reason, no rights are set
    if (keyHasRights == SEC_FALSE)
    {
        SEC_LOG_ERROR(
                "error-code=%d Key does not contain any output rights.  key-rights=[%s], enabled=[%s]",
                SEC_RESULT_OPL_NOT_ENGAGED,
                _SecKeyCtrl_RightsVectorToString(krv, keyStr, sizeof(keyStr)),
                _SecKeyCtrl_RightsVectorToString(deviceEnabledRights, devStr,
                        sizeof(devStr)));
        return SEC_RESULT_OPL_NOT_ENGAGED;
    }

    // SVP check.
    if (krv[SEC_KEYOUTPUTRIGHT_SVP_REQUIRED])
    {
        // SecApi-2.1 spec: SVP must also contain an output protection level
        if (!(
                krv[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED] ||
                krv[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] ||
                krv[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED]))
        {
            SEC_LOG_ERROR(
                    "error-code=%d SVP right for key must be accompanied by a protection level.  key-rights=[%s], enabled=[%s]",
                    SEC_RESULT_INVALID_SVP_DATA,
                    _SecKeyCtrl_RightsVectorToString(krv,keyStr,sizeof(keyStr)),
                    _SecKeyCtrl_RightsVectorToString(deviceEnabledRights,devStr,sizeof(devStr)));
            return SEC_RESULT_INVALID_SVP_DATA;
        }
        if (!deviceEnabledRights[SEC_KEYOUTPUTRIGHT_SVP_REQUIRED])
        {
            SEC_LOG_ERROR(
                    "error-code=%d, SVP is not enabled on device.  key-rights=[%s], enabled=[%s]",
                    SEC_RESULT_SVP_NOT_ENGAGED,
                    _SecKeyCtrl_RightsVectorToString(krv,keyStr,sizeof(keyStr)),
                    _SecKeyCtrl_RightsVectorToString(deviceEnabledRights,devStr,sizeof(devStr)));
            return SEC_RESULT_SVP_NOT_ENGAGED;
        }
        else if (!( deviceEnabledRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_DTCP_ALLOWED] ||
                deviceEnabledRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_1_4_ALLOWED] ||
                deviceEnabledRights[SEC_KEYOUTPUTRIGHT_DIGITAL_OPL_HDCP_2_2_ALLOWED]))
        {
            SEC_LOG_ERROR(
                    "error-code=%d SVP right on device must be accompanied by a protection level.  key-rights=[%s], enabled=[%s]",
                    SEC_RESULT_INVALID_SVP_DATA,
                    _SecKeyCtrl_RightsVectorToString(krv,keyStr,sizeof(keyStr)),
                    _SecKeyCtrl_RightsVectorToString(deviceEnabledRights,devStr,sizeof(devStr)));
            return SEC_RESULT_INVALID_SVP_DATA;
        }
    }

    // check what the key allows
    for(int i=0;i<SEC_KEYRIGHTS_LEN;i++)
    {
        if (i == SEC_KEYOUTPUTRIGHT_SVP_REQUIRED)
            continue;

        SEC_BYTE r = i;

        if (deviceEnabledRights[r])
        {
            if (SEC_TRACE_KEYCTRL)
                SEC_PRINT("%s enabled/",_opr_str[r]);

            if (!krv[r])
            {
                if (SEC_TRACE_KEYCTRL) SEC_PRINT("not allowed for key\n");

                SEC_LOG_ERROR(
                        "error-code=%d, %s is enabled on device but not allowed for key.  key-rights=[%s],enabled=[%s]",
                        SEC_RESULT_OPL_NOT_ENGAGED, _opr_str[r],
                        _SecKeyCtrl_RightsVectorToString(krv, keyStr, sizeof(keyStr)),
                        _SecKeyCtrl_RightsVectorToString(deviceEnabledRights, devStr, sizeof(devStr)));
                return SEC_RESULT_OPL_NOT_ENGAGED;
            }
            else
            {
                if (SEC_TRACE_KEYCTRL) SEC_PRINT("allowed for key\n");
                allowed++;
            }
        }
    }

    if (!allowed)
    {
        SEC_LOG_ERROR(
                "error-code=%d, device does not have rights enabled.  key-rights=[%s],enabled=[%s]",
                SEC_RESULT_OPL_NOT_ENGAGED,
                _SecKeyCtrl_RightsVectorToString(krv, keyStr, sizeof(keyStr)),
                _SecKeyCtrl_RightsVectorToString(deviceEnabledRights, devStr,
                        sizeof(devStr)));
        return SEC_RESULT_OPL_NOT_ENGAGED;
    }

    return SEC_RESULT_SUCCESS;
}

/**
 * Get the allowed rights settings from the device and compare against
 * the passed in keyRights vector
 */
Sec_Result SecKeyCtrl_VerifyRights(int* device_settings_init_flag, SEC_BYTE *keyRights)
{
    SEC_BYTE device_settings[SEC_KEYRIGHTS_LEN];

    memset(device_settings, 0, sizeof(device_settings));


    /* deviceRights are returned as a byte vector with Sec_KeyOutputRight slot set to 1
     * if the right is allowed. */
    if (SEC_RESULT_SUCCESS != SecKeyCtrl_GetDeviceOutputRights(device_settings_init_flag, device_settings))
    {
        SEC_LOG_ERROR("SecKeyCtrl_GetDeviceSettings failed");
        return SEC_RESULT_FAILURE;
    }

    return SecKeyCtrl_ComputeAllowedRights(keyRights, device_settings);
}

Sec_Result SecKeyCtrl_PropsVerifyRights(int* device_settings_init_flag, Sec_KeyProperties *props)
{
    return SecKeyCtrl_VerifyRights(device_settings_init_flag, props->rights);
}

Sec_Result SecKeyCtrl_KeyVerifyRights(int* device_settings_init_flag, Sec_KeyHandle *keyHandle)
{
    Sec_KeyProperties keyProps;

    if (SEC_RESULT_SUCCESS != SecKey_GetProperties(keyHandle, &keyProps))
    {
        SEC_LOG_ERROR("SecKey_GetProperties failed");
        return SEC_RESULT_FAILURE;
    }

    return SecKeyCtrl_VerifyRights(device_settings_init_flag, keyProps.rights);
}


/**
 * If the 'ignoreRightsCheck' flag is set, output rights are not validated.  This functionality
 * exists for key wrapping where output rights don't apply.
 */
Sec_Result SecKeyCtrl_ValidateKeyProperties(int* device_settings_init_flag, Sec_KeyProperties *keyProps,
        SEC_BOOL ignoreRightsCheck)
{
    SEC_SIZE tmpTime = 0;
    char tmpTimeStr[32];
    SEC_SIZE now = SecUtils_GetUtcNow();
    Sec_Result result;

    /* default properties are set on a key that was not provisioned as jtype or exported. */
    if (SecKeyCtrl_IsDefaultKeyProperties(keyProps))
    {
        return SEC_RESULT_SUCCESS;
    }

    if (strlen(keyProps->notBefore) > 0)
    {
        if (SEC_INVALID_EPOCH == SecUtils_IsoTime2Epoch(keyProps->notBefore, &tmpTime))
        {
            SEC_LOG_ERROR(
                    "SecUtils_Isotime2Epoch parse failed for notBefore `%s'",
                    keyProps->notBefore);
            return SEC_RESULT_FAILURE;
        }
        if (now < tmpTime)
        {
            SEC_LOG_ERROR("key is not yet available. notBefore=%s, now=%s",
                    keyProps->notBefore,
                    SecUtils_Epoch2IsoTime(now, tmpTimeStr, sizeof(tmpTimeStr)));
            return SEC_RESULT_FAILURE;
        }
    }
    if (strlen(keyProps->notOnOrAfter) > 0)
    {
        if (SEC_INVALID_EPOCH == SecUtils_IsoTime2Epoch(keyProps->notOnOrAfter, &tmpTime))
        {
            SEC_LOG_ERROR(
                    "SecUtils_IsoTime2Epoch parse failed for notOnOrAfter `%s'",
                    keyProps->notOnOrAfter);
            return SEC_RESULT_FAILURE;
        }

        if (now >= tmpTime)
        {
            SEC_LOG_ERROR(
                    "key has expired. notOnOrAfter=%s, now=%s",
                    keyProps->notOnOrAfter,
                    SecUtils_Epoch2IsoTime(now, tmpTimeStr, sizeof(tmpTimeStr)));
            return SEC_RESULT_FAILURE;
        }
    }

    if (ignoreRightsCheck)
    {
        return SEC_RESULT_SUCCESS;
    }

    /* check output rights */
    if (SEC_RESULT_SUCCESS != (result = SecKeyCtrl_PropsVerifyRights(device_settings_init_flag, keyProps)))
    {
        SEC_LOG_ERROR("SecKeyCtrl_KeyVerifyRights failed");
        return result;
    }

    return SEC_RESULT_SUCCESS;
}

