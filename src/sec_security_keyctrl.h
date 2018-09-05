
#ifndef SEC_SECURITY_KEYCTRL_H_
#define SEC_SECURITY_KEYCTRL_H_

#include "sec_security.h"

/**
 * Sec Key Control functions.
 */

#ifdef __cplusplus
extern "C"
{
#endif

Sec_Result SecKeyCtrl_DeviceSettingsInit(int* device_settings_init_flag);
void SecKeyCtrl_DeviceSettingsShutdown(int* device_settings_init_flag);

Sec_Result SecKeyCtrl_ComputeAllowedRights(const SEC_BYTE *keyRights, const SEC_BYTE *device_settings);

Sec_Result SecKeyCtrl_GetRightsFromPlatformDefault(SEC_BYTE *deviceRights);
Sec_Result SecKeyCtrl_GetDeviceOutputRights(int* device_settings_init_flag, SEC_BYTE *settings);

Sec_Result SecKeyCtrl_VerifyRights(int* device_settings_init_flag, SEC_BYTE *keyRights);
Sec_Result SecKeyCtrl_KeyVerifyRights(int* device_settings_init_flag, Sec_KeyHandle *keyHandle);
Sec_Result SecKeyCtrl_PropsVerifyRights(int* device_settings_init_flag, Sec_KeyProperties *props);

Sec_Result SecKeyCtrl_ValidateKeyProperties(int* device_settings_init_flag, Sec_KeyProperties *keyProps,
        SEC_BOOL ignoreRightsCheck);

void SecKeyCtrl_SetDefaultKeyProperties(Sec_KeyProperties *keyProperties, Sec_KeyType keyType, SEC_SIZE keyLength);

SEC_BOOL SecKeyCtrl_IsDefaultKeyProperties(Sec_KeyProperties *keyProps);
SEC_BOOL SecKeyCtrl_KeyPropertiesContainOutputRight(Sec_KeyProperties *keyProps, Sec_KeyOutputRight right);


#ifdef __cplusplus
}
#endif


#endif
