/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <errno.h>
#include <string.h>

#include <hardware/hardware.h>
#include <hardware/keymaster0.h>

#include <trusty_keymaster/legacy/trusty_keymaster_device.h>

using keymaster::TrustyKeymasterDevice;

/*
 * Generic device handling
 */
static int trusty_keymaster_open(const hw_module_t* module, const char* name,
                                 hw_device_t** device) {
    if (strcmp(name, KEYSTORE_KEYMASTER) != 0) {
        return -EINVAL;
    }

    TrustyKeymasterDevice* dev = new TrustyKeymasterDevice(module);
    if (dev == NULL) {
        return -ENOMEM;
    }
    *device = dev->hw_device();
    // Do not delete dev; it will get cleaned up when the caller calls device->close(), and must
    // exist until then.
    return 0;
}

static struct hw_module_methods_t keystore_module_methods = {
        .open = trusty_keymaster_open,
};

struct keystore_module HAL_MODULE_INFO_SYM __attribute__((visibility("default"))) = {
        .common =
                {
                        .tag = HARDWARE_MODULE_TAG,
                        .module_api_version = KEYMASTER_MODULE_API_VERSION_2_0,
                        .hal_api_version = HARDWARE_HAL_API_VERSION,
                        .id = KEYSTORE_HARDWARE_MODULE_ID,
                        .name = "Trusty Keymaster HAL",
                        .author = "The Android Open Source Project",
                        .methods = &keystore_module_methods,
                        .dso = 0,
                        .reserved = {},
                },
};
