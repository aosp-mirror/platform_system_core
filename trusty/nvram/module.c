/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <hardware/nvram.h>

// This function is defined in trusty_nvram_implementation.cpp.
int trusty_nvram_open(const hw_module_t* module,
                      const char* device_id,
                      hw_device_t** device_ptr);

static struct hw_module_methods_t nvram_module_methods = {
    .open = trusty_nvram_open,
};

struct nvram_module HAL_MODULE_INFO_SYM
    __attribute__((visibility("default"))) = {
        .common = {.tag = HARDWARE_MODULE_TAG,
                   .module_api_version = NVRAM_MODULE_API_VERSION_0_1,
                   .hal_api_version = HARDWARE_HAL_API_VERSION,
                   .id = NVRAM_HARDWARE_MODULE_ID,
                   .name = "Trusty NVRAM HAL",
                   .author = "The Android Open Source Project",
                   .methods = &nvram_module_methods,
                   .dso = 0,
                   .reserved = {}},
};
