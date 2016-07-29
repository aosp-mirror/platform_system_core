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

#include <nvram/hal/nvram_device_adapter.h>

#include "trusty_nvram_implementation.h"

extern "C" int trusty_nvram_open(const hw_module_t* module,
                                 const char* device_id,
                                 hw_device_t** device_ptr) {
  if (strcmp(NVRAM_HARDWARE_DEVICE_ID, device_id) != 0) {
    return -EINVAL;
  }

  nvram::NvramDeviceAdapter* adapter = new nvram::NvramDeviceAdapter(
      module, new nvram::TrustyNvramImplementation);
  *device_ptr = adapter->as_device();
  return 0;
}
