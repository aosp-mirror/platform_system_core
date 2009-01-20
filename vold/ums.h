
/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef _UMS_H
#define _UMS_H

// these must match the corresponding strings in java/android/android/os/UsbListener.java
#define VOLD_EVT_UMS_ENABLED              "ums_enabled"
#define VOLD_EVT_UMS_DISABLED             "ums_disabled"
#define VOLD_EVT_UMS_CONNECTED            "ums_connected"
#define VOLD_EVT_UMS_DISCONNECTED         "ums_disconnected"


int ums_send_status(void);
int ums_enable(char *device_file, char *lun_syspath);
int ums_disable(char *lun_syspath);
#endif
