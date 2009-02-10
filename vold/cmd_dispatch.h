
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

#ifndef _CMD_DISPATCH_H
#define _CMD_DISPATCH_H

// These must match the strings in java/android/android/os/UsbListener.java
#define VOLD_CMD_ENABLE_UMS         "enable_ums"
#define VOLD_CMD_DISABLE_UMS        "disable_ums"
#define VOLD_CMD_SEND_UMS_STATUS    "send_ums_status"

// these commands should contain a volume mount point after the colon
#define VOLD_CMD_MOUNT_VOLUME       "mount_volume:"
#define VOLD_CMD_EJECT_MEDIA        "eject_media:"
#define VOLD_CMD_FORMAT_MEDIA       "format_media:"

#endif
