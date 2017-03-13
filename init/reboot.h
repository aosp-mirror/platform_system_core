/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_REBOOT_H
#define _INIT_REBOOT_H

/* Reboot / shutdown the system.
 * cmd ANDROID_RB_* as defined in android_reboot.h
 * reason Reason string like "reboot", "userrequested"
 * rebootTarget Reboot target string like "bootloader". Otherwise, it should be an
 *              empty string.
 * runFsck Whether to run fsck after umount is done.
 */
void DoReboot(unsigned int cmd, const std::string& reason, const std::string& rebootTarget,
              bool runFsck) __attribute__((__noreturn__));

#endif
