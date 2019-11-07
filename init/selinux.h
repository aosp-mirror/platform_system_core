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

#pragma once

namespace android {
namespace init {

// Initialize SELinux, then exec init to run in the init SELinux context.
int SetupSelinux(char** argv);

// Restore the proper security context to files and directories on ramdisk, and
// those that were created before initial sepolicy load.
// This must happen before /dev is populated by ueventd.
void SelinuxRestoreContext();

// Set up SELinux logging to be written to kmsg, to match init's logging.
void SelinuxSetupKernelLogging();

// Return the Android API level with which the vendor SEPolicy was compiled.
// Used for version checks such as whether or not vendor_init should be used.
int SelinuxGetVendorAndroidVersion();

static constexpr char kEnvSelinuxStartedAt[] = "SELINUX_STARTED_AT";

}  // namespace init
}  // namespace android
