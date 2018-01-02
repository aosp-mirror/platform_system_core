/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef __DIAGNOSE_LINUX_USB_H
#define __DIAGNOSE_LINUX_USB_H

#include <string>

// USB permission error help text. The short version will be one line, long may be multi-line.
// Returns a string message to print, or an empty string if no problems could be found.
std::string UsbNoPermissionsShortHelpText();
std::string UsbNoPermissionsLongHelpText();

#endif
