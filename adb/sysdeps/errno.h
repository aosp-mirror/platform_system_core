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

#pragma once

#include <errno.h>
#include <string.h>

#if defined(_WIN32)
char* adb_strerror(int err);
#define strerror adb_strerror
#endif

// errno values differ between operating systems and between Linux architectures.
// Arbitrarily select the Linux asm-generic values to use in the wire protocol.
int errno_to_wire(int error);
int errno_from_wire(int error);
