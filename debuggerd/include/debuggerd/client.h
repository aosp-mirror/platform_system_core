/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdbool.h>
#include <sys/cdefs.h>
#include <unistd.h>

#include <android-base/unique_fd.h>

#include "dump_type.h"

// Trigger a dump of specified process to output_fd.
// output_fd is consumed, timeout of 0 will wait forever.
bool debuggerd_trigger_dump(pid_t tid, enum DebuggerdDumpType dump_type, unsigned int timeout_ms,
                            android::base::unique_fd output_fd);

int dump_backtrace_to_file(pid_t tid, enum DebuggerdDumpType dump_type, int output_fd);
int dump_backtrace_to_file_timeout(pid_t tid, enum DebuggerdDumpType dump_type, int timeout_secs,
                                   int output_fd);
