/*
 * Copyright 2022, The Android Open Source Project
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

#include "wrapper.hpp"

#include <android-base/unique_fd.h>

#include "tombstoned/tombstoned.h"

using android::base::unique_fd;

bool tombstoned_connect_files(pid_t pid, int& tombstoned_socket, int& text_output_fd,
                              int& proto_output_fd, DebuggerdDumpType dump_type) {
  unique_fd tombstoned_socket_unique, text_output_unique, proto_output_unique;

  bool result = tombstoned_connect(pid, &tombstoned_socket_unique, &text_output_unique,
                                   &proto_output_unique, dump_type);
  if (result) {
    tombstoned_socket = tombstoned_socket_unique.release();
    text_output_fd = text_output_unique.release();
    proto_output_fd = proto_output_unique.release();
  }

  return result;
}
