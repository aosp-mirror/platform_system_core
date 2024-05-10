/*
 * Copyright 2023, The Android Open Source Project
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

#include "tombstoned/tombstoned.h"

#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <linux/vm_sockets.h>
#include "util.h"

using android::base::unique_fd;

/*
  Port number that VirtualMachineService listens on connections from the guest VMs.
  Kep in sync with IVirtualMachineService.aidl
*/
const unsigned int VM_TOMBSTONES_SERVICE_PORT = 2000;

static bool is_microdroid() {
  return android::base::GetProperty("ro.hardware", "") == "microdroid";
}

static bool connect_tombstone_server_microdroid(unique_fd* text_output_fd,
                                                unique_fd* proto_output_fd,
                                                DebuggerdDumpType dump_type) {
  // We do not wait for the property to be set, the default behaviour is not export tombstones.
  if (!android::base::GetBoolProperty("microdroid_manager.export_tombstones.enabled", false)) {
    LOG(WARNING) << "exporting tombstones is not enabled";
    return false;
  }

  // Microdroid supports handling requests originating from crash_dump which
  // supports limited dump types. Java traces and incept management are not supported.
  switch (dump_type) {
    case kDebuggerdNativeBacktrace:
    case kDebuggerdTombstone:
    case kDebuggerdTombstoneProto:
      break;

    default:
      LOG(WARNING) << "Requested dump type: " << dump_type << " "
                   << "not supported";
  }

  int fd1 = TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM, 0));
  int fd2 = TEMP_FAILURE_RETRY(socket(AF_VSOCK, SOCK_STREAM, 0));
  if (fd1 < 0 || fd2 < 0) {
    LOG(WARNING) << "Unable to create virtual socket for writing tombstones";
    return false;
  }

  unique_fd vsock_output_fd(fd1), vsock_proto_fd(fd2);

  struct sockaddr_vm sa = (struct sockaddr_vm){
      .svm_family = AF_VSOCK,
      .svm_port = VM_TOMBSTONES_SERVICE_PORT,
      .svm_cid = VMADDR_CID_HOST,
  };

  if (TEMP_FAILURE_RETRY(connect(vsock_output_fd, (struct sockaddr*)&sa, sizeof(sa))) < 0) {
    PLOG(WARNING) << "Unable to connect to tombstone service in host";
    return false;
  }

  if (dump_type == kDebuggerdTombstoneProto) {
    if (TEMP_FAILURE_RETRY(connect(vsock_proto_fd, (struct sockaddr*)&sa, sizeof(sa))) < 0) {
      PLOG(WARNING) << "Unable to connect to tombstone service in host";
      return false;
    }
  }

  *text_output_fd = std::move(vsock_output_fd);
  if (proto_output_fd) {
    *proto_output_fd = std::move(vsock_proto_fd);
  }
  return true;
}

static bool notify_completion_microdroid(int vsock_out, int vsock_proto) {
  if (shutdown(vsock_out, SHUT_WR) || shutdown(vsock_proto, SHUT_WR)) return false;
  return true;
}
bool connect_tombstone_server(pid_t pid, unique_fd* tombstoned_socket, unique_fd* text_output_fd,
                              unique_fd* proto_output_fd, DebuggerdDumpType dump_type) {
  if (is_microdroid()) {
    return connect_tombstone_server_microdroid(text_output_fd, proto_output_fd, dump_type);
  }
  return tombstoned_connect(pid, tombstoned_socket, text_output_fd, proto_output_fd, dump_type);
}

bool notify_completion(int tombstoned_socket, int vsock_out, int vsock_proto) {
  if (is_microdroid()) {
    return notify_completion_microdroid(vsock_out, vsock_proto);
  }
  return tombstoned_notify_completion(tombstoned_socket);
}
