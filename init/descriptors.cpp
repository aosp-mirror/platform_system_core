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

#include "descriptors.h"

#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/android_get_control_file.h>
#include <cutils/sockets.h>

#include "util.h"

namespace android {
namespace init {

DescriptorInfo::DescriptorInfo(const std::string& name, const std::string& type, uid_t uid,
                               gid_t gid, int perm, const std::string& context)
        : name_(name), type_(type), uid_(uid), gid_(gid), perm_(perm), context_(context) {
}

DescriptorInfo::~DescriptorInfo() {
}

std::ostream& operator<<(std::ostream& os, const DescriptorInfo& info) {
  return os << "  descriptors " << info.name_ << " " << info.type_ << " " << std::oct << info.perm_;
}

bool DescriptorInfo::operator==(const DescriptorInfo& other) const {
  return name_ == other.name_ && type_ == other.type_ && key() == other.key();
}

void DescriptorInfo::CreateAndPublish(const std::string& globalContext) const {
  // Create
  const std::string& contextStr = context_.empty() ? globalContext : context_;
  int fd = Create(contextStr);
  if (fd < 0) return;

  // Publish
  std::string publishedName = key() + name_;
  std::for_each(publishedName.begin(), publishedName.end(),
                [] (char& c) { c = isalnum(c) ? c : '_'; });

  std::string val = std::to_string(fd);
  setenv(publishedName.c_str(), val.c_str(), 1);

  // make sure we don't close on exec
  fcntl(fd, F_SETFD, 0);
}

void DescriptorInfo::Clean() const {
}

SocketInfo::SocketInfo(const std::string& name, const std::string& type, uid_t uid,
                       gid_t gid, int perm, const std::string& context)
        : DescriptorInfo(name, type, uid, gid, perm, context) {
}

void SocketInfo::Clean() const {
    std::string path = android::base::StringPrintf("%s/%s", ANDROID_SOCKET_DIR, name().c_str());
    unlink(path.c_str());
}

int SocketInfo::Create(const std::string& context) const {
    auto types = android::base::Split(type(), "+");
    int flags =
        ((types[0] == "stream" ? SOCK_STREAM : (types[0] == "dgram" ? SOCK_DGRAM : SOCK_SEQPACKET)));
    bool passcred = types.size() > 1 && types[1] == "passcred";
    return CreateSocket(name().c_str(), flags, passcred, perm(), uid(), gid(), context.c_str());
}

const std::string SocketInfo::key() const {
  return ANDROID_SOCKET_ENV_PREFIX;
}

FileInfo::FileInfo(const std::string& name, const std::string& type, uid_t uid,
                   gid_t gid, int perm, const std::string& context)
        // defaults OK for uid,..., they are ignored for this class.
        : DescriptorInfo(name, type, uid, gid, perm, context) {
}

int FileInfo::Create(const std::string&) const {
  int flags = (type() == "r") ? O_RDONLY :
              (type() == "w") ? O_WRONLY :
                                O_RDWR;

  // Make sure we do not block on open (eg: devices can chose to block on
  // carrier detect).  Our intention is never to delay launch of a service
  // for such a condition.  The service can perform its own blocking on
  // carrier detect.
  android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(name().c_str(),
                                                      flags | O_NONBLOCK)));

  if (fd < 0) {
    PLOG(ERROR) << "Failed to open file '" << name().c_str() << "'";
    return -1;
  }

  // Fixup as we set O_NONBLOCK for open, the intent for fd is to block reads.
  fcntl(fd, F_SETFL, flags);

  LOG(INFO) << "Opened file '" << name().c_str() << "'"
            << ", flags " << std::oct << flags << std::dec;

  return fd.release();
}

const std::string FileInfo::key() const {
  return ANDROID_FILE_ENV_PREFIX;
}

}  // namespace init
}  // namespace android
