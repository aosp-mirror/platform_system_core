/*
 * Copyright (C) 2020 The Android Open Sourete Project
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

#define LOG_TAG "trusty-fuzz-utils"

#include <trusty/fuzz/utils.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <log/log_read.h>
#include <time.h>
#include <trusty/tipc.h>
#include <iostream>

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::unique_fd;

namespace {

const size_t kTimeoutSeconds = 5;
const std::string kTrustyLogTag = "trusty-log";

const time_t kInitialTime = time(nullptr);

void PrintTrustyLog() {
    auto logger_list = android_logger_list_open(LOG_ID_KERNEL, ANDROID_LOG_NONBLOCK, 1000, 0);
    if (logger_list == nullptr) {
        std::cerr << "Could not open android kernel log\n";
        return;
    }

    while (true) {
        log_msg log_msg;
        int rc = android_logger_list_read(logger_list, &log_msg);
        if (rc < 0) {
            break;
        }
        if (log_msg.entry.sec < kInitialTime) {
            continue;
        }
        char* msg = log_msg.msg();
        if (msg) {
            std::string line(msg, log_msg.entry.len);
            if (line.find(kTrustyLogTag) != std::string::npos) {
                std::cerr << line.substr(kTrustyLogTag.length() + 2) << std::endl;
            }
        }
    }

    android_logger_list_free(logger_list);
}

}  // namespace

namespace android {
namespace trusty {
namespace fuzz {

TrustyApp::TrustyApp(std::string tipc_dev, std::string ta_port)
    : tipc_dev_(tipc_dev), ta_port_(ta_port), ta_fd_(-1) {}

Result<void> TrustyApp::Connect() {
    alarm(kTimeoutSeconds);
    int fd = tipc_connect(tipc_dev_.c_str(), ta_port_.c_str());
    alarm(0);
    if (fd < 0) {
        return ErrnoError() << "failed to open TIPC device: ";
    }
    ta_fd_.reset(fd);

    return {};
}

Result<void> TrustyApp::Read(void* buf, size_t len) {
    if (ta_fd_ == -1) {
        return Error() << "TA is not connected to yet: ";
    }

    alarm(kTimeoutSeconds);
    int rc = read(ta_fd_, buf, len);
    alarm(0);
    if (rc < 0) {
        return Error() << "failed to read TIPC message from TA: ";
    }

    return {};
}

Result<void> TrustyApp::Write(const void* buf, size_t len) {
    if (ta_fd_ == -1) {
        return Error() << "TA is not connected to yet: ";
    }

    alarm(kTimeoutSeconds);
    int rc = write(ta_fd_, buf, len);
    alarm(0);
    if (rc < 0) {
        return Error() << "failed to write TIPC message to TA: ";
    }

    return {};
}

Result<int> TrustyApp::GetRawFd() {
    if (ta_fd_ == -1) {
        return Error() << "TA is not connected to yet: ";
    }

    return ta_fd_;
}

void TrustyApp::Disconnect() {
    ta_fd_.reset();
}

void Abort() {
    PrintTrustyLog();
    exit(-1);
}

}  // namespace fuzz
}  // namespace trusty
}  // namespace android
