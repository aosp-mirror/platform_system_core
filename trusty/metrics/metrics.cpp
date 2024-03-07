/*
 * Copyright (C) 2021 The Android Open Sourete Project
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

#define LOG_TAG "metrics"

#include <android-base/logging.h>
#include <fcntl.h>
#include <poll.h>
#include <trusty/metrics/metrics.h>
#include <trusty/metrics/tipc.h>
#include <trusty/tipc.h>
#include <unistd.h>

namespace android {
namespace trusty {
namespace metrics {

using android::base::ErrnoError;
using android::base::Error;

Result<void> TrustyMetrics::Open() {
    int fd = tipc_connect(tipc_dev_.c_str(), METRICS_PORT);
    if (fd < 0) {
        return ErrnoError() << "failed to connect to Trusty metrics TA";
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return ErrnoError() << "failed F_GETFL";
    }

    int rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if (rc < 0) {
        return ErrnoError() << "failed F_SETFL";
    }

    metrics_fd_.reset(fd);
    return {};
}

Result<void> TrustyMetrics::WaitForEvent(int timeout_ms) {
    if (!metrics_fd_.ok()) {
        return Error() << "connection to Metrics TA has not been initialized yet";
    }

    struct pollfd pfd = {
            .fd = metrics_fd_,
            .events = POLLIN,
    };

    int rc = poll(&pfd, 1, timeout_ms);
    if (rc != 1) {
        return ErrnoError() << "failed poll()";
    }

    if (!(pfd.revents & POLLIN)) {
        return ErrnoError() << "channel not ready";
    }

    return {};
}

Result<void> TrustyMetrics::HandleEvent() {
    if (!metrics_fd_.ok()) {
        return Error() << "connection to Metrics TA has not been initialized yet";
    }

    struct metrics_msg metrics_msg;
    int rc = read(metrics_fd_, &metrics_msg, sizeof(metrics_msg));
    if (rc < 0) {
        return ErrnoError() << "failed to read metrics message";
    }
    size_t msg_len = rc;

    if (msg_len < sizeof(metrics_req)) {
        return Error() << "message too small: " << rc;
    }
    uint32_t cmd = metrics_msg.req.cmd;
    uint32_t status = METRICS_NO_ERROR;

    switch (cmd) {
        case METRICS_CMD_REPORT_CRASH: {
            struct metrics_report_crash_req crash_args = metrics_msg.crash_args;
            auto app_id_ptr = crash_args.app_id;
            std::string app_id(app_id_ptr, UUID_STR_SIZE);

            HandleCrash(app_id);
            break;
        }

        case METRICS_CMD_REPORT_EVENT_DROP:
            HandleEventDrop();
            break;

        default:
            status = METRICS_ERR_UNKNOWN_CMD;
            break;
    }

    metrics_resp resp = {
            .cmd = cmd | METRICS_CMD_RESP_BIT,
            .status = status,
    };

    rc = write(metrics_fd_, &resp, sizeof(resp));
    if (rc < 0) {
        return ErrnoError() << "failed to request next metrics event";
    }

    if (rc != (int)sizeof(resp)) {
        return Error() << "unexpected number of bytes sent event: " << rc;
    }

    return {};
}

}  // namespace metrics
}  // namespace trusty
}  // namespace android
