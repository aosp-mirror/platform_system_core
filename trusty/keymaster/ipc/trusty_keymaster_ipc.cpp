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

#define LOG_TAG "TrustyKeymaster"

// TODO: make this generic in libtrusty

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <variant>
#include <vector>

#include <log/log.h>
#include <trusty/tipc.h>

#include <trusty_keymaster/ipc/keymaster_ipc.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

static int handle_ = -1;

int trusty_keymaster_connect() {
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, KEYMASTER_PORT);
    if (rc < 0) {
        return rc;
    }

    handle_ = rc;
    return 0;
}

class VectorEraser {
  public:
    VectorEraser(std::vector<uint8_t>* v) : _v(v) {}
    ~VectorEraser() {
        if (_v) {
            std::fill(const_cast<volatile uint8_t*>(_v->data()),
                      const_cast<volatile uint8_t*>(_v->data() + _v->size()), 0);
        }
    }
    void disarm() { _v = nullptr; }
    VectorEraser(const VectorEraser&) = delete;
    VectorEraser& operator=(const VectorEraser&) = delete;
    VectorEraser(VectorEraser&& other) = delete;
    VectorEraser& operator=(VectorEraser&&) = delete;

  private:
    std::vector<uint8_t>* _v;
};

std::variant<int, std::vector<uint8_t>> trusty_keymaster_call_2(uint32_t cmd, void* in,
                                                                uint32_t in_size) {
    if (handle_ < 0) {
        ALOGE("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(struct keymaster_message);
    struct keymaster_message* msg = reinterpret_cast<struct keymaster_message*>(malloc(msg_size));
    if (!msg) {
        ALOGE("failed to allocate msg buffer\n");
        return -EINVAL;
    }

    msg->cmd = cmd;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGE("failed to send cmd (%d) to %s: %s\n", cmd, KEYMASTER_PORT, strerror(errno));
        return -errno;
    }

    std::vector<uint8_t> out(TRUSTY_KEYMASTER_RECV_BUF_SIZE);
    VectorEraser out_eraser(&out);
    uint8_t* write_pos = out.data();
    uint8_t* out_end = out.data() + out.size();

    struct iovec iov[2];
    struct keymaster_message header;
    iov[0] = {.iov_base = &header, .iov_len = sizeof(struct keymaster_message)};
    while (true) {
        if (out_end - write_pos < KEYMASTER_MAX_BUFFER_LENGTH) {
            // In stead of using std::vector.resize(), allocate a new one to have chance
            // at zeroing the old buffer.
            std::vector<uint8_t> new_out(out.size() + KEYMASTER_MAX_BUFFER_LENGTH);
            // After the swap below this erases the old out buffer.
            VectorEraser new_out_eraser(&new_out);
            std::copy(out.data(), write_pos, new_out.begin());

            auto write_offset = write_pos - out.data();

            std::swap(new_out, out);

            write_pos = out.data() + write_offset;
            out_end = out.data() + out.size();
        }
        size_t buffer_size = 0;
        if (__builtin_sub_overflow(reinterpret_cast<uintptr_t>(out_end),
                                   reinterpret_cast<uintptr_t>(write_pos), &buffer_size)) {
            return -EOVERFLOW;
        }
        iov[1] = {.iov_base = write_pos, .iov_len = buffer_size};

        rc = readv(handle_, iov, 2);
        if (rc < 0) {
            ALOGE("failed to retrieve response for cmd (%d) to %s: %s\n", cmd, KEYMASTER_PORT,
                  strerror(errno));
            return -errno;
        }

        if ((size_t)rc < sizeof(struct keymaster_message)) {
            ALOGE("invalid response size (%d)\n", (int)rc);
            return -EINVAL;
        }

        if ((cmd | KEYMASTER_RESP_BIT) != (header.cmd & ~(KEYMASTER_STOP_BIT))) {
            ALOGE("invalid command (%d)", header.cmd);
            return -EINVAL;
        }
        write_pos += ((size_t)rc - sizeof(struct keymaster_message));
        if (header.cmd & KEYMASTER_STOP_BIT) {
            break;
        }
    }

    out.resize(write_pos - out.data());
    out_eraser.disarm();
    return out;
}

int trusty_keymaster_call(uint32_t cmd, void* in, uint32_t in_size, uint8_t* out,
                          uint32_t* out_size) {
    auto result = trusty_keymaster_call_2(cmd, in, in_size);
    if (auto out_buffer = std::get_if<std::vector<uint8_t>>(&result)) {
        if (out_buffer->size() <= *out_size) {
            std::copy(out_buffer->begin(), out_buffer->end(), out);
            std::fill(const_cast<volatile uint8_t*>(&*out_buffer->begin()),
                      const_cast<volatile uint8_t*>(&*out_buffer->end()), 0);

            *out_size = out_buffer->size();
            return 0;
        } else {
            ALOGE("Message was to large (%zu) for the provided buffer (%u)", out_buffer->size(),
                  *out_size);
            return -EMSGSIZE;
        }
    } else {
        return std::get<int>(result);
    }
}

void trusty_keymaster_disconnect() {
    if (handle_ >= 0) {
        tipc_close(handle_);
    }
    handle_ = -1;
}

keymaster_error_t translate_error(int err) {
    switch (err) {
        case 0:
            return KM_ERROR_OK;
        case -EPERM:
        case -EACCES:
            return KM_ERROR_SECURE_HW_ACCESS_DENIED;

        case -ECANCELED:
            return KM_ERROR_OPERATION_CANCELLED;

        case -ENODEV:
            return KM_ERROR_UNIMPLEMENTED;

        case -ENOMEM:
            return KM_ERROR_MEMORY_ALLOCATION_FAILED;

        case -EBUSY:
            return KM_ERROR_SECURE_HW_BUSY;

        case -EIO:
            return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;

        case -EOVERFLOW:
            return KM_ERROR_INVALID_INPUT_LENGTH;

        default:
            return KM_ERROR_UNKNOWN_ERROR;
    }
}

keymaster_error_t trusty_keymaster_send(uint32_t command, const keymaster::Serializable& req,
                                        keymaster::KeymasterResponse* rsp) {
    uint32_t req_size = req.SerializedSize();
    if (req_size > TRUSTY_KEYMASTER_SEND_BUF_SIZE) {
        ALOGE("Request too big: %u Max size: %u", req_size, TRUSTY_KEYMASTER_SEND_BUF_SIZE);
        return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    uint8_t send_buf[TRUSTY_KEYMASTER_SEND_BUF_SIZE];
    keymaster::Eraser send_buf_eraser(send_buf, TRUSTY_KEYMASTER_SEND_BUF_SIZE);
    req.Serialize(send_buf, send_buf + req_size);

    // Send it
    auto response = trusty_keymaster_call_2(command, send_buf, req_size);
    if (auto response_buffer = std::get_if<std::vector<uint8_t>>(&response)) {
        keymaster::Eraser response_buffer_erasor(response_buffer->data(), response_buffer->size());
        ALOGV("Received %zu byte response\n", response_buffer->size());

        const uint8_t* p = response_buffer->data();
        if (!rsp->Deserialize(&p, p + response_buffer->size())) {
            ALOGE("Error deserializing response of size %zu\n", response_buffer->size());
            return KM_ERROR_UNKNOWN_ERROR;
        } else if (rsp->error != KM_ERROR_OK) {
            ALOGE("Response of size %zu contained error code %d\n", response_buffer->size(),
                  (int)rsp->error);
        }
        return rsp->error;
    } else {
        auto rc = std::get<int>(response);
        // Reset the connection on tipc error
        trusty_keymaster_disconnect();
        trusty_keymaster_connect();
        ALOGE("tipc error: %d\n", rc);
        // TODO(swillden): Distinguish permanent from transient errors and set error_ appropriately.
        return translate_error(rc);
    }
}
