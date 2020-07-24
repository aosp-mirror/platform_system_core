/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <linux/types.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <libdm/dm.h>

using android::base::unique_fd;

#define DM_USER_MAP_READ 0
#define DM_USER_MAP_WRITE 1

struct dm_user_message {
    __u64 seq;
    __u64 type;
    __u64 flags;
    __u64 sector;
    __u64 len;
    __u8 buf[];
};

using namespace android::dm;

static int daemon_main(const std::string& device) {
    unique_fd block_fd(open(device.c_str(), O_RDWR));
    if (block_fd < 0) {
        PLOG(ERROR) << "Unable to open " << device;
        return 1;
    }

    unique_fd ctrl_fd(open("/dev/dm-user", O_RDWR));
    if (ctrl_fd < 0) {
        PLOG(ERROR) << "Unable to open /dev/dm-user";
        return 1;
    }

    size_t buf_size = 1UL << 16;
    auto buf = std::make_unique<char>(buf_size);

    /* Just keeps pumping messages between userspace and the kernel.  We won't
     * actually be doing anything, but the sequence numbers line up so it'll at
     * least make forward progress. */
    while (true) {
        struct dm_user_message* msg = (struct dm_user_message*)buf.get();

        memset(buf.get(), 0, buf_size);

        ssize_t readed = read(ctrl_fd.get(), buf.get(), buf_size);
        if (readed < 0) {
            PLOG(ERROR) << "Control read failed, trying with more space";
            buf_size *= 2;
            buf = std::make_unique<char>(buf_size);
            continue;
        }

        LOG(DEBUG) << android::base::StringPrintf("read() from dm-user returned %d bytes:",
                                                  (int)readed);
        LOG(DEBUG) << android::base::StringPrintf("    msg->seq:    0x%016llx", msg->seq);
        LOG(DEBUG) << android::base::StringPrintf("    msg->type:   0x%016llx", msg->type);
        LOG(DEBUG) << android::base::StringPrintf("    msg->flags:  0x%016llx", msg->flags);
        LOG(DEBUG) << android::base::StringPrintf("    msg->sector: 0x%016llx", msg->sector);
        LOG(DEBUG) << android::base::StringPrintf("    msg->len:    0x%016llx", msg->len);

        switch (msg->type) {
            case DM_USER_MAP_READ: {
                LOG(DEBUG) << android::base::StringPrintf(
                        "Responding to read of sector %lld with %lld bytes data", msg->sector,
                        msg->len);

                if ((sizeof(*msg) + msg->len) > buf_size) {
                    auto old_buf = std::move(buf);
                    buf_size = sizeof(*msg) + msg->len;
                    buf = std::make_unique<char>(buf_size);
                    memcpy(buf.get(), old_buf.get(), sizeof(*msg));
                    msg = (struct dm_user_message*)buf.get();
                }

                if (lseek(block_fd.get(), msg->sector * 512, SEEK_SET) < 0) {
                    PLOG(ERROR) << "lseek failed: " << device;
                    return 7;
                }
                if (!android::base::ReadFully(block_fd.get(), msg->buf, msg->len)) {
                    PLOG(ERROR) << "read failed: " << device;
                    return 7;
                }

                if (!android::base::WriteFully(ctrl_fd.get(), buf.get(), sizeof(*msg) + msg->len)) {
                    PLOG(ERROR) << "write control failed";
                    return 3;
                }
                break;
            }

            case DM_USER_MAP_WRITE:
                abort();
                break;
        }

        LOG(DEBUG) << "read() finished, next message";
    }

    return 0;
}

int main([[maybe_unused]] int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::KernelLogger);
    daemon_main(argv[1]);
    return 0;
}
