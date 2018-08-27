/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "libdm/dm.h"

#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <android-base/logging.h>
#include <android-base/macros.h>

namespace android {
namespace dm {

DeviceMapper::DeviceMapper() : fd_(-1) {
    fd_ = TEMP_FAILURE_RETRY(open("/dev/device-mapper", O_RDWR | O_CLOEXEC));
    if (fd_ < 0) {
        PLOG(ERROR) << "Failed to open device-mapper";
    }
}

DeviceMapper& DeviceMapper::Instance() {
    static DeviceMapper instance;
    return instance;
}
// Creates a new device mapper device
bool DeviceMapper::CreateDevice(const std::string& name) {
    if (name.empty()) {
        LOG(ERROR) << "Unnamed device mapper device creation is not supported";
        return false;
    }

    if (name.size() >= DM_NAME_LEN) {
        LOG(ERROR) << "[" << name << "] is too long to be device mapper name";
        return false;
    }

    struct dm_ioctl io;
    InitIo(&io, name);

    if (ioctl(fd_, DM_DEV_CREATE, &io)) {
        PLOG(ERROR) << "DM_DEV_CREATE failed for [" << name << "]";
        return false;
    }

    // Check to make sure the newly created device doesn't already have targets
    // added or opened by someone
    CHECK(io.target_count == 0) << "Unexpected targets for newly created [" << name << "] device";
    CHECK(io.open_count == 0) << "Unexpected opens for newly created [" << name << "] device";

    // Creates a new device mapper device with the name passed in
    return true;
}

bool DeviceMapper::DeleteDevice(const std::string& name) {
    if (name.empty()) {
        LOG(ERROR) << "Unnamed device mapper device creation is not supported";
        return false;
    }

    if (name.size() >= DM_NAME_LEN) {
        LOG(ERROR) << "[" << name << "] is too long to be device mapper name";
        return false;
    }

    struct dm_ioctl io;
    InitIo(&io, name);

    if (ioctl(fd_, DM_DEV_REMOVE, &io)) {
        PLOG(ERROR) << "DM_DEV_REMOVE failed for [" << name << "]";
        return false;
    }

    // Check to make sure appropriate uevent is generated so ueventd will
    // do the right thing and remove the corresponding device node and symlinks.
    CHECK(io.flags & DM_UEVENT_GENERATED_FLAG)
            << "Didn't generate uevent for [" << name << "] removal";

    return true;
}

const std::unique_ptr<DmTable> DeviceMapper::table(const std::string& /* name */) const {
    // TODO(b/110035986): Return the table, as read from the kernel instead
    return nullptr;
}

DmDeviceState DeviceMapper::GetState(const std::string& name) const {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        return DmDeviceState::INVALID;
    }
    if ((io.flags & DM_ACTIVE_PRESENT_FLAG) && !(io.flags & DM_SUSPEND_FLAG)) {
        return DmDeviceState::ACTIVE;
    }
    return DmDeviceState::SUSPENDED;
}

bool DeviceMapper::CreateDevice(const std::string& name, const DmTable& table) {
    if (!CreateDevice(name)) {
        return false;
    }
    if (!LoadTableAndActivate(name, table)) {
        DeleteDevice(name);
        return false;
    }
    return true;
}

bool DeviceMapper::LoadTableAndActivate(const std::string& name, const DmTable& table) {
    std::string ioctl_buffer(sizeof(struct dm_ioctl), 0);
    ioctl_buffer += table.Serialize();

    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(&ioctl_buffer[0]);
    InitIo(io, name);
    io->data_size = ioctl_buffer.size();
    io->data_start = sizeof(struct dm_ioctl);
    io->target_count = static_cast<uint32_t>(table.num_targets());
    if (table.readonly()) {
        io->flags |= DM_READONLY_FLAG;
    }
    if (ioctl(fd_, DM_TABLE_LOAD, io)) {
        PLOG(ERROR) << "DM_TABLE_LOAD failed";
        return false;
    }

    InitIo(io, name);
    if (ioctl(fd_, DM_DEV_SUSPEND, io)) {
        PLOG(ERROR) << "DM_TABLE_SUSPEND resume failed";
        return false;
    }
    return true;
}

// Reads all the available device mapper targets and their corresponding
// versions from the kernel and returns in a vector
bool DeviceMapper::GetAvailableTargets(std::vector<DmTargetTypeInfo>* targets) {
    targets->clear();

    // calculate the space needed to read a maximum of kMaxPossibleDmTargets
    uint32_t payload_size = sizeof(struct dm_target_versions);
    payload_size += DM_MAX_TYPE_NAME;
    // device mapper wants every target spec to be aligned at 8-byte boundary
    payload_size = DM_ALIGN(payload_size);
    payload_size *= kMaxPossibleDmTargets;

    uint32_t data_size = sizeof(struct dm_ioctl) + payload_size;
    auto buffer = std::unique_ptr<void, void (*)(void*)>(calloc(1, data_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory";
        return false;
    }

    // Sets appropriate data size and data_start to make sure we tell kernel
    // about the total size of the buffer we are passing and where to start
    // writing the list of targets.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    InitIo(io);
    io->data_size = data_size;
    io->data_start = sizeof(*io);

    if (ioctl(fd_, DM_LIST_VERSIONS, io)) {
        PLOG(ERROR) << "DM_LIST_VERSIONS failed";
        return false;
    }

    // If the provided buffer wasn't enough to list all targets, note that
    // any data beyond sizeof(*io) must not be read in this case
    if (io->flags & DM_BUFFER_FULL_FLAG) {
        LOG(INFO) << data_size << " is not enough memory to list all dm targets";
        return false;
    }

    // if there are no targets registered, return success with empty vector
    if (io->data_size == sizeof(*io)) {
        return true;
    }

    // Parse each target and list the name and version
    // TODO(b/110035986): Templatize this
    uint32_t next = sizeof(*io);
    data_size = io->data_size - next;
    struct dm_target_versions* vers =
            reinterpret_cast<struct dm_target_versions*>(static_cast<char*>(buffer.get()) + next);
    while (next && data_size) {
        targets->emplace_back(vers);
        if (vers->next == 0) {
            break;
        }
        next += vers->next;
        data_size -= vers->next;
        vers = reinterpret_cast<struct dm_target_versions*>(static_cast<char*>(buffer.get()) + next);
    }

    return true;
}

bool DeviceMapper::GetAvailableDevices(std::vector<DmBlockDevice>* devices) {
    devices->clear();

    // calculate the space needed to read a maximum of 256 targets, each with
    // name with maximum length of 16 bytes
    uint32_t payload_size = sizeof(struct dm_name_list);
    // 128-bytes for the name
    payload_size += DM_NAME_LEN;
    // dm wants every device spec to be aligned at 8-byte boundary
    payload_size = DM_ALIGN(payload_size);
    payload_size *= kMaxPossibleDmDevices;
    uint32_t data_size = sizeof(struct dm_ioctl) + payload_size;
    auto buffer = std::unique_ptr<void, void (*)(void*)>(calloc(1, data_size), free);
    if (buffer == nullptr) {
        LOG(ERROR) << "failed to allocate memory";
        return false;
    }

    // Sets appropriate data size and data_start to make sure we tell kernel
    // about the total size of the buffer we are passing and where to start
    // writing the list of targets.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    InitIo(io);
    io->data_size = data_size;
    io->data_start = sizeof(*io);

    if (ioctl(fd_, DM_LIST_DEVICES, io)) {
        PLOG(ERROR) << "DM_LIST_DEVICES failed";
        return false;
    }

    // If the provided buffer wasn't enough to list all devices any data
    // beyond sizeof(*io) must not be read.
    if (io->flags & DM_BUFFER_FULL_FLAG) {
        LOG(INFO) << data_size << " is not enough memory to list all dm devices";
        return false;
    }

    // if there are no devices created yet, return success with empty vector
    if (io->data_size == sizeof(*io)) {
        return true;
    }

    // Parse each device and add a new DmBlockDevice to the vector
    // created from the kernel data.
    uint32_t next = sizeof(*io);
    data_size = io->data_size - next;
    struct dm_name_list* dm_dev =
            reinterpret_cast<struct dm_name_list*>(static_cast<char*>(buffer.get()) + next);

    while (next && data_size) {
        devices->emplace_back((dm_dev));
        if (dm_dev->next == 0) {
            break;
        }
        next += dm_dev->next;
        data_size -= dm_dev->next;
        dm_dev = reinterpret_cast<struct dm_name_list*>(static_cast<char*>(buffer.get()) + next);
    }

    return true;
}

// Accepts a device mapper device name (like system_a, vendor_b etc) and
// returns the path to it's device node (or symlink to the device node)
bool DeviceMapper::GetDmDevicePathByName(const std::string& name, std::string* path) {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        PLOG(ERROR) << "DM_DEV_STATUS failed for " << name;
        return false;
    }

    uint32_t dev_num = minor(io.dev);
    *path = "/dev/block/dm-" + std::to_string(dev_num);
    return true;
}

bool DeviceMapper::GetTableStatus(const std::string& name, std::vector<TargetInfo>* table) {
    char buffer[4096];
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer);

    InitIo(io, name);
    io->data_size = sizeof(buffer);
    io->data_start = sizeof(*io);
    if (ioctl(fd_, DM_TABLE_STATUS, io) < 0) {
        PLOG(ERROR) << "DM_TABLE_STATUS failed for " << name;
        return false;
    }
    if (io->flags & DM_BUFFER_FULL_FLAG) {
        PLOG(ERROR) << "DM_TABLE_STATUS result for " << name << " was too large";
        return false;
    }

    uint32_t cursor = io->data_start;
    uint32_t data_end = std::min(io->data_size, uint32_t(sizeof(buffer)));
    for (uint32_t i = 0; i < io->target_count; i++) {
        if (cursor + sizeof(struct dm_target_spec) > data_end) {
            break;
        }
        // After each dm_target_spec is a status string. spec->next is an
        // offset from |io->data_start|, and we clamp it to the size of our
        // buffer.
        struct dm_target_spec* spec = reinterpret_cast<struct dm_target_spec*>(buffer + cursor);
        uint32_t data_offset = cursor + sizeof(dm_target_spec);
        uint32_t next_cursor = std::min(io->data_start + spec->next, data_end);

        std::string data;
        if (next_cursor > data_offset) {
            // Note: we use c_str() to eliminate any extra trailing 0s.
            data = std::string(buffer + data_offset, next_cursor - data_offset).c_str();
        }
        table->emplace_back(*spec, data);
        cursor = next_cursor;
    }
    return true;
}

// private methods of DeviceMapper
void DeviceMapper::InitIo(struct dm_ioctl* io, const std::string& name) const {
    CHECK(io != nullptr) << "nullptr passed to dm_ioctl initialization";
    memset(io, 0, sizeof(*io));

    io->version[0] = DM_VERSION0;
    io->version[1] = DM_VERSION1;
    io->version[2] = DM_VERSION2;
    io->data_size = sizeof(*io);
    io->data_start = 0;
    if (!name.empty()) {
        strlcpy(io->name, name.c_str(), sizeof(io->name));
    }
}

}  // namespace dm
}  // namespace android
