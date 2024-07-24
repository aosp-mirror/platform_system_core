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

#include <linux/dm-ioctl.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <chrono>
#include <functional>
#include <string_view>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <uuid/uuid.h>

#include "utility.h"

#ifndef DM_DEFERRED_REMOVE
#define DM_DEFERRED_REMOVE (1 << 17)
#endif
#ifndef DM_IMA_MEASUREMENT_FLAG
#define DM_IMA_MEASUREMENT_FLAG (1 << 19)
#endif

namespace android {
namespace dm {

using namespace std::literals;

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
bool DeviceMapper::CreateDevice(const std::string& name, const std::string& uuid) {
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
    if (!uuid.empty()) {
        snprintf(io.uuid, sizeof(io.uuid), "%s", uuid.c_str());
    }

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

bool DeviceMapper::DeleteDeviceIfExists(const std::string& name,
                                        const std::chrono::milliseconds& timeout_ms) {
    if (GetState(name) == DmDeviceState::INVALID) {
        return true;
    }
    return DeleteDevice(name, timeout_ms);
}

bool DeviceMapper::DeleteDeviceIfExists(const std::string& name) {
    return DeleteDeviceIfExists(name, 0ms);
}

bool DeviceMapper::DeleteDevice(const std::string& name,
                                const std::chrono::milliseconds& timeout_ms) {
    std::string unique_path;
    if (!GetDeviceUniquePath(name, &unique_path)) {
        LOG(ERROR) << "Failed to get unique path for device " << name;
    }
    // Expect to have uevent generated if the unique path actually exists. This may not exist
    // if the device was created but has never been activated before it gets deleted.
    bool need_uevent = !unique_path.empty() && access(unique_path.c_str(), F_OK) == 0;

    struct dm_ioctl io;
    InitIo(&io, name);

    if (ioctl(fd_, DM_DEV_REMOVE, &io)) {
        PLOG(ERROR) << "DM_DEV_REMOVE failed for [" << name << "]";
        return false;
    }

    // Check to make sure appropriate uevent is generated so ueventd will
    // do the right thing and remove the corresponding device node and symlinks.
    if (need_uevent && (io.flags & DM_UEVENT_GENERATED_FLAG) == 0) {
        LOG(ERROR) << "Didn't generate uevent for [" << name << "] removal";
        return false;
    }

    if (timeout_ms <= std::chrono::milliseconds::zero()) {
        return true;
    }
    if (unique_path.empty()) {
        return false;
    }
    if (!WaitForFileDeleted(unique_path, timeout_ms)) {
        LOG(ERROR) << "Failed waiting for " << unique_path << " to be deleted";
        return false;
    }
    return true;
}

bool DeviceMapper::DeleteDevice(const std::string& name) {
    return DeleteDevice(name, 0ms);
}

bool DeviceMapper::DeleteDeviceDeferred(const std::string& name) {
    struct dm_ioctl io;
    InitIo(&io, name);

    io.flags |= DM_DEFERRED_REMOVE;
    if (ioctl(fd_, DM_DEV_REMOVE, &io)) {
        PLOG(ERROR) << "DM_DEV_REMOVE with DM_DEFERRED_REMOVE failed for [" << name << "]";
        return false;
    }
    return true;
}

bool DeviceMapper::DeleteDeviceIfExistsDeferred(const std::string& name) {
    if (GetState(name) == DmDeviceState::INVALID) {
        return true;
    }
    return DeleteDeviceDeferred(name);
}

static std::string GenerateUuid() {
    uuid_t uuid_bytes;
    uuid_generate(uuid_bytes);

    char uuid_chars[37] = {};
    uuid_unparse_lower(uuid_bytes, uuid_chars);

    return std::string{uuid_chars};
}

static bool IsRecovery() {
    return access("/system/bin/recovery", F_OK) == 0;
}

bool DeviceMapper::CreateEmptyDevice(const std::string& name) {
    std::string uuid = GenerateUuid();
    return CreateDevice(name, uuid);
}

bool DeviceMapper::WaitForDevice(const std::string& name,
                                 const std::chrono::milliseconds& timeout_ms, std::string* path) {
    // We use the unique path for testing whether the device is ready. After
    // that, it's safe to use the dm-N path which is compatible with callers
    // that expect it to be formatted as such.
    std::string unique_path;
    if (!GetDeviceUniquePath(name, &unique_path) || !GetDmDevicePathByName(name, path)) {
        DeleteDevice(name);
        return false;
    }

    if (timeout_ms <= std::chrono::milliseconds::zero()) {
        return true;
    }

    if (IsRecovery()) {
        bool non_ab_device = android::base::GetProperty("ro.build.ab_update", "").empty();
        int sdk = android::base::GetIntProperty("ro.build.version.sdk", 0);
        if (non_ab_device && sdk && sdk <= 29) {
            LOG(INFO) << "Detected ueventd incompatibility, reverting to legacy libdm behavior.";
            unique_path = *path;
        }
    }

    if (!WaitForFile(unique_path, timeout_ms)) {
        LOG(ERROR) << "Failed waiting for device path: " << unique_path;
        DeleteDevice(name);
        return false;
    }
    return true;
}

bool DeviceMapper::CreateDevice(const std::string& name, const DmTable& table, std::string* path,
                                const std::chrono::milliseconds& timeout_ms) {
    if (!CreateEmptyDevice(name)) {
        return false;
    }

    if (!LoadTableAndActivate(name, table)) {
        DeleteDevice(name);
        return false;
    }

    if (!WaitForDevice(name, timeout_ms, path)) {
        DeleteDevice(name);
        return false;
    }

    return true;
}

bool DeviceMapper::GetDeviceUniquePath(const std::string& name, std::string* path) {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        PLOG(ERROR) << "Failed to get device path: " << name;
        return false;
    }

    if (io.uuid[0] == '\0') {
        LOG(ERROR) << "Device does not have a unique path: " << name;
        return false;
    }
    *path = "/dev/block/mapper/by-uuid/"s + io.uuid;
    return true;
}

bool DeviceMapper::GetDeviceNameAndUuid(dev_t dev, std::string* name, std::string* uuid) {
    struct dm_ioctl io;
    InitIo(&io, {});
    io.dev = dev;

    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        PLOG(ERROR) << "Failed to find device dev: " << major(dev) << ":" << minor(dev);
        return false;
    }

    if (name) {
        *name = io.name;
    }
    if (uuid) {
        *uuid = io.uuid;
    }
    return true;
}

std::optional<DeviceMapper::Info> DeviceMapper::GetDetailedInfo(const std::string& name) const {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        return std::nullopt;
    }
    return Info(io.flags);
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

bool DeviceMapper::ChangeState(const std::string& name, DmDeviceState state) {
    if (state != DmDeviceState::SUSPENDED && state != DmDeviceState::ACTIVE) {
        return false;
    }

    struct dm_ioctl io;
    InitIo(&io, name);

    if (state == DmDeviceState::SUSPENDED) io.flags = DM_SUSPEND_FLAG;

    if (ioctl(fd_, DM_DEV_SUSPEND, &io) < 0) {
        PLOG(ERROR) << "DM_DEV_SUSPEND "
                    << (state == DmDeviceState::SUSPENDED ? "suspend" : "resume") << " failed";
        return false;
    }
    return true;
}

bool DeviceMapper::CreateDevice(const std::string& name, const DmTable& table) {
    std::string ignore_path;
    if (!CreateDevice(name, table, &ignore_path, 0ms)) {
        return false;
    }
    return true;
}

bool DeviceMapper::LoadTable(const std::string& name, const DmTable& table) {
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
    return true;
}

bool DeviceMapper::LoadTableAndActivate(const std::string& name, const DmTable& table) {
    if (!LoadTable(name, table)) {
        return false;
    }

    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_SUSPEND, &io)) {
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
        vers = reinterpret_cast<struct dm_target_versions*>(static_cast<char*>(buffer.get()) +
                                                            next);
    }

    return true;
}

bool DeviceMapper::GetTargetByName(const std::string& name, DmTargetTypeInfo* info) {
    std::vector<DmTargetTypeInfo> targets;
    if (!GetAvailableTargets(&targets)) {
        return false;
    }
    for (const auto& target : targets) {
        if (target.name() == name) {
            if (info) *info = target;
            return true;
        }
    }
    return false;
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
        PLOG(WARNING) << "DM_DEV_STATUS failed for " << name;
        return false;
    }

    uint32_t dev_num = minor(io.dev);
    *path = "/dev/block/dm-" + std::to_string(dev_num);
    return true;
}

// Accepts a device mapper device name (like system_a, vendor_b etc) and
// returns its UUID.
bool DeviceMapper::GetDmDeviceUuidByName(const std::string& name, std::string* uuid) {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        PLOG(WARNING) << "DM_DEV_STATUS failed for " << name;
        return false;
    }

    *uuid = std::string(io.uuid);
    return true;
}

bool DeviceMapper::GetDeviceNumber(const std::string& name, dev_t* dev) {
    struct dm_ioctl io;
    InitIo(&io, name);
    if (ioctl(fd_, DM_DEV_STATUS, &io) < 0) {
        PLOG(WARNING) << "DM_DEV_STATUS failed for " << name;
        return false;
    }
    *dev = io.dev;
    return true;
}

bool DeviceMapper::GetDeviceString(const std::string& name, std::string* dev) {
    dev_t num;
    if (!GetDeviceNumber(name, &num)) {
        return false;
    }
    *dev = std::to_string(major(num)) + ":" + std::to_string(minor(num));
    return true;
}

bool DeviceMapper::GetTableStatus(const std::string& name, std::vector<TargetInfo>* table) {
    return GetTable(name, 0, table);
}

bool DeviceMapper::GetTableStatusIma(const std::string& name, std::vector<TargetInfo>* table) {
    return GetTable(name, DM_IMA_MEASUREMENT_FLAG, table);
}

bool DeviceMapper::GetTableInfo(const std::string& name, std::vector<TargetInfo>* table) {
    return GetTable(name, DM_STATUS_TABLE_FLAG, table);
}

// private methods of DeviceMapper
bool DeviceMapper::GetTable(const std::string& name, uint32_t flags,
                            std::vector<TargetInfo>* table) {
    std::vector<char> buffer;
    struct dm_ioctl* io = nullptr;

    for (buffer.resize(4096);; buffer.resize(buffer.size() * 2)) {
        io = reinterpret_cast<struct dm_ioctl*>(&buffer[0]);

        InitIo(io, name);
        io->data_size = buffer.size();
        io->data_start = sizeof(*io);
        io->flags = flags;
        if (ioctl(fd_, DM_TABLE_STATUS, io) < 0) {
            PLOG(ERROR) << "DM_TABLE_STATUS failed for " << name;
            return false;
        }
        if (!(io->flags & DM_BUFFER_FULL_FLAG)) break;
    }

    uint32_t cursor = io->data_start;
    uint32_t data_end = std::min(io->data_size, uint32_t(buffer.size()));
    for (uint32_t i = 0; i < io->target_count; i++) {
        if (cursor + sizeof(struct dm_target_spec) > data_end) {
            break;
        }
        // After each dm_target_spec is a status string. spec->next is an
        // offset from |io->data_start|, and we clamp it to the size of our
        // buffer.
        struct dm_target_spec* spec = reinterpret_cast<struct dm_target_spec*>(&buffer[cursor]);
        uint32_t data_offset = cursor + sizeof(dm_target_spec);
        uint32_t next_cursor = std::min(io->data_start + spec->next, data_end);

        std::string data;
        if (next_cursor > data_offset) {
            // Note: we use c_str() to eliminate any extra trailing 0s.
            data = std::string(&buffer[data_offset], next_cursor - data_offset).c_str();
        }
        table->emplace_back(*spec, data);
        cursor = next_cursor;
    }
    return true;
}

void DeviceMapper::InitIo(struct dm_ioctl* io, const std::string& name) const {
    CHECK(io != nullptr) << "nullptr passed to dm_ioctl initialization";
    memset(io, 0, sizeof(*io));

    io->version[0] = DM_VERSION0;
    io->version[1] = DM_VERSION1;
    io->version[2] = DM_VERSION2;
    io->data_size = sizeof(*io);
    io->data_start = 0;
    if (!name.empty()) {
        snprintf(io->name, sizeof(io->name), "%s", name.c_str());
    }
}

std::string DeviceMapper::GetTargetType(const struct dm_target_spec& spec) {
    if (const void* p = memchr(spec.target_type, '\0', sizeof(spec.target_type))) {
        ptrdiff_t length = reinterpret_cast<const char*>(p) - spec.target_type;
        return std::string{spec.target_type, static_cast<size_t>(length)};
    }
    return std::string{spec.target_type, sizeof(spec.target_type)};
}

std::optional<std::string> ExtractBlockDeviceName(const std::string& path) {
    static constexpr std::string_view kDevBlockPrefix("/dev/block/");
    std::string real_path;
    if (!android::base::Realpath(path, &real_path)) {
        real_path = path;
    }
    if (android::base::StartsWith(real_path, kDevBlockPrefix)) {
        return real_path.substr(kDevBlockPrefix.length());
    }
    return {};
}

bool DeviceMapper::IsDmBlockDevice(const std::string& path) {
    std::optional<std::string> name = ExtractBlockDeviceName(path);
    return name && android::base::StartsWith(*name, "dm-");
}

std::optional<std::string> DeviceMapper::GetDmDeviceNameByPath(const std::string& path) {
    std::optional<std::string> name = ExtractBlockDeviceName(path);
    if (!name) {
        LOG(WARNING) << path << " is not a block device";
        return std::nullopt;
    }
    if (!android::base::StartsWith(*name, "dm-")) {
        LOG(WARNING) << path << " is not a dm device";
        return std::nullopt;
    }
    std::string dm_name_file = "/sys/block/" + *name + "/dm/name";
    std::string dm_name;
    if (!android::base::ReadFileToString(dm_name_file, &dm_name)) {
        PLOG(ERROR) << "Failed to read file " << dm_name_file;
        return std::nullopt;
    }
    dm_name = android::base::Trim(dm_name);
    return dm_name;
}

std::optional<std::string> DeviceMapper::GetParentBlockDeviceByPath(const std::string& path) {
    std::optional<std::string> name = ExtractBlockDeviceName(path);
    if (!name) {
        LOG(WARNING) << path << " is not a block device";
        return std::nullopt;
    }
    if (!android::base::StartsWith(*name, "dm-")) {
        // Reached bottom of the device mapper stack.
        return std::nullopt;
    }
    auto slaves_dir = "/sys/block/" + *name + "/slaves";
    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(opendir(slaves_dir.c_str()), closedir);
    if (dir == nullptr) {
        PLOG(ERROR) << "Failed to open: " << slaves_dir;
        return std::nullopt;
    }
    std::string sub_device_name = "";
    for (auto entry = readdir(dir.get()); entry; entry = readdir(dir.get())) {
        if (entry->d_type != DT_LNK) continue;
        if (!sub_device_name.empty()) {
            LOG(ERROR) << "Too many slaves in " << slaves_dir;
            return std::nullopt;
        }
        sub_device_name = entry->d_name;
    }
    if (sub_device_name.empty()) {
        LOG(ERROR) << "No slaves in " << slaves_dir;
        return std::nullopt;
    }
    return "/dev/block/" + sub_device_name;
}

bool DeviceMapper::TargetInfo::IsOverflowSnapshot() const {
    return spec.target_type == "snapshot"s && data == "Overflow"s;
}

// Find directories in format of "/sys/block/dm-X".
static int DmNameFilter(const dirent* de) {
    if (android::base::StartsWith(de->d_name, "dm-")) {
        return 1;
    }
    return 0;
}

std::map<std::string, std::string> DeviceMapper::FindDmPartitions() {
    static constexpr auto DM_PATH_PREFIX = "/sys/block/";
    dirent** namelist;
    int n = scandir(DM_PATH_PREFIX, &namelist, DmNameFilter, alphasort);
    if (n == -1) {
        PLOG(ERROR) << "Failed to scan dir " << DM_PATH_PREFIX;
        return {};
    }
    if (n == 0) {
        LOG(ERROR) << "No dm block device found.";
        free(namelist);
        return {};
    }

    static constexpr auto DM_PATH_SUFFIX = "/dm/name";
    static constexpr auto DEV_PATH = "/dev/block/";
    std::map<std::string, std::string> dm_block_devices;
    while (n--) {
        std::string path = DM_PATH_PREFIX + std::string(namelist[n]->d_name) + DM_PATH_SUFFIX;
        std::string content;
        if (!android::base::ReadFileToString(path, &content)) {
            PLOG(WARNING) << "Failed to read " << path;
        } else {
            std::string dm_block_name = android::base::Trim(content);
            // AVB is using 'vroot' for the root block device but we're expecting 'system'.
            if (dm_block_name == "vroot") {
                dm_block_name = "system";
            } else if (android::base::EndsWith(dm_block_name, "-verity")) {
                auto npos = dm_block_name.rfind("-verity");
                dm_block_name = dm_block_name.substr(0, npos);
            } else if (!android::base::GetProperty("ro.boot.avb_version", "").empty()) {
                // Verified Boot 1.0 doesn't add a -verity suffix. On AVB 2 devices,
                // if DAP is enabled, then a -verity suffix must be used to
                // differentiate between dm-linear and dm-verity devices. If we get
                // here, we're AVB 2 and looking at a non-verity partition.
                free(namelist[n]);
                continue;
            }

            dm_block_devices.emplace(dm_block_name, DEV_PATH + std::string(namelist[n]->d_name));
        }
        free(namelist[n]);
    }
    free(namelist);

    return dm_block_devices;
}

bool DeviceMapper::CreatePlaceholderDevice(const std::string& name) {
    if (!CreateEmptyDevice(name)) {
        return false;
    }

    struct utsname uts;
    unsigned int major, minor;
    if (uname(&uts) != 0 || sscanf(uts.release, "%u.%u", &major, &minor) != 2) {
        LOG(ERROR) << "Could not parse the kernel version from uname";
        return true;
    }

    // On Linux 5.15+, there is no uevent until DM_TABLE_LOAD.
    if (major > 5 || (major == 5 && minor >= 15)) {
        DmTable table;
        table.Emplace<DmTargetError>(0, 1);
        if (!LoadTable(name, table)) {
            return false;
        }
    }
    return true;
}

bool DeviceMapper::SendMessage(const std::string& name, uint64_t sector,
                               const std::string& message) {
    std::string ioctl_buffer(sizeof(struct dm_ioctl) + sizeof(struct dm_target_msg), 0);
    ioctl_buffer += message;
    ioctl_buffer.push_back('\0');

    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(&ioctl_buffer[0]);
    InitIo(io, name);
    io->data_size = ioctl_buffer.size();
    io->data_start = sizeof(struct dm_ioctl);
    struct dm_target_msg* msg =
            reinterpret_cast<struct dm_target_msg*>(&ioctl_buffer[sizeof(struct dm_ioctl)]);
    msg->sector = sector;
    if (ioctl(fd_, DM_TARGET_MSG, io)) {
        PLOG(ERROR) << "DM_TARGET_MSG failed";
        return false;
    }
    return true;
}

}  // namespace dm
}  // namespace android
