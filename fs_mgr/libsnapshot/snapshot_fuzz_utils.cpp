// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ftw.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sysexits.h>

#include <chrono>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <libsnapshot/auto_device.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>

#include "snapshot_fuzz_utils.h"
#include "utility.h"

// Prepends the errno string, but it is good enough.
#ifndef PCHECK
#define PCHECK(x) CHECK(x) << strerror(errno) << ": "
#endif

using namespace android::storage_literals;
using namespace std::chrono_literals;
using namespace std::string_literals;

using android::base::Basename;
using android::base::ReadFileToString;
using android::base::SetProperty;
using android::base::Split;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;
using android::dm::DeviceMapper;
using android::dm::DmTarget;
using android::dm::LoopControl;
using android::fiemap::IImageManager;
using android::fiemap::ImageManager;
using android::fs_mgr::BlockDeviceInfo;
using android::fs_mgr::FstabEntry;
using android::fs_mgr::IPartitionOpener;
using chromeos_update_engine::DynamicPartitionMetadata;

static const char MNT_DIR[] = "/mnt";
static const char BLOCK_SYSFS[] = "/sys/block";

static const char FAKE_ROOT_NAME[] = "snapshot_fuzz";
static const auto SUPER_IMAGE_SIZE = 16_MiB;
static const auto DATA_IMAGE_SIZE = 16_MiB;
static const auto FAKE_ROOT_SIZE = 64_MiB;

namespace android::snapshot {

bool Mkdir(const std::string& path) {
    if (mkdir(path.c_str(), 0750) == -1 && errno != EEXIST) {
        PLOG(ERROR) << "Cannot create " << path;
        return false;
    }
    return true;
}

bool RmdirRecursive(const std::string& path) {
    auto callback = [](const char* child, const struct stat*, int file_type, struct FTW*) -> int {
        switch (file_type) {
            case FTW_D:
            case FTW_DP:
            case FTW_DNR:
                if (rmdir(child) == -1) {
                    PLOG(ERROR) << "rmdir " << child;
                    return -1;
                }
                return 0;
            case FTW_NS:
            default:
                if (rmdir(child) != -1) break;
                [[fallthrough]];
            case FTW_F:
            case FTW_SL:
            case FTW_SLN:
                if (unlink(child) == -1) {
                    PLOG(ERROR) << "unlink " << child;
                    return -1;
                }
                return 0;
        }
        return 0;
    };

    return nftw(path.c_str(), callback, 128, FTW_DEPTH | FTW_MOUNT | FTW_PHYS) == 0;
}

std::string GetLinearBaseDeviceString(const DeviceMapper::TargetInfo& target) {
    if (target.spec.target_type != "linear"s) return {};
    auto tokens = Split(target.data, " ");
    CHECK_EQ(2, tokens.size());
    return tokens[0];
}

std::vector<std::string> GetSnapshotBaseDeviceStrings(const DeviceMapper::TargetInfo& target) {
    if (target.spec.target_type != "snapshot"s && target.spec.target_type != "snapshot-merge"s)
        return {};
    auto tokens = Split(target.data, " ");
    CHECK_EQ(4, tokens.size());
    return {tokens[0], tokens[1]};
}

bool ShouldDeleteLoopDevice(const std::string& node) {
    std::string backing_file;
    if (ReadFileToString(StringPrintf("%s/loop/backing_file", node.data()), &backing_file)) {
        if (StartsWith(backing_file, std::string(MNT_DIR) + "/" + FAKE_ROOT_NAME)) {
            return true;
        }
    }
    return false;
}

std::vector<DeviceMapper::TargetInfo> GetTableInfoIfExists(const std::string& dev_name) {
    auto& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::TargetInfo> table;
    if (!dm.GetTableInfo(dev_name, &table)) {
        PCHECK(errno == ENODEV);
        return {};
    }
    return table;
}

std::set<std::string> GetAllBaseDeviceStrings(const std::string& child_dev) {
    std::set<std::string> ret;
    for (const auto& child_target : GetTableInfoIfExists(child_dev)) {
        auto snapshot_bases = GetSnapshotBaseDeviceStrings(child_target);
        ret.insert(snapshot_bases.begin(), snapshot_bases.end());

        auto linear_base = GetLinearBaseDeviceString(child_target);
        if (!linear_base.empty()) {
            ret.insert(linear_base);
        }
    }
    return ret;
}

using PropertyList = std::set<std::string>;
void InsertProperty(const char* key, const char* /*name*/, void* cookie) {
    reinterpret_cast<PropertyList*>(cookie)->insert(key);
}

// Attempt to delete all devices that is based on dev_name, including itself.
void CheckDeleteDeviceMapperTree(const std::string& dev_name, bool known_allow_delete = false,
                                 uint64_t depth = 100) {
    CHECK(depth > 0) << "Reaching max depth when deleting " << dev_name
                     << ". There may be devices referencing itself. Check `dmctl list devices -v`.";

    auto& dm = DeviceMapper::Instance();
    auto table = GetTableInfoIfExists(dev_name);
    if (table.empty()) {
        PCHECK(dm.DeleteDeviceIfExists(dev_name)) << dev_name;
        return;
    }

    if (!known_allow_delete) {
        for (const auto& target : table) {
            auto base_device_string = GetLinearBaseDeviceString(target);
            if (base_device_string.empty()) continue;
            if (ShouldDeleteLoopDevice(
                        StringPrintf("/sys/dev/block/%s", base_device_string.data()))) {
                known_allow_delete = true;
                break;
            }
        }
    }
    if (!known_allow_delete) {
        return;
    }

    std::string dev_string;
    PCHECK(dm.GetDeviceString(dev_name, &dev_string));

    std::vector<DeviceMapper::DmBlockDevice> devices;
    PCHECK(dm.GetAvailableDevices(&devices));
    for (const auto& child_dev : devices) {
        auto child_bases = GetAllBaseDeviceStrings(child_dev.name());
        if (child_bases.find(dev_string) != child_bases.end()) {
            CheckDeleteDeviceMapperTree(child_dev.name(), true /* known_allow_delete */, depth - 1);
        }
    }

    PCHECK(dm.DeleteDeviceIfExists(dev_name)) << dev_name;
}

// Attempt to clean up residues from previous runs.
void CheckCleanupDeviceMapperDevices() {
    auto& dm = DeviceMapper::Instance();
    std::vector<DeviceMapper::DmBlockDevice> devices;
    PCHECK(dm.GetAvailableDevices(&devices));

    for (const auto& dev : devices) {
        CheckDeleteDeviceMapperTree(dev.name());
    }
}

void CheckUmount(const std::string& path) {
    PCHECK(TEMP_FAILURE_RETRY(umount(path.data()) == 0) || errno == ENOENT || errno == EINVAL)
            << path;
}

void CheckDetachLoopDevices(const std::set<std::string>& exclude_names = {}) {
    // ~SnapshotFuzzEnv automatically does the following.
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(BLOCK_SYSFS), closedir);
    PCHECK(dir != nullptr) << BLOCK_SYSFS;
    LoopControl loop_control;
    dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (exclude_names.find(dp->d_name) != exclude_names.end()) {
            continue;
        }
        if (!ShouldDeleteLoopDevice(StringPrintf("%s/%s", BLOCK_SYSFS, dp->d_name).data())) {
            continue;
        }
        PCHECK(loop_control.Detach(StringPrintf("/dev/block/%s", dp->d_name).data()));
    }
}

void CheckUmountAll() {
    CheckUmount(std::string(MNT_DIR) + "/snapshot_fuzz_data");
    CheckUmount(std::string(MNT_DIR) + "/" + FAKE_ROOT_NAME);
}

class AutoDeleteDir : public AutoDevice {
  public:
    static std::unique_ptr<AutoDeleteDir> New(const std::string& path) {
        if (!Mkdir(path)) {
            return std::unique_ptr<AutoDeleteDir>(new AutoDeleteDir(""));
        }
        return std::unique_ptr<AutoDeleteDir>(new AutoDeleteDir(path));
    }
    ~AutoDeleteDir() {
        if (!HasDevice()) return;
        PCHECK(rmdir(name_.c_str()) == 0 || errno == ENOENT) << name_;
    }

  private:
    AutoDeleteDir(const std::string& path) : AutoDevice(path) {}
};

class AutoUnmount : public AutoDevice {
  public:
    ~AutoUnmount() {
        if (!HasDevice()) return;
        CheckUmount(name_);
    }
    AutoUnmount(const std::string& path) : AutoDevice(path) {}
};

class AutoUnmountTmpfs : public AutoUnmount {
  public:
    static std::unique_ptr<AutoUnmount> New(const std::string& path, uint64_t size) {
        if (mount("tmpfs", path.c_str(), "tmpfs", 0,
                  (void*)StringPrintf("size=%" PRIu64, size).data()) == -1) {
            PLOG(ERROR) << "Cannot mount " << path;
            return std::unique_ptr<AutoUnmount>(new AutoUnmount(""));
        }
        return std::unique_ptr<AutoUnmount>(new AutoUnmount(path));
    }
  private:
    using AutoUnmount::AutoUnmount;
};

// A directory on tmpfs. Upon destruct, it is unmounted and deleted.
class AutoMemBasedDir : public AutoDevice {
  public:
    static std::unique_ptr<AutoMemBasedDir> New(const std::string& name, uint64_t size) {
        auto ret = std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(name));
        ret->auto_delete_mount_dir_ = AutoDeleteDir::New(ret->mount_path());
        if (!ret->auto_delete_mount_dir_->HasDevice()) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        ret->auto_umount_mount_point_ = AutoUnmountTmpfs::New(ret->mount_path(), size);
        if (!ret->auto_umount_mount_point_->HasDevice()) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        // tmp_path() and persist_path does not need to be deleted upon destruction, hence it is
        // not wrapped with AutoDeleteDir.
        if (!Mkdir(ret->tmp_path())) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        if (!Mkdir(ret->persist_path())) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        return ret;
    }
    // Return the temporary scratch directory.
    std::string tmp_path() const {
        CHECK(HasDevice());
        return mount_path() + "/tmp";
    }
    // Return the temporary scratch directory.
    std::string persist_path() const {
        CHECK(HasDevice());
        return mount_path() + "/persist";
    }
    // Delete all contents in tmp_path() and start over. tmp_path() itself is re-created.
    void CheckSoftReset() {
        PCHECK(RmdirRecursive(tmp_path()));
        PCHECK(Mkdir(tmp_path()));
    }

  private:
    AutoMemBasedDir(const std::string& name) : AutoDevice(name) {}
    std::string mount_path() const {
        CHECK(HasDevice());
        return MNT_DIR + "/"s + name_;
    }
    std::unique_ptr<AutoDeleteDir> auto_delete_mount_dir_;
    std::unique_ptr<AutoUnmount> auto_umount_mount_point_;
};

SnapshotFuzzEnv::SnapshotFuzzEnv() {
    CheckCleanupDeviceMapperDevices();
    CheckDetachLoopDevices();
    CheckUmountAll();

    fake_root_ = AutoMemBasedDir::New(FAKE_ROOT_NAME, FAKE_ROOT_SIZE);
    CHECK(fake_root_ != nullptr);
    CHECK(fake_root_->HasDevice());
    loop_control_ = std::make_unique<LoopControl>();

    fake_data_mount_point_ = MNT_DIR + "/snapshot_fuzz_data"s;
    auto_delete_data_mount_point_ = AutoDeleteDir::New(fake_data_mount_point_);
    CHECK(auto_delete_data_mount_point_ != nullptr);
    CHECK(auto_delete_data_mount_point_->HasDevice());

    const auto& fake_persist_path = fake_root_->persist_path();
    mapped_super_ = CheckMapImage(fake_persist_path + "/super.img", SUPER_IMAGE_SIZE,
                                  loop_control_.get(), &fake_super_);
    mapped_data_ = CheckMapImage(fake_persist_path + "/data.img", DATA_IMAGE_SIZE,
                                 loop_control_.get(), &fake_data_block_device_);
    mounted_data_ = CheckMountFormatData(fake_data_block_device_, fake_data_mount_point_);
}

SnapshotFuzzEnv::~SnapshotFuzzEnv() {
    CheckCleanupDeviceMapperDevices();
    mounted_data_ = nullptr;
    auto_delete_data_mount_point_ = nullptr;
    mapped_data_ = nullptr;
    mapped_super_ = nullptr;
    CheckDetachLoopDevices();
    loop_control_ = nullptr;
    fake_root_ = nullptr;
    CheckUmountAll();
}

void CheckZeroFill(const std::string& file, size_t size) {
    std::string zeros(size, '\0');
    PCHECK(WriteStringToFile(zeros, file)) << "Cannot write zeros to " << file;
}

void SnapshotFuzzEnv::CheckSoftReset() {
    fake_root_->CheckSoftReset();
    CheckZeroFill(super(), SUPER_IMAGE_SIZE);
    CheckCleanupDeviceMapperDevices();
    CheckDetachLoopDevices({Basename(fake_super_), Basename(fake_data_block_device_)});
}

std::unique_ptr<IImageManager> SnapshotFuzzEnv::CheckCreateFakeImageManager() {
    auto metadata_dir = fake_root_->tmp_path() + "/images_manager_metadata";
    auto data_dir = fake_data_mount_point_ + "/image_manager_data";
    PCHECK(Mkdir(metadata_dir));
    PCHECK(Mkdir(data_dir));
    return SnapshotFuzzImageManager::Open(metadata_dir, data_dir);
}

// Helper to create a loop device for a file.
static void CheckCreateLoopDevice(LoopControl* control, const std::string& file,
                                  const std::chrono::milliseconds& timeout_ms, std::string* path) {
    static constexpr int kOpenFlags = O_RDWR | O_NOFOLLOW | O_CLOEXEC;
    android::base::unique_fd file_fd(open(file.c_str(), kOpenFlags));
    PCHECK(file_fd >= 0) << "Could not open file: " << file;
    CHECK(control->Attach(file_fd, timeout_ms, path))
            << "Could not create loop device for: " << file;
}

class AutoDetachLoopDevice : public AutoDevice {
  public:
    AutoDetachLoopDevice(LoopControl* control, const std::string& device)
        : AutoDevice(device), control_(control) {}
    ~AutoDetachLoopDevice() { PCHECK(control_->Detach(name_)) << name_; }

  private:
    LoopControl* control_;
};

std::unique_ptr<AutoDevice> SnapshotFuzzEnv::CheckMapImage(const std::string& img_path,
                                                           uint64_t size, LoopControl* control,
                                                           std::string* mapped_path) {
    CheckZeroFill(img_path, size);
    CheckCreateLoopDevice(control, img_path, 1s, mapped_path);

    return std::make_unique<AutoDetachLoopDevice>(control, *mapped_path);
}

SnapshotTestModule SnapshotFuzzEnv::CheckCreateSnapshotManager(const SnapshotFuzzData& data) {
    SnapshotTestModule ret;
    auto partition_opener = std::make_unique<TestPartitionOpener>(super());
    ret.opener = partition_opener.get();
    CheckWriteSuperMetadata(data, *partition_opener);
    auto metadata_dir = fake_root_->tmp_path() + "/snapshot_metadata";
    PCHECK(Mkdir(metadata_dir));
    if (data.has_metadata_snapshots_dir()) {
        PCHECK(Mkdir(metadata_dir + "/snapshots"));
    }

    ret.device_info = new SnapshotFuzzDeviceInfo(this, data.device_info_data(),
                                                 std::move(partition_opener), metadata_dir);
    auto snapshot = SnapshotManager::New(ret.device_info /* takes ownership */);
    ret.snapshot = std::move(snapshot);

    return ret;
}

const std::string& SnapshotFuzzEnv::super() const {
    return fake_super_;
}

void SnapshotFuzzEnv::CheckWriteSuperMetadata(const SnapshotFuzzData& data,
                                              const IPartitionOpener& opener) {
    if (!data.is_super_metadata_valid()) {
        // Leave it zero.
        return;
    }

    BlockDeviceInfo super_device("super", SUPER_IMAGE_SIZE, 0, 0, 4096);
    std::vector<BlockDeviceInfo> devices = {super_device};
    auto builder = MetadataBuilder::New(devices, "super", 65536, 2);
    CHECK(builder != nullptr);

    // Attempt to create a super partition metadata using proto. All errors are ignored.
    for (const auto& group_proto : data.super_data().dynamic_partition_metadata().groups()) {
        (void)builder->AddGroup(group_proto.name(), group_proto.size());
        for (const auto& partition_name : group_proto.partition_names()) {
            (void)builder->AddPartition(partition_name, group_proto.name(),
                                        LP_PARTITION_ATTR_READONLY);
        }
    }

    for (const auto& partition_proto : data.super_data().partitions()) {
        auto p = builder->FindPartition(partition_proto.partition_name());
        if (p == nullptr) continue;
        (void)builder->ResizePartition(p, partition_proto.new_partition_info().size());
    }

    auto metadata = builder->Export();
    // metadata may be nullptr if it is not valid (e.g. partition name too long).
    // In this case, just use empty super partition data.
    if (metadata == nullptr) {
        builder = MetadataBuilder::New(devices, "super", 65536, 2);
        CHECK(builder != nullptr);
        metadata = builder->Export();
        CHECK(metadata != nullptr);
    }
    CHECK(FlashPartitionTable(opener, super(), *metadata.get()));
}

std::unique_ptr<AutoDevice> SnapshotFuzzEnv::CheckMountFormatData(const std::string& blk_device,
                                                                  const std::string& mount_point) {
    FstabEntry entry{
            .blk_device = blk_device,
            .length = static_cast<off64_t>(DATA_IMAGE_SIZE),
            .fs_type = "ext4",
            .mount_point = mount_point,
    };
    CHECK(0 == fs_mgr_do_format(entry, false /* crypt_footer */));
    CHECK(0 == fs_mgr_do_mount_one(entry));
    return std::make_unique<AutoUnmount>(mount_point);
}

SnapshotFuzzImageManager::~SnapshotFuzzImageManager() {
    // Remove relevant gsid.mapped_images.* props.
    for (const auto& name : mapped_) {
        CHECK(UnmapImageIfExists(name)) << "Cannot unmap " << name;
    }
}

bool SnapshotFuzzImageManager::MapImageDevice(const std::string& name,
                                              const std::chrono::milliseconds& timeout_ms,
                                              std::string* path) {
    if (impl_->MapImageDevice(name, timeout_ms, path)) {
        mapped_.insert(name);
        return true;
    }
    return false;
}

}  // namespace android::snapshot
