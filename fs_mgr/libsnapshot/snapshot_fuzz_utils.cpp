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

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <libsnapshot/auto_device.h>
#include <libsnapshot/snapshot.h>
#include <storage_literals/storage_literals.h>

#include "snapshot_fuzz_utils.h"

using namespace android::storage_literals;
using namespace std::string_literals;

using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;
using android::fiemap::IImageManager;
using android::fiemap::ImageManager;

static const char MNT_DIR[] = "/mnt";
static const char FAKE_ROOT_NAME[] = "snapshot_fuzz";
static const auto SUPER_IMAGE_SIZE = 16_MiB;
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
        if (rmdir(name_.c_str()) == -1) {
            PLOG(ERROR) << "Cannot remove " << name_;
        }
    }

  private:
    AutoDeleteDir(const std::string& path) : AutoDevice(path) {}
};

class AutoUnmount : public AutoDevice {
  public:
    static std::unique_ptr<AutoUnmount> New(const std::string& path, uint64_t size) {
        if (mount("tmpfs", path.c_str(), "tmpfs", 0,
                  (void*)StringPrintf("size=%" PRIu64, size).data()) == -1) {
            PLOG(ERROR) << "Cannot mount " << path;
            return std::unique_ptr<AutoUnmount>(new AutoUnmount(""));
        }
        return std::unique_ptr<AutoUnmount>(new AutoUnmount(path));
    }
    ~AutoUnmount() {
        if (!HasDevice()) return;
        if (umount(name_.c_str()) == -1) {
            PLOG(ERROR) << "Cannot umount " << name_;
        }
    }

  private:
    AutoUnmount(const std::string& path) : AutoDevice(path) {}
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
        ret->auto_umount_mount_point_ = AutoUnmount::New(ret->mount_path(), size);
        if (!ret->auto_umount_mount_point_->HasDevice()) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        // path() does not need to be deleted upon destruction, hence it is not wrapped with
        // AutoDeleteDir.
        if (!Mkdir(ret->path())) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        return ret;
    }
    // Return the scratch directory.
    std::string path() const {
        CHECK(HasDevice());
        return mount_path() + "/root";
    }
    // Delete all contents in path() and start over. path() itself is re-created.
    bool SoftReset() { return RmdirRecursive(path()) && Mkdir(path()); }

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
    fake_root_ = AutoMemBasedDir::New(FAKE_ROOT_NAME, FAKE_ROOT_SIZE);
}

SnapshotFuzzEnv::~SnapshotFuzzEnv() = default;

bool SnapshotFuzzEnv::InitOk() const {
    if (fake_root_ == nullptr || !fake_root_->HasDevice()) return false;
    return true;
}

bool SnapshotFuzzEnv::SoftReset() {
    return fake_root_->SoftReset();
}

std::unique_ptr<IImageManager> SnapshotFuzzEnv::CreateFakeImageManager(
        const std::string& fake_root) {
    auto images_dir = fake_root + "/images";
    auto metadata_dir = images_dir + "/metadata";
    auto data_dir = images_dir + "/data";

    if (!Mkdir(images_dir) || !Mkdir(metadata_dir) || !Mkdir(data_dir)) {
        return nullptr;
    }
    return ImageManager::Open(metadata_dir, data_dir);
}

std::unique_ptr<TestPartitionOpener> SnapshotFuzzEnv::CreatePartitionOpener(
        const std::string& fake_root) {
    auto fake_super = fake_root + "/super.img";
    std::string zeros(SUPER_IMAGE_SIZE, '\0');

    if (!WriteStringToFile(zeros, fake_super)) {
        PLOG(ERROR) << "Cannot write zeros to " << fake_super;
        return nullptr;
    }

    return std::make_unique<TestPartitionOpener>(fake_super);
}

std::string SnapshotFuzzEnv::root() const {
    CHECK(InitOk());
    return fake_root_->path();
}

std::unique_ptr<ISnapshotManager> SnapshotFuzzEnv::CreateSnapshotManager(
        const SnapshotManagerFuzzData& data) {
    // TODO(b/154633114): create valid super partition according to fuzz data
    auto partition_opener = CreatePartitionOpener(root());
    if (partition_opener == nullptr) return nullptr;
    auto metadata_dir = root() + "/snapshot_metadata";
    if (!Mkdir(metadata_dir)) return nullptr;

    auto device_info = new SnapshotFuzzDeviceInfo(data.device_info_data,
                                                  std::move(partition_opener), metadata_dir);
    auto snapshot = SnapshotManager::New(device_info /* takes ownership */);
    snapshot->images_ = CreateFakeImageManager(root());
    snapshot->has_local_image_manager_ = data.is_local_image_manager;

    return snapshot;
}

}  // namespace android::snapshot
