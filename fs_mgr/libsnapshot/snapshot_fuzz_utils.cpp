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
#include <android-base/stringprintf.h>
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

using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;
using android::dm::LoopControl;
using android::fiemap::IImageManager;
using android::fiemap::ImageManager;

// This directory is exempted from pinning in ImageManager.
static const char MNT_DIR[] = "/data/gsi/ota/test/";

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
        if (!Mkdir(MNT_DIR)) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        auto ret = std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(name));
        ret->auto_delete_mount_dir_ = AutoDeleteDir::New(ret->mount_path());
        if (!ret->auto_delete_mount_dir_->HasDevice()) {
            return std::unique_ptr<AutoMemBasedDir>(new AutoMemBasedDir(""));
        }
        ret->auto_umount_mount_point_ = AutoUnmount::New(ret->mount_path(), size);
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
    fake_root_ = AutoMemBasedDir::New(FAKE_ROOT_NAME, FAKE_ROOT_SIZE);
    CHECK(fake_root_ != nullptr);
    CHECK(fake_root_->HasDevice());
    loop_control_ = std::make_unique<LoopControl>();
    mapped_super_ = CheckMapSuper(fake_root_->persist_path(), loop_control_.get(), &fake_super_);
}

SnapshotFuzzEnv::~SnapshotFuzzEnv() = default;

void CheckZeroFill(const std::string& file, size_t size) {
    std::string zeros(size, '\0');
    PCHECK(WriteStringToFile(zeros, file)) << "Cannot write zeros to " << file;
}

void SnapshotFuzzEnv::CheckSoftReset() {
    fake_root_->CheckSoftReset();
    CheckZeroFill(super(), SUPER_IMAGE_SIZE);
}

std::unique_ptr<IImageManager> SnapshotFuzzEnv::CheckCreateFakeImageManager(
        const std::string& path) {
    auto images_dir = path + "/images";
    auto metadata_dir = images_dir + "/metadata";
    auto data_dir = images_dir + "/data";

    PCHECK(Mkdir(images_dir));
    PCHECK(Mkdir(metadata_dir));
    PCHECK(Mkdir(data_dir));
    return ImageManager::Open(metadata_dir, data_dir);
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
    ~AutoDetachLoopDevice() { control_->Detach(name_); }

  private:
    LoopControl* control_;
};

std::unique_ptr<AutoDevice> SnapshotFuzzEnv::CheckMapSuper(const std::string& fake_persist_path,
                                                           LoopControl* control,
                                                           std::string* fake_super) {
    auto super_img = fake_persist_path + "/super.img";
    CheckZeroFill(super_img, SUPER_IMAGE_SIZE);
    CheckCreateLoopDevice(control, super_img, 1s, fake_super);

    return std::make_unique<AutoDetachLoopDevice>(control, *fake_super);
}

std::unique_ptr<ISnapshotManager> SnapshotFuzzEnv::CheckCreateSnapshotManager(
        const SnapshotFuzzData& data) {
    auto partition_opener = std::make_unique<TestPartitionOpener>(super());
    auto metadata_dir = fake_root_->tmp_path() + "/snapshot_metadata";
    PCHECK(Mkdir(metadata_dir));

    auto device_info = new SnapshotFuzzDeviceInfo(data.device_info_data(),
                                                  std::move(partition_opener), metadata_dir);
    auto snapshot = SnapshotManager::New(device_info /* takes ownership */);
    snapshot->images_ = CheckCreateFakeImageManager(fake_root_->tmp_path());
    snapshot->has_local_image_manager_ = data.manager_data().is_local_image_manager();

    return snapshot;
}

const std::string& SnapshotFuzzEnv::super() const {
    return fake_super_;
}

}  // namespace android::snapshot
