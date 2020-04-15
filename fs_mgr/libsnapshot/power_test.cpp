//
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
//

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/parsedouble.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>

using namespace std::chrono_literals;
using namespace std::string_literals;
using android::base::borrowed_fd;
using android::base::unique_fd;
using android::dm::DeviceMapper;
using android::dm::DmDeviceState;
using android::dm::DmTable;
using android::dm::DmTargetSnapshot;
using android::dm::SnapshotStorageMode;
using android::fiemap::ImageManager;
using android::fs_mgr::Fstab;

namespace android {
namespace snapshot {

static void usage() {
    std::cerr << "Usage:\n";
    std::cerr << "  create <orig-payload> <new-payload>\n";
    std::cerr << "\n";
    std::cerr << "  Create a snapshot device containing the contents of\n";
    std::cerr << "  orig-payload, and then write the contents of new-payload.\n";
    std::cerr << "  The original files are not modified.\n";
    std::cerr << "\n";
    std::cerr << "  merge <fail-rate>\n";
    std::cerr << "\n";
    std::cerr << "  Merge the snapshot previously started by create, and wait\n";
    std::cerr << "  for it to complete. Once done, it is compared to the\n";
    std::cerr << "  new-payload for consistency. The original files are not \n";
    std::cerr << "  modified. If a fail-rate is passed (as a fraction between 0\n";
    std::cerr << "  and 100), every 10ms the device has that percent change of\n";
    std::cerr << "  injecting a kernel crash.\n";
    std::cerr << "\n";
    std::cerr << "  check <new-payload>\n";
    std::cerr << "  Verify that all artifacts are correct after a merge\n";
    std::cerr << "  completes.\n";
    std::cerr << "\n";
    std::cerr << "  cleanup\n";
    std::cerr << "  Remove all ImageManager artifacts from create/merge.\n";
}

class PowerTest final {
  public:
    PowerTest();
    bool Run(int argc, char** argv);

  private:
    bool OpenImageManager();
    bool Create(int argc, char** argv);
    bool Merge(int argc, char** argv);
    bool Check(int argc, char** argv);
    bool Cleanup();
    bool CleanupImage(const std::string& name);
    bool SetupImages(const std::string& first_file, borrowed_fd second_fd);
    bool MapImages();
    bool MapSnapshot(SnapshotStorageMode mode);
    bool GetMergeStatus(DmTargetSnapshot::Status* status);

    static constexpr char kSnapshotName[] = "snapshot-power-test";
    static constexpr char kSnapshotImageName[] = "snapshot-power-test-image";
    static constexpr char kSnapshotCowName[] = "snapshot-power-test-cow";

    DeviceMapper& dm_;
    std::unique_ptr<ImageManager> images_;
    std::string image_path_;
    std::string cow_path_;
    std::string snapshot_path_;
};

PowerTest::PowerTest() : dm_(DeviceMapper::Instance()) {}

bool PowerTest::Run([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    if (!OpenImageManager()) {
        return false;
    }

    if (argc < 2) {
        usage();
        return false;
    }
    if (argv[1] == "create"s) {
        return Create(argc, argv);
    } else if (argv[1] == "merge"s) {
        return Merge(argc, argv);
    } else if (argv[1] == "check"s) {
        return Check(argc, argv);
    } else if (argv[1] == "cleanup"s) {
        return Cleanup();
    } else {
        usage();
        return false;
    }
}

bool PowerTest::OpenImageManager() {
    std::vector<std::string> dirs = {
            "/data/gsi/test",
            "/metadata/gsi/test",
    };
    for (const auto& dir : dirs) {
        if (mkdir(dir.c_str(), 0700) && errno != EEXIST) {
            std::cerr << "mkdir " << dir << ": " << strerror(errno) << "\n";
            return false;
        }
    }

    images_ = ImageManager::Open("/metadata/gsi/test", "/data/gsi/test");
    if (!images_) {
        std::cerr << "Could not open ImageManager\n";
        return false;
    }
    return true;
}

bool PowerTest::Create(int argc, char** argv) {
    if (argc < 4) {
        usage();
        return false;
    }

    std::string first = argv[2];
    std::string second = argv[3];

    unique_fd second_fd(open(second.c_str(), O_RDONLY));
    if (second_fd < 0) {
        std::cerr << "open " << second << ": " << strerror(errno) << "\n";
        return false;
    }

    if (!Cleanup()) {
        return false;
    }
    if (!SetupImages(first, second_fd)) {
        return false;
    }
    if (!MapSnapshot(SnapshotStorageMode::Persistent)) {
        return false;
    }

    struct stat s;
    if (fstat(second_fd, &s)) {
        std::cerr << "fstat " << second << ": " << strerror(errno) << "\n";
        return false;
    }

    unique_fd snap_fd(open(snapshot_path_.c_str(), O_WRONLY));
    if (snap_fd < 0) {
        std::cerr << "open " << snapshot_path_ << ": " << strerror(errno) << "\n";
        return false;
    }

    uint8_t chunk[4096];
    uint64_t written = 0;
    while (written < s.st_size) {
        uint64_t remaining = s.st_size - written;
        size_t bytes = (size_t)std::min((uint64_t)sizeof(chunk), remaining);
        if (!android::base::ReadFully(second_fd, chunk, bytes)) {
            std::cerr << "read " << second << ": " << strerror(errno) << "\n";
            return false;
        }
        if (!android::base::WriteFully(snap_fd, chunk, bytes)) {
            std::cerr << "write " << snapshot_path_ << ": " << strerror(errno) << "\n";
            return false;
        }
        written += bytes;
    }
    if (fsync(snap_fd)) {
        std::cerr << "fsync: " << strerror(errno) << "\n";
        return false;
    }

    sync();

    snap_fd = {};
    if (!dm_.DeleteDeviceIfExists(kSnapshotName)) {
        std::cerr << "could not delete dm device " << kSnapshotName << "\n";
        return false;
    }
    if (!images_->UnmapImageIfExists(kSnapshotImageName)) {
        std::cerr << "failed to unmap " << kSnapshotImageName << "\n";
        return false;
    }
    if (!images_->UnmapImageIfExists(kSnapshotCowName)) {
        std::cerr << "failed to unmap " << kSnapshotImageName << "\n";
        return false;
    }
    return true;
}

bool PowerTest::Cleanup() {
    if (!dm_.DeleteDeviceIfExists(kSnapshotName)) {
        std::cerr << "could not delete dm device " << kSnapshotName << "\n";
        return false;
    }
    if (!CleanupImage(kSnapshotImageName) || !CleanupImage(kSnapshotCowName)) {
        return false;
    }
    return true;
}

bool PowerTest::CleanupImage(const std::string& name) {
    if (!images_->UnmapImageIfExists(name)) {
        std::cerr << "failed to unmap " << name << "\n";
        return false;
    }
    if (images_->BackingImageExists(name) && !images_->DeleteBackingImage(name)) {
        std::cerr << "failed to delete " << name << "\n";
        return false;
    }
    return true;
}

bool PowerTest::SetupImages(const std::string& first, borrowed_fd second_fd) {
    unique_fd first_fd(open(first.c_str(), O_RDONLY));
    if (first_fd < 0) {
        std::cerr << "open " << first << ": " << strerror(errno) << "\n";
        return false;
    }

    struct stat s1, s2;
    if (fstat(first_fd.get(), &s1)) {
        std::cerr << "first stat: " << strerror(errno) << "\n";
        return false;
    }
    if (fstat(second_fd.get(), &s2)) {
        std::cerr << "second stat: " << strerror(errno) << "\n";
        return false;
    }

    // Pick the bigger size of both images, rounding up to the nearest block.
    uint64_t s1_size = (s1.st_size + 4095) & ~uint64_t(4095);
    uint64_t s2_size = (s2.st_size + 4095) & ~uint64_t(4095);
    uint64_t image_size = std::max(s1_size, s2_size) + (1024 * 1024 * 128);
    if (!images_->CreateBackingImage(kSnapshotImageName, image_size, 0, nullptr)) {
        std::cerr << "failed to create " << kSnapshotImageName << "\n";
        return false;
    }
    // Use the same size for the cow.
    if (!images_->CreateBackingImage(kSnapshotCowName, image_size, 0, nullptr)) {
        std::cerr << "failed to create " << kSnapshotCowName << "\n";
        return false;
    }
    if (!MapImages()) {
        return false;
    }

    unique_fd image_fd(open(image_path_.c_str(), O_WRONLY));
    if (image_fd < 0) {
        std::cerr << "open: " << image_path_ << ": " << strerror(errno) << "\n";
        return false;
    }

    uint8_t chunk[4096];
    uint64_t written = 0;
    while (written < s1.st_size) {
        uint64_t remaining = s1.st_size - written;
        size_t bytes = (size_t)std::min((uint64_t)sizeof(chunk), remaining);
        if (!android::base::ReadFully(first_fd, chunk, bytes)) {
            std::cerr << "read: " << strerror(errno) << "\n";
            return false;
        }
        if (!android::base::WriteFully(image_fd, chunk, bytes)) {
            std::cerr << "write: " << strerror(errno) << "\n";
            return false;
        }
        written += bytes;
    }
    if (fsync(image_fd)) {
        std::cerr << "fsync: " << strerror(errno) << "\n";
        return false;
    }

    // Zero the first block of the COW.
    unique_fd cow_fd(open(cow_path_.c_str(), O_WRONLY));
    if (cow_fd < 0) {
        std::cerr << "open: " << cow_path_ << ": " << strerror(errno) << "\n";
        return false;
    }

    memset(chunk, 0, sizeof(chunk));
    if (!android::base::WriteFully(cow_fd, chunk, sizeof(chunk))) {
        std::cerr << "read: " << strerror(errno) << "\n";
        return false;
    }
    if (fsync(cow_fd)) {
        std::cerr << "fsync: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool PowerTest::MapImages() {
    if (!images_->MapImageDevice(kSnapshotImageName, 10s, &image_path_)) {
        std::cerr << "failed to map " << kSnapshotImageName << "\n";
        return false;
    }
    if (!images_->MapImageDevice(kSnapshotCowName, 10s, &cow_path_)) {
        std::cerr << "failed to map " << kSnapshotCowName << "\n";
        return false;
    }
    return true;
}

bool PowerTest::MapSnapshot(SnapshotStorageMode mode) {
    uint64_t sectors;
    {
        unique_fd fd(open(image_path_.c_str(), O_RDONLY));
        if (fd < 0) {
            std::cerr << "open: " << image_path_ << ": " << strerror(errno) << "\n";
            return false;
        }
        sectors = get_block_device_size(fd) / 512;
    }

    DmTable table;
    table.Emplace<DmTargetSnapshot>(0, sectors, image_path_, cow_path_, mode, 8);
    if (!dm_.CreateDevice(kSnapshotName, table, &snapshot_path_, 10s)) {
        std::cerr << "failed to create snapshot device\n";
        return false;
    }
    return true;
}

bool PowerTest::GetMergeStatus(DmTargetSnapshot::Status* status) {
    std::vector<DeviceMapper::TargetInfo> targets;
    if (!dm_.GetTableStatus(kSnapshotName, &targets)) {
        std::cerr << "failed to get merge status\n";
        return false;
    }
    if (targets.size() != 1) {
        std::cerr << "merge device has wrong number of targets\n";
        return false;
    }
    if (!DmTargetSnapshot::ParseStatusText(targets[0].data, status)) {
        std::cerr << "could not parse merge target status text\n";
        return false;
    }
    return true;
}

static std::string GetUserdataBlockDeviceName() {
    Fstab fstab;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return {};
    }

    auto entry = android::fs_mgr::GetEntryForMountPoint(&fstab, "/data");
    if (!entry) {
        return {};
    }

    auto prefix = "/dev/block/"s;
    if (!android::base::StartsWith(entry->blk_device, prefix)) {
        return {};
    }
    return entry->blk_device.substr(prefix.size());
}

bool PowerTest::Merge(int argc, char** argv) {
    // Start an f2fs GC to really stress things. :TODO: figure out data device
    auto userdata_dev = GetUserdataBlockDeviceName();
    if (userdata_dev.empty()) {
        std::cerr << "could not locate userdata block device\n";
        return false;
    }

    auto cmd =
            android::base::StringPrintf("echo 1 > /sys/fs/f2fs/%s/gc_urgent", userdata_dev.c_str());
    system(cmd.c_str());

    if (dm_.GetState(kSnapshotName) == DmDeviceState::INVALID) {
        if (!MapImages()) {
            return false;
        }
        if (!MapSnapshot(SnapshotStorageMode::Merge)) {
            return false;
        }
    }

    std::random_device r;
    std::default_random_engine re(r());
    std::uniform_real_distribution<double> dist(0.0, 100.0);

    std::optional<double> failure_rate;
    if (argc >= 3) {
        double d;
        if (!android::base::ParseDouble(argv[2], &d)) {
            std::cerr << "Could not parse failure rate as double: " << argv[2] << "\n";
            return false;
        }
        failure_rate = d;
    }

    while (true) {
        DmTargetSnapshot::Status status;
        if (!GetMergeStatus(&status)) {
            return false;
        }
        if (!status.error.empty()) {
            std::cerr << "merge reported error: " << status.error << "\n";
            return false;
        }
        if (status.sectors_allocated == status.metadata_sectors) {
            break;
        }

        std::cerr << status.sectors_allocated << " / " << status.metadata_sectors << "\n";

        if (failure_rate && *failure_rate >= dist(re)) {
            system("echo 1 > /proc/sys/kernel/sysrq");
            system("echo c > /proc/sysrq-trigger");
        }

        std::this_thread::sleep_for(10ms);
    }

    std::cout << "Merge completed.\n";
    return true;
}

bool PowerTest::Check([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    if (argc < 3) {
        std::cerr << "Expected argument: <new-image-path>\n";
        return false;
    }
    std::string md_path, image_path;
    std::string canonical_path = argv[2];

    if (!dm_.GetDmDevicePathByName(kSnapshotName, &md_path)) {
        std::cerr << "could not get dm-path for merge device\n";
        return false;
    }
    if (!images_->GetMappedImageDevice(kSnapshotImageName, &image_path)) {
        std::cerr << "could not get image path\n";
        return false;
    }

    unique_fd md_fd(open(md_path.c_str(), O_RDONLY));
    if (md_fd < 0) {
        std::cerr << "open: " << md_path << ": " << strerror(errno) << "\n";
        return false;
    }
    unique_fd image_fd(open(image_path.c_str(), O_RDONLY));
    if (image_fd < 0) {
        std::cerr << "open: " << image_path << ": " << strerror(errno) << "\n";
        return false;
    }
    unique_fd canonical_fd(open(canonical_path.c_str(), O_RDONLY));
    if (canonical_fd < 0) {
        std::cerr << "open: " << canonical_path << ": " << strerror(errno) << "\n";
        return false;
    }

    struct stat s;
    if (fstat(canonical_fd, &s)) {
        std::cerr << "fstat: " << canonical_path << ": " << strerror(errno) << "\n";
        return false;
    }
    uint64_t canonical_size = s.st_size;
    uint64_t md_size = get_block_device_size(md_fd);
    uint64_t image_size = get_block_device_size(image_fd);
    if (image_size != md_size) {
        std::cerr << "image size does not match merge device size\n";
        return false;
    }
    if (canonical_size > image_size) {
        std::cerr << "canonical size " << canonical_size << " is greater than image size "
                  << image_size << "\n";
        return false;
    }

    constexpr size_t kBlockSize = 4096;
    uint8_t canonical_buffer[kBlockSize];
    uint8_t image_buffer[kBlockSize];
    uint8_t md_buffer[kBlockSize];

    uint64_t remaining = canonical_size;
    uint64_t blockno = 0;
    while (remaining) {
        size_t bytes = (size_t)std::min((uint64_t)kBlockSize, remaining);
        if (!android::base::ReadFully(canonical_fd, canonical_buffer, bytes)) {
            std::cerr << "read: " << canonical_buffer << ": " << strerror(errno) << "\n";
            return false;
        }
        if (!android::base::ReadFully(image_fd, image_buffer, bytes)) {
            std::cerr << "read: " << image_buffer << ": " << strerror(errno) << "\n";
            return false;
        }
        if (!android::base::ReadFully(md_fd, md_buffer, bytes)) {
            std::cerr << "read: " << md_buffer << ": " << strerror(errno) << "\n";
            return false;
        }
        if (memcmp(canonical_buffer, image_buffer, bytes)) {
            std::cerr << "canonical and image differ at block " << blockno << "\n";
            return false;
        }
        if (memcmp(canonical_buffer, md_buffer, bytes)) {
            std::cerr << "canonical and image differ at block " << blockno << "\n";
            return false;
        }

        remaining -= bytes;
        blockno++;
    }

    std::cout << "Images all match.\n";
    return true;
}

}  // namespace snapshot
}  // namespace android

int main(int argc, char** argv) {
    android::snapshot::PowerTest test;

    if (!test.Run(argc, argv)) {
        std::cerr << "Unexpected error running test." << std::endl;
        return 1;
    }
    fflush(stdout);
    return 0;
}
