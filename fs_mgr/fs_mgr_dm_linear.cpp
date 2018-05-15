/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "fs_mgr_dm_linear.h"

#include <inttypes.h>
#include <linux/dm-ioctl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_dm_ioctl.h"

namespace android {
namespace fs_mgr {

std::string LogicalPartitionExtent::Serialize() const {
    // Note: we need to include an explicit null-terminator.
    std::string argv =
        android::base::StringPrintf("%s %" PRIu64, block_device_.c_str(), first_sector_);
    argv.push_back(0);

    // The kernel expects each target to be aligned.
    size_t spec_bytes = sizeof(struct dm_target_spec) + argv.size();
    size_t padding = ((spec_bytes + 7) & ~7) - spec_bytes;
    for (size_t i = 0; i < padding; i++) {
        argv.push_back(0);
    }

    struct dm_target_spec spec;
    spec.sector_start = logical_sector_;
    spec.length = num_sectors_;
    spec.status = 0;
    strcpy(spec.target_type, "linear");
    spec.next = sizeof(struct dm_target_spec) + argv.size();

    return std::string((char*)&spec, sizeof(spec)) + argv;
}

static bool LoadDmTable(int dm_fd, const LogicalPartition& partition) {
    // Combine all dm_target_spec buffers together.
    std::string target_string;
    for (const auto& extent : partition.extents) {
        target_string += extent.Serialize();
    }

    // Allocate the ioctl buffer.
    size_t buffer_size = sizeof(struct dm_ioctl) + target_string.size();
    std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(buffer_size);

    // Initialize the ioctl buffer header, then copy our target specs in.
    struct dm_ioctl* io = reinterpret_cast<struct dm_ioctl*>(buffer.get());
    fs_mgr_dm_ioctl_init(io, buffer_size, partition.name);
    io->target_count = partition.extents.size();
    if (partition.attributes & kPartitionReadonly) {
        io->flags |= DM_READONLY_FLAG;
    }
    memcpy(io + 1, target_string.c_str(), target_string.size());

    if (ioctl(dm_fd, DM_TABLE_LOAD, io)) {
        PERROR << "Failed ioctl() on DM_TABLE_LOAD, partition " << partition.name;
        return false;
    }
    return true;
}

static bool LoadTablesAndActivate(int dm_fd, const LogicalPartition& partition) {
    if (!LoadDmTable(dm_fd, partition)) {
        return false;
    }

    struct dm_ioctl io;
    return fs_mgr_dm_resume_table(&io, partition.name, dm_fd);
}

static bool CreateDmDeviceForPartition(int dm_fd, const LogicalPartition& partition) {
    struct dm_ioctl io;
    if (!fs_mgr_dm_create_device(&io, partition.name, dm_fd)) {
        return false;
    }
    if (!LoadTablesAndActivate(dm_fd, partition)) {
        // Remove the device rather than leave it in an inactive state.
        fs_mgr_dm_destroy_device(&io, partition.name, dm_fd);
        return false;
    }

    LINFO << "Created device-mapper device: " << partition.name;
    return true;
}

bool CreateLogicalPartitions(const LogicalPartitionTable& table) {
    android::base::unique_fd dm_fd(open("/dev/device-mapper", O_RDWR));
    if (dm_fd < 0) {
        PLOG(ERROR) << "failed to open /dev/device-mapper";
        return false;
    }
    for (const auto& partition : table.partitions) {
        if (!CreateDmDeviceForPartition(dm_fd, partition)) {
            LOG(ERROR) << "could not create dm-linear device for partition: " << partition.name;
            return false;
        }
    }
    return true;
}

std::unique_ptr<LogicalPartitionTable> LoadPartitionsFromDeviceTree() {
    return nullptr;
}

}  // namespace fs_mgr
}  // namespace android
