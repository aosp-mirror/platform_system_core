/*
 *  Copyright 2018 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef _LIBDM_DM_H_
#define _LIBDM_DM_H_

#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/kdev_t.h>
#include <stdint.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "dm_table.h"

// The minimum expected device mapper major.minor version
#define DM_VERSION0 (4)
#define DM_VERSION1 (0)
#define DM_VERSION2 (0)

#define DM_ALIGN_MASK (7)
#define DM_ALIGN(x) ((x + DM_ALIGN_MASK) & ~DM_ALIGN_MASK)

namespace android {
namespace dm {

enum class DmDeviceState { INVALID, SUSPENDED, ACTIVE };

class DeviceMapper final {
  public:
    class DmBlockDevice final {
      public:
        // only allow creating this with dm_name_list
        DmBlockDevice() = delete;

        explicit DmBlockDevice(struct dm_name_list* d) : name_(d->name), dev_(d->dev){};

        // Returs device mapper name associated with the block device
        const std::string& name() const { return name_; }

        // Return major number for the block device
        uint32_t Major() const { return major(dev_); }

        // Return minor number for the block device
        uint32_t Minor() const { return minor(dev_); }
        ~DmBlockDevice() = default;

      private:
        std::string name_;
        uint64_t dev_;
    };

    // Removes a device mapper device with the given name.
    // Returns 'true' on success, false otherwise.
    bool DeleteDevice(const std::string& name);

    // Reads the device mapper table from the device with given anme and
    // returns it in a DmTable object.
    const std::unique_ptr<DmTable> table(const std::string& name) const;

    // Returns the current state of the underlying device mapper device
    // with given name.
    // One of INVALID, SUSPENDED or ACTIVE.
    DmDeviceState GetState(const std::string& name) const;

    // Creates a device, loads the given table, and activates it. If the device
    // is not able to be activated, it is destroyed, and false is returned.
    bool CreateDevice(const std::string& name, const DmTable& table);

    // Loads the device mapper table from parameter into the underlying device
    // mapper device with given name and activate / resumes the device in the
    // process. A device with the given name must already exist.
    //
    // Returns 'true' on success, false otherwise.
    bool LoadTableAndActivate(const std::string& name, const DmTable& table);

    // Returns true if a list of available device mapper targets registered in the kernel was
    // successfully read and stored in 'targets'. Returns 'false' otherwise.
    bool GetAvailableTargets(std::vector<DmTargetTypeInfo>* targets);

    // Return 'true' if it can successfully read the list of device mapper block devices
    // currently created. 'devices' will be empty if the kernel interactions
    // were successful and there are no block devices at the moment. Returns
    // 'false' in case of any failure along the way.
    bool GetAvailableDevices(std::vector<DmBlockDevice>* devices);

    // Returns the path to the device mapper device node in '/dev' corresponding to
    // 'name'. If the device does not exist, false is returned, and the path
    // parameter is not set.
    bool GetDmDevicePathByName(const std::string& name, std::string* path);

    // The only way to create a DeviceMapper object.
    static DeviceMapper& Instance();

    ~DeviceMapper() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }

    // Query the status of a table, given a device name. The output vector will
    // contain one TargetInfo for each target in the table. If the device does
    // not exist, or there were too many targets, the call will fail and return
    // false.
    struct TargetInfo {
        struct dm_target_spec spec;
        std::string data;
        TargetInfo(const struct dm_target_spec& spec, const std::string& data)
            : spec(spec), data(data) {}
    };
    bool GetTableStatus(const std::string& name, std::vector<TargetInfo>* table);

  private:
    // Maximum possible device mapper targets registered in the kernel.
    // This is only used to read the list of targets from kernel so we allocate
    // a finite amount of memory. This limit is in no way enforced by the kernel.
    static constexpr uint32_t kMaxPossibleDmTargets = 256;

    // Maximum possible device mapper created block devices. Note that this is restricted by
    // the minor numbers (that used to be 8 bits) that can be range from 0 to 2^20-1 in newer
    // kernels. In Android systems however, we never expect these to grow beyond the artificial
    // limit we are imposing here of 256.
    static constexpr uint32_t kMaxPossibleDmDevices = 256;

    void InitIo(struct dm_ioctl* io, const std::string& name = std::string()) const;

    DeviceMapper();

    // Creates a device mapper device with given name.
    // Return 'true' on success and 'false' on failure to
    // create OR if a device mapper device with the same name already
    // exists.
    bool CreateDevice(const std::string& name);

    int fd_;
    // Non-copyable & Non-movable
    DeviceMapper(const DeviceMapper&) = delete;
    DeviceMapper& operator=(const DeviceMapper&) = delete;
    DeviceMapper& operator=(DeviceMapper&&) = delete;
    DeviceMapper(DeviceMapper&&) = delete;
};

}  // namespace dm
}  // namespace android

#endif /* _LIBDM_DM_H_ */
