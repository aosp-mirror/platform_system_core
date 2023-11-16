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

#include <dirent.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/kdev_t.h>
#include <linux/types.h>
#include <stdint.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dm_table.h"

// The minimum expected device mapper major.minor version
#define DM_VERSION0 (4)
#define DM_VERSION1 (0)
#define DM_VERSION2 (0)

#define DM_ALIGN_MASK (7)
#define DM_ALIGN(x) (((x) + DM_ALIGN_MASK) & ~DM_ALIGN_MASK)

namespace android {
namespace dm {

enum class DmDeviceState { INVALID, SUSPENDED, ACTIVE };

static constexpr uint64_t kSectorSize = 512;

// Returns `path` without /dev/block prefix if `path` starts with that prefix.
// Or, if `path` is a symlink, do the same with its real path.
std::optional<std::string> ExtractBlockDeviceName(const std::string& path);

// This interface is for testing purposes. See DeviceMapper proper for what these methods do.
class IDeviceMapper {
  public:
    virtual ~IDeviceMapper() {}

    struct TargetInfo {
        struct dm_target_spec spec;
        std::string data;
        TargetInfo() {}
        TargetInfo(const struct dm_target_spec& spec, const std::string& data)
            : spec(spec), data(data) {}

        bool IsOverflowSnapshot() const;
    };

    virtual bool CreateDevice(const std::string& name, const DmTable& table, std::string* path,
                              const std::chrono::milliseconds& timeout_ms) = 0;
    virtual DmDeviceState GetState(const std::string& name) const = 0;
    virtual bool LoadTableAndActivate(const std::string& name, const DmTable& table) = 0;
    virtual bool LoadTable(const std::string& name, const DmTable& table) = 0;
    virtual bool GetTableInfo(const std::string& name, std::vector<TargetInfo>* table) = 0;
    virtual bool GetTableStatus(const std::string& name, std::vector<TargetInfo>* table) = 0;
    virtual bool GetDmDevicePathByName(const std::string& name, std::string* path) = 0;
    virtual bool GetDeviceString(const std::string& name, std::string* dev) = 0;
    virtual bool DeleteDeviceIfExists(const std::string& name) = 0;
};

class DeviceMapper final : public IDeviceMapper {
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

    class Info {
        uint32_t flags_;

      public:
        explicit Info(uint32_t flags) : flags_(flags) {}

        bool IsActiveTablePresent() const { return flags_ & DM_ACTIVE_PRESENT_FLAG; }
        bool IsBufferFull() const { return flags_ & DM_BUFFER_FULL_FLAG; }
        bool IsInactiveTablePresent() const { return flags_ & DM_INACTIVE_PRESENT_FLAG; }
        bool IsReadOnly() const { return flags_ & DM_READONLY_FLAG; }
        bool IsSuspended() const { return !IsActiveTablePresent() || (flags_ & DM_SUSPEND_FLAG); }
    };

    // Removes a device mapper device with the given name.
    // Returns 'true' on success, false otherwise.
    bool DeleteDevice(const std::string& name);
    bool DeleteDeviceIfExists(const std::string& name) override;
    // Removes a device mapper device with the given name and waits for |timeout_ms| milliseconds
    // for the corresponding block device to be deleted.
    bool DeleteDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms);
    bool DeleteDeviceIfExists(const std::string& name, const std::chrono::milliseconds& timeout_ms);

    // Enqueues a deletion of device mapper device with the given name once last reference is
    // closed.
    // Returns 'true' on success, false otherwise.
    bool DeleteDeviceDeferred(const std::string& name);
    bool DeleteDeviceIfExistsDeferred(const std::string& name);

    // Fetches and returns the complete state of the underlying device mapper
    // device with given name.
    std::optional<Info> GetDetailedInfo(const std::string& name) const;

    // Returns the current state of the underlying device mapper device
    // with given name.
    // One of INVALID, SUSPENDED or ACTIVE.
    DmDeviceState GetState(const std::string& name) const override;

    // Puts the given device to the specified status, which must be either:
    // - SUSPENDED: suspend the device, or
    // - ACTIVE: resumes the device.
    bool ChangeState(const std::string& name, DmDeviceState state);

    // Creates empty device.
    // This supports a use case when a caller doesn't need a device straight away, but instead
    // asks kernel to create it beforehand, thus avoiding blocking itself from waiting for ueventd
    // to create user space paths.
    // Callers are expected to then activate their device by calling LoadTableAndActivate function.
    // To avoid race conditions, callers must still synchronize with ueventd by calling
    // WaitForDevice function.
    bool CreateEmptyDevice(const std::string& name);

    // Waits for device paths to be created in the user space.
    bool WaitForDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms,
                       std::string* path);

    // Creates a device, loads the given table, and activates it. If the device
    // is not able to be activated, it is destroyed, and false is returned.
    // After creation, |path| contains the result of calling
    // GetDmDevicePathByName, and the path is guaranteed to exist. If after
    // |timeout_ms| the path is not available, the device will be deleted and
    // this function will return false.
    //
    // This variant must be used when depending on the device path. The
    // following manual sequence should not be used:
    //
    //   1. CreateDevice(name, table)
    //   2. GetDmDevicePathByName(name, &path)
    //   3. fs_mgr::WaitForFile(path, <timeout>)
    //
    // This sequence has a race condition where, if another process deletes a
    // device, CreateDevice may acquire the same path. When this happens, the
    // WaitForFile() may early-return since ueventd has not yet processed all
    // of the outstanding udev events. The caller may unexpectedly get an
    // ENOENT on a system call using the affected path.
    //
    // If |timeout_ms| is 0ms, then this function will return true whether or
    // not |path| is available. It is the caller's responsibility to ensure
    // there are no races.
    bool CreateDevice(const std::string& name, const DmTable& table, std::string* path,
                      const std::chrono::milliseconds& timeout_ms) override;

    // Create a device and activate the given table, without waiting to acquire
    // a valid path. If the caller will use GetDmDevicePathByName(), it should
    // use the timeout variant above.
    bool CreateDevice(const std::string& name, const DmTable& table);

    // Loads the device mapper table from parameter into the underlying device
    // mapper device with given name and activate / resumes the device in the
    // process. A device with the given name must already exist.
    //
    // Returns 'true' on success, false otherwise.
    bool LoadTableAndActivate(const std::string& name, const DmTable& table) override;

    // Same as LoadTableAndActivate, but there is no resume step. This puts the
    // new table in the inactive slot.
    //
    // Returns 'true' on success, false otherwise.
    bool LoadTable(const std::string& name, const DmTable& table) override;

    // Returns true if a list of available device mapper targets registered in the kernel was
    // successfully read and stored in 'targets'. Returns 'false' otherwise.
    bool GetAvailableTargets(std::vector<DmTargetTypeInfo>* targets);

    // Finds a target by name and returns its information if found. |info| may
    // be null to check for the existence of a target.
    bool GetTargetByName(const std::string& name, DmTargetTypeInfo* info);

    // Return 'true' if it can successfully read the list of device mapper block devices
    // currently created. 'devices' will be empty if the kernel interactions
    // were successful and there are no block devices at the moment. Returns
    // 'false' in case of any failure along the way.
    bool GetAvailableDevices(std::vector<DmBlockDevice>* devices);

    // Returns the path to the device mapper device node in '/dev' corresponding to
    // 'name'. If the device does not exist, false is returned, and the path
    // parameter is not set.
    //
    // This returns a path in the format "/dev/block/dm-N" that can be easily
    // re-used with sysfs.
    //
    // WaitForFile() should not be used in conjunction with this call, since it
    // could race with ueventd.
    bool GetDmDevicePathByName(const std::string& name, std::string* path);

    // Returns the device mapper UUID for a given name.  If the device does not
    // exist, false is returned, and the path parameter is not set.
    //
    // WaitForFile() should not be used in conjunction with this call, since it
    // could race with ueventd.
    bool GetDmDeviceUuidByName(const std::string& name, std::string* path);

    // Returns a device's unique path as generated by ueventd. This will return
    // true as long as the device has been created, even if ueventd has not
    // processed it yet.
    //
    // The formatting of this path is /dev/block/mapper/by-uuid/<uuid>.
    bool GetDeviceUniquePath(const std::string& name, std::string* path);

    // Returns the dev_t for the named device-mapper node.
    bool GetDeviceNumber(const std::string& name, dev_t* dev);

    // Returns a major:minor string for the named device-mapper node, that can
    // be used as inputs to DmTargets that take a block device.
    bool GetDeviceString(const std::string& name, std::string* dev) override;

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
    bool GetTableStatus(const std::string& name, std::vector<TargetInfo>* table) override;

    // Identical to GetTableStatus, except also retrives the active table for the device
    // mapper device from the kernel.
    bool GetTableInfo(const std::string& name, std::vector<TargetInfo>* table) override;

    static std::string GetTargetType(const struct dm_target_spec& spec);

    // Returns true if given path is a path to a dm block device.
    bool IsDmBlockDevice(const std::string& path);

    // Returns name of a dm-device with the given path, or std::nulloptr if given path is not a
    // dm-device.
    std::optional<std::string> GetDmDeviceNameByPath(const std::string& path);

    // Returns a parent block device of a dm device with the given path, or std::nullopt if:
    //  * Given path doesn't correspond to a dm device.
    //  * A dm device is based on top of more than one block devices.
    //  * A failure occurred.
    std::optional<std::string> GetParentBlockDeviceByPath(const std::string& path);

    // Iterate the content over "/sys/block/dm-x/dm/name" and find
    // all the dm-wrapped block devices.
    //
    // Returns mapping <partition-name, /dev/block/dm-x>
    std::map<std::string, std::string> FindDmPartitions();

    // Create a placeholder device. This is useful for ensuring that a uevent is in the pipeline,
    // to reduce the amount of time a future WaitForDevice will block. On kernels < 5.15, this
    // simply calls CreateEmptyDevice. On 5.15 and higher, it also loads (but does not activate)
    // a placeholder table containing dm-error.
    bool CreatePlaceholderDevice(const std::string& name);

    bool GetDeviceNameAndUuid(dev_t dev, std::string* name, std::string* uuid);

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

    bool CreateDevice(const std::string& name, const std::string& uuid = {});
    bool GetTable(const std::string& name, uint32_t flags, std::vector<TargetInfo>* table);
    void InitIo(struct dm_ioctl* io, const std::string& name = std::string()) const;

    DeviceMapper();

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
