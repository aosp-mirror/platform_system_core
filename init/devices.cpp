/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include "devices.h"

#include <errno.h>
#include <fnmatch.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <libdm/dm.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/selinux.h>

#include "selabel.h"
#include "util.h"

using namespace std::chrono_literals;

using android::base::Basename;
using android::base::ConsumePrefix;
using android::base::Dirname;
using android::base::ReadFileToString;
using android::base::Readlink;
using android::base::Realpath;
using android::base::Split;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Trim;

namespace android {
namespace init {

/* Given a path that may start with a PCI device, populate the supplied buffer
 * with the PCI domain/bus number and the peripheral ID and return 0.
 * If it doesn't start with a PCI device, or there is some error, return -1 */
static bool FindPciDevicePrefix(const std::string& path, std::string* result) {
    result->clear();

    if (!StartsWith(path, "/devices/pci")) return false;

    /* Beginning of the prefix is the initial "pci" after "/devices/" */
    std::string::size_type start = 9;

    /* End of the prefix is two path '/' later, capturing the domain/bus number
     * and the peripheral ID. Example: pci0000:00/0000:00:1f.2 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    end = path.find('/', end + 1);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length <= 4) {
        // The minimum string that will get to this check is 'pci/', which is malformed,
        // so return false
        return false;
    }

    *result = path.substr(start, length);
    return true;
}

/* Given a path that may start with a virtual block device, populate
 * the supplied buffer with the virtual block device ID and return 0.
 * If it doesn't start with a virtual block device, or there is some
 * error, return -1 */
static bool FindVbdDevicePrefix(const std::string& path, std::string* result) {
    result->clear();

    if (!StartsWith(path, "/devices/vbd-")) return false;

    /* Beginning of the prefix is the initial "vbd-" after "/devices/" */
    std::string::size_type start = 13;

    /* End of the prefix is one path '/' later, capturing the
       virtual block device ID. Example: 768 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length == 0) return false;

    *result = path.substr(start, length);
    return true;
}

// Given a path that may start with a virtual dm block device, populate
// the supplied buffer with the dm module's instantiated name.
// If it doesn't start with a virtual block device, or there is some
// error, return false.
static bool FindDmDevice(const Uevent& uevent, std::string* name, std::string* uuid) {
    if (!StartsWith(uevent.path, "/devices/virtual/block/dm-")) return false;
    if (uevent.action == "remove") return false;  // Avoid error spam from ioctl

    dev_t dev = makedev(uevent.major, uevent.minor);

    auto& dm = android::dm::DeviceMapper::Instance();
    return dm.GetDeviceNameAndUuid(dev, name, uuid);
}

Permissions::Permissions(const std::string& name, mode_t perm, uid_t uid, gid_t gid,
                         bool no_fnm_pathname)
    : name_(name),
      perm_(perm),
      uid_(uid),
      gid_(gid),
      prefix_(false),
      wildcard_(false),
      no_fnm_pathname_(no_fnm_pathname) {
    // Set 'prefix_' or 'wildcard_' based on the below cases:
    //
    // 1) No '*' in 'name' -> Neither are set and Match() checks a given path for strict
    //    equality with 'name'
    //
    // 2) '*' only appears as the last character in 'name' -> 'prefix'_ is set to true and
    //    Match() checks if 'name' is a prefix of a given path.
    //
    // 3) '*' appears elsewhere -> 'wildcard_' is set to true and Match() uses fnmatch()
    //    with FNM_PATHNAME to compare 'name' to a given path.
    auto wildcard_position = name_.find('*');
    if (wildcard_position != std::string::npos) {
        if (wildcard_position == name_.length() - 1) {
            prefix_ = true;
            name_.pop_back();
        } else {
            wildcard_ = true;
        }
    }
}

bool Permissions::Match(const std::string& path) const {
    if (prefix_) return StartsWith(path, name_);
    if (wildcard_)
        return fnmatch(name_.c_str(), path.c_str(), no_fnm_pathname_ ? 0 : FNM_PATHNAME) == 0;
    return path == name_;
}

bool SysfsPermissions::MatchWithSubsystem(const std::string& path,
                                          const std::string& subsystem) const {
    std::string path_basename = Basename(path);
    if (name().find(subsystem) != std::string::npos) {
        if (Match("/sys/class/" + subsystem + "/" + path_basename)) return true;
        if (Match("/sys/bus/" + subsystem + "/devices/" + path_basename)) return true;
    }
    return Match(path);
}

void SysfsPermissions::SetPermissions(const std::string& path) const {
    std::string attribute_file = path + "/" + attribute_;
    LOG(VERBOSE) << "fixup " << attribute_file << " " << uid() << " " << gid() << " " << std::oct
                 << perm();

    if (access(attribute_file.c_str(), F_OK) == 0) {
        if (chown(attribute_file.c_str(), uid(), gid()) != 0) {
            PLOG(ERROR) << "chown(" << attribute_file << ", " << uid() << ", " << gid()
                        << ") failed";
        }
        if (chmod(attribute_file.c_str(), perm()) != 0) {
            PLOG(ERROR) << "chmod(" << attribute_file << ", " << perm() << ") failed";
        }
    }
}

BlockDeviceInfo DeviceHandler::GetBlockDeviceInfo(const std::string& uevent_path) const {
    BlockDeviceInfo info;

    if (!boot_part_uuid_.empty()) {
        // Only use the more specific "MMC" / "NVME" / "SCSI" match if a
        // partition UUID was passed.
        //
        // Old bootloaders that aren't passing the partition UUID instead
        // pass the path to the closest "platform" device. It would
        // break them if we chose this deeper (more specific) path.
        //
        // When we have a UUID we _want_ the more specific path since it can
        // handle, for instance, differentiating two USB disks that are on
        // the same USB controller. Using the closest platform device would
        // classify them both the same by using the path to the USB controller.
        if (FindMmcDevice(uevent_path, &info.str)) {
            info.type = "mmc";
        } else if (FindNvmeDevice(uevent_path, &info.str)) {
            info.type = "nvme";
        } else if (FindScsiDevice(uevent_path, &info.str)) {
            info.type = "scsi";
        }
    } else if (FindPlatformDevice(uevent_path, &info.str)) {
        info.type = "platform";
    } else if (FindPciDevicePrefix(uevent_path, &info.str)) {
        info.type = "pci";
    } else if (FindVbdDevicePrefix(uevent_path, &info.str)) {
        info.type = "vbd";
    } else {
        // Re-clear device to be extra certain in case one of the FindXXX()
        // functions returned false but still modified it.
        info.str = "";
    }

    info.is_boot_device = boot_devices_.find(info.str) != boot_devices_.end();

    return info;
}

bool DeviceHandler::IsBootDeviceStrict() const {
    // When using the newer "boot_part_uuid" to specify the boot device then
    // we require all core system partitions to be on the boot device.
    return !boot_part_uuid_.empty();
}

bool DeviceHandler::IsBootDevice(const Uevent& uevent) const {
    auto device = GetBlockDeviceInfo(uevent.path);
    return device.is_boot_device;
}

std::string DeviceHandler::GetPartitionNameForDevice(const std::string& query_device) {
    static const auto partition_map = [] {
        std::vector<std::pair<std::string, std::string>> partition_map;
        auto parser = [&partition_map](const std::string& key, const std::string& value) {
            if (key != "androidboot.partition_map") {
                return;
            }
            for (const auto& map : Split(value, ";")) {
                auto map_pieces = Split(map, ",");
                if (map_pieces.size() != 2) {
                    LOG(ERROR) << "Expected a comma separated device,partition mapping, but found '"
                               << map << "'";
                    continue;
                }
                partition_map.emplace_back(map_pieces[0], map_pieces[1]);
            }
        };
        android::fs_mgr::ImportKernelCmdline(parser);
        android::fs_mgr::ImportBootconfig(parser);
        return partition_map;
    }();

    for (const auto& [device, partition] : partition_map) {
        if (query_device == device) {
            return partition;
        }
    }
    return {};
}

// Given a path to a device that may have a parent in the passed set of
// subsystems, find the parent device that's in the passed set of subsystems.
// If we don't find a parent in the passed set of subsystems, return false.
bool DeviceHandler::FindSubsystemDevice(std::string path, std::string* device_path,
                                        const std::set<std::string>& subsystem_paths) const {
    device_path->clear();

    // Uevents don't contain the mount point, so we need to add it here.
    path.insert(0, sysfs_mount_point_);

    std::string directory = Dirname(path);

    while (directory != "/" && directory != ".") {
        std::string subsystem_link_path;
        if (Realpath(directory + "/subsystem", &subsystem_link_path) &&
            subsystem_paths.find(subsystem_link_path) != subsystem_paths.end()) {
            // We need to remove the mount point that we added above before returning.
            directory.erase(0, sysfs_mount_point_.size());

            // Skip /devices/platform or /devices/ if present
            static constexpr std::string_view devices_platform_prefix = "/devices/platform/";
            static constexpr std::string_view devices_prefix = "/devices/";
            std::string_view sv = directory;

            if (!ConsumePrefix(&sv, devices_platform_prefix)) {
                ConsumePrefix(&sv, devices_prefix);
            }
            *device_path = sv;

            return true;
        }

        auto last_slash = path.rfind('/');
        if (last_slash == std::string::npos) return false;

        path.erase(last_slash);
        directory = Dirname(path);
    }

    return false;
}

bool DeviceHandler::FindPlatformDevice(const std::string& path,
                                       std::string* platform_device_path) const {
    const std::set<std::string> subsystem_paths = {
            sysfs_mount_point_ + "/bus/platform",
            sysfs_mount_point_ + "/bus/amba",
    };

    return FindSubsystemDevice(path, platform_device_path, subsystem_paths);
}

bool DeviceHandler::FindMmcDevice(const std::string& path, std::string* mmc_device_path) const {
    const std::set<std::string> subsystem_paths = {
            sysfs_mount_point_ + "/bus/mmc",
    };

    return FindSubsystemDevice(path, mmc_device_path, subsystem_paths);
}

bool DeviceHandler::FindNvmeDevice(const std::string& path, std::string* nvme_device_path) const {
    const std::set<std::string> subsystem_paths = {
            sysfs_mount_point_ + "/class/nvme",
    };

    return FindSubsystemDevice(path, nvme_device_path, subsystem_paths);
}

bool DeviceHandler::FindScsiDevice(const std::string& path, std::string* scsi_device_path) const {
    const std::set<std::string> subsystem_paths = {
            sysfs_mount_point_ + "/bus/scsi",
    };

    return FindSubsystemDevice(path, scsi_device_path, subsystem_paths);
}

void DeviceHandler::FixupSysPermissions(const std::string& upath,
                                        const std::string& subsystem) const {
    // upaths omit the "/sys" that paths in this list
    // contain, so we prepend it...
    std::string path = "/sys" + upath;

    for (const auto& s : sysfs_permissions_) {
        if (s.MatchWithSubsystem(path, subsystem)) s.SetPermissions(path);
    }

    if (!skip_restorecon_ && access(path.c_str(), F_OK) == 0) {
        LOG(VERBOSE) << "restorecon_recursive: " << path;
        if (selinux_android_restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE) != 0) {
            PLOG(ERROR) << "selinux_android_restorecon(" << path << ") failed";
        }
    }
}

std::tuple<mode_t, uid_t, gid_t> DeviceHandler::GetDevicePermissions(
    const std::string& path, const std::vector<std::string>& links) const {
    // Search the perms list in reverse so that ueventd.$hardware can override ueventd.rc.
    for (auto it = dev_permissions_.crbegin(); it != dev_permissions_.crend(); ++it) {
        if (it->Match(path) || std::any_of(links.cbegin(), links.cend(),
                                           [it](const auto& link) { return it->Match(link); })) {
            return {it->perm(), it->uid(), it->gid()};
        }
    }
    /* Default if nothing found. */
    return {0600, 0, 0};
}

void DeviceHandler::MakeDevice(const std::string& path, bool block, int major, int minor,
                               const std::vector<std::string>& links) const {
    auto [mode, uid, gid] = GetDevicePermissions(path, links);
    mode |= (block ? S_IFBLK : S_IFCHR);

    std::string secontext;
    if (!SelabelLookupFileContextBestMatch(path, links, mode, &secontext)) {
        PLOG(ERROR) << "Device '" << path << "' not created; cannot find SELinux label";
        return;
    }
    if (!secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

    gid_t new_group = -1;

    dev_t dev = makedev(major, minor);
    /* Temporarily change egid to avoid race condition setting the gid of the
     * device node. Unforunately changing the euid would prevent creation of
     * some device nodes, so the uid has to be set with chown() and is still
     * racy. Fixing the gid race at least fixed the issue with system_server
     * opening dynamic input devices under the AID_INPUT gid. */
    if (setegid(gid)) {
        PLOG(ERROR) << "setegid(" << gid << ") for " << path << " device failed";
        goto out;
    }
    /* If the node already exists update its SELinux label and the file mode to handle cases when
     * it was created with the wrong context and file mode during coldboot procedure. */
    if (mknod(path.c_str(), mode, dev) && (errno == EEXIST) && !secontext.empty()) {
        char* fcon = nullptr;
        int rc = lgetfilecon(path.c_str(), &fcon);
        if (rc < 0) {
            PLOG(ERROR) << "Cannot get SELinux label on '" << path << "' device";
            goto out;
        }

        bool different = fcon != secontext;
        freecon(fcon);

        if (different && lsetfilecon(path.c_str(), secontext.c_str())) {
            PLOG(ERROR) << "Cannot set '" << secontext << "' SELinux label on '" << path
                        << "' device";
        }

        struct stat s;
        if (stat(path.c_str(), &s) == 0) {
            if (gid != s.st_gid) {
                new_group = gid;
            }
            if (mode != s.st_mode) {
                if (chmod(path.c_str(), mode) != 0) {
                    PLOG(ERROR) << "Cannot chmod " << path << " to " << mode;
                }
            }
        } else {
            PLOG(ERROR) << "Cannot stat " << path;
        }
    }

out:
    if (chown(path.c_str(), uid, new_group) < 0) {
        PLOG(ERROR) << "Cannot chown " << path << " " << uid << " " << new_group;
    }
    if (setegid(AID_ROOT)) {
        PLOG(FATAL) << "setegid(AID_ROOT) failed";
    }

    if (!secontext.empty()) {
        setfscreatecon(nullptr);
    }
}

// replaces any unacceptable characters with '_', the
// length of the resulting string is equal to the input string
void SanitizePartitionName(std::string* string) {
    const char* accept =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";

    if (!string) return;

    std::string::size_type pos = 0;
    while ((pos = string->find_first_not_of(accept, pos)) != std::string::npos) {
        (*string)[pos] = '_';
    }
}

std::vector<std::string> DeviceHandler::GetBlockDeviceSymlinks(const Uevent& uevent) const {
    BlockDeviceInfo info;
    std::string partition;
    std::string uuid;

    if (FindDmDevice(uevent, &partition, &uuid)) {
        std::vector<std::string> symlinks = {"/dev/block/mapper/" + partition};
        if (!uuid.empty()) {
            symlinks.emplace_back("/dev/block/mapper/by-uuid/" + uuid);
        }
        return symlinks;
    }

    info = GetBlockDeviceInfo(uevent.path);

    if (info.type.empty()) {
        return {};
    }

    std::vector<std::string> links;

    LOG(VERBOSE) << "found " << info.type << " device " << info.str;

    auto link_path = "/dev/block/" + info.type + "/" + info.str;

    if (!uevent.partition_name.empty()) {
        std::string partition_name_sanitized(uevent.partition_name);
        SanitizePartitionName(&partition_name_sanitized);
        if (partition_name_sanitized != uevent.partition_name) {
            LOG(VERBOSE) << "Linking partition '" << uevent.partition_name << "' as '"
                         << partition_name_sanitized << "'";
        }
        links.emplace_back(link_path + "/by-name/" + partition_name_sanitized);
        // Adds symlink: /dev/block/by-name/<partition_name>.
        if (info.is_boot_device) {
            links.emplace_back("/dev/block/by-name/" + partition_name_sanitized);
        }
    } else if (info.is_boot_device) {
        // If we don't have a partition name but we are a partition on a boot device, create a
        // symlink of /dev/block/by-name/<device_name> for symmetry.
        links.emplace_back("/dev/block/by-name/" + uevent.device_name);
        auto partition_name = GetPartitionNameForDevice(uevent.device_name);
        if (!partition_name.empty()) {
            links.emplace_back("/dev/block/by-name/" + partition_name);
        }
    }

    std::string model;
    if (ReadFileToString("/sys/class/block/" + uevent.device_name + "/queue/zoned", &model) &&
        !StartsWith(model, "none")) {
        links.emplace_back("/dev/block/by-name/zoned_device");
        links.emplace_back("/dev/sys/block/by-name/zoned_device");
    }

    auto last_slash = uevent.path.rfind('/');
    links.emplace_back(link_path + "/" + uevent.path.substr(last_slash + 1));

    return links;
}

static void RemoveDeviceMapperLinks(const std::string& devpath) {
    std::vector<std::string> dirs = {
            "/dev/block/mapper",
            "/dev/block/mapper/by-uuid",
    };
    for (const auto& dir : dirs) {
        if (access(dir.c_str(), F_OK) != 0) continue;

        std::unique_ptr<DIR, decltype(&closedir)> dh(opendir(dir.c_str()), closedir);
        if (!dh) {
            PLOG(ERROR) << "Failed to open directory " << dir;
            continue;
        }

        struct dirent* dp;
        std::string link_path;
        while ((dp = readdir(dh.get())) != nullptr) {
            if (dp->d_type != DT_LNK) continue;

            auto path = dir + "/" + dp->d_name;
            if (Readlink(path, &link_path) && link_path == devpath) {
                unlink(path.c_str());
            }
        }
    }
}

void DeviceHandler::HandleDevice(const std::string& action, const std::string& devpath, bool block,
                                 int major, int minor, const std::vector<std::string>& links) const {
    if (action == "add") {
        MakeDevice(devpath, block, major, minor, links);
    }

    // Handle device-mapper nodes.
    // On kernels <= 5.10, the "add" event is fired on DM_DEV_CREATE, but does not contain name
    // information until DM_TABLE_LOAD - thus, we wait for a "change" event.
    // On kernels >= 5.15, the "add" event is fired on DM_TABLE_LOAD, followed by a "change"
    // event.
    if (action == "add" || (action == "change" && StartsWith(devpath, "/dev/block/dm-"))) {
        for (const auto& link : links) {
            std::string target;
            if (StartsWith(link, "/dev/block/")) {
                target = devpath;
            } else if (StartsWith(link, "/dev/sys/block/")) {
                target = "/sys/class/block/" + Basename(devpath);
            } else {
                LOG(ERROR) << "Unrecognized link type: " << link;
                continue;
            }

            if (!mkdir_recursive(Dirname(link), 0755)) {
                PLOG(ERROR) << "Failed to create directory " << Dirname(link);
            }

            if (symlink(target.c_str(), link.c_str())) {
                if (errno != EEXIST) {
                    PLOG(ERROR) << "Failed to symlink " << devpath << " to " << link;
                } else if (std::string link_path;
                           Readlink(link, &link_path) && link_path != devpath) {
                    PLOG(ERROR) << "Failed to symlink " << devpath << " to " << link
                                << ", which already links to: " << link_path;
                }
            }
        }
    }

    if (action == "remove") {
        if (StartsWith(devpath, "/dev/block/dm-")) {
            RemoveDeviceMapperLinks(devpath);
        }
        for (const auto& link : links) {
            std::string link_path;
            if (Readlink(link, &link_path) && link_path == devpath) {
                unlink(link.c_str());
            }
        }
        unlink(devpath.c_str());
    }
}

void DeviceHandler::HandleAshmemUevent(const Uevent& uevent) {
    if (uevent.device_name == "ashmem") {
        static const std::string boot_id_path = "/proc/sys/kernel/random/boot_id";
        std::string boot_id;
        if (!ReadFileToString(boot_id_path, &boot_id)) {
            PLOG(ERROR) << "Cannot duplicate ashmem device node. Failed to read " << boot_id_path;
            return;
        }
        boot_id = Trim(boot_id);

        Uevent dup_ashmem_uevent = uevent;
        dup_ashmem_uevent.device_name += boot_id;
        dup_ashmem_uevent.path += boot_id;
        HandleUevent(dup_ashmem_uevent);
    }
}

// Check Uevents looking for the kernel's boot partition UUID
//
// When we can stop checking uevents (either because we're done or because
// we weren't looking for the kernel's boot partition UUID) then return
// true. Return false if we're not done yet.
bool DeviceHandler::CheckUeventForBootPartUuid(const Uevent& uevent) {
    // If we aren't using boot_part_uuid then we're done.
    if (boot_part_uuid_.empty()) {
        return true;
    }

    // Finding the boot partition is a one-time thing that we do at init
    // time, not steady state. This is because the boot partition isn't
    // allowed to go away or change. Once we found the boot partition we don't
    // expect to run again.
    if (found_boot_part_uuid_) {
        LOG(WARNING) << __PRETTY_FUNCTION__
                     << " shouldn't run after kernel boot partition is found";
        return true;
    }

    // We only need to look at newly-added block devices. Note that if someone
    // is replaying events all existing devices will get "add"ed.
    if (uevent.subsystem != "block" || uevent.action != "add") {
        return false;
    }

    // If it's not the partition we care about then move on.
    if (uevent.partition_uuid != boot_part_uuid_) {
        return false;
    }

    auto device = GetBlockDeviceInfo(uevent.path);

    LOG(INFO) << "Boot device " << device.str << " found via partition UUID";
    found_boot_part_uuid_ = true;
    boot_devices_.clear();
    boot_devices_.insert(device.str);

    return true;
}

void DeviceHandler::HandleUevent(const Uevent& uevent) {
    if (uevent.action == "add" || uevent.action == "change" || uevent.action == "bind" ||
        uevent.action == "online") {
        FixupSysPermissions(uevent.path, uevent.subsystem);
    }

    // if it's not a /dev device, nothing to do
    if (uevent.major < 0 || uevent.minor < 0) return;

    std::string devpath;
    std::vector<std::string> links;
    bool block = false;

    if (uevent.subsystem == "block") {
        block = true;
        devpath = "/dev/block/" + Basename(uevent.path);

        if (StartsWith(uevent.path, "/devices")) {
            links = GetBlockDeviceSymlinks(uevent);
        }
    } else if (const auto subsystem =
                   std::find(subsystems_.cbegin(), subsystems_.cend(), uevent.subsystem);
               subsystem != subsystems_.cend()) {
        devpath = subsystem->ParseDevPath(uevent);
    } else if (uevent.subsystem == "usb") {
        if (!uevent.device_name.empty()) {
            devpath = "/dev/" + uevent.device_name;
        } else {
            // This imitates the file system that would be created
            // if we were using devfs instead.
            // Minors are broken up into groups of 128, starting at "001"
            int bus_id = uevent.minor / 128 + 1;
            int device_id = uevent.minor % 128 + 1;
            devpath = StringPrintf("/dev/bus/usb/%03d/%03d", bus_id, device_id);
        }
    } else if (StartsWith(uevent.subsystem, "usb")) {
        // ignore other USB events
        return;
    } else if (uevent.subsystem == "misc" && StartsWith(uevent.device_name, "dm-user/")) {
        devpath = "/dev/dm-user/" + uevent.device_name.substr(8);
    } else if (uevent.subsystem == "misc" && uevent.device_name == "vfio/vfio") {
        devpath = "/dev/" + uevent.device_name;
    } else {
        devpath = "/dev/" + Basename(uevent.path);
    }

    mkdir_recursive(Dirname(devpath), 0755);

    HandleDevice(uevent.action, devpath, block, uevent.major, uevent.minor, links);

    // Duplicate /dev/ashmem device and name it /dev/ashmem<boot_id>.
    // TODO(b/111903542): remove once all users of /dev/ashmem are migrated to libcutils API.
    HandleAshmemUevent(uevent);
}

void DeviceHandler::ColdbootDone() {
    skip_restorecon_ = false;
}

DeviceHandler::DeviceHandler(std::vector<Permissions> dev_permissions,
                             std::vector<SysfsPermissions> sysfs_permissions,
                             std::vector<Subsystem> subsystems, std::set<std::string> boot_devices,
                             std::string boot_part_uuid, bool skip_restorecon)
    : dev_permissions_(std::move(dev_permissions)),
      sysfs_permissions_(std::move(sysfs_permissions)),
      subsystems_(std::move(subsystems)),
      boot_devices_(std::move(boot_devices)),
      boot_part_uuid_(boot_part_uuid),
      skip_restorecon_(skip_restorecon),
      sysfs_mount_point_("/sys") {
    // If both a boot partition UUID and a list of boot devices are
    // specified then we ignore the boot_devices in favor of boot_part_uuid.
    if (boot_devices_.size() && !boot_part_uuid.empty()) {
        LOG(WARNING) << "Both boot_devices and boot_part_uuid provided; ignoring bootdevices";
        boot_devices_.clear();
    }
}

DeviceHandler::DeviceHandler()
    : DeviceHandler(std::vector<Permissions>{}, std::vector<SysfsPermissions>{},
                    std::vector<Subsystem>{}, std::set<std::string>{}, "", false) {}

}  // namespace init
}  // namespace android
