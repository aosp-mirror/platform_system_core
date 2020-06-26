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
#include <map>
#include <memory>
#include <string>
#include <sstream>
#include <thread>
#include <iomanip>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/selinux.h>

#include "selinux.h"
#include "util.h"

#ifdef _INIT_INIT_H
#error "Do not include init.h in files used by ueventd; it will expose init's globals"
#endif

using namespace std::chrono_literals;

using android::base::Basename;
using android::base::Dirname;
using android::base::ReadFileToString;
using android::base::Readlink;
using android::base::Realpath;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Trim;

namespace android {
namespace init {

const int Aliases::ANY = -1;

std::string Aliases::ToString() const {
    std::stringstream fmt, major_hex, minor_hex;

    major_hex << std::hex << major_;
    minor_hex << std::hex << minor_;

    fmt << std::hex
        << "AliasTo:" << alias_to_ << " "
        << "Major:" << (major_ == Aliases::ANY ? "Any" : major_hex.str()) << " "
        << "Minor:" << (minor_ == Aliases::ANY ? "Any" : minor_hex.str()) << " "
        << "ProductId:" << productId_ << " "
        << "VendorId:" << vendorId_;

    return fmt.str();
}

bool Aliases::Matches(int productId, int vendorId, int major, int minor) const {
    return
        ((this->minor_ == Aliases::ANY) || this->minor_ == minor) &&
        ((this->major_ == Aliases::ANY) || this->major_ == major) &&
        (this->productId_ == productId) &&
        (this->vendorId_ == vendorId);
}

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
static bool FindDmDevicePartition(const std::string& path, std::string* result) {
    result->clear();
    if (!StartsWith(path, "/devices/virtual/block/dm-")) return false;
    if (getpid() == 1) return false;  // first_stage_init has no sepolicy needs

    static std::map<std::string, std::string> cache;
    // wait_for_file will not work, the content is also delayed ...
    for (android::base::Timer t; t.duration() < 200ms; std::this_thread::sleep_for(10ms)) {
        if (ReadFileToString("/sys" + path + "/dm/name", result) && !result->empty()) {
            // Got it, set cache with result, when node arrives
            cache[path] = *result = Trim(*result);
            return true;
        }
    }
    auto it = cache.find(path);
    if ((it == cache.end()) || (it->second.empty())) return false;
    // Return cached results, when node goes away
    *result = it->second;
    return true;
}

Aliases::Aliases(const std::string& to, int productId, int vendorId, int major, int minor)
    : minor_(minor), major_(major), productId_(productId), vendorId_(vendorId), alias_to_(to) {
}

Permissions::Permissions(const std::string& name, mode_t perm, uid_t uid, gid_t gid)
    : name_(name), perm_(perm), uid_(uid), gid_(gid), prefix_(false), wildcard_(false) {
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
    if (wildcard_) return fnmatch(name_.c_str(), path.c_str(), FNM_PATHNAME) == 0;
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

// Given a path that may start with a platform device, find the parent platform device by finding a
// parent directory with a 'subsystem' symlink that points to the platform bus.
// If it doesn't start with a platform device, return false
bool DeviceHandler::FindPlatformDevice(std::string path, std::string* platform_device_path) const {
    platform_device_path->clear();

    // Uevents don't contain the mount point, so we need to add it here.
    path.insert(0, sysfs_mount_point_);

    std::string directory = Dirname(path);

    while (directory != "/" && directory != ".") {
        std::string subsystem_link_path;
        if (Realpath(directory + "/subsystem", &subsystem_link_path) &&
            subsystem_link_path == sysfs_mount_point_ + "/bus/platform") {
            // We need to remove the mount point that we added above before returning.
            directory.erase(0, sysfs_mount_point_.size());
            *platform_device_path = directory;
            return true;
        }

        auto last_slash = path.rfind('/');
        if (last_slash == std::string::npos) return false;

        path.erase(last_slash);
        directory = Dirname(path);
    }

    return false;
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
    auto[mode, uid, gid] = GetDevicePermissions(path, links);
    mode |= (block ? S_IFBLK : S_IFCHR);

    std::string secontext;
    if (!SelabelLookupFileContextBestMatch(path, links, mode, &secontext)) {
        PLOG(ERROR) << "Device '" << path << "' not created; cannot find SELinux label";
        return;
    }
    if (!secontext.empty()) {
        setfscreatecon(secontext.c_str());
    }

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
    /* If the node already exists update its SELinux label to handle cases when
     * it was created with the wrong context during coldboot procedure. */
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
    }

out:
    chown(path.c_str(), uid, -1);
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
    std::string device;
    std::string type;
    std::string partition;

    if (FindPlatformDevice(uevent.path, &device)) {
        // Skip /devices/platform or /devices/ if present
        static const std::string devices_platform_prefix = "/devices/platform/";
        static const std::string devices_prefix = "/devices/";

        if (StartsWith(device, devices_platform_prefix)) {
            device = device.substr(devices_platform_prefix.length());
        } else if (StartsWith(device, devices_prefix)) {
            device = device.substr(devices_prefix.length());
        }

        type = "platform";
    } else if (FindPciDevicePrefix(uevent.path, &device)) {
        type = "pci";
    } else if (FindVbdDevicePrefix(uevent.path, &device)) {
        type = "vbd";
    } else if (FindDmDevicePartition(uevent.path, &partition)) {
        return {"/dev/block/mapper/" + partition};
    } else {
        return {};
    }

    std::vector<std::string> links;

    LOG(VERBOSE) << "found " << type << " device " << device;

    auto link_path = "/dev/block/" + type + "/" + device;

    bool is_boot_device = boot_devices_.find(device) != boot_devices_.end();
    if (!uevent.partition_name.empty()) {
        std::string partition_name_sanitized(uevent.partition_name);
        SanitizePartitionName(&partition_name_sanitized);
        if (partition_name_sanitized != uevent.partition_name) {
            LOG(VERBOSE) << "Linking partition '" << uevent.partition_name << "' as '"
                         << partition_name_sanitized << "'";
        }
        links.emplace_back(link_path + "/by-name/" + partition_name_sanitized);
        // Adds symlink: /dev/block/by-name/<partition_name>.
        if (is_boot_device) {
            links.emplace_back("/dev/block/by-name/" + partition_name_sanitized);
        }
    } else if (is_boot_device) {
        // If we don't have a partition name but we are a partition on a boot device, create a
        // symlink of /dev/block/by-name/<device_name> for symmetry.
        links.emplace_back("/dev/block/by-name/" + uevent.device_name);
    }

    auto last_slash = uevent.path.rfind('/');
    links.emplace_back(link_path + "/" + uevent.path.substr(last_slash + 1));

    return links;
}

void DeviceHandler::HandleDevice(const std::string& action, const std::string& dev_path,
                                 const std::string& upath, bool block,
                                 int major, int minor, const std::vector<std::string>& links) const {
    std::string state_link_path, alias_link_path;
    std::stringstream slfmt;

    // Create a symlink in /dev/aliases that will point to the
    // alias.
    slfmt << "/dev/aliases/" << major << "_" << minor;
    state_link_path = slfmt.str();

    if (action == "add") {
        std::string alias_path;
        std::vector<std::string> all_links(links);

        // Add the alias link to the device to the list of links to
        // create.
        if (GetDeviceAlias(upath, major, minor, alias_link_path))
            all_links.push_back(alias_link_path);

        MakeDevice(dev_path, block, major, minor, all_links);

        for (const auto& link_path : all_links) {
            std::string link_target;

            if (!mkdir_recursive(Dirname(link_path), 0755))
                PLOG(ERROR) << "Failed to create directory " << Dirname(link_path);

            // Only create a link in /dev/aliases for the device
            // aliases we created from an 'alias' line in the
            // configuration. This is a way to save what aliases we've
            // created in /dev for a specific device and allow use to
            // find the exact aliases we created without keeping state
            // within ueventd.

            // alias_link is the link (eg: /dev/modem -> /dev/ttyACM0)
            // that we want to be creating.
            if (!alias_link_path.empty()
                && link_path == alias_link_path
                && symlink(alias_link_path.c_str(), state_link_path.c_str())) {

                // If creating the symlink failed, it can be because
                // of a misc error, or it can be because the file
                // already exists. We don't want to replace the file
                // so we make it an explicit error message that the
                // configuration is wrong.

                if (errno != EEXIST)
                    PLOG(ERROR) << "Failed to create symlink from " << state_link_path
                                << " to " << alias_link_path;

                else if (Readlink(state_link_path, &link_target) && link_target != alias_link_path)
                    PLOG(ERROR) << "Failed to create symlink from " << state_link_path
                                << " to " << alias_link_path << ", it already links to " << link_target;
            }
            else {
                if (symlink(dev_path.c_str(), link_path.c_str())) {
                    if (errno != EEXIST)
                        PLOG(ERROR) << "Failed to create symlink from " << link_path
                                    << " to " << dev_path;

                    else if (Readlink(link_path, &link_target) && link_target != dev_path)
                        PLOG(ERROR) << "Failed to create symlink from " << link_path
                                    << " to " << dev_path << ", it already links to: " << link_target;

                    // Delete the link in /dev/aliases
                    unlink(state_link_path.c_str());
                }
                else LOG(INFO) << "Device symlink: " << link_path << " ==> " << dev_path;
            }
        }
    }

    if (action == "remove") {
        std::string state_link_target;

        LOG(INFO) << "Removing device: " << dev_path;

        for (const auto& link : links) {
            std::string link_path;
            if (Readlink(link, &link_path) && link_path == dev_path) {
                unlink(link.c_str());
            }
        }

        // If an alias for that major/minor exists...
        if (Readlink(state_link_path, &state_link_target)) {

            // Read what the alias link points.
            if (Readlink(state_link_target, &alias_link_path)) {

                // ... and if that links points to the right
                // device, erase both the link in /dev/aliases,
                // and what it points to.
                if (alias_link_path == dev_path) {
                    LOG(INFO) << "Removing alias: " << state_link_target;

                    unlink(state_link_path.c_str());
                    unlink(state_link_target.c_str());
                }
            }
        }

        unlink(dev_path.c_str());
    }
}

void DeviceHandler::HandleUevent(const Uevent& uevent) {
    if (uevent.action == "add" || uevent.action == "change" || uevent.action == "online") {
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
    } else {
        devpath = "/dev/" + Basename(uevent.path);
    }

    mkdir_recursive(Dirname(devpath), 0755);

    HandleDevice(uevent.action, devpath, uevent.path, block, uevent.major, uevent.minor, links);
}

static bool FormatDeviceAlias(const Aliases& alias, int minor, int interfaceNumber,
                              std::string& alias_link) {
    std::string::size_type a = 0, b;
    std::stringstream fmt;

    while ((b = alias.AliasTo().find("%", a)) != std::string::npos) {
        fmt << alias.AliasTo().substr(a, b - a);

        if (alias.AliasTo()[b + 1] == 'i') {
            if (interfaceNumber >= 0)
                fmt << std::setfill('0') << std::setw(2) << interfaceNumber;
            else {
                LOG(ERROR) << "No bInterfaceNumber found for device, can't create alias";
                return false;
            }
        }
        else if (alias.AliasTo()[b + 1] == 'm')
            fmt << minor;
        else {
            LOG(ERROR) << "Unknown symlink mask format: %" << alias.AliasTo()[b + 1];
            return false;
        }

        a = (b += 2);
    }

    if (fmt.str().empty())
        alias_link = alias.AliasTo();
    else
        alias_link = fmt.str();

    return true;
}

bool DeviceHandler::GetDeviceAlias(const std::string &upath, int major, int minor,
                                   std::string& alias_link) const {
    bool found = false;
    std::string sys_path;
    std::string parent_dir, iface_dir;
    std::string vendorId_s, vendorId_path;
    std::string bInterfaceNumber_path, bInterfaceNumber_s;
    std::string productId_s, productId_path;
    int vendorId = -1, productId = -1, interfaceNumber = -1;

    parent_dir = Dirname("/sys" + upath);

    // If we can't associate an idVendor for the device, then we
    // silently quit this as we won't ever by able to create an
    // alias..
    while ((parent_dir != "/sys" && parent_dir != ".")) {
        std::string vendorId_path = parent_dir + "/idVendor";

        // Get the vendor ID
        if (!android::base::ReadFileToString(vendorId_path, &vendorId_s)) {
            // Can't find the vendor ID? move up the path.
            auto last_slash = parent_dir.rfind('/');
            if (last_slash == std::string::npos) break;

            parent_dir.erase(last_slash);
        }
        // Found the idVendor, move to the next step.
        else { found = true; break; }
    }

    if (!found) return false;

    // Look in /sys for the information we need.
    sys_path = "/sys" + upath;
    productId_path = parent_dir + "/idProduct";
    bInterfaceNumber_path = sys_path + "/device/bInterfaceNumber";

    // Get the product ID or fail because we need that.
    if (!android::base::ReadFileToString(productId_path, &productId_s)) {
        PLOG(ERROR) << "Failed to read product ID " << productId_path;
        return false;
    }

    // Try to get the bInterfaceNumber.
    android::base::ReadFileToString(bInterfaceNumber_path, &bInterfaceNumber_s);

    vendorId = std::stoi(vendorId_s, 0, 16);
    productId = std::stoi(productId_s, 0, 16);

    if (!bInterfaceNumber_s.empty())
        interfaceNumber = std::stoi(bInterfaceNumber_s, 0, 16);

    // Iterate through all the configured aliases.
    for (const auto& alias : aliases_) {
        std::string dev_s, sAliasPath;

        if (alias.Matches(productId, vendorId, major, minor)) {
#ifdef DEBUG
            LOG(INFO) << std::hex
                      << "productId:" << productId << " "
                      << "vendorId:" << vendorId << " "
                      << "major:" << major << " "
                      << "minor:" << minor << " "
                      << "interfaceNumber:" << std::dec << interfaceNumber;
#endif

            return FormatDeviceAlias(alias, minor, interfaceNumber, alias_link);
        }
    }

    return false;
}

void DeviceHandler::ColdbootDone() {
    skip_restorecon_ = false;
}

DeviceHandler::DeviceHandler(std::vector<Permissions> dev_permissions,
                             std::vector<SysfsPermissions> sysfs_permissions,
                             std::vector<Subsystem> subsystems,
                             std::vector<Aliases> aliases,
                             std::set<std::string> boot_devices,
                             bool skip_restorecon)
    : dev_permissions_(std::move(dev_permissions)),
      sysfs_permissions_(std::move(sysfs_permissions)),
      subsystems_(std::move(subsystems)),
      aliases_(std::move(aliases)),
      boot_devices_(std::move(boot_devices)),
      skip_restorecon_(skip_restorecon),
      sysfs_mount_point_("/sys") {}

DeviceHandler::DeviceHandler()
    : DeviceHandler(std::vector<Permissions>{}, std::vector<SysfsPermissions>{},
                    std::vector<Subsystem>{}, std::vector<Aliases>{}, std::set<std::string>{}, false) {}

}  // namespace init
}  // namespace android
