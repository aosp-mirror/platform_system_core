/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/android.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/fs.h>
#include <cutils/iosched_policy.h>
#include <cutils/list.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <fstream>
#include <memory>

#include "action.h"
#include "bootchart.h"
#include "devices.h"
#include "fs_mgr.h"
#include "import_parser.h"
#include "init.h"
#include "init_parser.h"
#include "keychords.h"
#include "log.h"
#include "property_service.h"
#include "service.h"
#include "signal_handler.h"
#include "ueventd.h"
#include "util.h"
#include "watchdogd.h"

using android::base::StringPrintf;

struct selabel_handle *sehandle;
struct selabel_handle *sehandle_prop;

static int property_triggers_enabled = 0;

static char qemu[32];

std::string default_console = "/dev/console";
static time_t process_needs_restart_at;

const char *ENV[32];

static std::unique_ptr<Timer> waiting_for_exec(nullptr);

static int epoll_fd = -1;

static std::unique_ptr<Timer> waiting_for_prop(nullptr);
static std::string wait_prop_name;
static std::string wait_prop_value;

void register_epoll_handler(int fd, void (*fn)()) {
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = reinterpret_cast<void*>(fn);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        PLOG(ERROR) << "epoll_ctl failed";
    }
}

/* add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    size_t n;
    size_t key_len = strlen(key);

    /* The last environment entry is reserved to terminate the list */
    for (n = 0; n < (arraysize(ENV) - 1); n++) {

        /* Delete any existing entry for this key */
        if (ENV[n] != NULL) {
            size_t entry_key_len = strcspn(ENV[n], "=");
            if ((entry_key_len == key_len) && (strncmp(ENV[n], key, entry_key_len) == 0)) {
                free((char*)ENV[n]);
                ENV[n] = NULL;
            }
        }

        /* Add entry if a free slot is available */
        if (ENV[n] == NULL) {
            char* entry;
            asprintf(&entry, "%s=%s", key, val);
            ENV[n] = entry;
            return 0;
        }
    }

    LOG(ERROR) << "No env. room to store: '" << key << "':'" << val << "'";

    return -1;
}

bool start_waiting_for_exec()
{
    if (waiting_for_exec) {
        return false;
    }
    waiting_for_exec.reset(new Timer());
    return true;
}

void stop_waiting_for_exec()
{
    if (waiting_for_exec) {
        LOG(INFO) << "Wait for exec took " << *waiting_for_exec;
        waiting_for_exec.reset();
    }
}

bool start_waiting_for_property(const char *name, const char *value)
{
    if (waiting_for_prop) {
        return false;
    }
    if (property_get(name) != value) {
        // Current property value is not equal to expected value
        wait_prop_name = name;
        wait_prop_value = value;
        waiting_for_prop.reset(new Timer());
    } else {
        LOG(INFO) << "start_waiting_for_property(\""
                  << name << "\", \"" << value << "\"): already set";
    }
    return true;
}

void property_changed(const char *name, const char *value)
{
    if (property_triggers_enabled)
        ActionManager::GetInstance().QueuePropertyTrigger(name, value);
    if (waiting_for_prop) {
        if (wait_prop_name == name && wait_prop_value == value) {
            wait_prop_name.clear();
            wait_prop_value.clear();
            LOG(INFO) << "Wait for property took " << *waiting_for_prop;
            waiting_for_prop.reset();
        }
    }
}

static void restart_processes()
{
    process_needs_restart_at = 0;
    ServiceManager::GetInstance().ForEachServiceWithFlags(SVC_RESTARTING, [](Service* s) {
        s->RestartIfNeeded(&process_needs_restart_at);
    });
}

void handle_control_message(const std::string& msg, const std::string& name) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(name);
    if (svc == nullptr) {
        LOG(ERROR) << "no such service '" << name << "'";
        return;
    }

    if (msg == "start") {
        svc->Start();
    } else if (msg == "stop") {
        svc->Stop();
    } else if (msg == "restart") {
        svc->Restart();
    } else {
        LOG(ERROR) << "unknown control msg '" << msg << "'";
    }
}

static int wait_for_coldboot_done_action(const std::vector<std::string>& args) {
    Timer t;

    LOG(VERBOSE) << "Waiting for " COLDBOOT_DONE "...";

    // Historically we had a 1s timeout here because we weren't otherwise
    // tracking boot time, and many OEMs made their sepolicy regular
    // expressions too expensive (http://b/19899875).

    // Now we're tracking boot time, just log the time taken to a system
    // property. We still panic if it takes more than a minute though,
    // because any build that slow isn't likely to boot at all, and we'd
    // rather any test lab devices fail back to the bootloader.
    if (wait_for_file(COLDBOOT_DONE, 60s) < 0) {
        LOG(ERROR) << "Timed out waiting for " COLDBOOT_DONE;
        panic();
    }

    property_set("ro.boottime.init.cold_boot_wait", std::to_string(t.duration_ms()).c_str());
    return 0;
}

/*
 * Writes 512 bytes of output from Hardware RNG (/dev/hw_random, backed
 * by Linux kernel's hw_random framework) into Linux RNG's via /dev/urandom.
 * Does nothing if Hardware RNG is not present.
 *
 * Since we don't yet trust the quality of Hardware RNG, these bytes are not
 * mixed into the primary pool of Linux RNG and the entropy estimate is left
 * unmodified.
 *
 * If the HW RNG device /dev/hw_random is present, we require that at least
 * 512 bytes read from it are written into Linux RNG. QA is expected to catch
 * devices/configurations where these I/O operations are blocking for a long
 * time. We do not reboot or halt on failures, as this is a best-effort
 * attempt.
 */
static int mix_hwrng_into_linux_rng_action(const std::vector<std::string>& args)
{
    int result = -1;
    int hwrandom_fd = -1;
    int urandom_fd = -1;
    char buf[512];
    ssize_t chunk_size;
    size_t total_bytes_written = 0;

    hwrandom_fd = TEMP_FAILURE_RETRY(
            open("/dev/hw_random", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (hwrandom_fd == -1) {
        if (errno == ENOENT) {
            LOG(ERROR) << "/dev/hw_random not found";
            // It's not an error to not have a Hardware RNG.
            result = 0;
        } else {
            PLOG(ERROR) << "Failed to open /dev/hw_random";
        }
        goto ret;
    }

    urandom_fd = TEMP_FAILURE_RETRY(
            open("/dev/urandom", O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
    if (urandom_fd == -1) {
        PLOG(ERROR) << "Failed to open /dev/urandom";
        goto ret;
    }

    while (total_bytes_written < sizeof(buf)) {
        chunk_size = TEMP_FAILURE_RETRY(
                read(hwrandom_fd, buf, sizeof(buf) - total_bytes_written));
        if (chunk_size == -1) {
            PLOG(ERROR) << "Failed to read from /dev/hw_random";
            goto ret;
        } else if (chunk_size == 0) {
            LOG(ERROR) << "Failed to read from /dev/hw_random: EOF";
            goto ret;
        }

        chunk_size = TEMP_FAILURE_RETRY(write(urandom_fd, buf, chunk_size));
        if (chunk_size == -1) {
            PLOG(ERROR) << "Failed to write to /dev/urandom";
            goto ret;
        }
        total_bytes_written += chunk_size;
    }

    LOG(INFO) << "Mixed " << total_bytes_written << " bytes from /dev/hw_random into /dev/urandom";
    result = 0;

ret:
    if (hwrandom_fd != -1) {
        close(hwrandom_fd);
    }
    if (urandom_fd != -1) {
        close(urandom_fd);
    }
    return result;
}

static void security_failure() {
    LOG(ERROR) << "Security failure...";
    panic();
}

static bool set_highest_available_option_value(std::string path, int min, int max)
{
    std::ifstream inf(path, std::fstream::in);
    if (!inf) {
        LOG(ERROR) << "Cannot open for reading: " << path;
        return false;
    }

    int current = max;
    while (current >= min) {
        // try to write out new value
        std::string str_val = std::to_string(current);
        std::ofstream of(path, std::fstream::out);
        if (!of) {
            LOG(ERROR) << "Cannot open for writing: " << path;
            return false;
        }
        of << str_val << std::endl;
        of.close();

        // check to make sure it was recorded
        inf.seekg(0);
        std::string str_rec;
        inf >> str_rec;
        if (str_val.compare(str_rec) == 0) {
            break;
        }
        current--;
    }
    inf.close();

    if (current < min) {
        LOG(ERROR) << "Unable to set minimum option value " << min << " in " << path;
        return false;
    }
    return true;
}

#define MMAP_RND_PATH "/proc/sys/vm/mmap_rnd_bits"
#define MMAP_RND_COMPAT_PATH "/proc/sys/vm/mmap_rnd_compat_bits"

/* __attribute__((unused)) due to lack of mips support: see mips block
 * in set_mmap_rnd_bits_action */
static bool __attribute__((unused)) set_mmap_rnd_bits_min(int start, int min, bool compat) {
    std::string path;
    if (compat) {
        path = MMAP_RND_COMPAT_PATH;
    } else {
        path = MMAP_RND_PATH;
    }

    return set_highest_available_option_value(path, min, start);
}

/*
 * Set /proc/sys/vm/mmap_rnd_bits and potentially
 * /proc/sys/vm/mmap_rnd_compat_bits to the maximum supported values.
 * Returns -1 if unable to set these to an acceptable value.
 *
 * To support this sysctl, the following upstream commits are needed:
 *
 * d07e22597d1d mm: mmap: add new /proc tunable for mmap_base ASLR
 * e0c25d958f78 arm: mm: support ARCH_MMAP_RND_BITS
 * 8f0d3aa9de57 arm64: mm: support ARCH_MMAP_RND_BITS
 * 9e08f57d684a x86: mm: support ARCH_MMAP_RND_BITS
 * ec9ee4acd97c drivers: char: random: add get_random_long()
 * 5ef11c35ce86 mm: ASLR: use get_random_long()
 */
static int set_mmap_rnd_bits_action(const std::vector<std::string>& args)
{
    int ret = -1;

    /* values are arch-dependent */
#if defined(__aarch64__)
    /* arm64 supports 18 - 33 bits depending on pagesize and VA_SIZE */
    if (set_mmap_rnd_bits_min(33, 24, false)
            && set_mmap_rnd_bits_min(16, 16, true)) {
        ret = 0;
    }
#elif defined(__x86_64__)
    /* x86_64 supports 28 - 32 bits */
    if (set_mmap_rnd_bits_min(32, 32, false)
            && set_mmap_rnd_bits_min(16, 16, true)) {
        ret = 0;
    }
#elif defined(__arm__) || defined(__i386__)
    /* check to see if we're running on 64-bit kernel */
    bool h64 = !access(MMAP_RND_COMPAT_PATH, F_OK);
    /* supported 32-bit architecture must have 16 bits set */
    if (set_mmap_rnd_bits_min(16, 16, h64)) {
        ret = 0;
    }
#elif defined(__mips__) || defined(__mips64__)
    // TODO: add mips support b/27788820
    ret = 0;
#else
    LOG(ERROR) << "Unknown architecture";
#endif

    if (ret == -1) {
        LOG(ERROR) << "Unable to set adequate mmap entropy value!";
        security_failure();
    }
    return ret;
}

#define KPTR_RESTRICT_PATH "/proc/sys/kernel/kptr_restrict"
#define KPTR_RESTRICT_MINVALUE 2
#define KPTR_RESTRICT_MAXVALUE 4

/* Set kptr_restrict to the highest available level.
 *
 * Aborts if unable to set this to an acceptable value.
 */
static int set_kptr_restrict_action(const std::vector<std::string>& args)
{
    std::string path = KPTR_RESTRICT_PATH;

    if (!set_highest_available_option_value(path, KPTR_RESTRICT_MINVALUE, KPTR_RESTRICT_MAXVALUE)) {
        LOG(ERROR) << "Unable to set adequate kptr_restrict value!";
        security_failure();
    }
    return 0;
}

static int keychord_init_action(const std::vector<std::string>& args)
{
    keychord_init();
    return 0;
}

static int console_init_action(const std::vector<std::string>& args)
{
    std::string console = property_get("ro.boot.console");
    if (!console.empty()) {
        default_console = "/dev/" + console;
    }
    return 0;
}

static void import_kernel_nv(const std::string& key, const std::string& value, bool for_emulator) {
    if (key.empty()) return;

    if (for_emulator) {
        // In the emulator, export any kernel option with the "ro.kernel." prefix.
        property_set(StringPrintf("ro.kernel.%s", key.c_str()).c_str(), value.c_str());
        return;
    }

    if (key == "qemu") {
        strlcpy(qemu, value.c_str(), sizeof(qemu));
    } else if (android::base::StartsWith(key, "androidboot.")) {
        property_set(StringPrintf("ro.boot.%s", key.c_str() + 12).c_str(), value.c_str());
    }
}

static void export_oem_lock_status() {
    if (property_get("ro.oem_unlock_supported") != "1") {
        return;
    }

    std::string value = property_get("ro.boot.verifiedbootstate");

    if (!value.empty()) {
        property_set("ro.boot.flash.locked", value == "orange" ? "0" : "1");
    }
}

static void export_kernel_boot_props() {
    struct {
        const char *src_prop;
        const char *dst_prop;
        const char *default_value;
    } prop_map[] = {
        { "ro.boot.serialno",   "ro.serialno",   "", },
        { "ro.boot.mode",       "ro.bootmode",   "unknown", },
        { "ro.boot.baseband",   "ro.baseband",   "unknown", },
        { "ro.boot.bootloader", "ro.bootloader", "unknown", },
        { "ro.boot.hardware",   "ro.hardware",   "unknown", },
        { "ro.boot.revision",   "ro.revision",   "0", },
    };
    for (size_t i = 0; i < arraysize(prop_map); i++) {
        std::string value = property_get(prop_map[i].src_prop);
        property_set(prop_map[i].dst_prop, (!value.empty()) ? value.c_str() : prop_map[i].default_value);
    }
}

static void process_kernel_dt() {
    static const char android_dir[] = "/proc/device-tree/firmware/android";

    std::string file_name = StringPrintf("%s/compatible", android_dir);

    std::string dt_file;
    android::base::ReadFileToString(file_name, &dt_file);
    if (!dt_file.compare("android,firmware")) {
        LOG(ERROR) << "firmware/android is not compatible with 'android,firmware'";
        return;
    }

    std::unique_ptr<DIR, int(*)(DIR*)>dir(opendir(android_dir), closedir);
    if (!dir) return;

    struct dirent *dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (dp->d_type != DT_REG || !strcmp(dp->d_name, "compatible") || !strcmp(dp->d_name, "name")) {
            continue;
        }

        file_name = StringPrintf("%s/%s", android_dir, dp->d_name);

        android::base::ReadFileToString(file_name, &dt_file);
        std::replace(dt_file.begin(), dt_file.end(), ',', '.');

        std::string property_name = StringPrintf("ro.boot.%s", dp->d_name);
        property_set(property_name.c_str(), dt_file.c_str());
    }
}

static void process_kernel_cmdline() {
    // The first pass does the common stuff, and finds if we are in qemu.
    // The second pass is only necessary for qemu to export all kernel params
    // as properties.
    import_kernel_cmdline(false, import_kernel_nv);
    if (qemu[0]) import_kernel_cmdline(true, import_kernel_nv);
}

static int property_enable_triggers_action(const std::vector<std::string>& args)
{
    /* Enable property triggers. */
    property_triggers_enabled = 1;
    return 0;
}

static int queue_property_triggers_action(const std::vector<std::string>& args)
{
    ActionManager::GetInstance().QueueBuiltinAction(property_enable_triggers_action, "enable_property_trigger");
    ActionManager::GetInstance().QueueAllPropertyTriggers();
    return 0;
}

static void selinux_init_all_handles(void)
{
    sehandle = selinux_android_file_context_handle();
    selinux_android_set_sehandle(sehandle);
    sehandle_prop = selinux_android_prop_context_handle();
}

enum selinux_enforcing_status { SELINUX_PERMISSIVE, SELINUX_ENFORCING };

static selinux_enforcing_status selinux_status_from_cmdline() {
    selinux_enforcing_status status = SELINUX_ENFORCING;

    import_kernel_cmdline(false, [&](const std::string& key, const std::string& value, bool in_qemu) {
        if (key == "androidboot.selinux" && value == "permissive") {
            status = SELINUX_PERMISSIVE;
        }
    });

    return status;
}

static bool selinux_is_enforcing(void)
{
    if (ALLOW_PERMISSIVE_SELINUX) {
        return selinux_status_from_cmdline() == SELINUX_ENFORCING;
    }
    return true;
}

static int audit_callback(void *data, security_class_t /*cls*/, char *buf, size_t len) {

    property_audit_data *d = reinterpret_cast<property_audit_data*>(data);

    if (!d || !d->name || !d->cr) {
        LOG(ERROR) << "audit_callback invoked with null data arguments!";
        return 0;
    }

    snprintf(buf, len, "property=%s pid=%d uid=%d gid=%d", d->name,
            d->cr->pid, d->cr->uid, d->cr->gid);
    return 0;
}

static void selinux_initialize(bool in_kernel_domain) {
    Timer t;

    selinux_callback cb;
    cb.func_log = selinux_klog_callback;
    selinux_set_callback(SELINUX_CB_LOG, cb);
    cb.func_audit = audit_callback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);

    if (in_kernel_domain) {
        LOG(INFO) << "Loading SELinux policy...";
        if (selinux_android_load_policy() < 0) {
            PLOG(ERROR) << "failed to load policy";
            security_failure();
        }

        bool kernel_enforcing = (security_getenforce() == 1);
        bool is_enforcing = selinux_is_enforcing();
        if (kernel_enforcing != is_enforcing) {
            if (security_setenforce(is_enforcing)) {
                PLOG(ERROR) << "security_setenforce(%s) failed" << (is_enforcing ? "true" : "false");
                security_failure();
            }
        }

        if (!write_file("/sys/fs/selinux/checkreqprot", "0")) {
            security_failure();
        }

        // init's first stage can't set properties, so pass the time to the second stage.
        setenv("INIT_SELINUX_TOOK", std::to_string(t.duration_ms()).c_str(), 1);
    } else {
        selinux_init_all_handles();
    }
}

// Set the UDC controller for the ConfigFS USB Gadgets.
// Read the UDC controller in use from "/sys/class/udc".
// In case of multiple UDC controllers select the first one.
static void set_usb_controller() {
    std::unique_ptr<DIR, decltype(&closedir)>dir(opendir("/sys/class/udc"), closedir);
    if (!dir) return;

    dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (dp->d_name[0] == '.') continue;

        property_set("sys.usb.controller", dp->d_name);
        break;
    }
}

/* Returns a new path consisting of base_path and the file name in reference_path. */
static std::string get_path(const std::string& base_path, const std::string& reference_path) {
    std::string::size_type pos = reference_path.rfind('/');
    if (pos == std::string::npos) {
        return base_path + '/' + reference_path;
    } else {
        return base_path + reference_path.substr(pos);
    }
}

/* Imports the fstab info from cmdline. */
static std::string import_cmdline_fstab() {
    std::string prefix, fstab, fstab_full;

    import_kernel_cmdline(false,
        [&](const std::string& key, const std::string& value, bool in_qemu __attribute__((__unused__))) {
            if (key == "android.early.prefix") {
                prefix = value;
            } else if (key == "android.early.fstab") {
                fstab = value;
            }
        });
    if (!fstab.empty()) {
        // Convert "mmcblk0p09+/odm+ext4+ro+verify" to "mmcblk0p09 /odm ext4 ro verify"
        std::replace(fstab.begin(), fstab.end(), '+', ' ');
        for (const auto& entry : android::base::Split(fstab, "\n")) {
            fstab_full += prefix + entry + '\n';
        }
    }
    return fstab_full;
}

/* Early mount vendor and ODM partitions. The fstab info is read from kernel cmdline. */
static void early_mount() {
    std::string fstab_string = import_cmdline_fstab();
    if (fstab_string.empty()) {
        LOG(INFO) << "Failed to load vendor fstab from kernel cmdline";
        return;
    }
    FILE *fstab_file = fmemopen((void *)fstab_string.c_str(), fstab_string.length(), "r");
    if (!fstab_file) {
        PLOG(ERROR) << "Failed to open fstab string as FILE";
        return;
    }
    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_file(fstab_file), fs_mgr_free_fstab);
    fclose(fstab_file);
    if (!fstab) {
        LOG(ERROR) << "Failed to parse fstab string: " << fstab_string;
        return;
    }
    LOG(INFO) << "Loaded vendor fstab from cmdline";

    if (early_device_socket_open()) {
        LOG(ERROR) << "Failed to open device uevent socket";
        return;
    }

    /* Create /dev/device-mapper for dm-verity */
    early_create_dev("/sys/devices/virtual/misc/device-mapper", EARLY_CHAR_DEV);

    for (int i = 0; i < fstab->num_entries; ++i) {
        struct fstab_rec *rec = &fstab->recs[i];
        std::string mount_point = rec->mount_point;
        std::string syspath = rec->blk_device;

        if (mount_point != "/vendor" && mount_point != "/odm")
            continue;

        /* Create mount target under /dev/block/ from sysfs via uevent */
        LOG(INFO) << "Mounting " << mount_point << " from " << syspath << "...";
        char *devpath = strdup(get_path("/dev/block", syspath).c_str());
        if (!devpath) {
            PLOG(ERROR) << "Failed to strdup dev path in early mount " << syspath;
            continue;
        }
        rec->blk_device = devpath;
        early_create_dev(syspath, EARLY_BLOCK_DEV);

        int rc = fs_mgr_early_setup_verity(rec);
        if (rc == FS_MGR_EARLY_SETUP_VERITY_SUCCESS) {
            /* Mount target is changed to /dev/block/dm-<n>; initiate its creation from sysfs counterpart */
            early_create_dev(get_path("/sys/devices/virtual/block", rec->blk_device), EARLY_BLOCK_DEV);
        } else if (rc == FS_MGR_EARLY_SETUP_VERITY_FAIL) {
            LOG(ERROR) << "Failed to set up dm-verity on " << rec->blk_device;
            continue;
        } else { /* FS_MGR_EARLY_SETUP_VERITY_NO_VERITY */
            LOG(INFO) << "dm-verity disabled on debuggable device; mount directly on " << rec->blk_device;
        }

        mkdir(mount_point.c_str(), 0755);
        rc = mount(rec->blk_device, mount_point.c_str(), rec->fs_type, rec->flags, rec->fs_options);
        if (rc) {
            PLOG(ERROR) << "Failed to mount on " << rec->blk_device;
        }
    }
    early_device_socket_close();
}

int main(int argc, char** argv) {
    if (!strcmp(basename(argv[0]), "ueventd")) {
        return ueventd_main(argc, argv);
    }

    if (!strcmp(basename(argv[0]), "watchdogd")) {
        return watchdogd_main(argc, argv);
    }

    boot_clock::time_point start_time = boot_clock::now();

    // Clear the umask.
    umask(0);

    add_environment("PATH", _PATH_DEFPATH);

    bool is_first_stage = (getenv("INIT_SECOND_STAGE") == nullptr);

    // Don't expose the raw commandline to unprivileged processes.
    chmod("/proc/cmdline", 0440);

    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    if (is_first_stage) {
        mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
        mkdir("/dev/pts", 0755);
        mkdir("/dev/socket", 0755);
        mount("devpts", "/dev/pts", "devpts", 0, NULL);
        #define MAKE_STR(x) __STRING(x)
        mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC));
        gid_t groups[] = { AID_READPROC };
        setgroups(arraysize(groups), groups);
        mount("sysfs", "/sys", "sysfs", 0, NULL);
        mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL);
        mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11));
        mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8));
        mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9));
    }

    // Now that tmpfs is mounted on /dev and we have /dev/kmsg, we can actually
    // talk to the outside world...
    InitKernelLogging(argv);

    LOG(INFO) << "init " << (is_first_stage ? "first" : "second") << " stage started!";

    if (is_first_stage) {
        // Mount devices defined in android.early.* kernel commandline
        early_mount();

        // Set up SELinux, loading the SELinux policy.
        selinux_initialize(true);

        // We're in the kernel domain, so re-exec init to transition to the init domain now
        // that the SELinux policy has been loaded.
        if (restorecon("/init") == -1) {
            PLOG(ERROR) << "restorecon failed";
            security_failure();
        }

        setenv("INIT_SECOND_STAGE", "true", 1);

        static constexpr uint32_t kNanosecondsPerMillisecond = 1e6;
        uint64_t start_ms = start_time.time_since_epoch().count() / kNanosecondsPerMillisecond;
        setenv("INIT_STARTED_AT", StringPrintf("%" PRIu64, start_ms).c_str(), 1);

        char* path = argv[0];
        char* args[] = { path, nullptr };
        if (execv(path, args) == -1) {
            PLOG(ERROR) << "execv(\"" << path << "\") failed";
            security_failure();
        }
    } else {
        // Indicate that booting is in progress to background fw loaders, etc.
        close(open("/dev/.booting", O_WRONLY | O_CREAT | O_CLOEXEC, 0000));

        property_init();

        // If arguments are passed both on the command line and in DT,
        // properties set in DT always have priority over the command-line ones.
        process_kernel_dt();
        process_kernel_cmdline();

        // Propagate the kernel variables to internal variables
        // used by init as well as the current required properties.
        export_kernel_boot_props();

        // Make the time that init started available for bootstat to log.
        property_set("ro.boottime.init", getenv("INIT_STARTED_AT"));
        property_set("ro.boottime.init.selinux", getenv("INIT_SELINUX_TOOK"));

        // Clean up our environment.
        unsetenv("INIT_SECOND_STAGE");
        unsetenv("INIT_STARTED_AT");
        unsetenv("INIT_SELINUX_TOOK");

        // Now set up SELinux for second stage.
        selinux_initialize(false);
    }

    // These directories were necessarily created before initial policy load
    // and therefore need their security context restored to the proper value.
    // This must happen before /dev is populated by ueventd.
    LOG(INFO) << "Running restorecon...";
    restorecon("/dev");
    restorecon("/dev/kmsg");
    restorecon("/dev/socket");
    restorecon("/dev/random");
    restorecon("/dev/urandom");
    restorecon("/dev/__properties__");
    restorecon("/plat_property_contexts");
    restorecon("/nonplat_property_contexts");
    restorecon("/sys", SELINUX_ANDROID_RESTORECON_RECURSE);
    restorecon("/dev/block", SELINUX_ANDROID_RESTORECON_RECURSE);
    restorecon("/dev/device-mapper");

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        PLOG(ERROR) << "epoll_create1 failed";
        exit(1);
    }

    signal_handler_init();

    property_load_boot_defaults();
    export_oem_lock_status();
    start_property_service();
    set_usb_controller();

    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);

    Parser& parser = Parser::GetInstance();
    parser.AddSectionParser("service",std::make_unique<ServiceParser>());
    parser.AddSectionParser("on", std::make_unique<ActionParser>());
    parser.AddSectionParser("import", std::make_unique<ImportParser>());
    std::string bootscript = property_get("ro.boot.init_rc");
    if (bootscript.empty()) {
        parser.ParseConfig("/init.rc");
    } else {
        parser.ParseConfig(bootscript);
    }

    ActionManager& am = ActionManager::GetInstance();

    am.QueueEventTrigger("early-init");

    // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
    am.QueueBuiltinAction(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    // ... so that we can start queuing up actions that require stuff from /dev.
    am.QueueBuiltinAction(mix_hwrng_into_linux_rng_action, "mix_hwrng_into_linux_rng");
    am.QueueBuiltinAction(set_mmap_rnd_bits_action, "set_mmap_rnd_bits");
    am.QueueBuiltinAction(set_kptr_restrict_action, "set_kptr_restrict");
    am.QueueBuiltinAction(keychord_init_action, "keychord_init");
    am.QueueBuiltinAction(console_init_action, "console_init");

    // Trigger all the boot actions to get us started.
    am.QueueEventTrigger("init");

    // Repeat mix_hwrng_into_linux_rng in case /dev/hw_random or /dev/random
    // wasn't ready immediately after wait_for_coldboot_done
    am.QueueBuiltinAction(mix_hwrng_into_linux_rng_action, "mix_hwrng_into_linux_rng");

    // Don't mount filesystems or start core system services in charger mode.
    std::string bootmode = property_get("ro.bootmode");
    if (bootmode == "charger") {
        am.QueueEventTrigger("charger");
    } else {
        am.QueueEventTrigger("late-init");
    }

    // Run all property triggers based on current state of the properties.
    am.QueueBuiltinAction(queue_property_triggers_action, "queue_property_triggers");

    while (true) {
        if (!(waiting_for_exec || waiting_for_prop)) {
            am.ExecuteOneCommand();
            restart_processes();
        }

        // By default, sleep until something happens.
        int epoll_timeout_ms = -1;

        // If there's a process that needs restarting, wake up in time for that.
        if (process_needs_restart_at != 0) {
            epoll_timeout_ms = (process_needs_restart_at - time(nullptr)) * 1000;
            if (epoll_timeout_ms < 0) epoll_timeout_ms = 0;
        }

        // If there's more work to do, wake up again immediately.
        if (am.HasMoreCommands()) epoll_timeout_ms = 0;

        epoll_event ev;
        int nr = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd, &ev, 1, epoll_timeout_ms));
        if (nr == -1) {
            PLOG(ERROR) << "epoll_wait failed";
        } else if (nr == 1) {
            ((void (*)()) ev.data.ptr)();
        }
    }

    return 0;
}
