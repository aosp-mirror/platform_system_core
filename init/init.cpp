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
#include <fstream>
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
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <mtd/mtd-user.h>

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/android.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/android_reboot.h>
#include <cutils/fs.h>
#include <cutils/iosched_policy.h>
#include <cutils/list.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>

#include <memory>

#include "action.h"
#include "bootchart.h"
#include "devices.h"
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

struct selabel_handle *sehandle;
struct selabel_handle *sehandle_prop;

static int property_triggers_enabled = 0;

static char qemu[32];

int have_console;
std::string console_name = "/dev/console";
static time_t process_needs_restart;

const char *ENV[32];

bool waiting_for_exec = false;

static int epoll_fd = -1;

void register_epoll_handler(int fd, void (*fn)()) {
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = reinterpret_cast<void*>(fn);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        ERROR("epoll_ctl failed: %s\n", strerror(errno));
    }
}

/* add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    size_t n;
    size_t key_len = strlen(key);

    /* The last environment entry is reserved to terminate the list */
    for (n = 0; n < (ARRAY_SIZE(ENV) - 1); n++) {

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

    ERROR("No env. room to store: '%s':'%s'\n", key, val);

    return -1;
}

void property_changed(const char *name, const char *value)
{
    if (property_triggers_enabled)
        ActionManager::GetInstance().QueuePropertyTrigger(name, value);
}

static void restart_processes()
{
    process_needs_restart = 0;
    ServiceManager::GetInstance().
        ForEachServiceWithFlags(SVC_RESTARTING, [] (Service* s) {
                s->RestartIfNeeded(process_needs_restart);
            });
}

void handle_control_message(const std::string& msg, const std::string& name) {
    Service* svc = ServiceManager::GetInstance().FindServiceByName(name);
    if (svc == nullptr) {
        ERROR("no such service '%s'\n", name.c_str());
        return;
    }

    if (msg == "start") {
        svc->Start();
    } else if (msg == "stop") {
        svc->Stop();
    } else if (msg == "restart") {
        svc->Restart();
    } else {
        ERROR("unknown control msg '%s'\n", msg.c_str());
    }
}

static int wait_for_coldboot_done_action(const std::vector<std::string>& args) {
    Timer t;

    NOTICE("Waiting for %s...\n", COLDBOOT_DONE);
    // Any longer than 1s is an unreasonable length of time to delay booting.
    // If you're hitting this timeout, check that you didn't make your
    // sepolicy regular expressions too expensive (http://b/19899875).
    if (wait_for_file(COLDBOOT_DONE, 1)) {
        ERROR("Timed out waiting for %s\n", COLDBOOT_DONE);
    }

    NOTICE("Waiting for %s took %.2fs.\n", COLDBOOT_DONE, t.duration());
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
          ERROR("/dev/hw_random not found\n");
          /* It's not an error to not have a Hardware RNG. */
          result = 0;
        } else {
          ERROR("Failed to open /dev/hw_random: %s\n", strerror(errno));
        }
        goto ret;
    }

    urandom_fd = TEMP_FAILURE_RETRY(
            open("/dev/urandom", O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
    if (urandom_fd == -1) {
        ERROR("Failed to open /dev/urandom: %s\n", strerror(errno));
        goto ret;
    }

    while (total_bytes_written < sizeof(buf)) {
        chunk_size = TEMP_FAILURE_RETRY(
                read(hwrandom_fd, buf, sizeof(buf) - total_bytes_written));
        if (chunk_size == -1) {
            ERROR("Failed to read from /dev/hw_random: %s\n", strerror(errno));
            goto ret;
        } else if (chunk_size == 0) {
            ERROR("Failed to read from /dev/hw_random: EOF\n");
            goto ret;
        }

        chunk_size = TEMP_FAILURE_RETRY(write(urandom_fd, buf, chunk_size));
        if (chunk_size == -1) {
            ERROR("Failed to write to /dev/urandom: %s\n", strerror(errno));
            goto ret;
        }
        total_bytes_written += chunk_size;
    }

    INFO("Mixed %zu bytes from /dev/hw_random into /dev/urandom",
                total_bytes_written);
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
    ERROR("Security failure; rebooting into recovery mode...\n");
    android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
    while (true) { pause(); }  // never reached
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
    std::ifstream inf(path, std::fstream::in);
    if (!inf) {
        return false;
    }
    while (start >= min) {
        // try to write out new value
        std::string str_val = std::to_string(start);
        std::ofstream of(path, std::fstream::out);
        if (!of) {
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
        start--;
    }
    inf.close();
    return (start >= min);
}

/*
 * Set /proc/sys/vm/mmap_rnd_bits and potentially
 * /proc/sys/vm/mmap_rnd_compat_bits to the maximum supported values.
 * Returns -1 if unable to set these to an acceptable value.  Apply
 * upstream patch-sets https://lkml.org/lkml/2015/12/21/337 and
 * https://lkml.org/lkml/2016/2/4/831 to enable this.
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
    ERROR("Unknown architecture\n");
#endif

#ifdef __BRILLO__
    // TODO: b/27794137
    ret = 0;
#endif
    if (ret == -1) {
        ERROR("Unable to set adequate mmap entropy value!\n");
        security_failure();
    }
    return ret;
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
        console_name = "/dev/" + console;
    }

    int fd = open(console_name.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    fd = open("/dev/tty0", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        const char *msg;
            msg = "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"  // console is 40 cols x 30 lines
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "             A N D R O I D ";
        write(fd, msg, strlen(msg));
        close(fd);
    }

    return 0;
}

static void import_kernel_nv(const std::string& key, const std::string& value, bool for_emulator) {
    if (key.empty()) return;

    if (for_emulator) {
        // In the emulator, export any kernel option with the "ro.kernel." prefix.
        property_set(android::base::StringPrintf("ro.kernel.%s", key.c_str()).c_str(), value.c_str());
        return;
    }

    if (key == "qemu") {
        strlcpy(qemu, value.c_str(), sizeof(qemu));
    } else if (android::base::StartsWith(key, "androidboot.")) {
        property_set(android::base::StringPrintf("ro.boot.%s", key.c_str() + 12).c_str(),
                     value.c_str());
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
    for (size_t i = 0; i < ARRAY_SIZE(prop_map); i++) {
        std::string value = property_get(prop_map[i].src_prop);
        property_set(prop_map[i].dst_prop, (!value.empty()) ? value.c_str() : prop_map[i].default_value);
    }
}

static void process_kernel_dt() {
    static const char android_dir[] = "/proc/device-tree/firmware/android";

    std::string file_name = android::base::StringPrintf("%s/compatible", android_dir);

    std::string dt_file;
    android::base::ReadFileToString(file_name, &dt_file);
    if (!dt_file.compare("android,firmware")) {
        ERROR("firmware/android is not compatible with 'android,firmware'\n");
        return;
    }

    std::unique_ptr<DIR, int(*)(DIR*)>dir(opendir(android_dir), closedir);
    if (!dir) return;

    struct dirent *dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (dp->d_type != DT_REG || !strcmp(dp->d_name, "compatible") || !strcmp(dp->d_name, "name")) {
            continue;
        }

        file_name = android::base::StringPrintf("%s/%s", android_dir, dp->d_name);

        android::base::ReadFileToString(file_name, &dt_file);
        std::replace(dt_file.begin(), dt_file.end(), ',', '.');

        std::string property_name = android::base::StringPrintf("ro.boot.%s", dp->d_name);
        property_set(property_name.c_str(), dt_file.c_str());
    }
}

static void process_kernel_cmdline() {
    // Don't expose the raw commandline to unprivileged processes.
    chmod("/proc/cmdline", 0440);

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

int selinux_reload_policy(void)
{
    INFO("SELinux: Attempting to reload policy files\n");

    if (selinux_android_reload_policy() == -1) {
        return -1;
    }

    if (sehandle)
        selabel_close(sehandle);

    if (sehandle_prop)
        selabel_close(sehandle_prop);

    selinux_init_all_handles();
    return 0;
}

static int audit_callback(void *data, security_class_t /*cls*/, char *buf, size_t len) {

    property_audit_data *d = reinterpret_cast<property_audit_data*>(data);

    if (!d || !d->name || !d->cr) {
        ERROR("audit_callback invoked with null data arguments!");
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
        INFO("Loading SELinux policy...\n");
        if (selinux_android_load_policy() < 0) {
            ERROR("failed to load policy: %s\n", strerror(errno));
            security_failure();
        }

        bool kernel_enforcing = (security_getenforce() == 1);
        bool is_enforcing = selinux_is_enforcing();
        if (kernel_enforcing != is_enforcing) {
            if (security_setenforce(is_enforcing)) {
                ERROR("security_setenforce(%s) failed: %s\n",
                      is_enforcing ? "true" : "false", strerror(errno));
                security_failure();
            }
        }

        if (write_file("/sys/fs/selinux/checkreqprot", "0") == -1) {
            security_failure();
        }

        NOTICE("(Initializing SELinux %s took %.2fs.)\n",
               is_enforcing ? "enforcing" : "non-enforcing", t.duration());
    } else {
        selinux_init_all_handles();
    }
}

int main(int argc, char** argv) {
    if (!strcmp(basename(argv[0]), "ueventd")) {
        return ueventd_main(argc, argv);
    }

    if (!strcmp(basename(argv[0]), "watchdogd")) {
        return watchdogd_main(argc, argv);
    }

    // Clear the umask.
    umask(0);

    add_environment("PATH", _PATH_DEFPATH);

    bool is_first_stage = (argc == 1) || (strcmp(argv[1], "--second-stage") != 0);

    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    if (is_first_stage) {
        mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
        mkdir("/dev/pts", 0755);
        mkdir("/dev/socket", 0755);
        mount("devpts", "/dev/pts", "devpts", 0, NULL);
        #define MAKE_STR(x) __STRING(x)
        mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC));
        mount("sysfs", "/sys", "sysfs", 0, NULL);
    }

    // We must have some place other than / to create the device nodes for
    // kmsg and null, otherwise we won't be able to remount / read-only
    // later on. Now that tmpfs is mounted on /dev, we can actually talk
    // to the outside world.
    open_devnull_stdio();
    klog_init();
    klog_set_level(KLOG_NOTICE_LEVEL);

    NOTICE("init %s started!\n", is_first_stage ? "first stage" : "second stage");

    if (!is_first_stage) {
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
    }

    // Set up SELinux, including loading the SELinux policy if we're in the kernel domain.
    selinux_initialize(is_first_stage);

    // If we're in the kernel domain, re-exec init to transition to the init domain now
    // that the SELinux policy has been loaded.
    if (is_first_stage) {
        if (restorecon("/init") == -1) {
            ERROR("restorecon failed: %s\n", strerror(errno));
            security_failure();
        }
        char* path = argv[0];
        char* args[] = { path, const_cast<char*>("--second-stage"), nullptr };
        if (execv(path, args) == -1) {
            ERROR("execv(\"%s\") failed: %s\n", path, strerror(errno));
            security_failure();
        }
    }

    // These directories were necessarily created before initial policy load
    // and therefore need their security context restored to the proper value.
    // This must happen before /dev is populated by ueventd.
    NOTICE("Running restorecon...\n");
    restorecon("/dev");
    restorecon("/dev/socket");
    restorecon("/dev/__properties__");
    restorecon("/property_contexts");
    restorecon_recursive("/sys");

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        ERROR("epoll_create1 failed: %s\n", strerror(errno));
        exit(1);
    }

    signal_handler_init();

    property_load_boot_defaults();
    export_oem_lock_status();
    start_property_service();

    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);

    Parser& parser = Parser::GetInstance();
    parser.AddSectionParser("service",std::make_unique<ServiceParser>());
    parser.AddSectionParser("on", std::make_unique<ActionParser>());
    parser.AddSectionParser("import", std::make_unique<ImportParser>());
    parser.ParseConfig("/init.rc");

    ActionManager& am = ActionManager::GetInstance();

    am.QueueEventTrigger("early-init");

    // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
    am.QueueBuiltinAction(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    // ... so that we can start queuing up actions that require stuff from /dev.
    am.QueueBuiltinAction(mix_hwrng_into_linux_rng_action, "mix_hwrng_into_linux_rng");
    am.QueueBuiltinAction(set_mmap_rnd_bits_action, "set_mmap_rnd_bits");
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
        if (!waiting_for_exec) {
            am.ExecuteOneCommand();
            restart_processes();
        }

        int timeout = -1;
        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

        if (am.HasMoreCommands()) {
            timeout = 0;
        }

        bootchart_sample(&timeout);

        epoll_event ev;
        int nr = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd, &ev, 1, timeout));
        if (nr == -1) {
            ERROR("epoll_wait failed: %s\n", strerror(errno));
        } else if (nr == 1) {
            ((void (*)()) ev.data.ptr)();
        }
    }

    return 0;
}
