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

#include "init.h"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <unistd.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr_vendor_overlay.h>
#include <keyutils.h>
#include <libavb/libavb.h>
#include <libgsi/libgsi.h>
#include <processgroup/processgroup.h>
#include <processgroup/setup.h>
#include <selinux/android.h>

#include "action_parser.h"
#include "builtins.h"
#include "epoll.h"
#include "first_stage_init.h"
#include "first_stage_mount.h"
#include "import_parser.h"
#include "keychords.h"
#include "lmkd_service.h"
#include "mount_handler.h"
#include "mount_namespace.h"
#include "property_service.h"
#include "proto_utils.h"
#include "reboot.h"
#include "reboot_utils.h"
#include "security.h"
#include "selabel.h"
#include "selinux.h"
#include "service.h"
#include "service_parser.h"
#include "sigchld_handler.h"
#include "system/core/init/property_service.pb.h"
#include "util.h"

using namespace std::chrono_literals;
using namespace std::string_literals;

using android::base::boot_clock;
using android::base::GetProperty;
using android::base::ReadFileToString;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::Trim;
using android::fs_mgr::AvbHandle;

namespace android {
namespace init {

static int property_triggers_enabled = 0;

static char qemu[32];

static int signal_fd = -1;
static int property_fd = -1;

static std::unique_ptr<Timer> waiting_for_prop(nullptr);
static std::string wait_prop_name;
static std::string wait_prop_value;
static std::string shutdown_command;
static bool do_shutdown = false;
static bool load_debug_prop = false;

static std::unique_ptr<Subcontext> subcontext;

void DumpState() {
    ServiceList::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}

Parser CreateParser(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(
                                               &service_list, subcontext.get(), std::nullopt));
    parser.AddSectionParser("on",
                            std::make_unique<ActionParser>(&action_manager, subcontext.get()));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    return parser;
}

// parser that only accepts new services
Parser CreateServiceOnlyParser(ServiceList& service_list, bool from_apex) {
    Parser parser;

    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&service_list, subcontext.get(),
                                                            std::nullopt, from_apex));
    return parser;
}

static void LoadBootScripts(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser = CreateParser(action_manager, service_list);

    std::string bootscript = GetProperty("ro.boot.init_rc", "");
    if (bootscript.empty()) {
        parser.ParseConfig("/system/etc/init/hw/init.rc");
        if (!parser.ParseConfig("/system/etc/init")) {
            late_import_paths.emplace_back("/system/etc/init");
        }
        // late_import is available only in Q and earlier release. As we don't
        // have system_ext in those versions, skip late_import for system_ext.
        parser.ParseConfig("/system_ext/etc/init");
        if (!parser.ParseConfig("/product/etc/init")) {
            late_import_paths.emplace_back("/product/etc/init");
        }
        if (!parser.ParseConfig("/odm/etc/init")) {
            late_import_paths.emplace_back("/odm/etc/init");
        }
        if (!parser.ParseConfig("/vendor/etc/init")) {
            late_import_paths.emplace_back("/vendor/etc/init");
        }
    } else {
        parser.ParseConfig(bootscript);
    }
}

bool start_waiting_for_property(const char *name, const char *value)
{
    if (waiting_for_prop) {
        return false;
    }
    if (GetProperty(name, "") != value) {
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

void ResetWaitForProp() {
    wait_prop_name.clear();
    wait_prop_value.clear();
    waiting_for_prop.reset();
}

static void TriggerShutdown(const std::string& command) {
    // We can't call HandlePowerctlMessage() directly in this function,
    // because it modifies the contents of the action queue, which can cause the action queue
    // to get into a bad state if this function is called from a command being executed by the
    // action queue.  Instead we set this flag and ensure that shutdown happens before the next
    // command is run in the main init loop.
    shutdown_command = command;
    do_shutdown = true;
}

void property_changed(const std::string& name, const std::string& value) {
    // If the property is sys.powerctl, we bypass the event queue and immediately handle it.
    // This is to ensure that init will always and immediately shutdown/reboot, regardless of
    // if there are other pending events to process or if init is waiting on an exec service or
    // waiting on a property.
    // In non-thermal-shutdown case, 'shutdown' trigger will be fired to let device specific
    // commands to be executed.
    if (name == "sys.powerctl") {
        TriggerShutdown(value);
    }

    if (property_triggers_enabled) ActionManager::GetInstance().QueuePropertyChange(name, value);

    // We always record how long init waited for ueventd to tell us cold boot finished.
    // If we aren't waiting on this property, it means that ueventd finished before we even started
    // to wait.
    if (name == kColdBootDoneProp) {
        auto time_waited = waiting_for_prop ? waiting_for_prop->duration().count() : 0;
        property_set("ro.boottime.init.cold_boot_wait", std::to_string(time_waited));
    }

    if (waiting_for_prop) {
        if (wait_prop_name == name && wait_prop_value == value) {
            LOG(INFO) << "Wait for property '" << wait_prop_name << "=" << wait_prop_value
                      << "' took " << *waiting_for_prop;
            ResetWaitForProp();
        }
    }
}

static std::optional<boot_clock::time_point> HandleProcessActions() {
    std::optional<boot_clock::time_point> next_process_action_time;
    for (const auto& s : ServiceList::GetInstance()) {
        if ((s->flags() & SVC_RUNNING) && s->timeout_period()) {
            auto timeout_time = s->time_started() + *s->timeout_period();
            if (boot_clock::now() > timeout_time) {
                s->Timeout();
            } else {
                if (!next_process_action_time || timeout_time < *next_process_action_time) {
                    next_process_action_time = timeout_time;
                }
            }
        }

        if (!(s->flags() & SVC_RESTARTING)) continue;

        auto restart_time = s->time_started() + s->restart_period();
        if (boot_clock::now() > restart_time) {
            if (auto result = s->Start(); !result) {
                LOG(ERROR) << "Could not restart process '" << s->name() << "': " << result.error();
            }
        } else {
            if (!next_process_action_time || restart_time < *next_process_action_time) {
                next_process_action_time = restart_time;
            }
        }
    }
    return next_process_action_time;
}

static Result<void> DoControlStart(Service* service) {
    return service->Start();
}

static Result<void> DoControlStop(Service* service) {
    service->Stop();
    return {};
}

static Result<void> DoControlRestart(Service* service) {
    service->Restart();
    return {};
}

enum class ControlTarget {
    SERVICE,    // function gets called for the named service
    INTERFACE,  // action gets called for every service that holds this interface
};

struct ControlMessageFunction {
    ControlTarget target;
    std::function<Result<void>(Service*)> action;
};

static const std::map<std::string, ControlMessageFunction>& get_control_message_map() {
    // clang-format off
    static const std::map<std::string, ControlMessageFunction> control_message_functions = {
        {"sigstop_on",        {ControlTarget::SERVICE,
                               [](auto* service) { service->set_sigstop(true); return Result<void>{}; }}},
        {"sigstop_off",       {ControlTarget::SERVICE,
                               [](auto* service) { service->set_sigstop(false); return Result<void>{}; }}},
        {"start",             {ControlTarget::SERVICE,   DoControlStart}},
        {"stop",              {ControlTarget::SERVICE,   DoControlStop}},
        {"restart",           {ControlTarget::SERVICE,   DoControlRestart}},
        {"interface_start",   {ControlTarget::INTERFACE, DoControlStart}},
        {"interface_stop",    {ControlTarget::INTERFACE, DoControlStop}},
        {"interface_restart", {ControlTarget::INTERFACE, DoControlRestart}},
    };
    // clang-format on

    return control_message_functions;
}

bool HandleControlMessage(const std::string& msg, const std::string& name, pid_t pid) {
    const auto& map = get_control_message_map();
    const auto it = map.find(msg);

    if (it == map.end()) {
        LOG(ERROR) << "Unknown control msg '" << msg << "'";
        return false;
    }

    std::string cmdline_path = StringPrintf("proc/%d/cmdline", pid);
    std::string process_cmdline;
    if (ReadFileToString(cmdline_path, &process_cmdline)) {
        std::replace(process_cmdline.begin(), process_cmdline.end(), '\0', ' ');
        process_cmdline = Trim(process_cmdline);
    } else {
        process_cmdline = "unknown process";
    }

    const ControlMessageFunction& function = it->second;

    Service* svc = nullptr;

    switch (function.target) {
        case ControlTarget::SERVICE:
            svc = ServiceList::GetInstance().FindService(name);
            break;
        case ControlTarget::INTERFACE:
            svc = ServiceList::GetInstance().FindInterface(name);
            break;
        default:
            LOG(ERROR) << "Invalid function target from static map key ctl." << msg << ": "
                       << static_cast<std::underlying_type<ControlTarget>::type>(function.target);
            return false;
    }

    if (svc == nullptr) {
        LOG(ERROR) << "Control message: Could not find '" << name << "' for ctl." << msg
                   << " from pid: " << pid << " (" << process_cmdline << ")";
        return false;
    }

    if (auto result = function.action(svc); !result) {
        LOG(ERROR) << "Control message: Could not ctl." << msg << " for '" << name
                   << "' from pid: " << pid << " (" << process_cmdline << "): " << result.error();
        return false;
    }

    LOG(INFO) << "Control message: Processed ctl." << msg << " for '" << name
              << "' from pid: " << pid << " (" << process_cmdline << ")";
    return true;
}

static Result<void> wait_for_coldboot_done_action(const BuiltinArguments& args) {
    if (!start_waiting_for_property(kColdBootDoneProp, "true")) {
        LOG(FATAL) << "Could not wait for '" << kColdBootDoneProp << "'";
    }

    return {};
}

static Result<void> SetupCgroupsAction(const BuiltinArguments&) {
    // Have to create <CGROUPS_RC_DIR> using make_dir function
    // for appropriate sepolicy to be set for it
    make_dir(android::base::Dirname(CGROUPS_RC_PATH), 0711);
    if (!CgroupSetup()) {
        return ErrnoError() << "Failed to setup cgroups";
    }

    return {};
}

static void import_kernel_nv(const std::string& key, const std::string& value, bool for_emulator) {
    if (key.empty()) return;

    if (for_emulator) {
        // In the emulator, export any kernel option with the "ro.kernel." prefix.
        property_set("ro.kernel." + key, value);
        return;
    }

    if (key == "qemu") {
        strlcpy(qemu, value.c_str(), sizeof(qemu));
    } else if (android::base::StartsWith(key, "androidboot.")) {
        property_set("ro.boot." + key.substr(12), value);
    }
}

static void export_oem_lock_status() {
    if (!android::base::GetBoolProperty("ro.oem_unlock_supported", false)) {
        return;
    }
    import_kernel_cmdline(
            false, [](const std::string& key, const std::string& value, bool in_qemu) {
                if (key == "androidboot.verifiedbootstate") {
                    property_set("ro.boot.flash.locked", value == "orange" ? "0" : "1");
                }
            });
}

static void export_kernel_boot_props() {
    constexpr const char* UNSET = "";
    struct {
        const char *src_prop;
        const char *dst_prop;
        const char *default_value;
    } prop_map[] = {
        { "ro.boot.serialno",   "ro.serialno",   UNSET, },
        { "ro.boot.mode",       "ro.bootmode",   "unknown", },
        { "ro.boot.baseband",   "ro.baseband",   "unknown", },
        { "ro.boot.bootloader", "ro.bootloader", "unknown", },
        { "ro.boot.hardware",   "ro.hardware",   "unknown", },
        { "ro.boot.revision",   "ro.revision",   "0", },
    };
    for (const auto& prop : prop_map) {
        std::string value = GetProperty(prop.src_prop, prop.default_value);
        if (value != UNSET)
            property_set(prop.dst_prop, value);
    }
}

static void process_kernel_dt() {
    if (!is_android_dt_value_expected("compatible", "android,firmware")) {
        return;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(get_android_dt_dir().c_str()), closedir);
    if (!dir) return;

    std::string dt_file;
    struct dirent *dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (dp->d_type != DT_REG || !strcmp(dp->d_name, "compatible") || !strcmp(dp->d_name, "name")) {
            continue;
        }

        std::string file_name = get_android_dt_dir() + dp->d_name;

        android::base::ReadFileToString(file_name, &dt_file);
        std::replace(dt_file.begin(), dt_file.end(), ',', '.');

        property_set("ro.boot."s + dp->d_name, dt_file);
    }
}

static void process_kernel_cmdline() {
    // The first pass does the common stuff, and finds if we are in qemu.
    // The second pass is only necessary for qemu to export all kernel params
    // as properties.
    import_kernel_cmdline(false, import_kernel_nv);
    if (qemu[0]) import_kernel_cmdline(true, import_kernel_nv);
}

static Result<void> property_enable_triggers_action(const BuiltinArguments& args) {
    /* Enable property triggers. */
    property_triggers_enabled = 1;
    return {};
}

static Result<void> queue_property_triggers_action(const BuiltinArguments& args) {
    ActionManager::GetInstance().QueueBuiltinAction(property_enable_triggers_action, "enable_property_trigger");
    ActionManager::GetInstance().QueueAllPropertyActions();
    return {};
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

static void HandleSigtermSignal(const signalfd_siginfo& siginfo) {
    if (siginfo.ssi_pid != 0) {
        // Drop any userspace SIGTERM requests.
        LOG(DEBUG) << "Ignoring SIGTERM from pid " << siginfo.ssi_pid;
        return;
    }

    HandlePowerctlMessage("shutdown,container");
}

static void HandleSignalFd() {
    signalfd_siginfo siginfo;
    ssize_t bytes_read = TEMP_FAILURE_RETRY(read(signal_fd, &siginfo, sizeof(siginfo)));
    if (bytes_read != sizeof(siginfo)) {
        PLOG(ERROR) << "Failed to read siginfo from signal_fd";
        return;
    }

    switch (siginfo.ssi_signo) {
        case SIGCHLD:
            ReapAnyOutstandingChildren();
            break;
        case SIGTERM:
            HandleSigtermSignal(siginfo);
            break;
        default:
            PLOG(ERROR) << "signal_fd: received unexpected signal " << siginfo.ssi_signo;
            break;
    }
}

static void UnblockSignals() {
    const struct sigaction act { .sa_handler = SIG_DFL };
    sigaction(SIGCHLD, &act, nullptr);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_UNBLOCK, &mask, nullptr) == -1) {
        PLOG(FATAL) << "failed to unblock signals for PID " << getpid();
    }
}

static void InstallSignalFdHandler(Epoll* epoll) {
    // Applying SA_NOCLDSTOP to a defaulted SIGCHLD handler prevents the signalfd from receiving
    // SIGCHLD when a child process stops or continues (b/77867680#comment9).
    const struct sigaction act { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDSTOP };
    sigaction(SIGCHLD, &act, nullptr);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    if (!IsRebootCapable()) {
        // If init does not have the CAP_SYS_BOOT capability, it is running in a container.
        // In that case, receiving SIGTERM will cause the system to shut down.
        sigaddset(&mask, SIGTERM);
    }

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        PLOG(FATAL) << "failed to block signals";
    }

    // Register a handler to unblock signals in the child processes.
    const int result = pthread_atfork(nullptr, nullptr, &UnblockSignals);
    if (result != 0) {
        LOG(FATAL) << "Failed to register a fork handler: " << strerror(result);
    }

    signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (signal_fd == -1) {
        PLOG(FATAL) << "failed to create signalfd";
    }

    if (auto result = epoll->RegisterHandler(signal_fd, HandleSignalFd); !result) {
        LOG(FATAL) << result.error();
    }
}

void HandleKeychord(const std::vector<int>& keycodes) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled != "running") {
        LOG(WARNING) << "Not starting service for keychord " << android::base::Join(keycodes, ' ')
                     << " because ADB is disabled";
        return;
    }

    auto found = false;
    for (const auto& service : ServiceList::GetInstance()) {
        auto svc = service.get();
        if (svc->keycodes() == keycodes) {
            found = true;
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord "
                      << android::base::Join(keycodes, ' ');
            if (auto result = svc->Start(); !result) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord "
                           << android::base::Join(keycodes, ' ') << ": " << result.error();
            }
        }
    }
    if (!found) {
        LOG(ERROR) << "Service for keychord " << android::base::Join(keycodes, ' ') << " not found";
    }
}

static void UmountDebugRamdisk() {
    if (umount("/debug_ramdisk") != 0) {
        LOG(ERROR) << "Failed to umount /debug_ramdisk";
    }
}

static void RecordStageBoottimes(const boot_clock::time_point& second_stage_start_time) {
    int64_t first_stage_start_time_ns = -1;
    if (auto first_stage_start_time_str = getenv(kEnvFirstStageStartedAt);
        first_stage_start_time_str) {
        property_set("ro.boottime.init", first_stage_start_time_str);
        android::base::ParseInt(first_stage_start_time_str, &first_stage_start_time_ns);
    }
    unsetenv(kEnvFirstStageStartedAt);

    int64_t selinux_start_time_ns = -1;
    if (auto selinux_start_time_str = getenv(kEnvSelinuxStartedAt); selinux_start_time_str) {
        android::base::ParseInt(selinux_start_time_str, &selinux_start_time_ns);
    }
    unsetenv(kEnvSelinuxStartedAt);

    if (selinux_start_time_ns == -1) return;
    if (first_stage_start_time_ns == -1) return;

    property_set("ro.boottime.init.first_stage",
                 std::to_string(selinux_start_time_ns - first_stage_start_time_ns));
    property_set("ro.boottime.init.selinux",
                 std::to_string(second_stage_start_time.time_since_epoch().count() -
                                selinux_start_time_ns));
}

void SendLoadPersistentPropertiesMessage() {
    auto init_message = InitMessage{};
    init_message.set_load_persistent_properties(true);
    if (auto result = SendMessage(property_fd, init_message); !result) {
        LOG(ERROR) << "Failed to send load persistent properties message: " << result.error();
    }
}

void SendStopSendingMessagesMessage() {
    auto init_message = InitMessage{};
    init_message.set_stop_sending_messages(true);
    if (auto result = SendMessage(property_fd, init_message); !result) {
        LOG(ERROR) << "Failed to send 'stop sending messages' message: " << result.error();
    }
}

void SendStartSendingMessagesMessage() {
    auto init_message = InitMessage{};
    init_message.set_start_sending_messages(true);
    if (auto result = SendMessage(property_fd, init_message); !result) {
        LOG(ERROR) << "Failed to send 'start sending messages' message: " << result.error();
    }
}

static void HandlePropertyFd() {
    auto message = ReadMessage(property_fd);
    if (!message) {
        LOG(ERROR) << "Could not read message from property service: " << message.error();
        return;
    }

    auto property_message = PropertyMessage{};
    if (!property_message.ParseFromString(*message)) {
        LOG(ERROR) << "Could not parse message from property service";
        return;
    }

    switch (property_message.msg_case()) {
        case PropertyMessage::kControlMessage: {
            auto& control_message = property_message.control_message();
            bool success = HandleControlMessage(control_message.msg(), control_message.name(),
                                                control_message.pid());

            uint32_t response = success ? PROP_SUCCESS : PROP_ERROR_HANDLE_CONTROL_MESSAGE;
            if (control_message.has_fd()) {
                int fd = control_message.fd();
                TEMP_FAILURE_RETRY(send(fd, &response, sizeof(response), 0));
                close(fd);
            }
            break;
        }
        case PropertyMessage::kChangedMessage: {
            auto& changed_message = property_message.changed_message();
            property_changed(changed_message.name(), changed_message.value());
            break;
        }
        default:
            LOG(ERROR) << "Unknown message type from property service: "
                       << property_message.msg_case();
    }
}

int SecondStageMain(int argc, char** argv) {
    if (REBOOT_BOOTLOADER_ON_PANIC) {
        InstallRebootSignalHandlers();
    }

    boot_clock::time_point start_time = boot_clock::now();

    trigger_shutdown = TriggerShutdown;

    SetStdioToDevNull(argv);
    InitKernelLogging(argv);
    LOG(INFO) << "init second stage started!";

    // Will handle EPIPE at the time of write by checking the errno
    signal(SIGPIPE, SIG_IGN);

    // Set init and its forked children's oom_adj.
    if (auto result =
                WriteFile("/proc/1/oom_score_adj", StringPrintf("%d", DEFAULT_OOM_SCORE_ADJUST));
        !result) {
        LOG(ERROR) << "Unable to write " << DEFAULT_OOM_SCORE_ADJUST
                   << " to /proc/1/oom_score_adj: " << result.error();
    }

    // Set up a session keyring that all processes will have access to. It
    // will hold things like FBE encryption keys. No process should override
    // its session keyring.
    keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 1);

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

    // Make the time that init stages started available for bootstat to log.
    RecordStageBoottimes(start_time);

    // Set libavb version for Framework-only OTA match in Treble build.
    const char* avb_version = getenv("INIT_AVB_VERSION");
    if (avb_version) property_set("ro.boot.avb_version", avb_version);

    // See if need to load debug props to allow adb root, when the device is unlocked.
    const char* force_debuggable_env = getenv("INIT_FORCE_DEBUGGABLE");
    if (force_debuggable_env && AvbHandle::IsDeviceUnlocked()) {
        load_debug_prop = "true"s == force_debuggable_env;
    }

    // Clean up our environment.
    unsetenv("INIT_AVB_VERSION");
    unsetenv("INIT_FORCE_DEBUGGABLE");

    // Now set up SELinux for second stage.
    SelinuxSetupKernelLogging();
    SelabelInitialize();
    SelinuxRestoreContext();

    Epoll epoll;
    if (auto result = epoll.Open(); !result) {
        PLOG(FATAL) << result.error();
    }

    InstallSignalFdHandler(&epoll);

    property_load_boot_defaults(load_debug_prop);
    UmountDebugRamdisk();
    fs_mgr_vendor_overlay_mount_all();
    export_oem_lock_status();

    StartPropertyService(&property_fd);
    if (auto result = epoll.RegisterHandler(property_fd, HandlePropertyFd); !result) {
        LOG(FATAL) << "Could not register epoll handler for property fd: " << result.error();
    }

    MountHandler mount_handler(&epoll);
    set_usb_controller();

    const BuiltinFunctionMap& function_map = GetBuiltinFunctionMap();
    Action::set_function_map(&function_map);

    if (!SetupMountNamespaces()) {
        PLOG(FATAL) << "SetupMountNamespaces failed";
    }

    subcontext = InitializeSubcontext();

    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sm = ServiceList::GetInstance();

    LoadBootScripts(am, sm);

    // Turning this on and letting the INFO logging be discarded adds 0.2s to
    // Nexus 9 boot time, so it's disabled by default.
    if (false) DumpState();

    // Make the GSI status available before scripts start running.
    if (android::gsi::IsGsiRunning()) {
        property_set("ro.gsid.image_running", "1");
    } else {
        property_set("ro.gsid.image_running", "0");
    }

    am.QueueBuiltinAction(SetupCgroupsAction, "SetupCgroups");

    am.QueueBuiltinAction(SetKptrRestrictAction, "SetKptrRestrict");
    am.QueueEventTrigger("early-init");

    // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
    am.QueueBuiltinAction(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    // ... so that we can start queuing up actions that require stuff from /dev.
    am.QueueBuiltinAction(MixHwrngIntoLinuxRngAction, "MixHwrngIntoLinuxRng");
    am.QueueBuiltinAction(SetMmapRndBitsAction, "SetMmapRndBits");
    Keychords keychords;
    am.QueueBuiltinAction(
            [&epoll, &keychords](const BuiltinArguments& args) -> Result<void> {
                for (const auto& svc : ServiceList::GetInstance()) {
                    keychords.Register(svc->keycodes());
                }
                keychords.Start(&epoll, HandleKeychord);
                return {};
            },
            "KeychordInit");

    // Trigger all the boot actions to get us started.
    am.QueueEventTrigger("init");

    // Repeat mix_hwrng_into_linux_rng in case /dev/hw_random or /dev/random
    // wasn't ready immediately after wait_for_coldboot_done
    am.QueueBuiltinAction(MixHwrngIntoLinuxRngAction, "MixHwrngIntoLinuxRng");

    // Don't mount filesystems or start core system services in charger mode.
    std::string bootmode = GetProperty("ro.bootmode", "");
    if (bootmode == "charger") {
        am.QueueEventTrigger("charger");
    } else {
        am.QueueEventTrigger("late-init");
    }

    // Run all property triggers based on current state of the properties.
    am.QueueBuiltinAction(queue_property_triggers_action, "queue_property_triggers");

    while (true) {
        // By default, sleep until something happens.
        auto epoll_timeout = std::optional<std::chrono::milliseconds>{};

        if (do_shutdown && !IsShuttingDown()) {
            do_shutdown = false;
            HandlePowerctlMessage(shutdown_command);
        }

        if (!(waiting_for_prop || Service::is_exec_service_running())) {
            am.ExecuteOneCommand();
        }
        if (!(waiting_for_prop || Service::is_exec_service_running())) {
            if (!IsShuttingDown()) {
                auto next_process_action_time = HandleProcessActions();

                // If there's a process that needs restarting, wake up in time for that.
                if (next_process_action_time) {
                    epoll_timeout = std::chrono::ceil<std::chrono::milliseconds>(
                            *next_process_action_time - boot_clock::now());
                    if (*epoll_timeout < 0ms) epoll_timeout = 0ms;
                }
            }

            // If there's more work to do, wake up again immediately.
            if (am.HasMoreCommands()) epoll_timeout = 0ms;
        }

        auto pending_functions = epoll.Wait(epoll_timeout);
        if (!pending_functions) {
            LOG(ERROR) << pending_functions.error();
        } else if (!pending_functions->empty()) {
            // We always reap children before responding to the other pending functions. This is to
            // prevent a race where other daemons see that a service has exited and ask init to
            // start it again via ctl.start before init has reaped it.
            ReapAnyOutstandingChildren();
            for (const auto& function : *pending_functions) {
                (*function)();
            }
        }
    }

    return 0;
}

}  // namespace init
}  // namespace android
