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

#include "property_service.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wchar.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <memory>
#include <queue>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <bootimg.h>
#include <fs_mgr.h>
#include <property_info_parser/property_info_parser.h>
#include <property_info_serializer/property_info_serializer.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>

#include "init.h"
#include "persistent_properties.h"
#include "property_type.h"
#include "util.h"

using android::base::ReadFileToString;
using android::base::Split;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::Trim;
using android::base::WriteStringToFile;
using android::properties::BuildTrie;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoAreaFile;
using android::properties::PropertyInfoEntry;

#define RECOVERY_MOUNT_POINT "/recovery"

namespace android {
namespace init {

static bool persistent_properties_loaded = false;

static int property_set_fd = -1;

static PropertyInfoAreaFile property_info_area;

uint32_t InitPropertySet(const std::string& name, const std::string& value);

uint32_t (*property_set)(const std::string& name, const std::string& value) = InitPropertySet;

void CreateSerializedPropertyInfo();

void property_init() {
    mkdir("/dev/__properties__", S_IRWXU | S_IXGRP | S_IXOTH);
    CreateSerializedPropertyInfo();
    if (__system_property_area_init()) {
        LOG(FATAL) << "Failed to initialize property area";
    }
    if (!property_info_area.LoadDefaultPath()) {
        LOG(FATAL) << "Failed to load serialized property info file";
    }
}
static bool CheckMacPerms(const std::string& name, const char* target_context,
                          const char* source_context, const ucred& cr) {
    if (!target_context || !source_context) {
        return false;
    }

    property_audit_data audit_data;

    audit_data.name = name.c_str();
    audit_data.cr = &cr;

    bool has_access = (selinux_check_access(source_context, target_context, "property_service",
                                            "set", &audit_data) == 0);

    return has_access;
}

bool is_legal_property_name(const std::string& name) {
    size_t namelen = name.size();

    if (namelen < 1) return false;
    if (name[0] == '.') return false;
    if (name[namelen - 1] == '.') return false;

    /* Only allow alphanumeric, plus '.', '-', '@', ':', or '_' */
    /* Don't allow ".." to appear in a property name */
    for (size_t i = 0; i < namelen; i++) {
        if (name[i] == '.') {
            // i=0 is guaranteed to never have a dot. See above.
            if (name[i-1] == '.') return false;
            continue;
        }
        if (name[i] == '_' || name[i] == '-' || name[i] == '@' || name[i] == ':') continue;
        if (name[i] >= 'a' && name[i] <= 'z') continue;
        if (name[i] >= 'A' && name[i] <= 'Z') continue;
        if (name[i] >= '0' && name[i] <= '9') continue;
        return false;
    }

    return true;
}

static uint32_t PropertySetImpl(const std::string& name, const std::string& value) {
    size_t valuelen = value.size();

    if (!is_legal_property_name(name)) {
        LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: bad name";
        return PROP_ERROR_INVALID_NAME;
    }

    if (valuelen >= PROP_VALUE_MAX && !StartsWith(name, "ro.")) {
        LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                   << "value too long";
        return PROP_ERROR_INVALID_VALUE;
    }

    if (mbstowcs(nullptr, value.data(), 0) == static_cast<std::size_t>(-1)) {
        LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                   << "value not a UTF8 encoded string";
        return PROP_ERROR_INVALID_VALUE;
    }

    prop_info* pi = (prop_info*) __system_property_find(name.c_str());
    if (pi != nullptr) {
        // ro.* properties are actually "write-once".
        if (StartsWith(name, "ro.")) {
            LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                       << "property already set";
            return PROP_ERROR_READ_ONLY_PROPERTY;
        }

        __system_property_update(pi, value.c_str(), valuelen);
    } else {
        int rc = __system_property_add(name.c_str(), name.size(), value.c_str(), valuelen);
        if (rc < 0) {
            LOG(ERROR) << "property_set(\"" << name << "\", \"" << value << "\") failed: "
                       << "__system_property_add failed";
            return PROP_ERROR_SET_FAILED;
        }
    }

    // Don't write properties to disk until after we have read all default
    // properties to prevent them from being overwritten by default values.
    if (persistent_properties_loaded && StartsWith(name, "persist.")) {
        WritePersistentProperty(name, value);
    }
    property_changed(name, value);
    return PROP_SUCCESS;
}

typedef int (*PropertyAsyncFunc)(const std::string&, const std::string&);

struct PropertyChildInfo {
    pid_t pid;
    PropertyAsyncFunc func;
    std::string name;
    std::string value;
};

static std::queue<PropertyChildInfo> property_children;

static void PropertyChildLaunch() {
    auto& info = property_children.front();
    pid_t pid = fork();
    if (pid < 0) {
        LOG(ERROR) << "Failed to fork for property_set_async";
        while (!property_children.empty()) {
            property_children.pop();
        }
        return;
    }
    if (pid != 0) {
        info.pid = pid;
    } else {
        if (info.func(info.name, info.value) != 0) {
            LOG(ERROR) << "property_set_async(\"" << info.name << "\", \"" << info.value
                       << "\") failed";
        }
        _exit(0);
    }
}

bool PropertyChildReap(pid_t pid) {
    if (property_children.empty()) {
        return false;
    }
    auto& info = property_children.front();
    if (info.pid != pid) {
        return false;
    }
    if (PropertySetImpl(info.name, info.value) != PROP_SUCCESS) {
        LOG(ERROR) << "Failed to set async property " << info.name;
    }
    property_children.pop();
    if (!property_children.empty()) {
        PropertyChildLaunch();
    }
    return true;
}

static uint32_t PropertySetAsync(const std::string& name, const std::string& value,
                                 PropertyAsyncFunc func) {
    if (value.empty()) {
        return PropertySetImpl(name, value);
    }

    PropertyChildInfo info;
    info.func = func;
    info.name = name;
    info.value = value;
    property_children.push(info);
    if (property_children.size() == 1) {
        PropertyChildLaunch();
    }
    return PROP_SUCCESS;
}

static int RestoreconRecursiveAsync(const std::string& name, const std::string& value) {
    return selinux_android_restorecon(value.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE);
}

uint32_t PropertySet(const std::string& name, const std::string& value) {
    if (name == "selinux.restorecon_recursive") {
        return PropertySetAsync(name, value, RestoreconRecursiveAsync);
    }

    return PropertySetImpl(name, value);
}

uint32_t InitPropertySet(const std::string& name, const std::string& value) {
    if (StartsWith(name, "ctl.")) {
        LOG(ERROR) << "Do not set ctl. properties from init; call the Service functions directly";
        return PROP_ERROR_INVALID_NAME;
    }

    const char* type = nullptr;
    property_info_area->GetPropertyInfo(name.c_str(), nullptr, &type);

    if (type == nullptr || !CheckType(type, value)) {
        LOG(ERROR) << "property_set: name: '" << name << "' type check failed, type: '"
                   << (type ?: "(null)") << "' value: '" << value << "'";
        return PROP_ERROR_INVALID_VALUE;
    }

    return PropertySet(name, value);
}

class SocketConnection {
  public:
    SocketConnection(int socket, const ucred& cred) : socket_(socket), cred_(cred) {}

    ~SocketConnection() { close(socket_); }

    bool RecvUint32(uint32_t* value, uint32_t* timeout_ms) {
        return RecvFully(value, sizeof(*value), timeout_ms);
    }

    bool RecvChars(char* chars, size_t size, uint32_t* timeout_ms) {
        return RecvFully(chars, size, timeout_ms);
    }

    bool RecvString(std::string* value, uint32_t* timeout_ms) {
        uint32_t len = 0;
        if (!RecvUint32(&len, timeout_ms)) {
            return false;
        }

        if (len == 0) {
            *value = "";
            return true;
        }

        // http://b/35166374: don't allow init to make arbitrarily large allocations.
        if (len > 0xffff) {
            LOG(ERROR) << "sys_prop: RecvString asked to read huge string: " << len;
            errno = ENOMEM;
            return false;
        }

        std::vector<char> chars(len);
        if (!RecvChars(&chars[0], len, timeout_ms)) {
            return false;
        }

        *value = std::string(&chars[0], len);
        return true;
    }

    bool SendUint32(uint32_t value) {
        int result = TEMP_FAILURE_RETRY(send(socket_, &value, sizeof(value), 0));
        return result == sizeof(value);
    }

    int socket() { return socket_; }

    const ucred& cred() { return cred_; }

    std::string source_context() const {
        char* source_context = nullptr;
        getpeercon(socket_, &source_context);
        std::string result = source_context;
        freecon(source_context);
        return result;
    }

  private:
    bool PollIn(uint32_t* timeout_ms) {
        struct pollfd ufds[1];
        ufds[0].fd = socket_;
        ufds[0].events = POLLIN;
        ufds[0].revents = 0;
        while (*timeout_ms > 0) {
            auto start_time = std::chrono::steady_clock::now();
            int nr = poll(ufds, 1, *timeout_ms);
            auto now = std::chrono::steady_clock::now();
            auto time_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
            uint64_t millis = time_elapsed.count();
            *timeout_ms = (millis > *timeout_ms) ? 0 : *timeout_ms - millis;

            if (nr > 0) {
                return true;
            }

            if (nr == 0) {
                // Timeout
                break;
            }

            if (nr < 0 && errno != EINTR) {
                PLOG(ERROR) << "sys_prop: error waiting for uid " << cred_.uid
                            << " to send property message";
                return false;
            } else {  // errno == EINTR
                // Timer rounds milliseconds down in case of EINTR we want it to be rounded up
                // to avoid slowing init down by causing EINTR with under millisecond timeout.
                if (*timeout_ms > 0) {
                    --(*timeout_ms);
                }
            }
        }

        LOG(ERROR) << "sys_prop: timeout waiting for uid " << cred_.uid
                   << " to send property message.";
        return false;
    }

    bool RecvFully(void* data_ptr, size_t size, uint32_t* timeout_ms) {
        size_t bytes_left = size;
        char* data = static_cast<char*>(data_ptr);
        while (*timeout_ms > 0 && bytes_left > 0) {
            if (!PollIn(timeout_ms)) {
                return false;
            }

            int result = TEMP_FAILURE_RETRY(recv(socket_, data, bytes_left, MSG_DONTWAIT));
            if (result <= 0) {
                return false;
            }

            bytes_left -= result;
            data += result;
        }

        return bytes_left == 0;
    }

    int socket_;
    ucred cred_;

    DISALLOW_IMPLICIT_CONSTRUCTORS(SocketConnection);
};

// This returns one of the enum of PROP_SUCCESS or PROP_ERROR*.
uint32_t HandlePropertySet(const std::string& name, const std::string& value,
                           const std::string& source_context, const ucred& cr) {
    if (!is_legal_property_name(name)) {
        LOG(ERROR) << "PropertySet: illegal property name \"" << name << "\"";
        return PROP_ERROR_INVALID_NAME;
    }

    if (StartsWith(name, "ctl.")) {
        // ctl. properties have their name ctl.<action> and their value is the name of the service
        // to apply that action to.  Permissions for these actions are based on the service, so we
        // must create a fake name of ctl.<service> to check permissions.
        auto control_string = "ctl." + value;
        const char* target_context = nullptr;
        const char* type = nullptr;
        property_info_area->GetPropertyInfo(control_string.c_str(), &target_context, &type);
        if (!CheckMacPerms(control_string, target_context, source_context.c_str(), cr)) {
            LOG(ERROR) << "PropertySet: Unable to " << (name.c_str() + 4) << " service ctl ["
                       << value << "]"
                       << " uid:" << cr.uid << " gid:" << cr.gid << " pid:" << cr.pid;
            return PROP_ERROR_HANDLE_CONTROL_MESSAGE;
        }

        handle_control_message(name.c_str() + 4, value.c_str());
        return PROP_SUCCESS;
    }

    const char* target_context = nullptr;
    const char* type = nullptr;
    property_info_area->GetPropertyInfo(name.c_str(), &target_context, &type);

    if (!CheckMacPerms(name, target_context, source_context.c_str(), cr)) {
        LOG(ERROR) << "PropertySet: permission denied uid:" << cr.uid << " name:" << name;
        return PROP_ERROR_PERMISSION_DENIED;
    }

    if (type == nullptr || !CheckType(type, value)) {
        LOG(ERROR) << "PropertySet: name: '" << name << "' type check failed, type: '"
                   << (type ?: "(null)") << "' value: '" << value << "'";
        return PROP_ERROR_INVALID_VALUE;
    }

    // sys.powerctl is a special property that is used to make the device reboot.  We want to log
    // any process that sets this property to be able to accurately blame the cause of a shutdown.
    if (name == "sys.powerctl") {
        std::string cmdline_path = StringPrintf("proc/%d/cmdline", cr.pid);
        std::string process_cmdline;
        std::string process_log_string;
        if (ReadFileToString(cmdline_path, &process_cmdline)) {
            // Since cmdline is null deliminated, .c_str() conveniently gives us just the process
            // path.
            process_log_string = StringPrintf(" (%s)", process_cmdline.c_str());
        }
        LOG(INFO) << "Received sys.powerctl='" << value << "' from pid: " << cr.pid
                  << process_log_string;
    }

    return PropertySet(name, value);
}

static void handle_property_set_fd() {
    static constexpr uint32_t kDefaultSocketTimeout = 2000; /* ms */

    int s = accept4(property_set_fd, nullptr, nullptr, SOCK_CLOEXEC);
    if (s == -1) {
        return;
    }

    ucred cr;
    socklen_t cr_size = sizeof(cr);
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cr_size) < 0) {
        close(s);
        PLOG(ERROR) << "sys_prop: unable to get SO_PEERCRED";
        return;
    }

    SocketConnection socket(s, cr);
    uint32_t timeout_ms = kDefaultSocketTimeout;

    uint32_t cmd = 0;
    if (!socket.RecvUint32(&cmd, &timeout_ms)) {
        PLOG(ERROR) << "sys_prop: error while reading command from the socket";
        socket.SendUint32(PROP_ERROR_READ_CMD);
        return;
    }

    switch (cmd) {
    case PROP_MSG_SETPROP: {
        char prop_name[PROP_NAME_MAX];
        char prop_value[PROP_VALUE_MAX];

        if (!socket.RecvChars(prop_name, PROP_NAME_MAX, &timeout_ms) ||
            !socket.RecvChars(prop_value, PROP_VALUE_MAX, &timeout_ms)) {
          PLOG(ERROR) << "sys_prop(PROP_MSG_SETPROP): error while reading name/value from the socket";
          return;
        }

        prop_name[PROP_NAME_MAX-1] = 0;
        prop_value[PROP_VALUE_MAX-1] = 0;

        HandlePropertySet(prop_value, prop_value, socket.source_context(), socket.cred());
        break;
      }

    case PROP_MSG_SETPROP2: {
        std::string name;
        std::string value;
        if (!socket.RecvString(&name, &timeout_ms) ||
            !socket.RecvString(&value, &timeout_ms)) {
          PLOG(ERROR) << "sys_prop(PROP_MSG_SETPROP2): error while reading name/value from the socket";
          socket.SendUint32(PROP_ERROR_READ_DATA);
          return;
        }

        auto result = HandlePropertySet(name, value, socket.source_context(), socket.cred());
        socket.SendUint32(result);
        break;
      }

    default:
        LOG(ERROR) << "sys_prop: invalid command " << cmd;
        socket.SendUint32(PROP_ERROR_INVALID_CMD);
        break;
    }
}

static bool load_properties_from_file(const char *, const char *);

/*
 * Filter is used to decide which properties to load: NULL loads all keys,
 * "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
 */
static void load_properties(char *data, const char *filter)
{
    char *key, *value, *eol, *sol, *tmp, *fn;
    size_t flen = 0;

    if (filter) {
        flen = strlen(filter);
    }

    sol = data;
    while ((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = 0;
        sol = eol;

        while (isspace(*key)) key++;
        if (*key == '#') continue;

        tmp = eol - 2;
        while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

        if (!strncmp(key, "import ", 7) && flen == 0) {
            fn = key + 7;
            while (isspace(*fn)) fn++;

            key = strchr(fn, ' ');
            if (key) {
                *key++ = 0;
                while (isspace(*key)) key++;
            }

            load_properties_from_file(fn, key);

        } else {
            value = strchr(key, '=');
            if (!value) continue;
            *value++ = 0;

            tmp = value - 2;
            while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

            while (isspace(*value)) value++;

            if (flen > 0) {
                if (filter[flen - 1] == '*') {
                    if (strncmp(key, filter, flen - 1)) continue;
                } else {
                    if (strcmp(key, filter)) continue;
                }
            }

            property_set(key, value);
        }
    }
}

// Filter is used to decide which properties to load: NULL loads all keys,
// "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
static bool load_properties_from_file(const char* filename, const char* filter) {
    Timer t;
    auto file_contents = ReadFile(filename);
    if (!file_contents) {
        PLOG(WARNING) << "Couldn't load property file '" << filename
                      << "': " << file_contents.error();
        return false;
    }
    file_contents->push_back('\n');
    load_properties(file_contents->data(), filter);
    LOG(VERBOSE) << "(Loading properties from " << filename << " took " << t << ".)";
    return true;
}

// persist.sys.usb.config values can't be combined on build-time when property
// files are split into each partition.
// So we need to apply the same rule of build/make/tools/post_process_props.py
// on runtime.
static void update_sys_usb_config() {
    bool is_debuggable = android::base::GetBoolProperty("ro.debuggable", false);
    std::string config = android::base::GetProperty("persist.sys.usb.config", "");
    if (config.empty()) {
        property_set("persist.sys.usb.config", is_debuggable ? "adb" : "none");
    } else if (is_debuggable && config.find("adb") == std::string::npos &&
               config.length() + 4 < PROP_VALUE_MAX) {
        config.append(",adb");
        property_set("persist.sys.usb.config", config);
    }
}

void property_load_boot_defaults() {
    if (!load_properties_from_file("/system/etc/prop.default", NULL)) {
        // Try recovery path
        if (!load_properties_from_file("/prop.default", NULL)) {
            // Try legacy path
            load_properties_from_file("/default.prop", NULL);
        }
    }
    load_properties_from_file("/odm/default.prop", NULL);
    load_properties_from_file("/vendor/default.prop", NULL);

    update_sys_usb_config();
}

static void load_override_properties() {
    if (ALLOW_LOCAL_PROP_OVERRIDE) {
        load_properties_from_file("/data/local.prop", NULL);
    }
}

/* When booting an encrypted system, /data is not mounted when the
 * property service is started, so any properties stored there are
 * not loaded.  Vold triggers init to load these properties once it
 * has mounted /data.
 */
void load_persist_props(void) {
    // Devices with FDE have load_persist_props called twice; the first time when the temporary
    // /data partition is mounted and then again once /data is truly mounted.  We do not want to
    // read persistent properties from the temporary /data partition or mark persistent properties
    // as having been loaded during the first call, so we return in that case.
    std::string crypto_state = android::base::GetProperty("ro.crypto.state", "");
    std::string crypto_type = android::base::GetProperty("ro.crypto.type", "");
    if (crypto_state == "encrypted" && crypto_type == "block") {
        static size_t num_calls = 0;
        if (++num_calls == 1) return;
    }

    load_override_properties();
    /* Read persistent properties after all default values have been loaded. */
    auto persistent_properties = LoadPersistentProperties();
    for (const auto& persistent_property_record : persistent_properties.properties()) {
        property_set(persistent_property_record.name(), persistent_property_record.value());
    }
    persistent_properties_loaded = true;
    property_set("ro.persistent_properties.ready", "true");
}

void load_recovery_id_prop() {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    if (!fstab) {
        PLOG(ERROR) << "unable to read default fstab";
        return;
    }

    fstab_rec* rec = fs_mgr_get_entry_for_mount_point(fstab.get(), RECOVERY_MOUNT_POINT);
    if (rec == NULL) {
        LOG(ERROR) << "/recovery not specified in fstab";
        return;
    }

    int fd = open(rec->blk_device, O_RDONLY);
    if (fd == -1) {
        PLOG(ERROR) << "error opening block device " << rec->blk_device;
        return;
    }

    boot_img_hdr hdr;
    if (android::base::ReadFully(fd, &hdr, sizeof(hdr))) {
        std::string hex = bytes_to_hex(reinterpret_cast<uint8_t*>(hdr.id), sizeof(hdr.id));
        property_set("ro.recovery_id", hex);
    } else {
        PLOG(ERROR) << "error reading /recovery";
    }

    close(fd);
}

void load_system_props() {
    load_properties_from_file("/system/build.prop", NULL);
    load_properties_from_file("/odm/build.prop", NULL);
    load_properties_from_file("/vendor/build.prop", NULL);
    load_properties_from_file("/factory/factory.prop", "ro.*");
    load_recovery_id_prop();
}

static int SelinuxAuditCallback(void* data, security_class_t /*cls*/, char* buf, size_t len) {
    property_audit_data* d = reinterpret_cast<property_audit_data*>(data);

    if (!d || !d->name || !d->cr) {
        LOG(ERROR) << "AuditCallback invoked with null data arguments!";
        return 0;
    }

    snprintf(buf, len, "property=%s pid=%d uid=%d gid=%d", d->name, d->cr->pid, d->cr->uid,
             d->cr->gid);
    return 0;
}

bool LoadPropertyInfoFromFile(const std::string& filename,
                              std::vector<PropertyInfoEntry>* property_infos) {
    auto file_contents = std::string();
    if (!ReadFileToString(filename, &file_contents)) {
        PLOG(ERROR) << "Could not read properties from '" << filename << "'";
        return false;
    }

    auto errors = std::vector<std::string>{};
    ParsePropertyInfoFile(file_contents, property_infos, &errors);
    // Individual parsing errors are reported but do not cause a failed boot, which is what
    // returning false would do here.
    for (const auto& error : errors) {
        LOG(ERROR) << "Could not read line from '" << filename << "': " << error;
    }

    return true;
}

void CreateSerializedPropertyInfo() {
    auto property_infos = std::vector<PropertyInfoEntry>();
    if (access("/system/etc/selinux/plat_property_contexts", R_OK) != -1) {
        if (!LoadPropertyInfoFromFile("/system/etc/selinux/plat_property_contexts",
                                      &property_infos)) {
            return;
        }
        // Don't check for failure here, so we always have a sane list of properties.
        // E.g. In case of recovery, the vendor partition will not have mounted and we
        // still need the system / platform properties to function.
        LoadPropertyInfoFromFile("/vendor/etc/selinux/nonplat_property_contexts", &property_infos);
    } else {
        if (!LoadPropertyInfoFromFile("/plat_property_contexts", &property_infos)) {
            return;
        }
        LoadPropertyInfoFromFile("/nonplat_property_contexts", &property_infos);
    }

    auto serialized_contexts = std::string();
    auto error = std::string();
    if (!BuildTrie(property_infos, "u:object_r:default_prop:s0", "string", &serialized_contexts,
                   &error)) {
        LOG(ERROR) << "Unable to serialize property contexts: " << error;
        return;
    }

    constexpr static const char kPropertyInfosPath[] = "/dev/__properties__/property_info";
    if (!WriteStringToFile(serialized_contexts, kPropertyInfosPath, 0444, 0, 0, false)) {
        PLOG(ERROR) << "Unable to write serialized property infos to file";
    }
    selinux_android_restorecon(kPropertyInfosPath, 0);
}

void start_property_service() {
    selinux_callback cb;
    cb.func_audit = SelinuxAuditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);

    property_set("ro.property_service.version", "2");

    property_set_fd = CreateSocket(PROP_SERVICE_NAME, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                   false, 0666, 0, 0, nullptr);
    if (property_set_fd == -1) {
        PLOG(FATAL) << "start_property_service socket creation failed";
    }

    listen(property_set_fd, 8);

    register_epoll_handler(property_set_fd, handle_property_set_fd);
}

}  // namespace init
}  // namespace android
