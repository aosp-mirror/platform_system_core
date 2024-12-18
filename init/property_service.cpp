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

#include <android/api-level.h>
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
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <wchar.h>

#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <string_view>
#include <thread>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_mgr.h>
#include <private/android_filesystem_config.h>
#include <property_info_parser/property_info_parser.h>
#include <property_info_serializer/property_info_serializer.h>
#include <selinux/android.h>
#include <selinux/label.h>
#include <selinux/selinux.h>
#include <vendorsupport/api_level.h>

#include "debug_ramdisk.h"
#include "epoll.h"
#include "init.h"
#include "persistent_properties.h"
#include "property_type.h"
#include "proto_utils.h"
#include "second_stage_resources.h"
#include "selinux.h"
#include "subcontext.h"
#include "system/core/init/property_service.pb.h"
#include "util.h"

static constexpr char APPCOMPAT_OVERRIDE_PROP_FOLDERNAME[] =
        "/dev/__properties__/appcompat_override";
static constexpr char APPCOMPAT_OVERRIDE_PROP_TREE_FILE[] =
        "/dev/__properties__/appcompat_override/property_info";
using namespace std::literals;

using android::base::ErrnoError;
using android::base::Error;
using android::base::GetIntProperty;
using android::base::GetProperty;
using android::base::ParseInt;
using android::base::ReadFileToString;
using android::base::Result;
using android::base::Split;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::Trim;
using android::base::unique_fd;
using android::base::WriteStringToFile;
using android::properties::BuildTrie;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoAreaFile;
using android::properties::PropertyInfoEntry;

namespace android {
namespace init {

class PersistWriteThread;

constexpr auto FINGERPRINT_PROP = "ro.build.fingerprint";
constexpr auto LEGACY_FINGERPRINT_PROP = "ro.build.legacy.fingerprint";
constexpr auto ID_PROP = "ro.build.id";
constexpr auto LEGACY_ID_PROP = "ro.build.legacy.id";
constexpr auto VBMETA_DIGEST_PROP = "ro.boot.vbmeta.digest";
constexpr auto DIGEST_SIZE_USED = 8;

static bool persistent_properties_loaded = false;

static int from_init_socket = -1;
static int init_socket = -1;
static bool accept_messages = false;
static std::mutex accept_messages_lock;
static std::mutex selinux_check_access_lock;
static std::thread property_service_thread;
static std::thread property_service_for_system_thread;

static std::unique_ptr<PersistWriteThread> persist_write_thread;

static PropertyInfoAreaFile property_info_area;

struct PropertyAuditData {
    const ucred* cr;
    const char* name;
};

static int PropertyAuditCallback(void* data, security_class_t /*cls*/, char* buf, size_t len) {
    auto* d = reinterpret_cast<PropertyAuditData*>(data);

    if (!d || !d->name || !d->cr) {
        LOG(ERROR) << "AuditCallback invoked with null data arguments!";
        return 0;
    }

    snprintf(buf, len, "property=%s pid=%d uid=%d gid=%d", d->name, d->cr->pid, d->cr->uid,
             d->cr->gid);
    return 0;
}

void StartSendingMessages() {
    auto lock = std::lock_guard{accept_messages_lock};
    accept_messages = true;
}

void StopSendingMessages() {
    auto lock = std::lock_guard{accept_messages_lock};
    accept_messages = false;
}

bool CanReadProperty(const std::string& source_context, const std::string& name) {
    const char* target_context = nullptr;
    property_info_area->GetPropertyInfo(name.c_str(), &target_context, nullptr);

    PropertyAuditData audit_data;

    audit_data.name = name.c_str();

    ucred cr = {.pid = 0, .uid = 0, .gid = 0};
    audit_data.cr = &cr;

    auto lock = std::lock_guard{selinux_check_access_lock};
    return selinux_check_access(source_context.c_str(), target_context, "file", "read",
                                &audit_data) == 0;
}

static bool CheckMacPerms(const std::string& name, const char* target_context,
                          const char* source_context, const ucred& cr) {
    if (!target_context || !source_context) {
        return false;
    }

    PropertyAuditData audit_data;

    audit_data.name = name.c_str();
    audit_data.cr = &cr;

    auto lock = std::lock_guard{selinux_check_access_lock};
    return selinux_check_access(source_context, target_context, "property_service", "set",
                                &audit_data) == 0;
}

void NotifyPropertyChange(const std::string& name, const std::string& value) {
    // If init hasn't started its main loop, then it won't be handling property changed messages
    // anyway, so there's no need to try to send them.
    auto lock = std::lock_guard{accept_messages_lock};
    if (accept_messages) {
        PropertyChanged(name, value);
    }
}

class AsyncRestorecon {
  public:
    void TriggerRestorecon(const std::string& path) {
        auto guard = std::lock_guard{mutex_};
        paths_.emplace(path);

        if (!thread_started_) {
            thread_started_ = true;
            std::thread{&AsyncRestorecon::ThreadFunction, this}.detach();
        }
    }

  private:
    void ThreadFunction() {
        auto lock = std::unique_lock{mutex_};

        while (!paths_.empty()) {
            auto path = paths_.front();
            paths_.pop();

            lock.unlock();
            if (selinux_android_restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE) != 0) {
                LOG(ERROR) << "Asynchronous restorecon of '" << path << "' failed'";
            }
            android::base::SetProperty(kRestoreconProperty, path);
            lock.lock();
        }

        thread_started_ = false;
    }

    std::mutex mutex_;
    std::queue<std::string> paths_;
    bool thread_started_ = false;
};

class SocketConnection {
  public:
    SocketConnection() = default;
    SocketConnection(int socket, const ucred& cred) : socket_(socket), cred_(cred) {}
    SocketConnection(SocketConnection&&) = default;

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
        if (!socket_.ok()) {
            return true;
        }
        int result = TEMP_FAILURE_RETRY(send(socket_.get(), &value, sizeof(value), 0));
        return result == sizeof(value);
    }

    bool GetSourceContext(std::string* source_context) const {
        char* c_source_context = nullptr;
        if (getpeercon(socket_.get(), &c_source_context) != 0) {
            return false;
        }
        *source_context = c_source_context;
        freecon(c_source_context);
        return true;
    }

    [[nodiscard]] int Release() { return socket_.release(); }

    const ucred& cred() { return cred_; }

    SocketConnection& operator=(SocketConnection&&) = default;

  private:
    bool PollIn(uint32_t* timeout_ms) {
        struct pollfd ufd = {
                .fd = socket_.get(),
                .events = POLLIN,
        };
        while (*timeout_ms > 0) {
            auto start_time = std::chrono::steady_clock::now();
            int nr = poll(&ufd, 1, *timeout_ms);
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

            int result = TEMP_FAILURE_RETRY(recv(socket_.get(), data, bytes_left, MSG_DONTWAIT));
            if (result <= 0) {
                PLOG(ERROR) << "sys_prop: recv error";
                return false;
            }

            bytes_left -= result;
            data += result;
        }

        if (bytes_left != 0) {
            LOG(ERROR) << "sys_prop: recv data is not properly obtained.";
        }

        return bytes_left == 0;
    }

    unique_fd socket_;
    ucred cred_;

    DISALLOW_COPY_AND_ASSIGN(SocketConnection);
};

class PersistWriteThread {
  public:
    PersistWriteThread();
    void Write(std::string name, std::string value, SocketConnection socket);

  private:
    void Work();

  private:
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::tuple<std::string, std::string, SocketConnection>> work_;
};

static std::optional<uint32_t> PropertySet(const std::string& name, const std::string& value,
                                           SocketConnection* socket, std::string* error) {
    size_t valuelen = value.size();

    if (!IsLegalPropertyName(name)) {
        *error = "Illegal property name";
        return {PROP_ERROR_INVALID_NAME};
    }

    if (auto result = IsLegalPropertyValue(name, value); !result.ok()) {
        *error = result.error().message();
        return {PROP_ERROR_INVALID_VALUE};
    }

    if (name == "sys.powerctl") {
        // No action here - NotifyPropertyChange will trigger the appropriate action, and since this
        // can come to the second thread, we mustn't call out to the __system_property_* functions
        // which support multiple readers but only one mutator.
    } else {
        prop_info* pi = (prop_info*)__system_property_find(name.c_str());
        if (pi != nullptr) {
            // ro.* properties are actually "write-once".
            if (StartsWith(name, "ro.")) {
                *error = "Read-only property was already set";
                return {PROP_ERROR_READ_ONLY_PROPERTY};
            }

            __system_property_update(pi, value.c_str(), valuelen);
        } else {
            int rc = __system_property_add(name.c_str(), name.size(), value.c_str(), valuelen);
            if (rc < 0) {
                *error = "__system_property_add failed";
                return {PROP_ERROR_SET_FAILED};
            }
        }

        // Don't write properties to disk until after we have read all default
        // properties to prevent them from being overwritten by default values.
        bool need_persist = StartsWith(name, "persist.") || StartsWith(name, "next_boot.");
        if (socket && persistent_properties_loaded && need_persist) {
            if (persist_write_thread) {
                persist_write_thread->Write(name, value, std::move(*socket));
                return {};
            }
            WritePersistentProperty(name, value);
        }
    }

    NotifyPropertyChange(name, value);
    return {PROP_SUCCESS};
}

// Helper for PropertySet, for the case where no socket is used, and therefore an asynchronous
// return is not possible.
static uint32_t PropertySetNoSocket(const std::string& name, const std::string& value,
                                    std::string* error) {
    auto ret = PropertySet(name, value, nullptr, error);
    CHECK(ret.has_value());
    return *ret;
}

static uint32_t SendControlMessage(const std::string& msg, const std::string& name, pid_t pid,
                                   SocketConnection* socket, std::string* error) {
    auto lock = std::lock_guard{accept_messages_lock};
    if (!accept_messages) {
        // If we're already shutting down and you're asking us to stop something,
        // just say we did (https://issuetracker.google.com/336223505).
        if (msg == "stop") return PROP_SUCCESS;

        *error = "Received control message after shutdown, ignoring";
        return PROP_ERROR_HANDLE_CONTROL_MESSAGE;
    }

    // We must release the fd before sending it to init, otherwise there will be a race with init.
    // If init calls close() before Release(), then fdsan will see the wrong tag and abort().
    int fd = -1;
    if (socket != nullptr && SelinuxGetVendorAndroidVersion() > __ANDROID_API_Q__) {
        fd = socket->Release();
    }

    bool queue_success = QueueControlMessage(msg, name, pid, fd);
    if (!queue_success && fd != -1) {
        uint32_t response = PROP_ERROR_HANDLE_CONTROL_MESSAGE;
        TEMP_FAILURE_RETRY(send(fd, &response, sizeof(response), 0));
        close(fd);
    }

    return PROP_SUCCESS;
}

bool CheckControlPropertyPerms(const std::string& name, const std::string& value,
                               const std::string& source_context, const ucred& cr) {
    // We check the legacy method first but these properties are dontaudit, so we only log an audit
    // if the newer method fails as well.  We only do this with the legacy ctl. properties.
    if (name == "ctl.start" || name == "ctl.stop" || name == "ctl.restart") {
        // The legacy permissions model is that ctl. properties have their name ctl.<action> and
        // their value is the name of the service to apply that action to.  Permissions for these
        // actions are based on the service, so we must create a fake name of ctl.<service> to
        // check permissions.
        auto control_string_legacy = "ctl." + value;
        const char* target_context_legacy = nullptr;
        const char* type_legacy = nullptr;
        property_info_area->GetPropertyInfo(control_string_legacy.c_str(), &target_context_legacy,
                                            &type_legacy);

        if (CheckMacPerms(control_string_legacy, target_context_legacy, source_context.c_str(), cr)) {
            return true;
        }
    }

    auto control_string_full = name + "$" + value;
    const char* target_context_full = nullptr;
    const char* type_full = nullptr;
    property_info_area->GetPropertyInfo(control_string_full.c_str(), &target_context_full,
                                        &type_full);

    return CheckMacPerms(control_string_full, target_context_full, source_context.c_str(), cr);
}

// This returns one of the enum of PROP_SUCCESS or PROP_ERROR*.
uint32_t CheckPermissions(const std::string& name, const std::string& value,
                          const std::string& source_context, const ucred& cr, std::string* error) {
    if (!IsLegalPropertyName(name)) {
        *error = "Illegal property name";
        return PROP_ERROR_INVALID_NAME;
    }

    if (StartsWith(name, "ctl.")) {
        if (!CheckControlPropertyPerms(name, value, source_context, cr)) {
            *error = StringPrintf("Invalid permissions to perform '%s' on '%s'", name.c_str() + 4,
                                  value.c_str());
            return PROP_ERROR_HANDLE_CONTROL_MESSAGE;
        }

        return PROP_SUCCESS;
    }

    const char* target_context = nullptr;
    const char* type = nullptr;
    property_info_area->GetPropertyInfo(name.c_str(), &target_context, &type);

    if (!CheckMacPerms(name, target_context, source_context.c_str(), cr)) {
        *error = "SELinux permission check failed";
        return PROP_ERROR_PERMISSION_DENIED;
    }

    if (!CheckType(type, value)) {
        *error = StringPrintf("Property type check failed, value doesn't match expected type '%s'",
                              (type ?: "(null)"));
        return PROP_ERROR_INVALID_VALUE;
    }

    return PROP_SUCCESS;
}

// This returns one of the enum of PROP_SUCCESS or PROP_ERROR*, or std::nullopt
// if asynchronous.
std::optional<uint32_t> HandlePropertySet(const std::string& name, const std::string& value,
                                          const std::string& source_context, const ucred& cr,
                                          SocketConnection* socket, std::string* error) {
    if (auto ret = CheckPermissions(name, value, source_context, cr, error); ret != PROP_SUCCESS) {
        return {ret};
    }

    if (StartsWith(name, "ctl.")) {
        return {SendControlMessage(name.c_str() + 4, value, cr.pid, socket, error)};
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
        if (value == "reboot,userspace") {
            *error = "Userspace reboot is deprecated.";
            return {PROP_ERROR_INVALID_VALUE};
        }
    }

    // If a process other than init is writing a non-empty value, it means that process is
    // requesting that init performs a restorecon operation on the path specified by 'value'.
    // We use a thread to do this restorecon operation to prevent holding up init, as it may take
    // a long time to complete.
    if (name == kRestoreconProperty && cr.pid != 1 && !value.empty()) {
        static AsyncRestorecon async_restorecon;
        async_restorecon.TriggerRestorecon(value);
        return {PROP_SUCCESS};
    }

    return PropertySet(name, value, socket, error);
}

// Helper for HandlePropertySet, for the case where no socket is used, and
// therefore an asynchronous return is not possible.
uint32_t HandlePropertySetNoSocket(const std::string& name, const std::string& value,
                                   const std::string& source_context, const ucred& cr,
                                   std::string* error) {
    auto ret = HandlePropertySet(name, value, source_context, cr, nullptr, error);
    CHECK(ret.has_value());
    return *ret;
}

static void handle_property_set_fd(int fd) {
    static constexpr uint32_t kDefaultSocketTimeout = 2000; /* ms */

    int s = accept4(fd, nullptr, nullptr, SOCK_CLOEXEC);
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

        std::string source_context;
        if (!socket.GetSourceContext(&source_context)) {
            PLOG(ERROR) << "Unable to set property '" << prop_name << "': getpeercon() failed";
            return;
        }

        const auto& cr = socket.cred();
        std::string error;
        auto result = HandlePropertySetNoSocket(prop_name, prop_value, source_context, cr, &error);
        if (result != PROP_SUCCESS) {
            LOG(ERROR) << "Unable to set property '" << prop_name << "' from uid:" << cr.uid
                       << " gid:" << cr.gid << " pid:" << cr.pid << ": " << error;
        }

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

        std::string source_context;
        if (!socket.GetSourceContext(&source_context)) {
            PLOG(ERROR) << "Unable to set property '" << name << "': getpeercon() failed";
            socket.SendUint32(PROP_ERROR_PERMISSION_DENIED);
            return;
        }

        // HandlePropertySet takes ownership of the socket if the set is handled asynchronously.
        const auto& cr = socket.cred();
        std::string error;
        auto result = HandlePropertySet(name, value, source_context, cr, &socket, &error);
        if (!result) {
            // Result will be sent after completion.
            return;
        }
        if (*result != PROP_SUCCESS) {
            LOG(ERROR) << "Unable to set property '" << name << "' from uid:" << cr.uid
                       << " gid:" << cr.gid << " pid:" << cr.pid << ": " << error;
        }
        socket.SendUint32(*result);
        break;
      }

    default:
        LOG(ERROR) << "sys_prop: invalid command " << cmd;
        socket.SendUint32(PROP_ERROR_INVALID_CMD);
        break;
    }
}

uint32_t InitPropertySet(const std::string& name, const std::string& value) {
    ucred cr = {.pid = 1, .uid = 0, .gid = 0};
    std::string error;
    auto result = HandlePropertySetNoSocket(name, value, kInitContext, cr, &error);
    if (result != PROP_SUCCESS) {
        LOG(ERROR) << "Init cannot set '" << name << "' to '" << value << "': " << error;
    }

    return result;
}

static Result<void> load_properties_from_file(const char*, const char*,
                                              std::map<std::string, std::string>*);

/*
 * Filter is used to decide which properties to load: NULL loads all keys,
 * "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
 */
static void LoadProperties(char* data, const char* filter, const char* filename,
                           std::map<std::string, std::string>* properties) {
    char *key, *value, *eol, *sol, *tmp, *fn;
    size_t flen = 0;

    static constexpr const char* const kVendorPathPrefixes[4] = {
            "/vendor",
            "/odm",
            "/vendor_dlkm",
            "/odm_dlkm",
    };

    const char* context = kInitContext;
    if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_P__) {
        for (const auto& vendor_path_prefix : kVendorPathPrefixes) {
            if (StartsWith(filename, vendor_path_prefix)) {
                context = kVendorContext;
            }
        }
    }

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

            std::string raw_filename(fn);
            auto expanded_filename = ExpandProps(raw_filename);

            if (!expanded_filename.ok()) {
                LOG(ERROR) << "Could not expand filename ': " << expanded_filename.error();
                continue;
            }

            if (auto res = load_properties_from_file(expanded_filename->c_str(), key, properties);
                !res.ok()) {
                LOG(WARNING) << res.error();
            }
        } else {
            value = strchr(key, '=');
            if (!value) continue;
            *value++ = 0;

            tmp = value - 2;
            while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

            while (isspace(*value)) value++;

            if (flen > 0) {
                if (filter[flen - 1] == '*') {
                    if (strncmp(key, filter, flen - 1) != 0) continue;
                } else {
                    if (strcmp(key, filter) != 0) continue;
                }
            }

            if (StartsWith(key, "ctl.") || key == "sys.powerctl"s ||
                std::string{key} == kRestoreconProperty) {
                LOG(ERROR) << "Ignoring disallowed property '" << key
                           << "' with special meaning in prop file '" << filename << "'";
                continue;
            }

            ucred cr = {.pid = 1, .uid = 0, .gid = 0};
            std::string error;
            if (CheckPermissions(key, value, context, cr, &error) == PROP_SUCCESS) {
                auto it = properties->find(key);
                if (it == properties->end()) {
                    (*properties)[key] = value;
                } else if (it->second != value) {
                    LOG(WARNING) << "Overriding previous property '" << key << "':'" << it->second
                                 << "' with new value '" << value << "'";
                    it->second = value;
                }
            } else {
                LOG(ERROR) << "Do not have permissions to set '" << key << "' to '" << value
                           << "' in property file '" << filename << "': " << error;
            }
        }
    }
}

// Filter is used to decide which properties to load: NULL loads all keys,
// "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
static Result<void> load_properties_from_file(const char* filename, const char* filter,
                                              std::map<std::string, std::string>* properties) {
    Timer t;
    auto file_contents = ReadFile(filename);
    if (!file_contents.ok()) {
        return Error() << "Couldn't load property file '" << filename
                       << "': " << file_contents.error();
    }
    file_contents->push_back('\n');

    LoadProperties(file_contents->data(), filter, filename, properties);
    LOG(VERBOSE) << "(Loading properties from " << filename << " took " << t << ".)";
    return {};
}

static void LoadPropertiesFromSecondStageRes(std::map<std::string, std::string>* properties) {
    std::string prop = GetRamdiskPropForSecondStage();
    if (access(prop.c_str(), R_OK) != 0) {
        CHECK(errno == ENOENT) << "Cannot access " << prop << ": " << strerror(errno);
        return;
    }
    if (auto res = load_properties_from_file(prop.c_str(), nullptr, properties); !res.ok()) {
        LOG(WARNING) << res.error();
    }
}

// persist.sys.usb.config values can't be combined on build-time when property
// files are split into each partition.
// So we need to apply the same rule of build/make/tools/post_process_props.py
// on runtime.
static void update_sys_usb_config() {
    bool is_debuggable = android::base::GetBoolProperty("ro.debuggable", false);
    std::string config = android::base::GetProperty("persist.sys.usb.config", "");
    // b/150130503, add (config == "none") condition here to prevent appending
    // ",adb" if "none" is explicitly defined in default prop.
    if (config.empty() || config == "none") {
        InitPropertySet("persist.sys.usb.config", is_debuggable ? "adb" : "none");
    } else if (is_debuggable && config.find("adb") == std::string::npos &&
               config.length() + 4 < PROP_VALUE_MAX) {
        config.append(",adb");
        InitPropertySet("persist.sys.usb.config", config);
    }
}

static void load_override_properties() {
    if (ALLOW_LOCAL_PROP_OVERRIDE) {
        std::map<std::string, std::string> properties;
        load_properties_from_file("/data/local.prop", nullptr, &properties);
        for (const auto& [name, value] : properties) {
            std::string error;
            if (PropertySetNoSocket(name, value, &error) != PROP_SUCCESS) {
                LOG(ERROR) << "Could not set '" << name << "' to '" << value
                           << "' in /data/local.prop: " << error;
            }
        }
    }
}

// If the ro.product.[brand|device|manufacturer|model|name] properties have not been explicitly
// set, derive them from ro.product.${partition}.* properties
static void property_initialize_ro_product_props() {
    const char* RO_PRODUCT_PROPS_PREFIX = "ro.product.";
    const char* RO_PRODUCT_PROPS[] = {
            "brand", "device", "manufacturer", "model", "name",
    };
    const char* RO_PRODUCT_PROPS_ALLOWED_SOURCES[] = {
            "odm", "product", "system_ext", "system", "vendor",
    };
    const char* RO_PRODUCT_PROPS_DEFAULT_SOURCE_ORDER = "product,odm,vendor,system_ext,system";
    const std::string EMPTY = "";

    std::string ro_product_props_source_order =
            GetProperty("ro.product.property_source_order", EMPTY);

    if (!ro_product_props_source_order.empty()) {
        // Verify that all specified sources are valid
        for (const auto& source : Split(ro_product_props_source_order, ",")) {
            // Verify that the specified source is valid
            bool is_allowed_source = false;
            for (const auto& allowed_source : RO_PRODUCT_PROPS_ALLOWED_SOURCES) {
                if (source == allowed_source) {
                    is_allowed_source = true;
                    break;
                }
            }
            if (!is_allowed_source) {
                LOG(ERROR) << "Found unexpected source in ro.product.property_source_order; "
                              "using the default property source order";
                ro_product_props_source_order = RO_PRODUCT_PROPS_DEFAULT_SOURCE_ORDER;
                break;
            }
        }
    } else {
        ro_product_props_source_order = RO_PRODUCT_PROPS_DEFAULT_SOURCE_ORDER;
    }

    for (const auto& ro_product_prop : RO_PRODUCT_PROPS) {
        std::string base_prop(RO_PRODUCT_PROPS_PREFIX);
        base_prop += ro_product_prop;

        std::string base_prop_val = GetProperty(base_prop, EMPTY);
        if (!base_prop_val.empty()) {
            continue;
        }

        for (const auto& source : Split(ro_product_props_source_order, ",")) {
            std::string target_prop(RO_PRODUCT_PROPS_PREFIX);
            target_prop += source;
            target_prop += '.';
            target_prop += ro_product_prop;

            std::string target_prop_val = GetProperty(target_prop, EMPTY);
            if (!target_prop_val.empty()) {
                LOG(INFO) << "Setting product property " << base_prop << " to '" << target_prop_val
                          << "' (from " << target_prop << ")";
                std::string error;
                auto res = PropertySetNoSocket(base_prop, target_prop_val, &error);
                if (res != PROP_SUCCESS) {
                    LOG(ERROR) << "Error setting product property " << base_prop << ": err=" << res
                               << " (" << error << ")";
                }
                break;
            }
        }
    }
}

static void property_initialize_build_id() {
    std::string build_id = GetProperty(ID_PROP, "");
    if (!build_id.empty()) {
        return;
    }

    std::string legacy_build_id = GetProperty(LEGACY_ID_PROP, "");
    std::string vbmeta_digest = GetProperty(VBMETA_DIGEST_PROP, "");
    if (vbmeta_digest.size() < DIGEST_SIZE_USED) {
        LOG(ERROR) << "vbmeta digest size too small " << vbmeta_digest;
        // Still try to set the id field in the unexpected case.
        build_id = legacy_build_id;
    } else {
        // Derive the ro.build.id by appending the vbmeta digest to the base value.
        build_id = legacy_build_id + "." + vbmeta_digest.substr(0, DIGEST_SIZE_USED);
    }

    std::string error;
    auto res = PropertySetNoSocket(ID_PROP, build_id, &error);
    if (res != PROP_SUCCESS) {
        LOG(ERROR) << "Failed to set " << ID_PROP << " to " << build_id;
    }
}

static std::string ConstructBuildFingerprint(bool legacy) {
    const std::string UNKNOWN = "unknown";
    std::string build_fingerprint = GetProperty("ro.product.brand", UNKNOWN);
    build_fingerprint += '/';
    build_fingerprint += GetProperty("ro.product.name", UNKNOWN);

    // should be set in /product/etc/build.prop
    // when we have a dev option device, and we've switched the kernel to 16kb mode
    // we use the same system image, but we've switched out the kernel, so make it
    // visible at a high level
    bool has16KbDevOption =
            android::base::GetBoolProperty("ro.product.build.16k_page.enabled", false);
    if (has16KbDevOption && getpagesize() == 16384) {
        build_fingerprint += "_16kb";
    }

    build_fingerprint += '/';
    build_fingerprint += GetProperty("ro.product.device", UNKNOWN);
    build_fingerprint += ':';
    build_fingerprint += GetProperty("ro.build.version.release_or_codename", UNKNOWN);
    build_fingerprint += '/';

    std::string build_id =
            legacy ? GetProperty(LEGACY_ID_PROP, UNKNOWN) : GetProperty(ID_PROP, UNKNOWN);
    build_fingerprint += build_id;
    build_fingerprint += '/';
    build_fingerprint += GetProperty("ro.build.version.incremental", UNKNOWN);
    build_fingerprint += ':';
    build_fingerprint += GetProperty("ro.build.type", UNKNOWN);
    build_fingerprint += '/';
    build_fingerprint += GetProperty("ro.build.tags", UNKNOWN);

    return build_fingerprint;
}

// Derive the legacy build fingerprint if we overwrite the build id at runtime.
static void property_derive_legacy_build_fingerprint() {
    std::string legacy_build_fingerprint = GetProperty(LEGACY_FINGERPRINT_PROP, "");
    if (!legacy_build_fingerprint.empty()) {
        return;
    }

    // The device doesn't have a legacy build id, skipping the legacy fingerprint.
    std::string legacy_build_id = GetProperty(LEGACY_ID_PROP, "");
    if (legacy_build_id.empty()) {
        return;
    }

    legacy_build_fingerprint = ConstructBuildFingerprint(true /* legacy fingerprint */);
    LOG(INFO) << "Setting property '" << LEGACY_FINGERPRINT_PROP << "' to '"
              << legacy_build_fingerprint << "'";

    std::string error;
    auto res = PropertySetNoSocket(LEGACY_FINGERPRINT_PROP, legacy_build_fingerprint, &error);
    if (res != PROP_SUCCESS) {
        LOG(ERROR) << "Error setting property '" << LEGACY_FINGERPRINT_PROP << "': err=" << res
                   << " (" << error << ")";
    }
}

// If the ro.build.fingerprint property has not been set, derive it from constituent pieces
static void property_derive_build_fingerprint() {
    std::string build_fingerprint = GetProperty("ro.build.fingerprint", "");
    if (!build_fingerprint.empty()) {
        return;
    }

    build_fingerprint = ConstructBuildFingerprint(false /* legacy fingerprint */);
    LOG(INFO) << "Setting property '" << FINGERPRINT_PROP << "' to '" << build_fingerprint << "'";

    std::string error;
    auto res = PropertySetNoSocket(FINGERPRINT_PROP, build_fingerprint, &error);
    if (res != PROP_SUCCESS) {
        LOG(ERROR) << "Error setting property '" << FINGERPRINT_PROP << "': err=" << res << " ("
                   << error << ")";
    }
}

// If the ro.product.cpu.abilist* properties have not been explicitly
// set, derive them from ro.${partition}.product.cpu.abilist* properties.
static void property_initialize_ro_cpu_abilist() {
    // From high to low priority.
    const char* kAbilistSources[] = {
            "product",
            "odm",
            "vendor",
            "system",
    };
    const std::string EMPTY = "";
    const char* kAbilistProp = "ro.product.cpu.abilist";
    const char* kAbilist32Prop = "ro.product.cpu.abilist32";
    const char* kAbilist64Prop = "ro.product.cpu.abilist64";

    // If the properties are defined explicitly, just use them.
    if (GetProperty(kAbilistProp, EMPTY) != EMPTY) {
        return;
    }

    // Find the first source defining these properties by order.
    std::string abilist32_prop_val;
    std::string abilist64_prop_val;
    for (const auto& source : kAbilistSources) {
        const auto abilist32_prop = std::string("ro.") + source + ".product.cpu.abilist32";
        const auto abilist64_prop = std::string("ro.") + source + ".product.cpu.abilist64";
        abilist32_prop_val = GetProperty(abilist32_prop, EMPTY);
        abilist64_prop_val = GetProperty(abilist64_prop, EMPTY);
        // The properties could be empty on 32-bit-only or 64-bit-only devices,
        // but we cannot identify a property is empty or undefined by GetProperty().
        // So, we assume both of these 2 properties are empty as undefined.
        if (abilist32_prop_val != EMPTY || abilist64_prop_val != EMPTY) {
            break;
        }
    }

    // Merge ABI lists for ro.product.cpu.abilist
    auto abilist_prop_val = abilist64_prop_val;
    if (abilist32_prop_val != EMPTY) {
        if (abilist_prop_val != EMPTY) {
            abilist_prop_val += ",";
        }
        abilist_prop_val += abilist32_prop_val;
    }

    // Set these properties
    const std::pair<const char*, const std::string&> set_prop_list[] = {
            {kAbilistProp, abilist_prop_val},
            {kAbilist32Prop, abilist32_prop_val},
            {kAbilist64Prop, abilist64_prop_val},
    };
    for (const auto& [prop, prop_val] : set_prop_list) {
        LOG(INFO) << "Setting property '" << prop << "' to '" << prop_val << "'";

        std::string error;
        auto res = PropertySetNoSocket(prop, prop_val, &error);
        if (res != PROP_SUCCESS) {
            LOG(ERROR) << "Error setting property '" << prop << "': err=" << res << " (" << error
                       << ")";
        }
    }
}

static void property_initialize_ro_vendor_api_level() {
    // ro.vendor.api_level shows the api_level that the vendor images (vendor, odm, ...) are
    // required to support.
    constexpr auto VENDOR_API_LEVEL_PROP = "ro.vendor.api_level";

    if (__system_property_find(VENDOR_API_LEVEL_PROP) != nullptr) {
        // The device already have ro.vendor.api_level in its vendor/build.prop.
        // Skip initializing the ro.vendor.api_level property.
        return;
    }

    auto vendor_api_level = GetIntProperty("ro.board.first_api_level", __ANDROID_VENDOR_API_MAX__);
    if (vendor_api_level != __ANDROID_VENDOR_API_MAX__) {
        // Update the vendor_api_level with "ro.board.api_level" only if both "ro.board.api_level"
        // and "ro.board.first_api_level" are defined.
        vendor_api_level = GetIntProperty("ro.board.api_level", vendor_api_level);
    }

    auto product_first_api_level =
            GetIntProperty("ro.product.first_api_level", __ANDROID_API_FUTURE__);
    if (product_first_api_level == __ANDROID_API_FUTURE__) {
        // Fallback to "ro.build.version.sdk" if the "ro.product.first_api_level" is not defined.
        product_first_api_level = GetIntProperty("ro.build.version.sdk", __ANDROID_API_FUTURE__);
    }

    vendor_api_level =
            std::min(AVendorSupport_getVendorApiLevelOf(product_first_api_level), vendor_api_level);

    if (vendor_api_level < 0) {
        LOG(ERROR) << "Unexpected vendor api level for " << VENDOR_API_LEVEL_PROP << ". Check "
                   << "ro.product.first_api_level and ro.build.version.sdk.";
        vendor_api_level = __ANDROID_VENDOR_API_MAX__;
    }

    std::string error;
    auto res = PropertySetNoSocket(VENDOR_API_LEVEL_PROP, std::to_string(vendor_api_level), &error);
    if (res != PROP_SUCCESS) {
        LOG(ERROR) << "Failed to set " << VENDOR_API_LEVEL_PROP << " with " << vendor_api_level
                   << ": " << error << "(" << res << ")";
    }
}

void PropertyLoadBootDefaults() {
    // We read the properties and their values into a map, in order to always allow properties
    // loaded in the later property files to override the properties in loaded in the earlier
    // property files, regardless of if they are "ro." properties or not.
    std::map<std::string, std::string> properties;

    if (IsRecoveryMode()) {
        if (auto res = load_properties_from_file("/prop.default", nullptr, &properties);
            !res.ok()) {
            LOG(ERROR) << res.error();
        }
    }

    // /<part>/etc/build.prop is the canonical location of the build-time properties since S.
    // Falling back to /<part>/defalt.prop and /<part>/build.prop only when legacy path has to
    // be supported, which is controlled by the support_legacy_path_until argument.
    const auto load_properties_from_partition = [&properties](const std::string& partition,
                                                              int support_legacy_path_until) {
        auto path = "/" + partition + "/etc/build.prop";
        if (load_properties_from_file(path.c_str(), nullptr, &properties).ok()) {
            return;
        }
        // To read ro.<partition>.build.version.sdk, temporarily load the legacy paths into a
        // separate map. Then by comparing its value with legacy_version, we know that if the
        // partition is old enough so that we need to respect the legacy paths.
        std::map<std::string, std::string> temp;
        auto legacy_path1 = "/" + partition + "/default.prop";
        auto legacy_path2 = "/" + partition + "/build.prop";
        load_properties_from_file(legacy_path1.c_str(), nullptr, &temp);
        load_properties_from_file(legacy_path2.c_str(), nullptr, &temp);
        bool support_legacy_path = false;
        auto version_prop_name = "ro." + partition + ".build.version.sdk";
        auto it = temp.find(version_prop_name);
        if (it == temp.end()) {
            // This is embarassing. Without the prop, we can't determine how old the partition is.
            // Let's be conservative by assuming it is very very old.
            support_legacy_path = true;
        } else if (int value;
                   ParseInt(it->second.c_str(), &value) && value <= support_legacy_path_until) {
            support_legacy_path = true;
        }
        if (support_legacy_path) {
            // We don't update temp into properties directly as it might skip any (future) logic
            // for resolving duplicates implemented in load_properties_from_file.  Instead, read
            // the files again into the properties map.
            load_properties_from_file(legacy_path1.c_str(), nullptr, &properties);
            load_properties_from_file(legacy_path2.c_str(), nullptr, &properties);
        } else {
            LOG(FATAL) << legacy_path1 << " and " << legacy_path2 << " were not loaded "
                       << "because " << version_prop_name << "(" << it->second << ") is newer "
                       << "than " << support_legacy_path_until;
        }
    };

    // Order matters here. The more the partition is specific to a product, the higher its
    // precedence is.
    LoadPropertiesFromSecondStageRes(&properties);

    // system should have build.prop, unlike the other partitions
    if (auto res = load_properties_from_file("/system/build.prop", nullptr, &properties);
        !res.ok()) {
        LOG(WARNING) << res.error();
    }

    load_properties_from_partition("system_ext", /* support_legacy_path_until */ 30);
    load_properties_from_file("/system_dlkm/etc/build.prop", nullptr, &properties);
    // TODO(b/117892318): uncomment the following condition when vendor.imgs for aosp_* targets are
    // all updated.
    // if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_R__) {
    load_properties_from_file("/vendor/default.prop", nullptr, &properties);
    // }
    load_properties_from_file("/vendor/build.prop", nullptr, &properties);
    load_properties_from_file("/vendor_dlkm/etc/build.prop", nullptr, &properties);
    load_properties_from_file("/odm_dlkm/etc/build.prop", nullptr, &properties);
    load_properties_from_partition("odm", /* support_legacy_path_until */ 28);
    load_properties_from_partition("product", /* support_legacy_path_until */ 30);

    if (access(kDebugRamdiskProp, R_OK) == 0) {
        LOG(INFO) << "Loading " << kDebugRamdiskProp;
        if (auto res = load_properties_from_file(kDebugRamdiskProp, nullptr, &properties);
            !res.ok()) {
            LOG(WARNING) << res.error();
        }
    }

    for (const auto& [name, value] : properties) {
        std::string error;
        if (PropertySetNoSocket(name, value, &error) != PROP_SUCCESS) {
            LOG(ERROR) << "Could not set '" << name << "' to '" << value
                       << "' while loading .prop files" << error;
        }
    }

    property_initialize_ro_product_props();
    property_initialize_build_id();
    property_derive_build_fingerprint();
    property_derive_legacy_build_fingerprint();
    property_initialize_ro_cpu_abilist();
    property_initialize_ro_vendor_api_level();

    update_sys_usb_config();
}

void PropertyLoadDerivedDefaults() {
    const char* PAGE_PROP = "ro.boot.hardware.cpu.pagesize";
    if (GetProperty(PAGE_PROP, "").empty()) {
        std::string error;
        if (PropertySetNoSocket(PAGE_PROP, std::to_string(getpagesize()), &error) != PROP_SUCCESS) {
            LOG(ERROR) << "Could not set '" << PAGE_PROP << "' because: " << error;
        }
    }
}

bool LoadPropertyInfoFromFile(const std::string& filename,
                              std::vector<PropertyInfoEntry>* property_infos) {
    auto file_contents = std::string();
    if (!ReadFileToString(filename, &file_contents)) {
        PLOG(ERROR) << "Could not read properties from '" << filename << "'";
        return false;
    }

    auto errors = std::vector<std::string>{};
    bool require_prefix_or_exact = SelinuxGetVendorAndroidVersion() >= __ANDROID_API_R__;
    ParsePropertyInfoFile(file_contents, require_prefix_or_exact, property_infos, &errors);
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
        // Don't check for failure here, since we don't always have all of these partitions.
        // E.g. In case of recovery, the vendor partition will not have mounted and we
        // still need the system / platform properties to function.
        if (access("/system_ext/etc/selinux/system_ext_property_contexts", R_OK) != -1) {
            LoadPropertyInfoFromFile("/system_ext/etc/selinux/system_ext_property_contexts",
                                     &property_infos);
        }
        if (access("/vendor/etc/selinux/vendor_property_contexts", R_OK) != -1) {
            LoadPropertyInfoFromFile("/vendor/etc/selinux/vendor_property_contexts",
                                     &property_infos);
        }
        if (access("/product/etc/selinux/product_property_contexts", R_OK) != -1) {
            LoadPropertyInfoFromFile("/product/etc/selinux/product_property_contexts",
                                     &property_infos);
        }
        if (access("/odm/etc/selinux/odm_property_contexts", R_OK) != -1) {
            LoadPropertyInfoFromFile("/odm/etc/selinux/odm_property_contexts", &property_infos);
        }
    } else {
        if (!LoadPropertyInfoFromFile("/plat_property_contexts", &property_infos)) {
            return;
        }
        LoadPropertyInfoFromFile("/system_ext_property_contexts", &property_infos);
        LoadPropertyInfoFromFile("/vendor_property_contexts", &property_infos);
        LoadPropertyInfoFromFile("/product_property_contexts", &property_infos);
        LoadPropertyInfoFromFile("/odm_property_contexts", &property_infos);
    }

    auto serialized_contexts = std::string();
    auto error = std::string();
    if (!BuildTrie(property_infos, "u:object_r:default_prop:s0", "string", &serialized_contexts,
                   &error)) {
        LOG(ERROR) << "Unable to serialize property contexts: " << error;
        return;
    }

    if (!WriteStringToFile(serialized_contexts, PROP_TREE_FILE, 0444, 0, 0, false)) {
        PLOG(ERROR) << "Unable to write serialized property infos to file";
    }
    selinux_android_restorecon(PROP_TREE_FILE, 0);

#ifdef WRITE_APPCOMPAT_OVERRIDE_SYSTEM_PROPERTIES
    mkdir(APPCOMPAT_OVERRIDE_PROP_FOLDERNAME, S_IRWXU | S_IXGRP | S_IXOTH);
    if (!WriteStringToFile(serialized_contexts, APPCOMPAT_OVERRIDE_PROP_TREE_FILE, 0444, 0, 0,
                           false)) {
        PLOG(ERROR) << "Unable to write appcompat override property infos to file";
    }
    selinux_android_restorecon(APPCOMPAT_OVERRIDE_PROP_TREE_FILE, 0);
#endif
}

static void ExportKernelBootProps() {
    constexpr const char* UNSET = "";
    struct {
        const char* src_prop;
        const char* dst_prop;
        const char* default_value;
    } prop_map[] = {
            // clang-format off
        { "ro.boot.serialno",   "ro.serialno",   UNSET, },
        { "ro.boot.mode",       "ro.bootmode",   "unknown", },
        { "ro.boot.baseband",   "ro.baseband",   "unknown", },
        { "ro.boot.bootloader", "ro.bootloader", "unknown", },
        { "ro.boot.hardware",   "ro.hardware",   "unknown", },
        { "ro.boot.revision",   "ro.revision",   "0", },
            // clang-format on
    };
    for (const auto& prop : prop_map) {
        std::string value = GetProperty(prop.src_prop, prop.default_value);
        if (value != UNSET) InitPropertySet(prop.dst_prop, value);
    }
}

static void ProcessKernelDt() {
    if (!is_android_dt_value_expected("compatible", "android,firmware")) {
        return;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(android::fs_mgr::GetAndroidDtDir().c_str()),
                                            closedir);
    if (!dir) return;

    std::string dt_file;
    struct dirent* dp;
    while ((dp = readdir(dir.get())) != NULL) {
        if (dp->d_type != DT_REG || !strcmp(dp->d_name, "compatible") ||
            !strcmp(dp->d_name, "name")) {
            continue;
        }

        std::string file_name = android::fs_mgr::GetAndroidDtDir() + dp->d_name;

        android::base::ReadFileToString(file_name, &dt_file);
        std::replace(dt_file.begin(), dt_file.end(), ',', '.');

        InitPropertySet("ro.boot."s + dp->d_name, dt_file);
    }
}

constexpr auto ANDROIDBOOT_PREFIX = "androidboot."sv;

static void ProcessKernelCmdline() {
    android::fs_mgr::ImportKernelCmdline([&](const std::string& key, const std::string& value) {
        if (StartsWith(key, ANDROIDBOOT_PREFIX)) {
            InitPropertySet("ro.boot." + key.substr(ANDROIDBOOT_PREFIX.size()), value);
        }
    });
}


static void ProcessBootconfig() {
    android::fs_mgr::ImportBootconfig([&](const std::string& key, const std::string& value) {
        if (StartsWith(key, ANDROIDBOOT_PREFIX)) {
            InitPropertySet("ro.boot." + key.substr(ANDROIDBOOT_PREFIX.size()), value);
        }
    });
}

void PropertyInit() {
    selinux_callback cb;
    cb.func_audit = PropertyAuditCallback;
    selinux_set_callback(SELINUX_CB_AUDIT, cb);

    mkdir("/dev/__properties__", S_IRWXU | S_IXGRP | S_IXOTH);
    CreateSerializedPropertyInfo();
    if (__system_property_area_init()) {
        LOG(FATAL) << "Failed to initialize property area";
    }
    if (!property_info_area.LoadDefaultPath()) {
        LOG(FATAL) << "Failed to load serialized property info file";
    }

    // If arguments are passed both on the command line and in DT,
    // properties set in DT always have priority over the command-line ones.
    ProcessKernelDt();
    ProcessKernelCmdline();
    ProcessBootconfig();

    // Propagate the kernel variables to internal variables
    // used by init as well as the current required properties.
    ExportKernelBootProps();

    PropertyLoadBootDefaults();
    PropertyLoadDerivedDefaults();
}

static void HandleInitSocket() {
    auto message = ReadMessage(init_socket);
    if (!message.ok()) {
        LOG(ERROR) << "Could not read message from init_dedicated_recv_socket: " << message.error();
        return;
    }

    auto init_message = InitMessage{};
    if (!init_message.ParseFromString(*message)) {
        LOG(ERROR) << "Could not parse message from init";
        return;
    }

    switch (init_message.msg_case()) {
        case InitMessage::kLoadPersistentProperties: {
            load_override_properties();

            auto persistent_properties = LoadPersistentProperties();
            for (const auto& property_record : persistent_properties.properties()) {
                auto const& prop_name = property_record.name();
                auto const& prop_value = property_record.value();
                InitPropertySet(prop_name, prop_value);
            }

            // Apply debug ramdisk special settings after persistent properties are loaded.
            if (android::base::GetBoolProperty("ro.force.debuggable", false)) {
                // Always enable usb adb if device is booted with debug ramdisk.
                update_sys_usb_config();
            }
            InitPropertySet("ro.persistent_properties.ready", "true");
            persistent_properties_loaded = true;
            break;
        }
        default:
            LOG(ERROR) << "Unknown message type from init: " << init_message.msg_case();
    }
}

static void PropertyServiceThread(int fd, bool listen_init) {
    Epoll epoll;
    if (auto result = epoll.Open(); !result.ok()) {
        LOG(FATAL) << result.error();
    }

    if (auto result = epoll.RegisterHandler(fd, std::bind(handle_property_set_fd, fd));
        !result.ok()) {
        LOG(FATAL) << result.error();
    }

    if (listen_init) {
        if (auto result = epoll.RegisterHandler(init_socket, HandleInitSocket); !result.ok()) {
            LOG(FATAL) << result.error();
        }
    }

    while (true) {
        auto epoll_result = epoll.Wait(std::nullopt);
        if (!epoll_result.ok()) {
            LOG(ERROR) << epoll_result.error();
        }
    }
}

PersistWriteThread::PersistWriteThread() {
    auto new_thread = std::thread([this]() -> void { Work(); });
    thread_.swap(new_thread);
}

void PersistWriteThread::Work() {
    while (true) {
        std::tuple<std::string, std::string, SocketConnection> item;

        // Grab the next item within the lock.
        {
            std::unique_lock<std::mutex> lock(mutex_);

            while (work_.empty()) {
                cv_.wait(lock);
            }

            item = std::move(work_.front());
            work_.pop_front();
        }

        // Perform write/fsync outside the lock.
        WritePersistentProperty(std::get<0>(item), std::get<1>(item));
        NotifyPropertyChange(std::get<0>(item), std::get<1>(item));

        SocketConnection& socket = std::get<2>(item);
        socket.SendUint32(PROP_SUCCESS);
    }
}

void PersistWriteThread::Write(std::string name, std::string value, SocketConnection socket) {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        work_.emplace_back(std::move(name), std::move(value), std::move(socket));
    }
    cv_.notify_all();
}

void StartThread(const char* name, int mode, int gid, std::thread& t, bool listen_init) {
    int fd = -1;
    if (auto result = CreateSocket(name, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                   /*passcred=*/false, /*should_listen=*/false, mode, /*uid=*/0,
                                   /*gid=*/gid, /*socketcon=*/{});
        result.ok()) {
        fd = *result;
    } else {
        LOG(FATAL) << "start_property_service socket creation failed: " << result.error();
    }

    listen(fd, 8);

    auto new_thread = std::thread(PropertyServiceThread, fd, listen_init);
    t.swap(new_thread);
}

void StartPropertyService(int* epoll_socket) {
    InitPropertySet("ro.property_service.version", "2");

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0) {
        PLOG(FATAL) << "Failed to socketpair() between property_service and init";
    }
    *epoll_socket = from_init_socket = sockets[0];
    init_socket = sockets[1];
    StartSendingMessages();

    StartThread(PROP_SERVICE_FOR_SYSTEM_NAME, 0660, AID_SYSTEM, property_service_for_system_thread,
                true);
    StartThread(PROP_SERVICE_NAME, 0666, 0, property_service_thread, false);

    auto async_persist_writes =
            android::base::GetBoolProperty("ro.property_service.async_persist_writes", false);

    if (async_persist_writes) {
        persist_write_thread = std::make_unique<PersistWriteThread>();
    }
}

}  // namespace init
}  // namespace android
