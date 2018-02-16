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

#define TRACE_TAG TRANSPORT

#include "sysdeps.h"
#include "transport.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <deque>
#include <list>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>

#include <diagnose_usb.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_utils.h"
#include "fdevent.h"

static void transport_unref(atransport *t);

// TODO: unordered_map<TransportId, atransport*>
static auto& transport_list = *new std::list<atransport*>();
static auto& pending_list = *new std::list<atransport*>();

static auto& transport_lock = *new std::recursive_mutex();

const char* const kFeatureShell2 = "shell_v2";
const char* const kFeatureCmd = "cmd";
const char* const kFeatureStat2 = "stat_v2";
const char* const kFeatureLibusb = "libusb";
const char* const kFeaturePushSync = "push_sync";

TransportId NextTransportId() {
    static std::atomic<TransportId> next(1);
    return next++;
}

BlockingConnectionAdapter::BlockingConnectionAdapter(std::unique_ptr<BlockingConnection> connection)
    : underlying_(std::move(connection)) {}

BlockingConnectionAdapter::~BlockingConnectionAdapter() {
    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): destructing";
    Stop();
}

void BlockingConnectionAdapter::Start() {
    read_thread_ = std::thread([this]() {
        LOG(INFO) << this->transport_name_ << ": read thread spawning";
        while (true) {
            std::unique_ptr<apacket> packet(new apacket());
            if (!underlying_->Read(packet.get())) {
                PLOG(INFO) << this->transport_name_ << ": read failed";
                break;
            }
            read_callback_(this, std::move(packet));
        }
        std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "read failed"); });
    });

    write_thread_ = std::thread([this]() {
        LOG(INFO) << this->transport_name_ << ": write thread spawning";
        while (true) {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this]() { return this->stopped_ || !this->write_queue_.empty(); });

            if (this->stopped_) {
                return;
            }

            std::unique_ptr<apacket> packet = std::move(this->write_queue_.front());
            this->write_queue_.pop_front();
            lock.unlock();

            if (!this->underlying_->Write(packet.get())) {
                break;
            }
        }
        std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "write failed"); });
    });
}

void BlockingConnectionAdapter::Stop() {
    std::unique_lock<std::mutex> lock(mutex_);
    if (stopped_) {
        LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): already stopped";
        return;
    }

    stopped_ = true;
    lock.unlock();

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopping";

    this->underlying_->Close();

    this->cv_.notify_one();
    read_thread_.join();
    write_thread_.join();

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopped";
    std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "requested stop"); });
}

bool BlockingConnectionAdapter::Write(std::unique_ptr<apacket> packet) {
    {
        std::unique_lock<std::mutex> lock(this->mutex_);
        write_queue_.emplace_back(std::move(packet));
    }

    cv_.notify_one();
    return true;
}

bool FdConnection::Read(apacket* packet) {
    if (!ReadFdExactly(fd_.get(), &packet->msg, sizeof(amessage))) {
        D("remote local: read terminated (message)");
        return false;
    }

    if (packet->msg.data_length > MAX_PAYLOAD) {
        D("remote local: read overflow (data length = %" PRIu32 ")", packet->msg.data_length);
        return false;
    }

    packet->payload.resize(packet->msg.data_length);

    if (!ReadFdExactly(fd_.get(), &packet->payload[0], packet->payload.size())) {
        D("remote local: terminated (data)");
        return false;
    }

    return true;
}

bool FdConnection::Write(apacket* packet) {
    if (!WriteFdExactly(fd_.get(), &packet->msg, sizeof(packet->msg))) {
        D("remote local: write terminated");
        return false;
    }

    if (packet->msg.data_length) {
        if (!WriteFdExactly(fd_.get(), &packet->payload[0], packet->msg.data_length)) {
            D("remote local: write terminated");
            return false;
        }
    }

    return true;
}

void FdConnection::Close() {
    adb_shutdown(fd_.get());
    fd_.reset();
}

static std::string dump_packet(const char* name, const char* func, apacket* p) {
    unsigned command = p->msg.command;
    int len = p->msg.data_length;
    char cmd[9];
    char arg0[12], arg1[12];
    int n;

    for (n = 0; n < 4; n++) {
        int b = (command >> (n * 8)) & 255;
        if (b < 32 || b >= 127) break;
        cmd[n] = (char)b;
    }
    if (n == 4) {
        cmd[4] = 0;
    } else {
        /* There is some non-ASCII name in the command, so dump
            * the hexadecimal value instead */
        snprintf(cmd, sizeof cmd, "%08x", command);
    }

    if (p->msg.arg0 < 256U)
        snprintf(arg0, sizeof arg0, "%d", p->msg.arg0);
    else
        snprintf(arg0, sizeof arg0, "0x%x", p->msg.arg0);

    if (p->msg.arg1 < 256U)
        snprintf(arg1, sizeof arg1, "%d", p->msg.arg1);
    else
        snprintf(arg1, sizeof arg1, "0x%x", p->msg.arg1);

    std::string result = android::base::StringPrintf("%s: %s: [%s] arg0=%s arg1=%s (len=%d) ", name,
                                                     func, cmd, arg0, arg1, len);
    result += dump_hex(p->payload.data(), p->payload.size());
    return result;
}

void send_packet(apacket* p, atransport* t) {
    p->msg.magic = p->msg.command ^ 0xffffffff;
    // compute a checksum for connection/auth packets for compatibility reasons
    if (t->get_protocol_version() >= A_VERSION_SKIP_CHECKSUM) {
        p->msg.data_check = 0;
    } else {
        p->msg.data_check = calculate_apacket_checksum(p);
    }

    VLOG(TRANSPORT) << dump_packet(t->serial, "to remote", p);

    if (t == NULL) {
        fatal("Transport is null");
    }

    if (t->Write(p) != 0) {
        D("%s: failed to enqueue packet, closing transport", t->serial);
        t->Kick();
    }
}

void kick_transport(atransport* t) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    // As kick_transport() can be called from threads without guarantee that t is valid,
    // check if the transport is in transport_list first.
    //
    // TODO(jmgao): WTF? Is this actually true?
    if (std::find(transport_list.begin(), transport_list.end(), t) != transport_list.end()) {
        t->Kick();
    }
}

static int transport_registration_send = -1;
static int transport_registration_recv = -1;
static fdevent transport_registration_fde;

#if ADB_HOST

/* this adds support required by the 'track-devices' service.
 * this is used to send the content of "list_transport" to any
 * number of client connections that want it through a single
 * live TCP connection
 */
struct device_tracker {
    asocket socket;
    bool update_needed = false;
    bool long_output = false;
    device_tracker* next = nullptr;
};

/* linked list of all device trackers */
static device_tracker* device_tracker_list;

static void device_tracker_remove(device_tracker* tracker) {
    device_tracker** pnode = &device_tracker_list;
    device_tracker* node = *pnode;

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    while (node) {
        if (node == tracker) {
            *pnode = node->next;
            break;
        }
        pnode = &node->next;
        node = *pnode;
    }
}

static void device_tracker_close(asocket* socket) {
    device_tracker* tracker = (device_tracker*)socket;
    asocket* peer = socket->peer;

    D("device tracker %p removed", tracker);
    if (peer) {
        peer->peer = NULL;
        peer->close(peer);
    }
    device_tracker_remove(tracker);
    delete tracker;
}

static int device_tracker_enqueue(asocket* socket, std::string) {
    /* you can't read from a device tracker, close immediately */
    device_tracker_close(socket);
    return -1;
}

static int device_tracker_send(device_tracker* tracker, const std::string& string) {
    asocket* peer = tracker->socket.peer;

    std::string data;
    data.resize(4 + string.size());
    char buf[5];
    snprintf(buf, sizeof(buf), "%04x", static_cast<int>(string.size()));
    memcpy(&data[0], buf, 4);
    memcpy(&data[4], string.data(), string.size());
    return peer->enqueue(peer, std::move(data));
}

static void device_tracker_ready(asocket* socket) {
    device_tracker* tracker = reinterpret_cast<device_tracker*>(socket);

    // We want to send the device list when the tracker connects
    // for the first time, even if no update occurred.
    if (tracker->update_needed) {
        tracker->update_needed = false;

        std::string transports = list_transports(tracker->long_output);
        device_tracker_send(tracker, transports);
    }
}

asocket* create_device_tracker(bool long_output) {
    device_tracker* tracker = new device_tracker();
    if (tracker == nullptr) fatal("cannot allocate device tracker");

    D("device tracker %p created", tracker);

    tracker->socket.enqueue = device_tracker_enqueue;
    tracker->socket.ready = device_tracker_ready;
    tracker->socket.close = device_tracker_close;
    tracker->update_needed = true;
    tracker->long_output = long_output;

    tracker->next = device_tracker_list;
    device_tracker_list = tracker;

    return &tracker->socket;
}

// Check if all of the USB transports are connected.
bool iterate_transports(std::function<bool(const atransport*)> fn) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (const auto& t : transport_list) {
        if (!fn(t)) {
            return false;
        }
    }
    for (const auto& t : pending_list) {
        if (!fn(t)) {
            return false;
        }
    }
    return true;
}

// Call this function each time the transport list has changed.
void update_transports() {
    update_transport_status();

    // Notify `adb track-devices` clients.
    std::string transports = list_transports(false);

    device_tracker* tracker = device_tracker_list;
    while (tracker != nullptr) {
        device_tracker* next = tracker->next;
        // This may destroy the tracker if the connection is closed.
        device_tracker_send(tracker, transports);
        tracker = next;
    }
}

#else

void update_transports() {
    // Nothing to do on the device side.
}

#endif  // ADB_HOST

struct tmsg {
    atransport* transport;
    int action;
};

static int transport_read_action(int fd, struct tmsg* m) {
    char* p = (char*)m;
    int len = sizeof(*m);
    int r;

    while (len > 0) {
        r = adb_read(fd, p, len);
        if (r > 0) {
            len -= r;
            p += r;
        } else {
            D("transport_read_action: on fd %d: %s", fd, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int transport_write_action(int fd, struct tmsg* m) {
    char* p = (char*)m;
    int len = sizeof(*m);
    int r;

    while (len > 0) {
        r = adb_write(fd, p, len);
        if (r > 0) {
            len -= r;
            p += r;
        } else {
            D("transport_write_action: on fd %d: %s", fd, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void remove_transport(atransport*);

static void transport_registration_func(int _fd, unsigned ev, void*) {
    tmsg m;
    atransport* t;

    if (!(ev & FDE_READ)) {
        return;
    }

    if (transport_read_action(_fd, &m)) {
        fatal_errno("cannot read transport registration socket");
    }

    t = m.transport;

    if (m.action == 0) {
        D("transport: %s deleting", t->serial);

        {
            std::lock_guard<std::recursive_mutex> lock(transport_lock);
            transport_list.remove(t);
        }

        if (t->product) free(t->product);
        if (t->serial) free(t->serial);
        if (t->model) free(t->model);
        if (t->device) free(t->device);
        if (t->devpath) free(t->devpath);

        delete t;

        update_transports();
        return;
    }

    /* don't create transport threads for inaccessible devices */
    if (t->GetConnectionState() != kCsNoPerm) {
        /* initial references are the two threads */
        t->ref_count = 1;
        t->connection->SetTransportName(t->serial_name());
        t->connection->SetReadCallback([t](Connection*, std::unique_ptr<apacket> p) {
            if (!check_header(p.get(), t)) {
                D("%s: remote read: bad header", t->serial);
                return false;
            }

            VLOG(TRANSPORT) << dump_packet(t->serial, "from remote", p.get());
            apacket* packet = p.release();

            // TODO: Does this need to run on the main thread?
            fdevent_run_on_main_thread([packet, t]() { handle_packet(packet, t); });
            return true;
        });
        t->connection->SetErrorCallback([t](Connection*, const std::string& error) {
            D("%s: connection terminated: %s", t->serial, error.c_str());
            fdevent_run_on_main_thread([t]() {
                handle_offline(t);
                transport_unref(t);
            });
        });

        t->connection->Start();
#if ADB_HOST
        send_connect(t);
#endif
    }

    {
        std::lock_guard<std::recursive_mutex> lock(transport_lock);
        pending_list.remove(t);
        transport_list.push_front(t);
    }

    update_transports();
}

void init_transport_registration(void) {
    int s[2];

    if (adb_socketpair(s)) {
        fatal_errno("cannot open transport registration socketpair");
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    transport_registration_send = s[0];
    transport_registration_recv = s[1];

    fdevent_install(&transport_registration_fde, transport_registration_recv,
                    transport_registration_func, 0);

    fdevent_set(&transport_registration_fde, FDE_READ);
}

void kick_all_transports() {
    // To avoid only writing part of a packet to a transport after exit, kick all transports.
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto t : transport_list) {
        t->Kick();
    }
}

/* the fdevent select pump is single threaded */
static void register_transport(atransport* transport) {
    tmsg m;
    m.transport = transport;
    m.action = 1;
    D("transport: %s registered", transport->serial);
    if (transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}

static void remove_transport(atransport* transport) {
    tmsg m;
    m.transport = transport;
    m.action = 0;
    D("transport: %s removed", transport->serial);
    if (transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}

static void transport_unref(atransport* t) {
    CHECK(t != nullptr);

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    CHECK_GT(t->ref_count, 0u);
    t->ref_count--;
    if (t->ref_count == 0) {
        D("transport: %s unref (kicking and closing)", t->serial);
        t->connection->Stop();
        remove_transport(t);
    } else {
        D("transport: %s unref (count=%zu)", t->serial, t->ref_count);
    }
}

static int qual_match(const char* to_test, const char* prefix, const char* qual,
                      bool sanitize_qual) {
    if (!to_test || !*to_test) /* Return true if both the qual and to_test are null strings. */
        return !qual || !*qual;

    if (!qual) return 0;

    if (prefix) {
        while (*prefix) {
            if (*prefix++ != *to_test++) return 0;
        }
    }

    while (*qual) {
        char ch = *qual++;
        if (sanitize_qual && !isalnum(ch)) ch = '_';
        if (ch != *to_test++) return 0;
    }

    /* Everything matched so far.  Return true if *to_test is a NUL. */
    return !*to_test;
}

atransport* acquire_one_transport(TransportType type, const char* serial, TransportId transport_id,
                                  bool* is_ambiguous, std::string* error_out,
                                  bool accept_any_state) {
    atransport* result = nullptr;

    if (transport_id != 0) {
        *error_out =
            android::base::StringPrintf("no device with transport id '%" PRIu64 "'", transport_id);
    } else if (serial) {
        *error_out = android::base::StringPrintf("device '%s' not found", serial);
    } else if (type == kTransportLocal) {
        *error_out = "no emulators found";
    } else if (type == kTransportAny) {
        *error_out = "no devices/emulators found";
    } else {
        *error_out = "no devices found";
    }

    std::unique_lock<std::recursive_mutex> lock(transport_lock);
    for (const auto& t : transport_list) {
        if (t->GetConnectionState() == kCsNoPerm) {
            *error_out = UsbNoPermissionsLongHelpText();
            continue;
        }

        if (transport_id) {
            if (t->id == transport_id) {
                result = t;
                break;
            }
        } else if (serial) {
            if (t->MatchesTarget(serial)) {
                if (result) {
                    *error_out = "more than one device";
                    if (is_ambiguous) *is_ambiguous = true;
                    result = nullptr;
                    break;
                }
                result = t;
            }
        } else {
            if (type == kTransportUsb && t->type == kTransportUsb) {
                if (result) {
                    *error_out = "more than one device";
                    if (is_ambiguous) *is_ambiguous = true;
                    result = nullptr;
                    break;
                }
                result = t;
            } else if (type == kTransportLocal && t->type == kTransportLocal) {
                if (result) {
                    *error_out = "more than one emulator";
                    if (is_ambiguous) *is_ambiguous = true;
                    result = nullptr;
                    break;
                }
                result = t;
            } else if (type == kTransportAny) {
                if (result) {
                    *error_out = "more than one device/emulator";
                    if (is_ambiguous) *is_ambiguous = true;
                    result = nullptr;
                    break;
                }
                result = t;
            }
        }
    }
    lock.unlock();

    // Don't return unauthorized devices; the caller can't do anything with them.
    if (result && result->GetConnectionState() == kCsUnauthorized && !accept_any_state) {
        *error_out = "device unauthorized.\n";
        char* ADB_VENDOR_KEYS = getenv("ADB_VENDOR_KEYS");
        *error_out += "This adb server's $ADB_VENDOR_KEYS is ";
        *error_out += ADB_VENDOR_KEYS ? ADB_VENDOR_KEYS : "not set";
        *error_out += "\n";
        *error_out += "Try 'adb kill-server' if that seems wrong.\n";
        *error_out += "Otherwise check for a confirmation dialog on your device.";
        result = nullptr;
    }

    // Don't return offline devices; the caller can't do anything with them.
    if (result && result->GetConnectionState() == kCsOffline && !accept_any_state) {
        *error_out = "device offline";
        result = nullptr;
    }

    if (result) {
        *error_out = "success";
    }

    return result;
}

int atransport::Write(apacket* p) {
    return this->connection->Write(std::unique_ptr<apacket>(p)) ? 0 : -1;
}

void atransport::Kick() {
    if (!kicked_) {
        D("kicking transport %s", this->serial);
        kicked_ = true;
        this->connection->Stop();
    }
}

ConnectionState atransport::GetConnectionState() const {
    return connection_state_;
}

void atransport::SetConnectionState(ConnectionState state) {
    check_main_thread();
    connection_state_ = state;
}

const std::string atransport::connection_state_name() const {
    ConnectionState state = GetConnectionState();
    switch (state) {
        case kCsOffline:
            return "offline";
        case kCsBootloader:
            return "bootloader";
        case kCsDevice:
            return "device";
        case kCsHost:
            return "host";
        case kCsRecovery:
            return "recovery";
        case kCsNoPerm:
            return UsbNoPermissionsShortHelpText();
        case kCsSideload:
            return "sideload";
        case kCsUnauthorized:
            return "unauthorized";
        default:
            return "unknown";
    }
}

void atransport::update_version(int version, size_t payload) {
    protocol_version = std::min(version, A_VERSION);
    max_payload = std::min(payload, MAX_PAYLOAD);
}

int atransport::get_protocol_version() const {
    return protocol_version;
}

size_t atransport::get_max_payload() const {
    return max_payload;
}

namespace {

constexpr char kFeatureStringDelimiter = ',';

}  // namespace

const FeatureSet& supported_features() {
    // Local static allocation to avoid global non-POD variables.
    static const FeatureSet* features = new FeatureSet{
        kFeatureShell2, kFeatureCmd, kFeatureStat2,
        // Increment ADB_SERVER_VERSION whenever the feature list changes to
        // make sure that the adb client and server features stay in sync
        // (http://b/24370690).
    };

    return *features;
}

std::string FeatureSetToString(const FeatureSet& features) {
    return android::base::Join(features, kFeatureStringDelimiter);
}

FeatureSet StringToFeatureSet(const std::string& features_string) {
    if (features_string.empty()) {
        return FeatureSet();
    }

    auto names = android::base::Split(features_string, {kFeatureStringDelimiter});
    return FeatureSet(names.begin(), names.end());
}

bool CanUseFeature(const FeatureSet& feature_set, const std::string& feature) {
    return feature_set.count(feature) > 0 && supported_features().count(feature) > 0;
}

bool atransport::has_feature(const std::string& feature) const {
    return features_.count(feature) > 0;
}

void atransport::SetFeatures(const std::string& features_string) {
    features_ = StringToFeatureSet(features_string);
}

void atransport::AddDisconnect(adisconnect* disconnect) {
    disconnects_.push_back(disconnect);
}

void atransport::RemoveDisconnect(adisconnect* disconnect) {
    disconnects_.remove(disconnect);
}

void atransport::RunDisconnects() {
    for (const auto& disconnect : disconnects_) {
        disconnect->func(disconnect->opaque, this);
    }
    disconnects_.clear();
}

bool atransport::MatchesTarget(const std::string& target) const {
    if (serial) {
        if (target == serial) {
            return true;
        } else if (type == kTransportLocal) {
            // Local transports can match [tcp:|udp:]<hostname>[:port].
            const char* local_target_ptr = target.c_str();

            // For fastboot compatibility, ignore protocol prefixes.
            if (android::base::StartsWith(target, "tcp:") ||
                android::base::StartsWith(target, "udp:")) {
                local_target_ptr += 4;
            }

            // Parse our |serial| and the given |target| to check if the hostnames and ports match.
            std::string serial_host, error;
            int serial_port = -1;
            if (android::base::ParseNetAddress(serial, &serial_host, &serial_port, nullptr, &error)) {
                // |target| may omit the port to default to ours.
                std::string target_host;
                int target_port = serial_port;
                if (android::base::ParseNetAddress(local_target_ptr, &target_host, &target_port,
                                                   nullptr, &error) &&
                    serial_host == target_host && serial_port == target_port) {
                    return true;
                }
            }
        }
    }

    return (devpath && target == devpath) ||
           qual_match(target.c_str(), "product:", product, false) ||
           qual_match(target.c_str(), "model:", model, true) ||
           qual_match(target.c_str(), "device:", device, false);
}

#if ADB_HOST

// We use newline as our delimiter, make sure to never output it.
static std::string sanitize(std::string str, bool alphanumeric) {
    auto pred = alphanumeric ? [](const char c) { return !isalnum(c); }
                             : [](const char c) { return c == '\n'; };
    std::replace_if(str.begin(), str.end(), pred, '_');
    return str;
}

static void append_transport_info(std::string* result, const char* key, const char* value,
                                  bool alphanumeric) {
    if (value == nullptr || *value == '\0') {
        return;
    }

    *result += ' ';
    *result += key;
    *result += sanitize(value, alphanumeric);
}

static void append_transport(const atransport* t, std::string* result, bool long_listing) {
    const char* serial = t->serial;
    if (!serial || !serial[0]) {
        serial = "(no serial number)";
    }

    if (!long_listing) {
        *result += serial;
        *result += '\t';
        *result += t->connection_state_name();
    } else {
        android::base::StringAppendF(result, "%-22s %s", serial, t->connection_state_name().c_str());

        append_transport_info(result, "", t->devpath, false);
        append_transport_info(result, "product:", t->product, false);
        append_transport_info(result, "model:", t->model, true);
        append_transport_info(result, "device:", t->device, false);

        // Put id at the end, so that anyone parsing the output here can always find it by scanning
        // backwards from newlines, even with hypothetical devices named 'transport_id:1'.
        *result += " transport_id:";
        *result += std::to_string(t->id);
    }
    *result += '\n';
}

std::string list_transports(bool long_listing) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);

    auto sorted_transport_list = transport_list;
    sorted_transport_list.sort([](atransport*& x, atransport*& y) {
        if (x->type != y->type) {
            return x->type < y->type;
        }
        return strcmp(x->serial, y->serial) < 0;
    });

    std::string result;
    for (const auto& t : sorted_transport_list) {
        append_transport(t, &result, long_listing);
    }
    return result;
}

void close_usb_devices(std::function<bool(const atransport*)> predicate) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto& t : transport_list) {
        if (predicate(t)) {
            t->Kick();
        }
    }
}

/* hack for osx */
void close_usb_devices() {
    close_usb_devices([](const atransport*) { return true; });
}
#endif  // ADB_HOST

int register_socket_transport(int s, const char* serial, int port, int local) {
    atransport* t = new atransport();

    if (!serial) {
        char buf[32];
        snprintf(buf, sizeof(buf), "T-%p", t);
        serial = buf;
    }

    D("transport: %s init'ing for socket %d, on port %d", serial, s, port);
    if (init_socket_transport(t, s, port, local) < 0) {
        delete t;
        return -1;
    }

    std::unique_lock<std::recursive_mutex> lock(transport_lock);
    for (const auto& transport : pending_list) {
        if (transport->serial && strcmp(serial, transport->serial) == 0) {
            VLOG(TRANSPORT) << "socket transport " << transport->serial
                            << " is already in pending_list and fails to register";
            delete t;
            return -1;
        }
    }

    for (const auto& transport : transport_list) {
        if (transport->serial && strcmp(serial, transport->serial) == 0) {
            VLOG(TRANSPORT) << "socket transport " << transport->serial
                            << " is already in transport_list and fails to register";
            delete t;
            return -1;
        }
    }

    pending_list.push_front(t);
    t->serial = strdup(serial);

    lock.unlock();

    register_transport(t);
    return 0;
}

#if ADB_HOST
atransport* find_transport(const char* serial) {
    atransport* result = nullptr;

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto& t : transport_list) {
        if (t->serial && strcmp(serial, t->serial) == 0) {
            result = t;
            break;
        }
    }

    return result;
}

void kick_all_tcp_devices() {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto& t : transport_list) {
        if (t->IsTcpDevice()) {
            // Kicking breaks the read_transport thread of this transport out of any read, then
            // the read_transport thread will notify the main thread to make this transport
            // offline. Then the main thread will notify the write_transport thread to exit.
            // Finally, this transport will be closed and freed in the main thread.
            t->Kick();
        }
    }
}

#endif

void register_usb_transport(usb_handle* usb, const char* serial, const char* devpath,
                            unsigned writeable) {
    atransport* t = new atransport((writeable ? kCsOffline : kCsNoPerm));

    D("transport: %p init'ing for usb_handle %p (sn='%s')", t, usb, serial ? serial : "");
    init_usb_transport(t, usb);
    if (serial) {
        t->serial = strdup(serial);
    }

    if (devpath) {
        t->devpath = strdup(devpath);
    }

    {
        std::lock_guard<std::recursive_mutex> lock(transport_lock);
        pending_list.push_front(t);
    }

    register_transport(t);
}

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb) {
    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    transport_list.remove_if([usb](atransport* t) {
        if (auto connection = dynamic_cast<UsbConnection*>(t->connection.get())) {
            return connection->handle_ == usb && t->GetConnectionState() == kCsNoPerm;
        }
        return false;
    });
}

bool check_header(apacket* p, atransport* t) {
    if (p->msg.magic != (p->msg.command ^ 0xffffffff)) {
        VLOG(RWX) << "check_header(): invalid magic command = " << std::hex << p->msg.command
                  << ", magic = " << p->msg.magic;
        return false;
    }

    if (p->msg.data_length > t->get_max_payload()) {
        VLOG(RWX) << "check_header(): " << p->msg.data_length
                  << " atransport::max_payload = " << t->get_max_payload();
        return false;
    }

    return true;
}

#if ADB_HOST
std::shared_ptr<RSA> atransport::NextKey() {
    if (keys_.empty()) keys_ = adb_auth_get_private_keys();

    std::shared_ptr<RSA> result = keys_[0];
    keys_.pop_front();
    return result;
}
#endif
