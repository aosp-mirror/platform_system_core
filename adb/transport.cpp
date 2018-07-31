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
#include "sysdeps/memory.h"

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
#include <queue>
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

static void register_transport(atransport* transport);
static void remove_transport(atransport* transport);
static void transport_unref(atransport* transport);

// TODO: unordered_map<TransportId, atransport*>
static auto& transport_list = *new std::list<atransport*>();
static auto& pending_list = *new std::list<atransport*>();

static auto& transport_lock = *new std::recursive_mutex();

const char* const kFeatureShell2 = "shell_v2";
const char* const kFeatureCmd = "cmd";
const char* const kFeatureStat2 = "stat_v2";
const char* const kFeatureLibusb = "libusb";
const char* const kFeaturePushSync = "push_sync";

namespace {

// A class that helps the Clang Thread Safety Analysis deal with
// std::unique_lock. Given that std::unique_lock is movable, and the analysis
// can not currently perform alias analysis, it is not annotated. In order to
// assert that the mutex is held, a ScopedAssumeLocked can be created just after
// the std::unique_lock.
class SCOPED_CAPABILITY ScopedAssumeLocked {
  public:
    ScopedAssumeLocked(std::mutex& mutex) ACQUIRE(mutex) {}
    ~ScopedAssumeLocked() RELEASE() {}
};

// Tracks and handles atransport*s that are attempting reconnection.
class ReconnectHandler {
  public:
    ReconnectHandler() = default;
    ~ReconnectHandler() = default;

    // Starts the ReconnectHandler thread.
    void Start();

    // Requests the ReconnectHandler thread to stop.
    void Stop();

    // Adds the atransport* to the queue of reconnect attempts.
    void TrackTransport(atransport* transport);

  private:
    // The main thread loop.
    void Run();

    // Tracks a reconnection attempt.
    struct ReconnectAttempt {
        atransport* transport;
        std::chrono::steady_clock::time_point reconnect_time;
        size_t attempts_left;
    };

    // Only retry for up to one minute.
    static constexpr const std::chrono::seconds kDefaultTimeout = std::chrono::seconds(10);
    static constexpr const size_t kMaxAttempts = 6;

    // Protects all members.
    std::mutex reconnect_mutex_;
    bool running_ GUARDED_BY(reconnect_mutex_) = true;
    std::thread handler_thread_;
    std::condition_variable reconnect_cv_;
    std::queue<ReconnectAttempt> reconnect_queue_ GUARDED_BY(reconnect_mutex_);

    DISALLOW_COPY_AND_ASSIGN(ReconnectHandler);
};

void ReconnectHandler::Start() {
    check_main_thread();
    handler_thread_ = std::thread(&ReconnectHandler::Run, this);
}

void ReconnectHandler::Stop() {
    check_main_thread();
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        running_ = false;
    }
    reconnect_cv_.notify_one();
    handler_thread_.join();

    // Drain the queue to free all resources.
    std::lock_guard<std::mutex> lock(reconnect_mutex_);
    while (!reconnect_queue_.empty()) {
        ReconnectAttempt attempt = reconnect_queue_.front();
        reconnect_queue_.pop();
        remove_transport(attempt.transport);
    }
}

void ReconnectHandler::TrackTransport(atransport* transport) {
    check_main_thread();
    {
        std::lock_guard<std::mutex> lock(reconnect_mutex_);
        if (!running_) return;
        reconnect_queue_.emplace(ReconnectAttempt{
                transport, std::chrono::steady_clock::now() + ReconnectHandler::kDefaultTimeout,
                ReconnectHandler::kMaxAttempts});
    }
    reconnect_cv_.notify_one();
}

void ReconnectHandler::Run() {
    while (true) {
        ReconnectAttempt attempt;
        {
            std::unique_lock<std::mutex> lock(reconnect_mutex_);
            ScopedAssumeLocked assume_lock(reconnect_mutex_);

            if (!reconnect_queue_.empty()) {
                // FIXME: libstdc++ (used on Windows) implements condition_variable with
                //        system_clock as its clock, so we're probably hosed if the clock changes,
                //        even if we use steady_clock throughout. This problem goes away once we
                //        switch to libc++.
                reconnect_cv_.wait_until(lock, reconnect_queue_.front().reconnect_time);
            } else {
                reconnect_cv_.wait(lock);
            }

            if (!running_) return;
            if (reconnect_queue_.empty()) continue;

            // Go back to sleep in case |reconnect_cv_| woke up spuriously and we still
            // have more time to wait for the current attempt.
            auto now = std::chrono::steady_clock::now();
            if (reconnect_queue_.front().reconnect_time > now) {
                continue;
            }

            attempt = reconnect_queue_.front();
            reconnect_queue_.pop();
            if (attempt.transport->kicked()) {
                D("transport %s was kicked. giving up on it.", attempt.transport->serial.c_str());
                remove_transport(attempt.transport);
                continue;
            }
        }
        D("attempting to reconnect %s", attempt.transport->serial.c_str());

        if (!attempt.transport->Reconnect()) {
            D("attempting to reconnect %s failed.", attempt.transport->serial.c_str());
            if (attempt.attempts_left == 0) {
                D("transport %s exceeded the number of retry attempts. giving up on it.",
                  attempt.transport->serial.c_str());
                remove_transport(attempt.transport);
                continue;
            }

            std::lock_guard<std::mutex> lock(reconnect_mutex_);
            reconnect_queue_.emplace(ReconnectAttempt{
                    attempt.transport,
                    std::chrono::steady_clock::now() + ReconnectHandler::kDefaultTimeout,
                    attempt.attempts_left - 1});
            continue;
        }

        D("reconnection to %s succeeded.", attempt.transport->serial.c_str());
        register_transport(attempt.transport);
    }
}

static auto& reconnect_handler = *new ReconnectHandler();

}  // namespace

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
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_) {
        LOG(FATAL) << "BlockingConnectionAdapter(" << this->transport_name_
                   << "): started multiple times";
    }

    read_thread_ = std::thread([this]() {
        LOG(INFO) << this->transport_name_ << ": read thread spawning";
        while (true) {
            auto packet = std::make_unique<apacket>();
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
            ScopedAssumeLocked assume_locked(mutex_);
            cv_.wait(lock, [this]() REQUIRES(mutex_) {
                return this->stopped_ || !this->write_queue_.empty();
            });

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

    started_ = true;
}

void BlockingConnectionAdapter::Stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!started_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): not started";
            return;
        }

        if (stopped_) {
            LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_
                      << "): already stopped";
            return;
        }

        stopped_ = true;
    }

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopping";

    this->underlying_->Close();
    this->cv_.notify_one();

    // Move the threads out into locals with the lock taken, and then unlock to let them exit.
    std::thread read_thread;
    std::thread write_thread;

    {
        std::lock_guard<std::mutex> lock(mutex_);
        read_thread = std::move(read_thread_);
        write_thread = std::move(write_thread_);
    }

    read_thread.join();
    write_thread.join();

    LOG(INFO) << "BlockingConnectionAdapter(" << this->transport_name_ << "): stopped";
    std::call_once(this->error_flag_, [this]() { this->error_callback_(this, "requested stop"); });
}

bool BlockingConnectionAdapter::Write(std::unique_ptr<apacket> packet) {
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
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

    VLOG(TRANSPORT) << dump_packet(t->serial.c_str(), "to remote", p);

    if (t == nullptr) {
        fatal("Transport is null");
    }

    if (t->Write(p) != 0) {
        D("%s: failed to enqueue packet, closing transport", t->serial.c_str());
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
static fdevent* transport_registration_fde;

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
        peer->peer = nullptr;
        peer->close(peer);
    }
    device_tracker_remove(tracker);
    delete tracker;
}

static int device_tracker_enqueue(asocket* socket, apacket::payload_type) {
    /* you can't read from a device tracker, close immediately */
    device_tracker_close(socket);
    return -1;
}

static int device_tracker_send(device_tracker* tracker, const std::string& string) {
    asocket* peer = tracker->socket.peer;

    apacket::payload_type data;
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
        D("transport: %s deleting", t->serial.c_str());

        {
            std::lock_guard<std::recursive_mutex> lock(transport_lock);
            transport_list.remove(t);
        }

        delete t;

        update_transports();
        return;
    }

    /* don't create transport threads for inaccessible devices */
    if (t->GetConnectionState() != kCsNoPerm) {
        // The connection gets a reference to the atransport. It will release it
        // upon a read/write error.
        t->ref_count++;
        t->connection()->SetTransportName(t->serial_name());
        t->connection()->SetReadCallback([t](Connection*, std::unique_ptr<apacket> p) {
            if (!check_header(p.get(), t)) {
                D("%s: remote read: bad header", t->serial.c_str());
                return false;
            }

            VLOG(TRANSPORT) << dump_packet(t->serial.c_str(), "from remote", p.get());
            apacket* packet = p.release();

            // TODO: Does this need to run on the main thread?
            fdevent_run_on_main_thread([packet, t]() { handle_packet(packet, t); });
            return true;
        });
        t->connection()->SetErrorCallback([t](Connection*, const std::string& error) {
            D("%s: connection terminated: %s", t->serial.c_str(), error.c_str());
            fdevent_run_on_main_thread([t]() {
                handle_offline(t);
                transport_unref(t);
            });
        });

        t->connection()->Start();
#if ADB_HOST
        send_connect(t);
#endif
    }

    {
        std::lock_guard<std::recursive_mutex> lock(transport_lock);
        auto it = std::find(pending_list.begin(), pending_list.end(), t);
        if (it != pending_list.end()) {
            pending_list.remove(t);
            transport_list.push_front(t);
        }
    }

    update_transports();
}

void init_reconnect_handler(void) {
    reconnect_handler.Start();
}

void init_transport_registration(void) {
    int s[2];

    if (adb_socketpair(s)) {
        fatal_errno("cannot open transport registration socketpair");
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    transport_registration_send = s[0];
    transport_registration_recv = s[1];

    transport_registration_fde =
        fdevent_create(transport_registration_recv, transport_registration_func, nullptr);
    fdevent_set(transport_registration_fde, FDE_READ);
}

void kick_all_transports() {
    reconnect_handler.Stop();
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
    D("transport: %s registered", transport->serial.c_str());
    if (transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}

static void remove_transport(atransport* transport) {
    tmsg m;
    m.transport = transport;
    m.action = 0;
    D("transport: %s removed", transport->serial.c_str());
    if (transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}

static void transport_unref(atransport* t) {
    check_main_thread();
    CHECK(t != nullptr);

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    CHECK_GT(t->ref_count, 0u);
    t->ref_count--;
    if (t->ref_count == 0) {
        t->connection()->Stop();
        if (t->IsTcpDevice() && !t->kicked()) {
            D("transport: %s unref (attempting reconnection) %d", t->serial.c_str(), t->kicked());
            reconnect_handler.TrackTransport(t);
        } else {
            D("transport: %s unref (kicking and closing)", t->serial.c_str());
            remove_transport(t);
        }
    } else {
        D("transport: %s unref (count=%zu)", t->serial.c_str(), t->ref_count);
    }
}

static int qual_match(const std::string& to_test, const char* prefix, const std::string& qual,
                      bool sanitize_qual) {
    if (to_test.empty()) /* Return true if both the qual and to_test are empty strings. */
        return qual.empty();

    if (qual.empty()) return 0;

    const char* ptr = to_test.c_str();
    if (prefix) {
        while (*prefix) {
            if (*prefix++ != *ptr++) return 0;
        }
    }

    for (char ch : qual) {
        if (sanitize_qual && !isalnum(ch)) ch = '_';
        if (ch != *ptr++) return 0;
    }

    /* Everything matched so far.  Return true if *ptr is a NUL. */
    return !*ptr;
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

    if (result && !accept_any_state) {
        // The caller requires an active transport.
        // Make sure that we're actually connected.
        ConnectionState state = result->GetConnectionState();
        switch (state) {
            case kCsConnecting:
                *error_out = "device still connecting";
                result = nullptr;
                break;

            case kCsAuthorizing:
                *error_out = "device still authorizing";
                result = nullptr;
                break;

            case kCsUnauthorized: {
                *error_out = "device unauthorized.\n";
                char* ADB_VENDOR_KEYS = getenv("ADB_VENDOR_KEYS");
                *error_out += "This adb server's $ADB_VENDOR_KEYS is ";
                *error_out += ADB_VENDOR_KEYS ? ADB_VENDOR_KEYS : "not set";
                *error_out += "\n";
                *error_out += "Try 'adb kill-server' if that seems wrong.\n";
                *error_out += "Otherwise check for a confirmation dialog on your device.";
                result = nullptr;
                break;
            }

            case kCsOffline:
                *error_out = "device offline";
                result = nullptr;
                break;

            default:
                break;
        }
    }

    if (result) {
        *error_out = "success";
    }

    return result;
}

bool ConnectionWaitable::WaitForConnection(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    ScopedAssumeLocked assume_locked(mutex_);
    return cv_.wait_for(lock, timeout, [&]() REQUIRES(mutex_) {
        return connection_established_ready_;
    }) && connection_established_;
}

void ConnectionWaitable::SetConnectionEstablished(bool success) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connection_established_ready_) return;
        connection_established_ready_ = true;
        connection_established_ = success;
        D("connection established with %d", success);
    }
    cv_.notify_one();
}

atransport::~atransport() {
    // If the connection callback had not been run before, run it now.
    SetConnectionEstablished(false);
}

int atransport::Write(apacket* p) {
    return this->connection()->Write(std::unique_ptr<apacket>(p)) ? 0 : -1;
}

void atransport::Kick() {
    if (!kicked_.exchange(true)) {
        D("kicking transport %p %s", this, this->serial.c_str());
        this->connection()->Stop();
    }
}

ConnectionState atransport::GetConnectionState() const {
    return connection_state_;
}

void atransport::SetConnectionState(ConnectionState state) {
    check_main_thread();
    connection_state_ = state;
}

void atransport::SetConnection(std::unique_ptr<Connection> connection) {
    std::lock_guard<std::mutex> lock(mutex_);
    connection_ = std::shared_ptr<Connection>(std::move(connection));
}

std::string atransport::connection_state_name() const {
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
        case kCsAuthorizing:
            return "authorizing";
        case kCsConnecting:
            return "connecting";
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
    if (!serial.empty()) {
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

    return (target == devpath) || qual_match(target, "product:", product, false) ||
           qual_match(target, "model:", model, true) ||
           qual_match(target, "device:", device, false);
}

void atransport::SetConnectionEstablished(bool success) {
    connection_waitable_->SetConnectionEstablished(success);
}

bool atransport::Reconnect() {
    return reconnect_(this);
}

#if ADB_HOST

// We use newline as our delimiter, make sure to never output it.
static std::string sanitize(std::string str, bool alphanumeric) {
    auto pred = alphanumeric ? [](const char c) { return !isalnum(c); }
                             : [](const char c) { return c == '\n'; };
    std::replace_if(str.begin(), str.end(), pred, '_');
    return str;
}

static void append_transport_info(std::string* result, const char* key, const std::string& value,
                                  bool alphanumeric) {
    if (value.empty()) {
        return;
    }

    *result += ' ';
    *result += key;
    *result += sanitize(value, alphanumeric);
}

static void append_transport(const atransport* t, std::string* result, bool long_listing) {
    std::string serial = t->serial;
    if (serial.empty()) {
        serial = "(no serial number)";
    }

    if (!long_listing) {
        *result += serial;
        *result += '\t';
        *result += t->connection_state_name();
    } else {
        android::base::StringAppendF(result, "%-22s %s", serial.c_str(),
                                     t->connection_state_name().c_str());

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
        return x->serial < y->serial;
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

int register_socket_transport(unique_fd s, const char* serial, int port, int local,
                              atransport::ReconnectCallback reconnect) {
    atransport* t = new atransport(std::move(reconnect), kCsOffline);

    if (!serial) {
        char buf[32];
        snprintf(buf, sizeof(buf), "T-%p", t);
        serial = buf;
    }

    D("transport: %s init'ing for socket %d, on port %d", serial, s.get(), port);
    if (init_socket_transport(t, std::move(s), port, local) < 0) {
        delete t;
        return -1;
    }

    std::unique_lock<std::recursive_mutex> lock(transport_lock);
    for (const auto& transport : pending_list) {
        if (strcmp(serial, transport->serial.c_str()) == 0) {
            VLOG(TRANSPORT) << "socket transport " << transport->serial
                            << " is already in pending_list and fails to register";
            delete t;
            return -EALREADY;
        }
    }

    for (const auto& transport : transport_list) {
        if (strcmp(serial, transport->serial.c_str()) == 0) {
            VLOG(TRANSPORT) << "socket transport " << transport->serial
                            << " is already in transport_list and fails to register";
            delete t;
            return -EALREADY;
        }
    }

    pending_list.push_front(t);
    t->serial = serial;

    lock.unlock();

    auto waitable = t->connection_waitable();
    register_transport(t);

    if (local == 1) {
        // Do not wait for emulator transports.
        return 0;
    }

    return waitable->WaitForConnection(std::chrono::seconds(10)) ? 0 : -1;
}

#if ADB_HOST
atransport* find_transport(const char* serial) {
    atransport* result = nullptr;

    std::lock_guard<std::recursive_mutex> lock(transport_lock);
    for (auto& t : transport_list) {
        if (strcmp(serial, t->serial.c_str()) == 0) {
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
    atransport* t = new atransport(writeable ? kCsOffline : kCsNoPerm);

    D("transport: %p init'ing for usb_handle %p (sn='%s')", t, usb, serial ? serial : "");
    init_usb_transport(t, usb);
    if (serial) {
        t->serial = serial;
    }

    if (devpath) {
        t->devpath = devpath;
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
        auto connection = t->connection();
        if (auto usb_connection = dynamic_cast<UsbConnection*>(connection.get())) {
            return usb_connection->handle_ == usb && t->GetConnectionState() == kCsNoPerm;
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
