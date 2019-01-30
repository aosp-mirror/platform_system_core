/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>

#include <android-base/macros.h>
#include <android-base/thread_annotations.h>
#include <openssl/rsa.h>

#include "adb.h"
#include "adb_unique_fd.h"
#include "usb.h"

typedef std::unordered_set<std::string> FeatureSet;

const FeatureSet& supported_features();

// Encodes and decodes FeatureSet objects into human-readable strings.
std::string FeatureSetToString(const FeatureSet& features);
FeatureSet StringToFeatureSet(const std::string& features_string);

// Returns true if both local features and |feature_set| support |feature|.
bool CanUseFeature(const FeatureSet& feature_set, const std::string& feature);

// Do not use any of [:;=,] in feature strings, they have special meaning
// in the connection banner.
extern const char* const kFeatureShell2;
// The 'cmd' command is available
extern const char* const kFeatureCmd;
extern const char* const kFeatureStat2;
// The server is running with libusb enabled.
extern const char* const kFeatureLibusb;
// adbd supports `push --sync`.
extern const char* const kFeaturePushSync;
// adbd supports installing .apex packages.
extern const char* const kFeatureApex;
// adbd has b/110953234 fixed.
extern const char* const kFeatureFixedPushMkdir;
// adbd supports android binder bridge (abb).
extern const char* const kFeatureAbb;

TransportId NextTransportId();

// Abstraction for a non-blocking packet transport.
struct Connection {
    Connection() = default;
    virtual ~Connection() = default;

    void SetTransportName(std::string transport_name) {
        transport_name_ = std::move(transport_name);
    }

    using ReadCallback = std::function<bool(Connection*, std::unique_ptr<apacket>)>;
    void SetReadCallback(ReadCallback callback) {
        CHECK(!read_callback_);
        read_callback_ = callback;
    }

    // Called after the Connection has terminated, either by an error or because Stop was called.
    using ErrorCallback = std::function<void(Connection*, const std::string&)>;
    void SetErrorCallback(ErrorCallback callback) {
        CHECK(!error_callback_);
        error_callback_ = callback;
    }

    virtual bool Write(std::unique_ptr<apacket> packet) = 0;

    virtual void Start() = 0;
    virtual void Stop() = 0;

    std::string transport_name_;
    ReadCallback read_callback_;
    ErrorCallback error_callback_;

    static std::unique_ptr<Connection> FromFd(unique_fd fd);
};

// Abstraction for a blocking packet transport.
struct BlockingConnection {
    BlockingConnection() = default;
    BlockingConnection(const BlockingConnection& copy) = delete;
    BlockingConnection(BlockingConnection&& move) = delete;

    // Destroy a BlockingConnection. Formerly known as 'Close' in atransport.
    virtual ~BlockingConnection() = default;

    // Read/Write a packet. These functions are concurrently called from a transport's reader/writer
    // threads.
    virtual bool Read(apacket* packet) = 0;
    virtual bool Write(apacket* packet) = 0;

    // Terminate a connection.
    // This method must be thread-safe, and must cause concurrent Reads/Writes to terminate.
    // Formerly known as 'Kick' in atransport.
    virtual void Close() = 0;
};

struct BlockingConnectionAdapter : public Connection {
    explicit BlockingConnectionAdapter(std::unique_ptr<BlockingConnection> connection);

    virtual ~BlockingConnectionAdapter();

    virtual bool Write(std::unique_ptr<apacket> packet) override final;

    virtual void Start() override final;
    virtual void Stop() override final;

    bool started_ GUARDED_BY(mutex_) = false;
    bool stopped_ GUARDED_BY(mutex_) = false;

    std::unique_ptr<BlockingConnection> underlying_;
    std::thread read_thread_ GUARDED_BY(mutex_);
    std::thread write_thread_ GUARDED_BY(mutex_);

    std::deque<std::unique_ptr<apacket>> write_queue_ GUARDED_BY(mutex_);
    std::mutex mutex_;
    std::condition_variable cv_;

    std::once_flag error_flag_;
};

struct FdConnection : public BlockingConnection {
    explicit FdConnection(unique_fd fd) : fd_(std::move(fd)) {}

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override;

  private:
    unique_fd fd_;
};

struct UsbConnection : public BlockingConnection {
    explicit UsbConnection(usb_handle* handle) : handle_(handle) {}
    ~UsbConnection();

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override final;

    usb_handle* handle_;
};

// Waits for a transport's connection to be not pending. This is a separate
// object so that the transport can be destroyed and another thread can be
// notified of it in a race-free way.
class ConnectionWaitable {
  public:
    ConnectionWaitable() = default;
    ~ConnectionWaitable() = default;

    // Waits until the first CNXN packet has been received by the owning
    // atransport, or the specified timeout has elapsed. Can be called from any
    // thread.
    //
    // Returns true if the CNXN packet was received in a timely fashion, false
    // otherwise.
    bool WaitForConnection(std::chrono::milliseconds timeout);

    // Can be called from any thread when the connection stops being pending.
    // Only the first invocation will be acknowledged, the rest will be no-ops.
    void SetConnectionEstablished(bool success);

  private:
    bool connection_established_ GUARDED_BY(mutex_) = false;
    bool connection_established_ready_ GUARDED_BY(mutex_) = false;
    std::mutex mutex_;
    std::condition_variable cv_;

    DISALLOW_COPY_AND_ASSIGN(ConnectionWaitable);
};

enum class ReconnectResult {
    Retry,
    Success,
    Abort,
};

class atransport {
  public:
    // TODO(danalbert): We expose waaaaaaay too much stuff because this was
    // historically just a struct, but making the whole thing a more idiomatic
    // class in one go is a very large change. Given how bad our testing is,
    // it's better to do this piece by piece.

    using ReconnectCallback = std::function<ReconnectResult(atransport*)>;

    atransport(ReconnectCallback reconnect, ConnectionState state)
        : id(NextTransportId()),
          kicked_(false),
          connection_state_(state),
          connection_waitable_(std::make_shared<ConnectionWaitable>()),
          connection_(nullptr),
          reconnect_(std::move(reconnect)) {
        // Initialize protocol to min version for compatibility with older versions.
        // Version will be updated post-connect.
        protocol_version = A_VERSION_MIN;
        max_payload = MAX_PAYLOAD;
    }
    atransport(ConnectionState state = kCsOffline)
        : atransport([](atransport*) { return ReconnectResult::Abort; }, state) {}
    virtual ~atransport();

    int Write(apacket* p);
    void Kick();
    bool kicked() const { return kicked_; }

    // ConnectionState can be read by all threads, but can only be written in the main thread.
    ConnectionState GetConnectionState() const;
    void SetConnectionState(ConnectionState state);

    void SetConnection(std::unique_ptr<Connection> connection);
    std::shared_ptr<Connection> connection() {
        std::lock_guard<std::mutex> lock(mutex_);
        return connection_;
    }

    void SetUsbHandle(usb_handle* h) { usb_handle_ = h; }
    usb_handle* GetUsbHandle() { return usb_handle_; }

    const TransportId id;
    size_t ref_count = 0;
    bool online = false;
    TransportType type = kTransportAny;

    // Used to identify transports for clients.
    std::string serial;
    std::string product;
    std::string model;
    std::string device;
    std::string devpath;

    bool IsTcpDevice() const { return type == kTransportLocal; }

#if ADB_HOST
    std::shared_ptr<RSA> NextKey();
    void ResetKeys();
#endif

    char token[TOKEN_SIZE] = {};
    size_t failed_auth_attempts = 0;

    std::string serial_name() const { return !serial.empty() ? serial : "<unknown>"; }
    std::string connection_state_name() const;

    void update_version(int version, size_t payload);
    int get_protocol_version() const;
    size_t get_max_payload() const;

    const FeatureSet& features() const {
        return features_;
    }

    bool has_feature(const std::string& feature) const;

    // Loads the transport's feature set from the given string.
    void SetFeatures(const std::string& features_string);

    void AddDisconnect(adisconnect* disconnect);
    void RemoveDisconnect(adisconnect* disconnect);
    void RunDisconnects();

    // Returns true if |target| matches this transport. A matching |target| can be any of:
    //   * <serial>
    //   * <devpath>
    //   * product:<product>
    //   * model:<model>
    //   * device:<device>
    //
    // If this is a local transport, serial will also match [tcp:|udp:]<hostname>[:port] targets.
    // For example, serial "100.100.100.100:5555" would match any of:
    //   * 100.100.100.100
    //   * tcp:100.100.100.100
    //   * udp:100.100.100.100:5555
    // This is to make it easier to use the same network target for both fastboot and adb.
    bool MatchesTarget(const std::string& target) const;

    // Notifies that the atransport is no longer waiting for the connection
    // being established.
    void SetConnectionEstablished(bool success);

    // Gets a shared reference to the ConnectionWaitable.
    std::shared_ptr<ConnectionWaitable> connection_waitable() { return connection_waitable_; }

    // Attempts to reconnect with the underlying Connection.
    ReconnectResult Reconnect();

  private:
    std::atomic<bool> kicked_;

    // A set of features transmitted in the banner with the initial connection.
    // This is stored in the banner as 'features=feature0,feature1,etc'.
    FeatureSet features_;
    int protocol_version;
    size_t max_payload;

    // A list of adisconnect callbacks called when the transport is kicked.
    std::list<adisconnect*> disconnects_;

    std::atomic<ConnectionState> connection_state_;
#if ADB_HOST
    std::deque<std::shared_ptr<RSA>> keys_;
#endif

    // A sharable object that can be used to wait for the atransport's
    // connection to be established.
    std::shared_ptr<ConnectionWaitable> connection_waitable_;

    // The underlying connection object.
    std::shared_ptr<Connection> connection_ GUARDED_BY(mutex_);

    // USB handle for the connection, if available.
    usb_handle* usb_handle_ = nullptr;

    // A callback that will be invoked when the atransport needs to reconnect.
    ReconnectCallback reconnect_;

    std::mutex mutex_;

    DISALLOW_COPY_AND_ASSIGN(atransport);
};

/*
 * Obtain a transport from the available transports.
 * If serial is non-null then only the device with that serial will be chosen.
 * If transport_id is non-zero then only the device with that transport ID will be chosen.
 * If multiple devices/emulators would match, *is_ambiguous (if non-null)
 * is set to true and nullptr returned.
 * If no suitable transport is found, error is set and nullptr returned.
 */
atransport* acquire_one_transport(TransportType type, const char* serial, TransportId transport_id,
                                  bool* is_ambiguous, std::string* error_out,
                                  bool accept_any_state = false);
void kick_transport(atransport* t);
void update_transports(void);

// Iterates across all of the current and pending transports.
// Stops iteration and returns false if fn returns false, otherwise returns true.
bool iterate_transports(std::function<bool(const atransport*)> fn);

void init_reconnect_handler(void);
void init_transport_registration(void);
void init_mdns_transport_discovery(void);
std::string list_transports(bool long_listing);
atransport* find_transport(const char* serial);
void kick_all_tcp_devices();
void kick_all_transports();

void register_transport(atransport* transport);
void register_usb_transport(usb_handle* h, const char* serial,
                            const char* devpath, unsigned writeable);

/* Connect to a network address and register it as a device */
void connect_device(const std::string& address, std::string* response);

/* cause new transports to be init'd and added to the list */
bool register_socket_transport(unique_fd s, std::string serial, int port, int local,
                               atransport::ReconnectCallback reconnect, int* error = nullptr);

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb);

bool check_header(apacket* p, atransport* t);

void close_usb_devices();
void close_usb_devices(std::function<bool(const atransport*)> predicate);

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(bool long_output);

#if !ADB_HOST
unique_fd tcp_listen_inaddr_any(int port, std::string* error);
void server_socket_thread(std::function<unique_fd(int, std::string*)> listen_func, int port);

#if defined(__ANDROID__)
void qemu_socket_thread(int port);
bool use_qemu_goldfish();
#endif

#endif

#endif   /* __TRANSPORT_H */
