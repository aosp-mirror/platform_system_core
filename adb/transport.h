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
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include <openssl/rsa.h>

#include "adb.h"
#include "adb_unique_fd.h"

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
// The server supports `push --sync`.
extern const char* const kFeaturePushSync;

TransportId NextTransportId();

// Abstraction for a blocking packet transport.
struct Connection {
    Connection() = default;
    Connection(const Connection& copy) = delete;
    Connection(Connection&& move) = delete;

    // Destroy a Connection. Formerly known as 'Close' in atransport.
    virtual ~Connection() = default;

    // Read/Write a packet. These functions are concurrently called from a transport's reader/writer
    // threads.
    virtual bool Read(apacket* packet) = 0;
    virtual bool Write(apacket* packet) = 0;

    // Terminate a connection.
    // This method must be thread-safe, and must cause concurrent Reads/Writes to terminate.
    // Formerly known as 'Kick' in atransport.
    virtual void Close() = 0;
};

struct FdConnection : public Connection {
    explicit FdConnection(unique_fd fd) : fd_(std::move(fd)) {}

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override;

  private:
    unique_fd fd_;
};

struct UsbConnection : public Connection {
    explicit UsbConnection(usb_handle* handle) : handle_(handle) {}
    ~UsbConnection();

    bool Read(apacket* packet) override final;
    bool Write(apacket* packet) override final;

    void Close() override final;

    usb_handle* handle_;
};

class atransport {
  public:
    // TODO(danalbert): We expose waaaaaaay too much stuff because this was
    // historically just a struct, but making the whole thing a more idiomatic
    // class in one go is a very large change. Given how bad our testing is,
    // it's better to do this piece by piece.

    atransport(ConnectionState state = kCsOffline)
        : id(NextTransportId()), connection_state_(state) {
        transport_fde = {};
        // Initialize protocol to min version for compatibility with older versions.
        // Version will be updated post-connect.
        protocol_version = A_VERSION_MIN;
        max_payload = MAX_PAYLOAD;
    }
    virtual ~atransport() {}

    int Write(apacket* p);
    void Kick();

    // ConnectionState can be read by all threads, but can only be written in the main thread.
    ConnectionState GetConnectionState() const;
    void SetConnectionState(ConnectionState state);

    const TransportId id;
    int fd = -1;
    int transport_socket = -1;
    fdevent transport_fde;
    size_t ref_count = 0;
    uint32_t sync_token = 0;
    bool online = false;
    TransportType type = kTransportAny;

    std::unique_ptr<Connection> connection;

    // Used to identify transports for clients.
    char* serial = nullptr;
    char* product = nullptr;
    char* model = nullptr;
    char* device = nullptr;
    char* devpath = nullptr;

    bool IsTcpDevice() const { return type == kTransportLocal; }

#if ADB_HOST
    std::shared_ptr<RSA> NextKey();
#endif

    char token[TOKEN_SIZE] = {};
    size_t failed_auth_attempts = 0;

    const std::string serial_name() const { return serial ? serial : "<unknown>"; }
    const std::string connection_state_name() const;

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

private:
    bool kicked_ = false;

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

void init_transport_registration(void);
void init_mdns_transport_discovery(void);
std::string list_transports(bool long_listing);
atransport* find_transport(const char* serial);
void kick_all_tcp_devices();
void kick_all_transports();

void register_usb_transport(usb_handle* h, const char* serial,
                            const char* devpath, unsigned writeable);

/* Connect to a network address and register it as a device */
void connect_device(const std::string& address, std::string* response);

/* cause new transports to be init'd and added to the list */
int register_socket_transport(int s, const char* serial, int port, int local);

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb);

bool check_header(apacket* p, atransport* t);

void close_usb_devices();
void close_usb_devices(std::function<bool(const atransport*)> predicate);

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(bool long_output);

#endif   /* __TRANSPORT_H */
