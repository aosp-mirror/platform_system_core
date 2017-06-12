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

#include "adb.h"

#include <openssl/rsa.h>

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

class atransport {
public:
    // TODO(danalbert): We expose waaaaaaay too much stuff because this was
    // historically just a struct, but making the whole thing a more idiomatic
    // class in one go is a very large change. Given how bad our testing is,
    // it's better to do this piece by piece.

    atransport(ConnectionState state = kCsOffline) : ref_count(0), connection_state_(state) {
        transport_fde = {};
        protocol_version = A_VERSION;
        max_payload = MAX_PAYLOAD;
    }
    virtual ~atransport() {}

    int (*read_from_remote)(apacket* p, atransport* t) = nullptr;
    void (*close)(atransport* t) = nullptr;

    void SetWriteFunction(int (*write_func)(apacket*, atransport*)) { write_func_ = write_func; }
    void SetKickFunction(void (*kick_func)(atransport*)) {
        kick_func_ = kick_func;
    }
    bool IsKicked() {
        return kicked_;
    }
    int Write(apacket* p);
    void Kick();

    // ConnectionState can be read by all threads, but can only be written in the main thread.
    ConnectionState GetConnectionState() const;
    void SetConnectionState(ConnectionState state);

    int fd = -1;
    int transport_socket = -1;
    fdevent transport_fde;
    std::atomic<size_t> ref_count;
    uint32_t sync_token = 0;
    bool online = false;
    TransportType type = kTransportAny;

    // USB handle or socket fd as needed.
    usb_handle* usb = nullptr;
    int sfd = -1;

    // Used to identify transports for clients.
    char* serial = nullptr;
    char* product = nullptr;
    char* model = nullptr;
    char* device = nullptr;
    char* devpath = nullptr;
    void SetLocalPortForEmulator(int port) {
        CHECK_EQ(local_port_for_emulator_, -1);
        local_port_for_emulator_ = port;
    }

    bool GetLocalPortForEmulator(int* port) const {
        if (type == kTransportLocal && local_port_for_emulator_ != -1) {
            *port = local_port_for_emulator_;
            return true;
        }
        return false;
    }

    bool IsTcpDevice() const {
        return type == kTransportLocal && local_port_for_emulator_ == -1;
    }

#if ADB_HOST
    std::shared_ptr<RSA> NextKey();
    bool SetSendConnectOnError();
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
    int local_port_for_emulator_ = -1;
    bool kicked_ = false;
    void (*kick_func_)(atransport*) = nullptr;
    int (*write_func_)(apacket*, atransport*) = nullptr;

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
    std::mutex write_msg_lock_;
    bool has_send_connect_on_error_ = false;
#endif

    DISALLOW_COPY_AND_ASSIGN(atransport);
};

/*
 * Obtain a transport from the available transports.
 * If serial is non-null then only the device with that serial will be chosen.
 * If multiple devices/emulators would match, *is_ambiguous (if non-null)
 * is set to true and nullptr returned.
 * If no suitable transport is found, error is set and nullptr returned.
 */
atransport* acquire_one_transport(TransportType type, const char* serial, bool* is_ambiguous,
                                  std::string* error_out, bool accept_any_state = false);
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
bool check_data(apacket* p);

void close_usb_devices();
void close_usb_devices(std::function<bool(const atransport*)> predicate);

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(void);

#endif   /* __TRANSPORT_H */
