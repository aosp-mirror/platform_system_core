/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "transport.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <memory>
#include <thread>
#include <unordered_set>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <dns_sd.h>

#include "adb_client.h"
#include "adb_mdns.h"
#include "adb_trace.h"
#include "adb_utils.h"
#include "adb_wifi.h"
#include "fdevent/fdevent.h"
#include "sysdeps.h"

static DNSServiceRef service_refs[kNumADBDNSServices];
static fdevent* service_ref_fdes[kNumADBDNSServices];
static auto& g_autoconn_whitelist = *new std::unordered_set<int>();

static int adb_DNSServiceIndexByName(std::string_view regType) {
    for (int i = 0; i < kNumADBDNSServices; ++i) {
        if (!strncmp(regType.data(), kADBDNSServices[i], strlen(kADBDNSServices[i]))) {
            return i;
        }
    }
    return -1;
}

static void config_auto_connect_services() {
    // ADB_MDNS_AUTO_CONNECT is a comma-delimited list of mdns services
    // that are allowed to auto-connect. By default, only allow "adb-tls-connect"
    // to auto-connect, since this is filtered down to auto-connect only to paired
    // devices.
    g_autoconn_whitelist.insert(kADBSecureConnectServiceRefIndex);
    const char* srvs = getenv("ADB_MDNS_AUTO_CONNECT");
    if (!srvs) {
        return;
    }

    if (strcmp(srvs, "0") == 0) {
        D("Disabling all auto-connecting");
        g_autoconn_whitelist.clear();
        return;
    }

    if (strcmp(srvs, "1") == 0) {
        D("Allow all auto-connecting");
        g_autoconn_whitelist.insert(kADBTransportServiceRefIndex);
        return;
    }

    // Selectively choose which services to allow auto-connect.
    // E.g. ADB_MDNS_AUTO_CONNECT=adb,adb-tls-connect would allow
    // _adb._tcp and _adb-tls-connnect._tcp services to auto-connect.
    auto srvs_list = android::base::Split(srvs, ",");
    std::unordered_set<int> new_whitelist;
    for (const auto& item : srvs_list) {
        auto full_srv = android::base::StringPrintf("_%s._tcp", item.data());
        int idx = adb_DNSServiceIndexByName(full_srv);
        if (idx >= 0) {
            new_whitelist.insert(idx);
        }
    }

    if (!new_whitelist.empty()) {
        g_autoconn_whitelist = std::move(new_whitelist);
    }
}

static bool adb_DNSServiceShouldAutoConnect(const char* regType, const char* serviceName) {
    // Try to auto-connect to any "_adb" or "_adb-tls-connect" services excluding emulator services.
    int index = adb_DNSServiceIndexByName(regType);
    if (index != kADBTransportServiceRefIndex && index != kADBSecureConnectServiceRefIndex) {
        return false;
    }
    if (g_autoconn_whitelist.find(index) == g_autoconn_whitelist.end()) {
        D("Auto-connect for regType '%s' disabled", regType);
        return false;
    }
    // Ignore adb-EMULATOR* service names, as it interferes with the
    // emulator ports that are already connected.
    if (android::base::StartsWith(serviceName, "adb-EMULATOR")) {
        LOG(INFO) << "Ignoring emulator transport service [" << serviceName << "]";
        return false;
    }
    return true;
}

// Use adb_DNSServiceRefSockFD() instead of calling DNSServiceRefSockFD()
// directly so that the socket is put through the appropriate compatibility
// layers to work with the rest of ADB's internal APIs.
static inline int adb_DNSServiceRefSockFD(DNSServiceRef ref) {
    return adb_register_socket(DNSServiceRefSockFD(ref));
}
#define DNSServiceRefSockFD ___xxx_DNSServiceRefSockFD

static void DNSSD_API register_service_ip(DNSServiceRef sdRef,
                                          DNSServiceFlags flags,
                                          uint32_t interfaceIndex,
                                          DNSServiceErrorType errorCode,
                                          const char* hostname,
                                          const sockaddr* address,
                                          uint32_t ttl,
                                          void* context);

static void pump_service_ref(int /*fd*/, unsigned ev, void* data) {
    DNSServiceRef* ref = reinterpret_cast<DNSServiceRef*>(data);

    if (ev & FDE_READ)
        DNSServiceProcessResult(*ref);
}

class AsyncServiceRef {
  public:
    bool Initialized() {
        return initialized_;
    }

    virtual ~AsyncServiceRef() {
        if (!initialized_) {
            return;
        }

        // Order matters here! Must destroy the fdevent first since it has a
        // reference to |sdRef_|.
        fdevent_destroy(fde_);
        DNSServiceRefDeallocate(sdRef_);
    }

  protected:
    DNSServiceRef sdRef_;

    void Initialize() {
        fde_ = fdevent_create(adb_DNSServiceRefSockFD(sdRef_), pump_service_ref, &sdRef_);
        if (fde_ == nullptr) {
            D("Unable to create fdevent");
            return;
        }
        fdevent_set(fde_, FDE_READ);
        initialized_ = true;
    }

  private:
    bool initialized_ = false;
    fdevent* fde_;
};

class ResolvedService : public AsyncServiceRef {
  public:
    virtual ~ResolvedService() = default;

    ResolvedService(std::string serviceName, std::string regType, uint32_t interfaceIndex,
                    const char* hosttarget, uint16_t port, int version)
        : serviceName_(serviceName),
          regType_(regType),
          hosttarget_(hosttarget),
          port_(port),
          sa_family_(0),
          ip_addr_data_(NULL),
          serviceVersion_(version) {
        memset(ip_addr_, 0, sizeof(ip_addr_));

        /* TODO: We should be able to get IPv6 support by adding
         * kDNSServiceProtocol_IPv6 to the flags below. However, when we do
         * this, we get served link-local addresses that are usually useless to
         * connect to. What's more, we seem to /only/ get those and nothing else.
         * If we want IPv6 in the future we'll have to figure out why.
         */
        DNSServiceErrorType ret =
            DNSServiceGetAddrInfo(
                &sdRef_, 0, interfaceIndex,
                kDNSServiceProtocol_IPv4, hosttarget,
                register_service_ip, reinterpret_cast<void*>(this));

        if (ret != kDNSServiceErr_NoError) {
            D("Got %d from DNSServiceGetAddrInfo.", ret);
        } else {
            Initialize();
        }

        D("Client version: %d Service version: %d\n", clientVersion_, serviceVersion_);
    }

    bool ConnectSecureWifiDevice() {
        if (!adb_wifi_is_known_host(serviceName_)) {
            LOG(INFO) << "serviceName=" << serviceName_ << " not in keystore";
            return false;
        }

        std::string response;
        connect_device(android::base::StringPrintf(addr_format_.c_str(), ip_addr_, port_),
                       &response);
        D("Secure connect to %s regtype %s (%s:%hu) : %s", serviceName_.c_str(), regType_.c_str(),
          ip_addr_, port_, response.c_str());
        return true;
    }

    void Connect(const sockaddr* address) {
        sa_family_ = address->sa_family;

        if (sa_family_ == AF_INET) {
            ip_addr_data_ = &reinterpret_cast<const sockaddr_in*>(address)->sin_addr;
            addr_format_ = "%s:%hu";
        } else if (sa_family_ == AF_INET6) {
            ip_addr_data_ = &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
            addr_format_ = "[%s]:%hu";
        } else {  // Should be impossible
            D("mDNS resolved non-IP address.");
            return;
        }

        // Winsock version requires the const cast Because Microsoft.
        if (!inet_ntop(sa_family_, const_cast<void*>(ip_addr_data_), ip_addr_, sizeof(ip_addr_))) {
            D("Could not convert IP address to string.");
            return;
        }

        // adb secure service needs to do something different from just
        // connecting here.
        if (adb_DNSServiceShouldAutoConnect(regType_.c_str(), serviceName_.c_str())) {
            std::string response;
            D("Attempting to serviceName=[%s], regtype=[%s] ipaddr=(%s:%hu)", serviceName_.c_str(),
              regType_.c_str(), ip_addr_, port_);
            int index = adb_DNSServiceIndexByName(regType_.c_str());
            if (index == kADBSecureConnectServiceRefIndex) {
                ConnectSecureWifiDevice();
            } else {
                connect_device(android::base::StringPrintf(addr_format_.c_str(), ip_addr_, port_),
                               &response);
                D("Connect to %s regtype %s (%s:%hu) : %s", serviceName_.c_str(), regType_.c_str(),
                  ip_addr_, port_, response.c_str());
            }
        } else {
            D("Not immediately connecting to serviceName=[%s], regtype=[%s] ipaddr=(%s:%hu)",
              serviceName_.c_str(), regType_.c_str(), ip_addr_, port_);
        }

        int adbSecureServiceType = serviceIndex();
        switch (adbSecureServiceType) {
            case kADBTransportServiceRefIndex:
                sAdbTransportServices->push_back(this);
                break;
            case kADBSecurePairingServiceRefIndex:
                sAdbSecurePairingServices->push_back(this);
                break;
            case kADBSecureConnectServiceRefIndex:
                sAdbSecureConnectServices->push_back(this);
                break;
            default:
                break;
        }
    }

    int serviceIndex() const { return adb_DNSServiceIndexByName(regType_.c_str()); }

    std::string hostTarget() const { return hosttarget_; }

    std::string serviceName() const { return serviceName_; }

    std::string regType() const { return regType_; }

    std::string ipAddress() const { return ip_addr_; }

    uint16_t port() const { return port_; }

    using ServiceRegistry = std::vector<ResolvedService*>;

    // unencrypted tcp connections
    static ServiceRegistry* sAdbTransportServices;

    static ServiceRegistry* sAdbSecurePairingServices;
    static ServiceRegistry* sAdbSecureConnectServices;

    static void initAdbServiceRegistries();

    static void forEachService(const ServiceRegistry& services, const std::string& hostname,
                               adb_secure_foreach_service_callback cb);

    static bool connectByServiceName(const ServiceRegistry& services,
                                     const std::string& service_name);

  private:
    int clientVersion_ = ADB_SECURE_CLIENT_VERSION;
    std::string addr_format_;
    std::string serviceName_;
    std::string regType_;
    std::string hosttarget_;
    const uint16_t port_;
    int sa_family_;
    const void* ip_addr_data_;
    char ip_addr_[INET6_ADDRSTRLEN];
    int serviceVersion_;
};

// static
std::vector<ResolvedService*>* ResolvedService::sAdbTransportServices = NULL;

// static
std::vector<ResolvedService*>* ResolvedService::sAdbSecurePairingServices = NULL;

// static
std::vector<ResolvedService*>* ResolvedService::sAdbSecureConnectServices = NULL;

// static
void ResolvedService::initAdbServiceRegistries() {
    if (!sAdbTransportServices) {
        sAdbTransportServices = new ServiceRegistry;
    }
    if (!sAdbSecurePairingServices) {
        sAdbSecurePairingServices = new ServiceRegistry;
    }
    if (!sAdbSecureConnectServices) {
        sAdbSecureConnectServices = new ServiceRegistry;
    }
}

// static
void ResolvedService::forEachService(const ServiceRegistry& services,
                                     const std::string& wanted_service_name,
                                     adb_secure_foreach_service_callback cb) {
    initAdbServiceRegistries();

    for (auto service : services) {
        auto service_name = service->serviceName();
        auto reg_type = service->regType();
        auto ip = service->ipAddress();
        auto port = service->port();

        if (wanted_service_name == "") {
            cb(service_name.c_str(), reg_type.c_str(), ip.c_str(), port);
        } else if (service_name == wanted_service_name) {
            cb(service_name.c_str(), reg_type.c_str(), ip.c_str(), port);
        }
    }
}

// static
bool ResolvedService::connectByServiceName(const ServiceRegistry& services,
                                           const std::string& service_name) {
    initAdbServiceRegistries();
    for (auto service : services) {
        if (service_name == service->serviceName()) {
            D("Got service_name match [%s]", service->serviceName().c_str());
            return service->ConnectSecureWifiDevice();
        }
    }
    D("No registered serviceNames matched [%s]", service_name.c_str());
    return false;
}

void adb_secure_foreach_pairing_service(const char* service_name,
                                        adb_secure_foreach_service_callback cb) {
    ResolvedService::forEachService(*ResolvedService::sAdbSecurePairingServices,
                                    service_name ? service_name : "", cb);
}

void adb_secure_foreach_connect_service(const char* service_name,
                                        adb_secure_foreach_service_callback cb) {
    ResolvedService::forEachService(*ResolvedService::sAdbSecureConnectServices,
                                    service_name ? service_name : "", cb);
}

bool adb_secure_connect_by_service_name(const char* service_name) {
    return ResolvedService::connectByServiceName(*ResolvedService::sAdbSecureConnectServices,
                                                 service_name);
}

static void DNSSD_API register_service_ip(DNSServiceRef /*sdRef*/,
                                          DNSServiceFlags /*flags*/,
                                          uint32_t /*interfaceIndex*/,
                                          DNSServiceErrorType /*errorCode*/,
                                          const char* /*hostname*/,
                                          const sockaddr* address,
                                          uint32_t /*ttl*/,
                                          void* context) {
    D("Got IP for service.");
    std::unique_ptr<ResolvedService> data(
        reinterpret_cast<ResolvedService*>(context));
    data->Connect(address);

    // For ADB Secure services, keep those ResolvedService's around
    // for later processing with secure connection establishment.
    if (data->serviceIndex() != kADBTransportServiceRefIndex) {
        data.release();
    }
}

static void DNSSD_API register_resolved_mdns_service(DNSServiceRef sdRef,
                                                     DNSServiceFlags flags,
                                                     uint32_t interfaceIndex,
                                                     DNSServiceErrorType errorCode,
                                                     const char* fullname,
                                                     const char* hosttarget,
                                                     uint16_t port,
                                                     uint16_t txtLen,
                                                     const unsigned char* txtRecord,
                                                     void* context);

class DiscoveredService : public AsyncServiceRef {
  public:
    DiscoveredService(uint32_t interfaceIndex, const char* serviceName, const char* regtype,
                      const char* domain)
        : serviceName_(serviceName), regType_(regtype) {
        DNSServiceErrorType ret =
            DNSServiceResolve(&sdRef_, 0, interfaceIndex, serviceName, regtype,
                              domain, register_resolved_mdns_service,
                              reinterpret_cast<void*>(this));

        D("DNSServiceResolve for "
          "interfaceIndex %u "
          "serviceName %s "
          "regtype %s "
          "domain %s "
          ": %d",
          interfaceIndex, serviceName, regtype, domain, ret);

        if (ret == kDNSServiceErr_NoError) {
            Initialize();
        }
    }

    const char* ServiceName() {
        return serviceName_.c_str();
    }

    const char* RegType() { return regType_.c_str(); }

  private:
    std::string serviceName_;
    std::string regType_;
};

static void adb_RemoveDNSService(const char* regType, const char* serviceName) {
    int index = adb_DNSServiceIndexByName(regType);
    ResolvedService::ServiceRegistry* services;
    switch (index) {
        case kADBTransportServiceRefIndex:
            services = ResolvedService::sAdbTransportServices;
            break;
        case kADBSecurePairingServiceRefIndex:
            services = ResolvedService::sAdbSecurePairingServices;
            break;
        case kADBSecureConnectServiceRefIndex:
            services = ResolvedService::sAdbSecureConnectServices;
            break;
        default:
            return;
    }

    std::string sName(serviceName);
    services->erase(std::remove_if(
            services->begin(), services->end(),
            [&sName](ResolvedService* service) { return (sName == service->serviceName()); }));
}

// Returns the version the device wanted to advertise,
// or -1 if parsing fails.
static int parse_version_from_txt_record(uint16_t txtLen, const unsigned char* txtRecord) {
    if (!txtLen) return -1;
    if (!txtRecord) return -1;

    // https://tools.ietf.org/html/rfc6763
    // """
    // 6.1.  General Format Rules for DNS TXT Records
    //
    // A DNS TXT record can be up to 65535 (0xFFFF) bytes long.  The total
    // length is indicated by the length given in the resource record header
    // in the DNS message.  There is no way to tell directly from the data
    // alone how long it is (e.g., there is no length count at the start, or
    // terminating NULL byte at the end).
    // """

    // Let's trust the TXT record's length byte
    // Worst case, it wastes 255 bytes
    std::vector<char> recordAsString(txtLen + 1, '\0');
    char* str = recordAsString.data();

    memcpy(str, txtRecord + 1 /* skip the length byte */, txtLen);

    // Check if it's the version key
    static const char* versionKey = "v=";
    size_t versionKeyLen = strlen(versionKey);

    if (strncmp(versionKey, str, versionKeyLen)) return -1;

    auto valueStart = str + versionKeyLen;

    long parsedNumber = strtol(valueStart, 0, 10);

    // No valid conversion. Also, 0
    // is not a valid version.
    if (!parsedNumber) return -1;

    // Outside bounds of long.
    if (parsedNumber == LONG_MIN || parsedNumber == LONG_MAX) return -1;

    // Possibly valid version
    return static_cast<int>(parsedNumber);
}

static void DNSSD_API register_resolved_mdns_service(
        DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex,
        DNSServiceErrorType errorCode, const char* fullname, const char* hosttarget, uint16_t port,
        uint16_t txtLen, const unsigned char* txtRecord, void* context) {
    D("Resolved a service.");
    std::unique_ptr<DiscoveredService> discovered(
        reinterpret_cast<DiscoveredService*>(context));

    if (errorCode != kDNSServiceErr_NoError) {
        D("Got error %d resolving service.", errorCode);
        return;
    }

    // TODO: Reject certain combinations of invalid or mismatched client and
    // service versions here before creating anything.
    // At the moment, there is nothing to reject, so accept everything
    // as an optimistic default.
    auto serviceVersion = parse_version_from_txt_record(txtLen, txtRecord);

    auto resolved = new ResolvedService(discovered->ServiceName(), discovered->RegType(),
                                        interfaceIndex, hosttarget, ntohs(port), serviceVersion);

    if (! resolved->Initialized()) {
        D("Unable to init resolved service");
        delete resolved;
    }

    if (flags) { /* Only ever equals MoreComing or 0 */
        D("releasing discovered service");
        discovered.release();
    }
}

static void DNSSD_API on_service_browsed(DNSServiceRef sdRef, DNSServiceFlags flags,
                                         uint32_t interfaceIndex, DNSServiceErrorType errorCode,
                                         const char* serviceName, const char* regtype,
                                         const char* domain, void* /*context*/) {
    if (errorCode != kDNSServiceErr_NoError) {
        D("Got error %d during mDNS browse.", errorCode);
        DNSServiceRefDeallocate(sdRef);
        int serviceIndex = adb_DNSServiceIndexByName(regtype);
        if (serviceIndex != -1) {
            fdevent_destroy(service_ref_fdes[serviceIndex]);
        }
        return;
    }

    if (flags & kDNSServiceFlagsAdd) {
        D("%s: Discover found new serviceName=[%s] regtype=[%s] domain=[%s]", __func__, serviceName,
          regtype, domain);
        auto discovered = new DiscoveredService(interfaceIndex, serviceName, regtype, domain);
        if (!discovered->Initialized()) {
            delete discovered;
        }
    } else {
        D("%s: Discover lost serviceName=[%s] regtype=[%s] domain=[%s]", __func__, serviceName,
          regtype, domain);
        adb_RemoveDNSService(regtype, serviceName);
    }
}

void init_mdns_transport_discovery_thread(void) {
    config_auto_connect_services();
    std::string res;
    std::for_each(g_autoconn_whitelist.begin(), g_autoconn_whitelist.end(), [&](const int& i) {
        res += kADBDNSServices[i];
        res += ",";
    });
    D("mdns auto-connect whitelist: [%s]", res.data());

    int errorCodes[kNumADBDNSServices];
    for (int i = 0; i < kNumADBDNSServices; ++i) {
        errorCodes[i] = DNSServiceBrowse(&service_refs[i], 0, 0, kADBDNSServices[i], nullptr,
                                         on_service_browsed, nullptr);

        if (errorCodes[i] != kDNSServiceErr_NoError) {
            D("Got %d browsing for mDNS service %s.", errorCodes[i], kADBDNSServices[i]);
        }

        if (errorCodes[i] == kDNSServiceErr_NoError) {
            fdevent_run_on_main_thread([i]() {
                service_ref_fdes[i] = fdevent_create(adb_DNSServiceRefSockFD(service_refs[i]),
                                                     pump_service_ref, &service_refs[i]);
                fdevent_set(service_ref_fdes[i], FDE_READ);
            });
        }
    }
}

void init_mdns_transport_discovery(void) {
    ResolvedService::initAdbServiceRegistries();
    std::thread(init_mdns_transport_discovery_thread).detach();
}

std::string mdns_check() {
    uint32_t daemon_version;
    uint32_t sz = sizeof(daemon_version);

    auto dnserr = DNSServiceGetProperty(kDNSServiceProperty_DaemonVersion, &daemon_version, &sz);
    std::string result = "ERROR: mdns daemon unavailable";
    if (dnserr != kDNSServiceErr_NoError) {
        return result;
    }

    result = android::base::StringPrintf("mdns daemon version [%u]", daemon_version);
    return result;
}

std::string mdns_list_discovered_services() {
    std::string result;
    auto cb = [&](const char* service_name, const char* reg_type, const char* ip_addr,
                  uint16_t port) {
        result += android::base::StringPrintf("%s\t%s\t%s:%u\n", service_name, reg_type, ip_addr,
                                              port);
    };

    ResolvedService::forEachService(*ResolvedService::sAdbTransportServices, "", cb);
    ResolvedService::forEachService(*ResolvedService::sAdbSecureConnectServices, "", cb);
    ResolvedService::forEachService(*ResolvedService::sAdbSecurePairingServices, "", cb);
    return result;
}
