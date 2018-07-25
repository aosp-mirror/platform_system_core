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

#include <thread>

#include <android-base/stringprintf.h>
#include <dns_sd.h>

#include "adb_mdns.h"
#include "adb_trace.h"
#include "fdevent.h"
#include "sysdeps.h"

static DNSServiceRef service_ref;
static fdevent* service_ref_fde;

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

        DNSServiceRefDeallocate(sdRef_);
        fdevent_destroy(fde_);
    }

  protected:
    DNSServiceRef sdRef_;

    void Initialize() {
        fde_ = fdevent_create(adb_DNSServiceRefSockFD(sdRef_), pump_service_ref, &sdRef_);
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

    ResolvedService(std::string name, uint32_t interfaceIndex,
                    const char* hosttarget, uint16_t port) :
            name_(name),
            port_(port) {

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
    }

    void Connect(const sockaddr* address) {
        char ip_addr[INET6_ADDRSTRLEN];
        const void* ip_addr_data;
        const char* addr_format;

        if (address->sa_family == AF_INET) {
            ip_addr_data =
                &reinterpret_cast<const sockaddr_in*>(address)->sin_addr;
            addr_format = "%s:%hu";
        } else if (address->sa_family == AF_INET6) {
            ip_addr_data =
                &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr;
            addr_format = "[%s]:%hu";
        } else { // Should be impossible
            D("mDNS resolved non-IP address.");
            return;
        }

        // Winsock version requires the const cast Because Microsoft.
        if (!inet_ntop(address->sa_family, const_cast<void*>(ip_addr_data),
                       ip_addr, INET6_ADDRSTRLEN)) {
            D("Could not convert IP address to string.");
            return;
        }

        std::string response;
        connect_device(android::base::StringPrintf(addr_format, ip_addr, port_),
                       &response);
        D("Connect to %s (%s:%hu) : %s", name_.c_str(), ip_addr, port_,
          response.c_str());
    }

  private:
    std::string name_;
    const uint16_t port_;
};

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
    DiscoveredService(uint32_t interfaceIndex, const char* serviceName,
                      const char* regtype, const char* domain)
        : serviceName_(serviceName) {

        DNSServiceErrorType ret =
            DNSServiceResolve(&sdRef_, 0, interfaceIndex, serviceName, regtype,
                              domain, register_resolved_mdns_service,
                              reinterpret_cast<void*>(this));

        if (ret != kDNSServiceErr_NoError) {
            D("Got %d from DNSServiceResolve.", ret);
        } else {
            Initialize();
        }
    }

    const char* ServiceName() {
        return serviceName_.c_str();
    }

  private:
    std::string serviceName_;
};

static void DNSSD_API register_resolved_mdns_service(DNSServiceRef sdRef,
                                                     DNSServiceFlags flags,
                                                     uint32_t interfaceIndex,
                                                     DNSServiceErrorType errorCode,
                                                     const char* fullname,
                                                     const char* hosttarget,
                                                     uint16_t port,
                                                     uint16_t /*txtLen*/,
                                                     const unsigned char* /*txtRecord*/,
                                                     void* context) {
    D("Resolved a service.");
    std::unique_ptr<DiscoveredService> discovered(
        reinterpret_cast<DiscoveredService*>(context));

    if (errorCode != kDNSServiceErr_NoError) {
        D("Got error %d resolving service.", errorCode);
        return;
    }


    auto resolved =
        new ResolvedService(discovered->ServiceName(),
                            interfaceIndex, hosttarget, ntohs(port));

    if (! resolved->Initialized()) {
        delete resolved;
    }

    if (flags) { /* Only ever equals MoreComing or 0 */
        discovered.release();
    }
}

static void DNSSD_API register_mdns_transport(DNSServiceRef sdRef,
                                              DNSServiceFlags flags,
                                              uint32_t interfaceIndex,
                                              DNSServiceErrorType errorCode,
                                              const char* serviceName,
                                              const char* regtype,
                                              const char* domain,
                                              void*  /*context*/) {
    D("Registering a transport.");
    if (errorCode != kDNSServiceErr_NoError) {
        D("Got error %d during mDNS browse.", errorCode);
        DNSServiceRefDeallocate(sdRef);
        fdevent_destroy(service_ref_fde);
        return;
    }

    auto discovered = new DiscoveredService(interfaceIndex, serviceName, regtype, domain);
    if (!discovered->Initialized()) {
        delete discovered;
    }
}

void init_mdns_transport_discovery_thread(void) {
    DNSServiceErrorType errorCode = DNSServiceBrowse(&service_ref, 0, 0, kADBServiceType, nullptr,
                                                     register_mdns_transport, nullptr);

    if (errorCode != kDNSServiceErr_NoError) {
        D("Got %d initiating mDNS browse.", errorCode);
        return;
    }

    fdevent_run_on_main_thread([]() {
        service_ref_fde =
            fdevent_create(adb_DNSServiceRefSockFD(service_ref), pump_service_ref, &service_ref);
        fdevent_set(service_ref_fde, FDE_READ);
    });
}

void init_mdns_transport_discovery(void) {
    std::thread(init_mdns_transport_discovery_thread).detach();
}
