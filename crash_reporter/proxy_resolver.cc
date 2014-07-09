// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/proxy_resolver.h"

#include <chromeos/dbus/dbus_method_invoker.h>

#include "crash-reporter/libproxies.h"

namespace crash_reporter {

DBusProxyResolver::DBusProxyResolver(dbus::Bus* bus) : bus_(bus) {}

void DBusProxyResolver::Init() {
  lib_cros_service_proxy_ = bus_->GetObjectProxy(
      kLibCrosServiceName, dbus::ObjectPath(kLibCrosServicePath));
  if (!lib_cros_service_proxy_) {
    LOG(WARNING) << "Unable to connect to LibCrosService.";
  }
}

std::vector<std::string> DBusProxyResolver::GetProxiesForUrl(
    const std::string& url, const base::TimeDelta& timeout) {
  if (!lib_cros_service_proxy_) return {kNoProxy};

  auto response = chromeos::dbus_utils::CallMethodAndBlockWithTimeout(
      timeout.InMilliseconds(), lib_cros_service_proxy_,
      kLibCrosProxyResolveSignalInterface,
      kLibCrosServiceResolveNetworkProxyMethodName, url);
  if (response) {
    std::string returned_message;
    if (chromeos::dbus_utils::ExtractMethodCallResults(response.get(), nullptr,
                                                       &returned_message)) {
      return ParseProxyString(returned_message);
    }
  }
  return {kNoProxy};
}

}  // namespace crash_reporter
