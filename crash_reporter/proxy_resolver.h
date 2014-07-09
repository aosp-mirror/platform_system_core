// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_PROXY_RESOLVER_H_
#define CRASH_REPORTER_PROXY_RESOLVER_H_

#include <string>
#include <vector>

#include <dbus/bus.h>
#include <dbus/object_proxy.h>

namespace base {
class TimeDelta;
}  // namespace base

namespace crash_reporter {

class ProxyResolver {
 public:
  virtual ~ProxyResolver() {}

  virtual std::vector<std::string> GetProxiesForUrl(
      const std::string& url, const base::TimeDelta& timeout) = 0;
};

class DBusProxyResolver : public ProxyResolver {
 public:
  explicit DBusProxyResolver(dbus::Bus* bus);
  ~DBusProxyResolver() override = default;

  void Init();

  std::vector<std::string> GetProxiesForUrl(
      const std::string& url, const base::TimeDelta& timeout) override;

 private:
  scoped_refptr<dbus::Bus> bus_;
  scoped_refptr<dbus::ObjectProxy> lib_cros_service_proxy_;
};

}  // namespace crash_reporter

#endif  // CRASH_REPORTER_PROXY_RESOLVER_H_
