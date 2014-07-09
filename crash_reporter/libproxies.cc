// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/libproxies.h"

#include <algorithm>

#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <chromeos/strings/string_utils.h>

namespace crash_reporter {

const char kLibCrosProxyResolveSignalInterface[] =
    "org.chromium.CrashReporterLibcrosProxyResolvedInterface";
const char kLibCrosProxyResolveName[] = "ProxyResolved";
const char kLibCrosServiceInterface[] = "org.chromium.LibCrosServiceInterface";
const char kLibCrosServiceName[] = "org.chromium.LibCrosService";
const char kLibCrosServicePath[] = "/org/chromium/LibCrosService";
const char kLibCrosServiceResolveNetworkProxyMethodName[] =
    "ResolveNetworkProxy";
const char kNoProxy[] = "direct://";

std::vector<std::string> ParseProxyString(const std::string& input) {
  std::vector<std::string> ret;
  // Some of this code taken from
  // https://chromium.googlesource.com/chromium/chromium/+/master/net/proxy
  for (const std::string& token : chromeos::string_utils::Split(input, ';')) {
    auto space =
        std::find_if(token.begin(), token.end(), IsAsciiWhitespace<char>);
    std::string scheme(token.begin(), space);
    base::StringToLowerASCII(&scheme);
    // Chrome uses "socks" to mean socks4 and "proxy" to mean http.
    if (scheme == "socks") {
      scheme += "4";
    } else if (scheme == "proxy") {
      scheme = "http";
    } else if (scheme != "https" && scheme != "socks4" && scheme != "socks5" &&
               scheme != "direct") {
      continue;  // Invalid proxy scheme
    }

    std::string host_and_port = std::string(space, token.end());
    base::TrimWhitespaceASCII(host_and_port, base::TRIM_ALL, &host_and_port);
    if (scheme != "direct" && host_and_port.empty())
      continue;  // Must supply host/port when non-direct proxy used.

    ret.push_back(scheme + "://" + host_and_port);
  }
  if (ret.empty() || ret.back() != kNoProxy)
    ret.push_back(kNoProxy);

  return ret;
}

}  // namespace crash_reporter
