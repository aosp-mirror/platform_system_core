// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_LIBPROXIES_H_
#define CRASH_REPORTER_LIBPROXIES_H_

#include <string>
#include <vector>

namespace crash_reporter {

extern const char kLibCrosProxyResolveSignalInterface[];
extern const char kLibCrosProxyResolveName[];
extern const char kLibCrosServiceInterface[];
extern const char kLibCrosServiceName[];
extern const char kLibCrosServicePath[];
extern const char kLibCrosServiceResolveNetworkProxyMethodName[];
extern const char kNoProxy[];

// Copied from src/update_engine/chrome_browser_proxy_resolver.cc
// Parses the browser's answer for resolved proxies.  It returns a
// list of strings, each of which is a resolved proxy.
std::vector<std::string> ParseProxyString(const std::string& input);

}  // namespace crash_reporter

#endif  // CRASH_REPORTER_LIBPROXIES_H_
