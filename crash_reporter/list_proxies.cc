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

#include <sysexits.h>
#include <unistd.h>  // for isatty()

#include <string>
#include <vector>

#include <base/cancelable_callback.h>
#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/memory/weak_ptr.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_tokenizer.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/daemons/dbus_daemon.h>
#include <brillo/syslog_logging.h>

#include "libcrosservice/dbus-proxies.h"

using std::unique_ptr;

namespace {

const char kLibCrosProxyResolvedSignalInterface[] =
    "org.chromium.CrashReporterLibcrosProxyResolvedInterface";
const char kLibCrosProxyResolvedName[] = "ProxyResolved";
const char kLibCrosServiceName[] = "org.chromium.LibCrosService";
const char kNoProxy[] = "direct://";

const int kTimeoutDefaultSeconds = 5;

const char kHelp[] = "help";
const char kQuiet[] = "quiet";
const char kTimeout[] = "timeout";
const char kVerbose[] = "verbose";
// Help message to show when the --help command line switch is specified.
const char kHelpMessage[] =
    "Chromium OS Crash helper: proxy lister\n"
    "\n"
    "Available Switches:\n"
    "  --quiet      Only print the proxies\n"
    "  --verbose    Print additional messages even when not run from a TTY\n"
    "  --timeout=N  Set timeout for browser resolving proxies (default is 5)\n"
    "  --help       Show this help.\n";

// Copied from src/update_engine/chrome_browser_proxy_resolver.cc
// Parses the browser's answer for resolved proxies.  It returns a
// list of strings, each of which is a resolved proxy.
std::vector<std::string> ParseProxyString(const std::string& input) {
  std::vector<std::string> ret;
  // Some of this code taken from
  // http://src.chromium.org/svn/trunk/src/net/proxy/proxy_server.cc and
  // http://src.chromium.org/svn/trunk/src/net/proxy/proxy_list.cc
  base::StringTokenizer entry_tok(input, ";");
  while (entry_tok.GetNext()) {
    std::string token = entry_tok.token();
    base::TrimWhitespaceASCII(token, base::TRIM_ALL, &token);

    // Start by finding the first space (if any).
    std::string::iterator space;
    for (space = token.begin(); space != token.end(); ++space) {
      if (base::IsAsciiWhitespace(*space)) {
        break;
      }
    }

    std::string scheme = base::ToLowerASCII(std::string(token.begin(), space));
    // Chrome uses "socks" to mean socks4 and "proxy" to mean http.
    if (scheme == "socks")
      scheme += "4";
    else if (scheme == "proxy")
      scheme = "http";
    else if (scheme != "https" &&
             scheme != "socks4" &&
             scheme != "socks5" &&
             scheme != "direct")
      continue;  // Invalid proxy scheme

    std::string host_and_port = std::string(space, token.end());
    base::TrimWhitespaceASCII(host_and_port, base::TRIM_ALL, &host_and_port);
    if (scheme != "direct" && host_and_port.empty())
      continue;  // Must supply host/port when non-direct proxy used.
    ret.push_back(scheme + "://" + host_and_port);
  }
  if (ret.empty() || *ret.rbegin() != kNoProxy)
    ret.push_back(kNoProxy);
  return ret;
}

// A class for interfacing with Chrome to resolve proxies for a given source
// url.  The class is initialized with the given source url to check, the
// signal interface and name that Chrome will reply to, and how long to wait
// for the resolve request to timeout.  Once initialized, the Run() function
// must be called, which blocks on the D-Bus call to Chrome.  The call returns
// after either the timeout or the proxy has been resolved.  The resolved
// proxies can then be accessed through the proxies() function.
class ProxyResolver : public brillo::DBusDaemon {
 public:
  ProxyResolver(const std::string& source_url,
                const std::string& signal_interface,
                const std::string& signal_name,
                base::TimeDelta timeout)
      : source_url_(source_url),
        signal_interface_(signal_interface),
        signal_name_(signal_name),
        timeout_(timeout),
        weak_ptr_factory_(this),
        timeout_callback_(base::Bind(&ProxyResolver::HandleBrowserTimeout,
                                     weak_ptr_factory_.GetWeakPtr())) {}

  ~ProxyResolver() override {}

  const std::vector<std::string>& proxies() {
    return proxies_;
  }

  int Run() override {
    // Add task for if the browser proxy call times out.
    base::MessageLoop::current()->PostDelayedTask(
        FROM_HERE,
        timeout_callback_.callback(),
        timeout_);

    return brillo::DBusDaemon::Run();
  }

 protected:
  // If the browser times out, quit the run loop.
  void HandleBrowserTimeout() {
    LOG(ERROR) << "Timeout while waiting for browser to resolve proxy";
    Quit();
  }

  // If the signal handler connects successfully, call the browser's
  // ResolveNetworkProxy D-Bus method.  Otherwise, don't do anything and let
  // the timeout task quit the run loop.
  void HandleDBusSignalConnected(const std::string& interface,
                                 const std::string& signal,
                                 bool success) {
    if (!success) {
      LOG(ERROR) << "Could not connect to signal " << interface << "."
                 << signal;
      timeout_callback_.Cancel();
      Quit();
      return;
    }

    brillo::ErrorPtr error;
    call_proxy_->ResolveNetworkProxy(source_url_,
                                     signal_interface_,
                                     signal_name_,
                                     &error);

    if (error) {
      LOG(ERROR) << "Call to ResolveNetworkProxy failed: "
                 << error->GetMessage();
      timeout_callback_.Cancel();
      Quit();
    }
  }

  // Handle incoming ProxyResolved signal.
  void HandleProxyResolvedSignal(const std::string& source_url,
                                 const std::string& proxy_info,
                                 const std::string& error_message) {
    timeout_callback_.Cancel();
    proxies_ = ParseProxyString(proxy_info);
    LOG(INFO) << "Found proxies via browser signal: "
              << base::JoinString(proxies_, "x");

    Quit();
  }

  int OnInit() override {
    int return_code = brillo::DBusDaemon::OnInit();
    if (return_code != EX_OK)
      return return_code;

    // Initialize D-Bus proxies.
    call_proxy_.reset(
        new org::chromium::LibCrosServiceInterfaceProxy(bus_,
                                                        kLibCrosServiceName));
    signal_proxy_.reset(
        new org::chromium::CrashReporterLibcrosProxyResolvedInterfaceProxy(
            bus_,
            kLibCrosServiceName));

    // Set up the D-Bus signal handler.
    // TODO(crbug.com/446115): Update ResolveNetworkProxy call to use an
    //     asynchronous return value rather than a return signal.
    signal_proxy_->RegisterProxyResolvedSignalHandler(
        base::Bind(&ProxyResolver::HandleProxyResolvedSignal,
                   weak_ptr_factory_.GetWeakPtr()),
        base::Bind(&ProxyResolver::HandleDBusSignalConnected,
                   weak_ptr_factory_.GetWeakPtr()));

    return EX_OK;
  }

 private:
  unique_ptr<org::chromium::LibCrosServiceInterfaceProxy> call_proxy_;
  unique_ptr<org::chromium::CrashReporterLibcrosProxyResolvedInterfaceProxy>
      signal_proxy_;

  const std::string source_url_;
  const std::string signal_interface_;
  const std::string signal_name_;
  base::TimeDelta timeout_;

  std::vector<std::string> proxies_;
  base::WeakPtrFactory<ProxyResolver> weak_ptr_factory_;

  base::CancelableClosure timeout_callback_;

  DISALLOW_COPY_AND_ASSIGN(ProxyResolver);
};

static bool ShowBrowserProxies(std::string url, base::TimeDelta timeout) {
  // Initialize and run the proxy resolver to watch for signals.
  ProxyResolver resolver(url,
                         kLibCrosProxyResolvedSignalInterface,
                         kLibCrosProxyResolvedName,
                         timeout);
  resolver.Run();

  std::vector<std::string> proxies = resolver.proxies();

  // If proxies is empty, then the timeout was reached waiting for the proxy
  // resolved signal.  If no proxies are defined, proxies will be populated
  // with "direct://".
  if (proxies.empty())
    return false;

  for (const auto& proxy : proxies) {
    printf("%s\n", proxy.c_str());
  }
  return true;
}

}  // namespace

int main(int argc, char *argv[]) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cl = base::CommandLine::ForCurrentProcess();

  if (cl->HasSwitch(kHelp)) {
    LOG(INFO) << kHelpMessage;
    return 0;
  }

  bool quiet = cl->HasSwitch(kQuiet);
  bool verbose = cl->HasSwitch(kVerbose);

  int timeout = kTimeoutDefaultSeconds;
  std::string str_timeout = cl->GetSwitchValueASCII(kTimeout);
  if (!str_timeout.empty() && !base::StringToInt(str_timeout, &timeout)) {
    LOG(ERROR) << "Invalid timeout value: " << str_timeout;
    return 1;
  }

  // Default to logging to syslog.
  int init_flags = brillo::kLogToSyslog;
  // Log to stderr if a TTY (and "-quiet" wasn't passed), or if "-verbose"
  // was passed.

  if ((!quiet && isatty(STDERR_FILENO)) || verbose)
    init_flags |= brillo::kLogToStderr;
  brillo::InitLog(init_flags);

  std::string url;
  base::CommandLine::StringVector urls = cl->GetArgs();
  if (!urls.empty()) {
    url = urls[0];
    LOG(INFO) << "Resolving proxies for URL: " << url;
  } else {
    LOG(INFO) << "Resolving proxies without URL";
  }

  if (!ShowBrowserProxies(url, base::TimeDelta::FromSeconds(timeout))) {
    LOG(ERROR) << "Error resolving proxies via the browser";
    LOG(INFO) << "Assuming direct proxy";
    printf("%s\n", kNoProxy);
  }

  return 0;
}
