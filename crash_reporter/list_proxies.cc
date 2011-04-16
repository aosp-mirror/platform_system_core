// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>  // for isatty()

#include <deque>
#include <string>

#include <dbus/dbus-glib-lowlevel.h>
#include <glib.h>

#include "base/command_line.h"
#include "base/file_util.h"
#include "base/string_tokenizer.h"
#include "base/string_util.h"
#include "base/values.h"
#include "chromeos/dbus/dbus.h"
#include "chromeos/syslog_logging.h"
#include "gflags/gflags.h"

#pragma GCC diagnostic ignored "-Wstrict-aliasing"
DEFINE_bool(quiet, false, "Only print the proxies");
// Number of seconds to wait for browser to send us a signal
DEFINE_int32(timeout, 5, "Set timeout for browser resolving proxies");
DEFINE_bool(verbose, false, "Print additional messages even "
                            "when not run from a TTY");
#pragma GCC diagnostic error "-Wstrict-aliasing"

const char kLibCrosProxyResolveSignalInterface[] =
    "org.chromium.CrashReporterLibcrosProxyResolvedInterface";
const char kLibCrosProxyResolveName[] = "ProxyResolved";
const char kLibCrosServiceInterface[] = "org.chromium.LibCrosServiceInterface";
const char kLibCrosServiceName[] = "org.chromium.LibCrosService";
const char kLibCrosServicePath[] = "/org/chromium/LibCrosService";
const char kLibCrosServiceResolveNetworkProxyMethodName[] =
    "ResolveNetworkProxy";
const char kNoProxy[] = "direct://";

static const char *GetGErrorMessage(const GError *error) {
  if (!error)
    return "Unknown error.";
  return error->message;
}

// Copied from src/update_engine/chrome_browser_proxy_resolver.cc
// Parses the browser's answer for resolved proxies.  It returns a
// list of strings, each of which is a resolved proxy.
std::deque<std::string> ParseProxyString(const std::string &input) {
  std::deque<std::string> ret;
  // Some of this code taken from
  // http://src.chromium.org/svn/trunk/src/net/proxy/proxy_server.cc and
  // http://src.chromium.org/svn/trunk/src/net/proxy/proxy_list.cc
  StringTokenizer entry_tok(input, ";");
  while (entry_tok.GetNext()) {
    std::string token = entry_tok.token();
    TrimWhitespaceASCII(token, TRIM_ALL, &token);

    // Start by finding the first space (if any).
    std::string::iterator space;
    for (space = token.begin(); space != token.end(); ++space) {
      if (IsAsciiWhitespace(*space)) {
        break;
      }
    }

    std::string scheme = std::string(token.begin(), space);
    StringToLowerASCII(&scheme);
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
    TrimWhitespaceASCII(host_and_port, TRIM_ALL, &host_and_port);
    if (scheme != "direct" && host_and_port.empty())
      continue;  // Must supply host/port when non-direct proxy used.
    ret.push_back(scheme + "://" + host_and_port);
  }
  if (ret.empty() || *ret.rbegin() != kNoProxy)
    ret.push_back(kNoProxy);
  return ret;
}

// Define a signal-watcher class to handle the D-Bus signal sent to us when
// the browser answers our request to resolve proxies.
class BrowserProxyResolvedSignalWatcher : public chromeos::dbus::SignalWatcher {
 public:
  explicit BrowserProxyResolvedSignalWatcher(GMainLoop *main_loop,
                                             std::deque<std::string> *proxies)
      : main_loop_(main_loop), proxies_(proxies) { }

  virtual void OnSignal(DBusMessage *message) {
    // Get args
    char *source_url = NULL;
    char *proxy_list = NULL;
    char *error = NULL;
    DBusError arg_error;
    dbus_error_init(&arg_error);
    if (!dbus_message_get_args(message, &arg_error,
                               DBUS_TYPE_STRING, &source_url,
                               DBUS_TYPE_STRING, &proxy_list,
                               DBUS_TYPE_STRING, &error,
                               DBUS_TYPE_INVALID)) {
      LOG(ERROR) << "Error reading D-Bus signal";
      return;
    }
    if (!source_url || !proxy_list) {
      LOG(ERROR) << "Error getting url, proxy list from D-Bus signal";
      return;
    }

    const std::deque<std::string> &proxies = ParseProxyString(proxy_list);
    for (std::deque<std::string>::const_iterator it = proxies.begin();
         it != proxies.end(); ++it) {
      LOG(INFO) << "Found proxy via browser signal: " << (*it).c_str();
      proxies_->push_back(*it);
    }

    g_main_loop_quit(main_loop_);
  }

 private:
  GMainLoop *main_loop_;
  std::deque<std::string> *proxies_;
};

static gboolean HandleBrowserTimeout(void *data) {
  GMainLoop *main_loop = reinterpret_cast<GMainLoop *>(data);
  LOG(ERROR) << "Timeout while waiting for browser to resolve proxy";
  g_main_loop_quit(main_loop);
  return false;  // only call once
}

static bool ShowBrowserProxies(const char *url) {
  GMainLoop *main_loop = g_main_loop_new(NULL, false);

  chromeos::dbus::BusConnection dbus = chromeos::dbus::GetSystemBusConnection();
  if (!dbus.HasConnection()) {
    LOG(ERROR) << "Error connecting to system D-Bus";
    return false;
  }
  chromeos::dbus::Proxy browser_proxy(dbus,
                                      kLibCrosServiceName,
                                      kLibCrosServicePath,
                                      kLibCrosServiceInterface);
  if (!browser_proxy) {
    LOG(ERROR) << "Error creating D-Bus proxy to interface "
               << "'" << kLibCrosServiceName << "'";
    return false;
  }

  // Watch for a proxy-resolved signal sent to us
  std::deque<std::string> proxies;
  BrowserProxyResolvedSignalWatcher proxy_resolver(main_loop, &proxies);
  proxy_resolver.StartMonitoring(kLibCrosProxyResolveSignalInterface,
                                 kLibCrosProxyResolveName);

  // Request the proxies for our URL.  The answer is sent to us via a
  // proxy-resolved signal.
  GError *gerror = NULL;
  if (!dbus_g_proxy_call(browser_proxy.gproxy(),
                         kLibCrosServiceResolveNetworkProxyMethodName,
                         &gerror,
                         G_TYPE_STRING, url,
                         G_TYPE_STRING, kLibCrosProxyResolveSignalInterface,
                         G_TYPE_STRING, kLibCrosProxyResolveName,
                         G_TYPE_INVALID, G_TYPE_INVALID)) {
    LOG(ERROR) << "Error performing D-Bus proxy call "
               << "'" << kLibCrosServiceResolveNetworkProxyMethodName << "'"
               << ": " << GetGErrorMessage(gerror);
    return false;
  }

  // Setup a timeout in case the browser doesn't respond with our signal
  g_timeout_add_seconds(FLAGS_timeout, &HandleBrowserTimeout, main_loop);

  // Loop until we either get the proxy-resolved signal, or until the
  // timeout is reached.
  g_main_loop_run(main_loop);

  // If there are no proxies, then we failed to get the proxy-resolved
  // signal (e.g. timeout was reached).
  if (proxies.empty())
    return false;

  for (std::deque<std::string>::const_iterator it = proxies.begin();
       it != proxies.end(); ++it) {
    printf("%s\n", (*it).c_str());
  }
  return true;
}

int main(int argc, char *argv[]) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  CommandLine::Init(argc, argv);

  // Default to logging to syslog.
  int init_flags = chromeos::kLogToSyslog;
  // Log to stderr if a TTY (and "-quiet" wasn't passed), or if "-verbose"
  // was passed.
  if ((!FLAGS_quiet && isatty(STDERR_FILENO)) || FLAGS_verbose)
    init_flags |= chromeos::kLogToStderr;
  chromeos::InitLog(init_flags);

  ::g_type_init();

  const char *url = NULL;
  if (argc >= 2) {
    url = argv[1];
    LOG(INFO) << "Resolving proxies for URL: " << url;
  } else {
    LOG(INFO) << "Resolving proxies without URL";
  }

  if (!ShowBrowserProxies(url)) {
    LOG(ERROR) << "Error resolving proxies via the browser";
    LOG(INFO) << "Assuming direct proxy";
    printf("%s\n", kNoProxy);
  }

  return 0;
}
