// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_daemon.h"
#include "metrics_library.h"

#include <glib-object.h>

extern "C" {
#include "marshal_void__string_boxed.h"
}

#include <base/logging.h>

#define SAFE_MESSAGE(e) ((e && e->message) ? e->message : "unknown error")

MetricsDaemon::NetworkState
MetricsDaemon::network_states_[MetricsDaemon::kNumberNetworkStates] = {
#define STATE(name, capname) { #name, "Network.Connman" # capname },
#include "network_states.h"
};

void MetricsDaemon::Run(bool run_as_daemon, bool testing) {
  Init(testing);
  if (!run_as_daemon || daemon(0, 0) == 0) {
    Loop();
  }
}

void MetricsDaemon::Init(bool testing) {
  testing_ = testing;
  network_state_id_ = kUnknownNetworkStateId;

  ::g_thread_init(NULL);
  ::g_type_init();
  ::dbus_g_thread_init();

  ::GError* error = NULL;
  ::DBusGConnection* dbc = ::dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
  // Note that LOG(FATAL) terminates the process; otherwise we'd have to worry
  // about leaking |error|.
  LOG_IF(FATAL, dbc == NULL) <<
    "cannot connect to dbus: " << SAFE_MESSAGE(error);

  ::DBusGProxy* net_proxy = ::dbus_g_proxy_new_for_name(
      dbc, "org.moblin.connman", "/", "org.moblin.connman.Metrics");
  LOG_IF(FATAL, net_proxy == NULL) << "no dbus proxy for network";

#if 0
  // Unclear how soon one can call dbus_g_type_get_map().  Doing it before the
  // call to dbus_g_bus_get() results in a (non-fatal) assertion failure.
  // GetProperties returns a hash table.
  hashtable_gtype = ::dbus_g_type_get_map("GHashTable", G_TYPE_STRING,
                                          G_TYPE_VALUE);
#endif

  dbus_g_object_register_marshaller(marshal_VOID__STRING_BOXED,
                                    G_TYPE_NONE,
                                    G_TYPE_STRING,
                                    G_TYPE_VALUE,
                                    G_TYPE_INVALID);
  ::dbus_g_proxy_add_signal(net_proxy, "ConnectionStateChanged",
                            G_TYPE_STRING, G_TYPE_VALUE, G_TYPE_INVALID);
  ::dbus_g_proxy_connect_signal(net_proxy, "ConnectionStateChanged",
                                G_CALLBACK(&StaticNetSignalHandler),
                                this, NULL);
}

void MetricsDaemon::Loop() {
  ::GMainLoop* loop = ::g_main_loop_new(NULL, false);
  ::g_main_loop_run(loop);
}

void MetricsDaemon::StaticNetSignalHandler(::DBusGProxy* proxy,
                                           const char* property,
                                           const ::GValue* value,
                                           void *data) {
  (static_cast<MetricsDaemon*>(data))->NetSignalHandler(proxy, property, value);
}

void MetricsDaemon::NetSignalHandler(::DBusGProxy* proxy,
                                     const char* property,
                                     const ::GValue* value) {
  if (strcmp("ConnectionState", property) != 0) {
    return;
  }

  const char* newstate = static_cast<const char*>(g_value_get_string(value));
  LogNetworkStateChange(newstate);
}

void MetricsDaemon::LogNetworkStateChange(const char* newstate) {
  NetworkStateId new_id = GetNetworkStateId(newstate);
  if (new_id == kUnknownNetworkStateId) {
    LOG(WARNING) << "unknown network connection state " << newstate;
    return;
  }
  NetworkStateId old_id = network_state_id_;
  if (new_id == old_id) {  // valid new state and no change
    return;
  }
  struct timeval now;
  if (gettimeofday(&now, NULL) != 0) {
    PLOG(WARNING) << "gettimeofday";
  }
  if (old_id != kUnknownNetworkStateId) {
    struct timeval diff;
    timersub(&now, &network_state_start_, &diff);
    int diff_ms = diff.tv_usec / 1000 + diff.tv_sec * 1000;
    // Saturates rather than overflowing.  We expect this to be statistically
    // insignificant, since INT_MAX milliseconds is 24.8 days.
    if (diff.tv_sec >= INT_MAX / 1000) {
      diff_ms = INT_MAX;
    }
    PublishMetric(network_states_[old_id].stat_name,
                  diff_ms,
                  1,
                  8 * 60 * 60 * 1000,  // 8 hours in milliseconds
                  100);
  }
  network_state_id_ = new_id;
  network_state_start_ = now;
}

MetricsDaemon::NetworkStateId
MetricsDaemon::GetNetworkStateId(const char* state_name) {
  for (int i = 0; i < kNumberNetworkStates; i++) {
    if (strcmp(state_name, network_states_[i].name) == 0) {
      return static_cast<NetworkStateId>(i);
    }
  }
  return static_cast<NetworkStateId>(-1);
}

void MetricsDaemon::PublishMetric(const char* name, int sample,
                                  int min, int max, int nbuckets) {
  if (testing_) {
    LOG(INFO) << "received metric: " << name << " " << sample <<
        " " << min << " " << max << " " << nbuckets;
  } else {
    MetricsLibrary::SendToChrome(name, sample, min, max, nbuckets);
  }
}
