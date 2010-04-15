// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_DAEMON_H_
#define METRICS_DAEMON_H_

#include <dbus/dbus-glib.h>
#include <sys/time.h>
#include <time.h>

class MetricsDaemon {

 public:
  MetricsDaemon()
      : network_state_id_(kUnknownNetworkStateId) {
  }
  ~MetricsDaemon() {}

  // Does all the work.  If |run_as_daemon| is true, daemonize by forking.  If
  // |testing| is true, log the stats instead of sending them to Chrome.
  void Run(bool run_as_daemon, bool testing);

 private:
  // Shared with Chrome for transport.
  static const char* kMetricsFilePath;
  static const int kMetricsMessageMaxLength = 4096;

  // The network states.  See network_states.h.
  typedef enum {
    // Initial/unknown network state id.
    kUnknownNetworkStateId = -1,
#define STATE(name, capname) kNetworkState ## capname,
#include "network_states.h"
    kNumberNetworkStates
  } NetworkStateId;

  typedef struct {
    const char* name;
    const char* stat_name;
  } NetworkState;

  // Initializes.
  void Init(bool testing);

  // Creates the event loop and enters it.
  void Loop();

  // Static callback for network events on DBus.
  static void StaticNetSignalHandler(::DBusGProxy* proxy, const char* property,
                                     const ::GValue* value, void* data);

  // Callback for network events on DBus.
  void NetSignalHandler(::DBusGProxy* proxy, const char* property,
                        const ::GValue* value);

  // This is called at each network state change.  The new state is identified
  // by the string @newstate.  As a side effect, this method ships to Chrome
  // (or prints to stdout when testing) the name and duration of the state
  // that has ended.
  void LogNetworkStateChange(const char* newstate);

  // Given a string with the name of a state, returns the id for the state.
  NetworkStateId GetNetworkStateId(const char* state_name);

  // Sends a stat to Chrome for transport to UMA.
  void ChromePublishMetric(const char* name, int value);

  // Prints a stat for testing.
  void TestPublishMetric(const char* name, int value);

#if 0
  // Fetches a name-value hash table from DBus.
  bool GetProperties(::DBusGProxy* proxy, ::GHashTable** table);

  // The type descriptor for a glib hash table.
  GType hashtable_gtype;
#endif

  // Array of network states of interest.
  static NetworkState network_states_[kNumberNetworkStates];

  bool testing_;                           // just testing
  NetworkStateId network_state_id_;        // id of current state
  struct timeval network_state_start_;     // when current state was entered
};

#endif  // METRICS_DAEMON_H_
