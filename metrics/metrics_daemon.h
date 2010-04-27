// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_DAEMON_H_
#define METRICS_DAEMON_H_

#include <dbus/dbus.h>
#include <time.h>

class MetricsDaemon {

 public:
  MetricsDaemon()
      : testing_(false),
        network_state_(kUnknownNetworkState),
        network_state_changed_(0),
        power_state_(kUnknownPowerState) {}
  ~MetricsDaemon() {}

  // Does all the work. If |run_as_daemon| is true, daemonizes by
  // forking. If |testing| is true, logs the stats instead of sending
  // them to Chrome.
  void Run(bool run_as_daemon, bool testing);

 private:
  // The network states (see network_states.h).
  enum NetworkState {
    kUnknownNetworkState = -1, // Initial/unknown network state.
#define STATE(name, capname) kNetworkState ## capname,
#include "network_states.h"
    kNumberNetworkStates
  };

  // The power states (see power_states.h).
  enum PowerState {
    kUnknownPowerState = -1, // Initial/unknown power state.
#define STATE(name, capname) kPowerState ## capname,
#include "power_states.h"
    kNumberPowerStates
  };

  // Initializes.
  void Init(bool testing);

  // Creates the event loop and enters it.
  void Loop();

  // D-Bus filter callback.
  static DBusHandlerResult MessageFilter(DBusConnection* connection,
                                         DBusMessage* message,
                                         void* user_data);

  // Processes network state change.
  void NetStateChanged(const char* state_name);

  // Given the state name, returns the state id.
  NetworkState LookupNetworkState(const char* state_name);

  // Processes power state change.
  void PowerStateChanged(const char* state_name);

  // Given the state name, returns the state id.
  PowerState LookupPowerState(const char* state_name);

  // Sends a stat to Chrome for transport to UMA (or prints it for
  // testing). See MetricsLibrary::SendToChrome in metrics_library.h
  // for a description of the arguments.
  void PublishMetric(const char* name, int sample,
                     int min, int max, int nbuckets);

  // D-Bus message match strings.
  static const char* dbus_matches_[];

  // Array of network states.
  static const char* network_states_[kNumberNetworkStates];

  // Array of power states.
  static const char* power_states_[kNumberPowerStates];

  bool testing_;                  // just testing
  NetworkState network_state_;    // current network state
  time_t network_state_changed_;  // timestamp last net state change
  PowerState power_state_;        // current power state
};

#endif  // METRICS_DAEMON_H_
