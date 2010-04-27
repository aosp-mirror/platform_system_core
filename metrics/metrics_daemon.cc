// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_daemon.h"
#include "metrics_library.h"

#include <dbus/dbus-glib-lowlevel.h>

#include <base/logging.h>

#define SAFE_MESSAGE(e) (e.message ? e.message : "unknown error")
#define DBUS_IFACE_CONNMAN_MANAGER "org.moblin.connman.Manager"
#define DBUS_IFACE_POWER_MANAGER "org.chromium.Power.Manager"

// static
const char*
MetricsDaemon::dbus_matches_[] = {
  "type='signal',"
  "sender='org.moblin.connman',"
  "interface='" DBUS_IFACE_CONNMAN_MANAGER "',"
  "path='/',"
  "member='StateChanged'",

  "type='signal',"
  "interface='" DBUS_IFACE_POWER_MANAGER "',"
  "path='/',"
  "member='PowerStateChanged'",
};

// static
const char *
MetricsDaemon::network_states_[MetricsDaemon::kNumberNetworkStates] = {
#define STATE(name, capname) #name,
#include "network_states.h"
};

// static
const char *
MetricsDaemon::power_states_[MetricsDaemon::kNumberPowerStates] = {
#define STATE(name, capname) #name,
#include "power_states.h"
};

void MetricsDaemon::Run(bool run_as_daemon, bool testing) {
  Init(testing);
  if (!run_as_daemon || daemon(0, 0) == 0) {
    Loop();
  }
}

void MetricsDaemon::Init(bool testing) {
  testing_ = testing;
  network_state_ = kUnknownNetworkState;
  network_state_changed_ = 0;
  power_state_ = kUnknownPowerState;

  g_thread_init(NULL);
  g_type_init();
  dbus_g_thread_init();

  DBusError error;
  dbus_error_init(&error);

  DBusConnection *connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
  LOG_IF(FATAL, dbus_error_is_set(&error)) <<
      "No D-Bus connection: " << SAFE_MESSAGE(error);

  dbus_connection_setup_with_g_main(connection, NULL);

  // Registers D-Bus matches for the signals we would like to catch.
  for (unsigned int m = 0; m < sizeof(dbus_matches_) / sizeof(char *); m++) {
    const char* match = dbus_matches_[m];
    LOG(INFO) << "adding dbus match: " << match;
    dbus_bus_add_match(connection, match, &error);
    LOG_IF(FATAL, dbus_error_is_set(&error)) <<
        "unable to add a match: " << SAFE_MESSAGE(error);
  }

  // Adds the D-Bus filter routine to be called back whenever one of
  // the registered D-Bus matches is successful. The daemon is not
  // activated for D-Bus messages that don't match.
  CHECK(dbus_connection_add_filter(connection, MessageFilter, this, NULL));
}

void MetricsDaemon::Loop() {
  GMainLoop* loop = g_main_loop_new(NULL, false);
  g_main_loop_run(loop);
}

// static
DBusHandlerResult MetricsDaemon::MessageFilter(DBusConnection* connection,
                                               DBusMessage* message,
                                               void* user_data) {
  LOG(INFO) << "message filter";

  int message_type = dbus_message_get_type(message);
  if (message_type != DBUS_MESSAGE_TYPE_SIGNAL) {
    LOG(WARNING) << "unexpected message type " << message_type;
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  // Signal messages always have interfaces.
  const char* interface = dbus_message_get_interface(message);
  CHECK(interface != NULL);

  MetricsDaemon* daemon = static_cast<MetricsDaemon*>(user_data);

  DBusMessageIter iter;
  dbus_message_iter_init(message, &iter);
  if (strcmp(interface, DBUS_IFACE_CONNMAN_MANAGER) == 0) {
    CHECK(strcmp(dbus_message_get_member(message), "StateChanged") == 0);

    char *state_name;
    dbus_message_iter_get_basic(&iter, &state_name);
    daemon->NetStateChanged(state_name);
  } else if (strcmp(interface, DBUS_IFACE_POWER_MANAGER) == 0) {
    CHECK(strcmp(dbus_message_get_member(message), "PowerStateChanged") == 0);

    char *state_name;
    dbus_message_iter_get_basic(&iter, &state_name);
    daemon->PowerStateChanged(state_name);
  } else {
    LOG(WARNING) << "unexpected interface: " << interface;
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  return DBUS_HANDLER_RESULT_HANDLED;
}

void MetricsDaemon::NetStateChanged(const char* state_name) {
  LOG(INFO) << "network state: " << state_name;

  time_t now = time(NULL);
  NetworkState state = LookupNetworkState(state_name);

  // Logs the time in seconds between the network going online to
  // going offline in order to measure the mean time to network
  // dropping. Going offline as part of suspend-to-RAM is not logged
  // as network drop -- the assumption is that the message for
  // suspend-to-RAM comes before the network offline message which
  // seems to and should be the case.
  if (state == kNetworkStateOffline &&
      network_state_ == kNetworkStateOnline &&
      power_state_ != kPowerStateMem) {
    int online_time = static_cast<int>(now - network_state_changed_);
    PublishMetric("Network.TimeToDrop", online_time,
                  1, 8 /* hours */ * 60 * 60, 50);
  }

  network_state_ = state;
  network_state_changed_ = now;
}

MetricsDaemon::NetworkState
MetricsDaemon::LookupNetworkState(const char* state_name) {
  for (int i = 0; i < kNumberNetworkStates; i++) {
    if (strcmp(state_name, network_states_[i]) == 0) {
      return static_cast<NetworkState>(i);
    }
  }
  LOG(WARNING) << "unknown network connection state: " << state_name;
  return kUnknownNetworkState;
}

void MetricsDaemon::PowerStateChanged(const char* state_name) {
  LOG(INFO) << "power state: " << state_name;
  power_state_ = LookupPowerState(state_name);
}

MetricsDaemon::PowerState
MetricsDaemon::LookupPowerState(const char* state_name) {
  for (int i = 0; i < kNumberPowerStates; i++) {
    if (strcmp(state_name, power_states_[i]) == 0) {
      return static_cast<PowerState>(i);
    }
  }
  LOG(WARNING) << "unknown power state: " << state_name;
  return kUnknownPowerState;
}

void MetricsDaemon::PublishMetric(const char* name, int sample,
                                  int min, int max, int nbuckets) {
  LOG(INFO) << "received metric: " << name << " " << sample <<
      " " << min << " " << max << " " << nbuckets;
  if (!testing_) {
    MetricsLibrary::SendToChrome(name, sample, min, max, nbuckets);
  }
}
