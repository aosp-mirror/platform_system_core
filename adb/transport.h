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

#ifndef __TRANSPORT_H
#define __TRANSPORT_H

#include <sys/types.h>

#include <string>

#include "adb.h"

/*
 * Obtain a transport from the available transports.
 * If state is != kCsAny, only transports in that state are considered.
 * If serial is non-NULL then only the device with that serial will be chosen.
 * If no suitable transport is found, error is set.
 */
atransport* acquire_one_transport(ConnectionState state, TransportType type,
                                  const char* serial, std::string* error_out);
void add_transport_disconnect(atransport* t, adisconnect* dis);
void remove_transport_disconnect(atransport* t, adisconnect* dis);
void kick_transport(atransport* t);
void run_transport_disconnects(atransport* t);
void update_transports(void);

/* transports are ref-counted
** get_device_transport does an acquire on your behalf before returning
*/
void init_transport_registration(void);
std::string list_transports(bool long_listing);
atransport* find_transport(const char* serial);

void register_usb_transport(usb_handle* h, const char* serial,
                            const char* devpath, unsigned writeable);

/* cause new transports to be init'd and added to the list */
int register_socket_transport(int s, const char* serial, int port, int local);

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle* usb);

/* these should only be used for the "adb disconnect" command */
void unregister_transport(atransport* t);
void unregister_all_tcp_transports();

int check_header(apacket* p);
int check_data(apacket* p);

/* for MacOS X cleanup */
void close_usb_devices();

void send_packet(apacket* p, atransport* t);

asocket* create_device_tracker(void);

#endif   /* __TRANSPORT_H */
