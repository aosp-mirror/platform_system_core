/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef __ADB_SOCKET_H
#define __ADB_SOCKET_H

#include <stddef.h>

#include <deque>
#include <memory>
#include <string>

#include "fdevent.h"
#include "range.h"

struct apacket;
class atransport;

/* An asocket represents one half of a connection between a local and
 * remote entity.  A local asocket is bound to a file descriptor.  A
 * remote asocket is bound to the protocol engine.
 */
struct asocket {
    /* the unique identifier for this asocket
     */
    unsigned id = 0;

    /* flag: set when the socket's peer has closed
     * but packets are still queued for delivery
     */
    int closing = 0;

    // flag: set when the socket failed to write, so the socket will not wait to
    // write packets and close directly.
    bool has_write_error = 0;

    /* flag: quit adbd when both ends close the
     * local service socket
     */
    int exit_on_close = 0;

    // the asocket we are connected to
    asocket* peer = nullptr;

    /* For local asockets, the fde is used to bind
     * us to our fd event system.  For remote asockets
     * these fields are not used.
     */
    fdevent fde = {};
    int fd = 0;

    // queue of data waiting to be written
    std::deque<Range> packet_queue;

    std::string smart_socket_data;

    /* enqueue is called by our peer when it has data
     * for us.  It should return 0 if we can accept more
     * data or 1 if not.  If we return 1, we must call
     * peer->ready() when we once again are ready to
     * receive data.
     */
    int (*enqueue)(asocket* s, std::string data) = nullptr;

    /* ready is called by the peer when it is ready for
     * us to send data via enqueue again
     */
    void (*ready)(asocket* s) = nullptr;

    /* shutdown is called by the peer before it goes away.
     * the socket should not do any further calls on its peer.
     * Always followed by a call to close. Optional, i.e. can be NULL.
     */
    void (*shutdown)(asocket* s) = nullptr;

    /* close is called by the peer when it has gone away.
     * we are not allowed to make any further calls on the
     * peer once our close method is called.
     */
    void (*close)(asocket* s) = nullptr;

    /* A socket is bound to atransport */
    atransport* transport = nullptr;

    size_t get_max_payload() const;
};

asocket *find_local_socket(unsigned local_id, unsigned remote_id);
void install_local_socket(asocket *s);
void remove_socket(asocket *s);
void close_all_sockets(atransport *t);

asocket *create_local_socket(int fd);
asocket *create_local_service_socket(const char* destination,
                                     const atransport* transport);

asocket *create_remote_socket(unsigned id, atransport *t);
void connect_to_remote(asocket *s, const char *destination);
void connect_to_smartsocket(asocket *s);

// Internal functions that are only made available here for testing purposes.
namespace internal {

#if ADB_HOST
char* skip_host_serial(char* service);
#endif

}  // namespace internal

#endif  // __ADB_SOCKET_H
