/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG TRACE_TRANSPORT

#include "sysdeps.h"
#include "transport.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <list>

#include <base/stringprintf.h>

#include "adb.h"
#include "adb_utils.h"

static void transport_unref(atransport *t);

static std::list<atransport*> transport_list;
static std::list<atransport*> pending_list;

ADB_MUTEX_DEFINE( transport_lock );

void kick_transport(atransport* t)
{
    if (t && !t->kicked)
    {
        int  kicked;

        adb_mutex_lock(&transport_lock);
        kicked = t->kicked;
        if (!kicked)
            t->kicked = 1;
        adb_mutex_unlock(&transport_lock);

        if (!kicked)
            t->kick(t);
    }
}

// Each atransport contains a list of adisconnects (t->disconnects).
// An adisconnect contains a link to the next/prev adisconnect, a function
// pointer to a disconnect callback which takes a void* piece of user data and
// the atransport, and some user data for the callback (helpfully named
// "opaque").
//
// The list is circular. New items are added to the entry member of the list
// (t->disconnects) by add_transport_disconnect.
//
// run_transport_disconnects invokes each function in the list.
//
// Gotchas:
//   * run_transport_disconnects assumes that t->disconnects is non-null, so
//     this can't be run on a zeroed atransport.
//   * The callbacks in this list are not removed when called, and this function
//     is not guarded against running more than once. As such, ensure that this
//     function is not called multiple times on the same atransport.
//     TODO(danalbert): Just fix this so that it is guarded once you have tests.
void run_transport_disconnects(atransport* t)
{
    adisconnect*  dis = t->disconnects.next;

    D("%s: run_transport_disconnects\n", t->serial);
    while (dis != &t->disconnects) {
        adisconnect*  next = dis->next;
        dis->func( dis->opaque, t );
        dis = next;
    }
}

static void dump_packet(const char* name, const char* func, apacket* p) {
    unsigned  command = p->msg.command;
    int       len     = p->msg.data_length;
    char      cmd[9];
    char      arg0[12], arg1[12];
    int       n;

    for (n = 0; n < 4; n++) {
        int  b = (command >> (n*8)) & 255;
        if (b < 32 || b >= 127)
            break;
        cmd[n] = (char)b;
    }
    if (n == 4) {
        cmd[4] = 0;
    } else {
        /* There is some non-ASCII name in the command, so dump
            * the hexadecimal value instead */
        snprintf(cmd, sizeof cmd, "%08x", command);
    }

    if (p->msg.arg0 < 256U)
        snprintf(arg0, sizeof arg0, "%d", p->msg.arg0);
    else
        snprintf(arg0, sizeof arg0, "0x%x", p->msg.arg0);

    if (p->msg.arg1 < 256U)
        snprintf(arg1, sizeof arg1, "%d", p->msg.arg1);
    else
        snprintf(arg1, sizeof arg1, "0x%x", p->msg.arg1);

    D("%s: %s: [%s] arg0=%s arg1=%s (len=%d) ",
        name, func, cmd, arg0, arg1, len);
    dump_hex(p->data, len);
}

static int
read_packet(int  fd, const char* name, apacket** ppacket)
{
    char *p = (char*)ppacket;  /* really read a packet address */
    int   r;
    int   len = sizeof(*ppacket);
    char  buff[8];
    if (!name) {
        snprintf(buff, sizeof buff, "fd=%d", fd);
        name = buff;
    }
    while(len > 0) {
        r = adb_read(fd, p, len);
        if(r > 0) {
            len -= r;
            p   += r;
        } else {
            D("%s: read_packet (fd=%d), error ret=%d errno=%d: %s\n", name, fd, r, errno, strerror(errno));
            if((r < 0) && (errno == EINTR)) continue;
            return -1;
        }
    }

    if (ADB_TRACING) {
        dump_packet(name, "from remote", *ppacket);
    }
    return 0;
}

static int
write_packet(int  fd, const char* name, apacket** ppacket)
{
    char *p = (char*) ppacket;  /* we really write the packet address */
    int r, len = sizeof(ppacket);
    char buff[8];
    if (!name) {
        snprintf(buff, sizeof buff, "fd=%d", fd);
        name = buff;
    }

    if (ADB_TRACING) {
        dump_packet(name, "to remote", *ppacket);
    }
    len = sizeof(ppacket);
    while(len > 0) {
        r = adb_write(fd, p, len);
        if(r > 0) {
            len -= r;
            p += r;
        } else {
            D("%s: write_packet (fd=%d) error ret=%d errno=%d: %s\n", name, fd, r, errno, strerror(errno));
            if((r < 0) && (errno == EINTR)) continue;
            return -1;
        }
    }
    return 0;
}

static void transport_socket_events(int fd, unsigned events, void *_t)
{
    atransport *t = reinterpret_cast<atransport*>(_t);
    D("transport_socket_events(fd=%d, events=%04x,...)\n", fd, events);
    if(events & FDE_READ){
        apacket *p = 0;
        if(read_packet(fd, t->serial, &p)){
            D("%s: failed to read packet from transport socket on fd %d\n", t->serial, fd);
        } else {
            handle_packet(p, (atransport *) _t);
        }
    }
}

void send_packet(apacket *p, atransport *t)
{
    unsigned char *x;
    unsigned sum;
    unsigned count;

    p->msg.magic = p->msg.command ^ 0xffffffff;

    count = p->msg.data_length;
    x = (unsigned char *) p->data;
    sum = 0;
    while(count-- > 0){
        sum += *x++;
    }
    p->msg.data_check = sum;

    print_packet("send", p);

    if (t == NULL) {
        D("Transport is null \n");
        // Zap errno because print_packet() and other stuff have errno effect.
        errno = 0;
        fatal_errno("Transport is null");
    }

    if(write_packet(t->transport_socket, t->serial, &p)){
        fatal_errno("cannot enqueue packet on transport socket");
    }
}

/* The transport is opened by transport_register_func before
** the input and output threads are started.
**
** The output thread issues a SYNC(1, token) message to let
** the input thread know to start things up.  In the event
** of transport IO failure, the output thread will post a
** SYNC(0,0) message to ensure shutdown.
**
** The transport will not actually be closed until both
** threads exit, but the input thread will kick the transport
** on its way out to disconnect the underlying device.
*/

static void *output_thread(void *_t)
{
    atransport *t = reinterpret_cast<atransport*>(_t);
    apacket *p;

    D("%s: starting transport output thread on fd %d, SYNC online (%d)\n",
       t->serial, t->fd, t->sync_token + 1);
    p = get_apacket();
    p->msg.command = A_SYNC;
    p->msg.arg0 = 1;
    p->msg.arg1 = ++(t->sync_token);
    p->msg.magic = A_SYNC ^ 0xffffffff;
    if(write_packet(t->fd, t->serial, &p)) {
        put_apacket(p);
        D("%s: failed to write SYNC packet\n", t->serial);
        goto oops;
    }

    D("%s: data pump started\n", t->serial);
    for(;;) {
        p = get_apacket();

        if(t->read_from_remote(p, t) == 0){
            D("%s: received remote packet, sending to transport\n",
              t->serial);
            if(write_packet(t->fd, t->serial, &p)){
                put_apacket(p);
                D("%s: failed to write apacket to transport\n", t->serial);
                goto oops;
            }
        } else {
            D("%s: remote read failed for transport\n", t->serial);
            put_apacket(p);
            break;
        }
    }

    D("%s: SYNC offline for transport\n", t->serial);
    p = get_apacket();
    p->msg.command = A_SYNC;
    p->msg.arg0 = 0;
    p->msg.arg1 = 0;
    p->msg.magic = A_SYNC ^ 0xffffffff;
    if(write_packet(t->fd, t->serial, &p)) {
        put_apacket(p);
        D("%s: failed to write SYNC apacket to transport", t->serial);
    }

oops:
    D("%s: transport output thread is exiting\n", t->serial);
    kick_transport(t);
    transport_unref(t);
    return 0;
}

static void *input_thread(void *_t)
{
    atransport *t = reinterpret_cast<atransport*>(_t);
    apacket *p;
    int active = 0;

    D("%s: starting transport input thread, reading from fd %d\n",
       t->serial, t->fd);

    for(;;){
        if(read_packet(t->fd, t->serial, &p)) {
            D("%s: failed to read apacket from transport on fd %d\n",
               t->serial, t->fd );
            break;
        }
        if(p->msg.command == A_SYNC){
            if(p->msg.arg0 == 0) {
                D("%s: transport SYNC offline\n", t->serial);
                put_apacket(p);
                break;
            } else {
                if(p->msg.arg1 == t->sync_token) {
                    D("%s: transport SYNC online\n", t->serial);
                    active = 1;
                } else {
                    D("%s: transport ignoring SYNC %d != %d\n",
                      t->serial, p->msg.arg1, t->sync_token);
                }
            }
        } else {
            if(active) {
                D("%s: transport got packet, sending to remote\n", t->serial);
                t->write_to_remote(p, t);
            } else {
                D("%s: transport ignoring packet while offline\n", t->serial);
            }
        }

        put_apacket(p);
    }

    // this is necessary to avoid a race condition that occured when a transport closes
    // while a client socket is still active.
    close_all_sockets(t);

    D("%s: transport input thread is exiting, fd %d\n", t->serial, t->fd);
    kick_transport(t);
    transport_unref(t);
    return 0;
}


static int transport_registration_send = -1;
static int transport_registration_recv = -1;
static fdevent transport_registration_fde;


#if ADB_HOST

/* this adds support required by the 'track-devices' service.
 * this is used to send the content of "list_transport" to any
 * number of client connections that want it through a single
 * live TCP connection
 */
struct device_tracker {
    asocket          socket;
    int              update_needed;
    device_tracker*  next;
};

/* linked list of all device trackers */
static device_tracker*   device_tracker_list;

static void
device_tracker_remove( device_tracker*  tracker )
{
    device_tracker**  pnode = &device_tracker_list;
    device_tracker*   node  = *pnode;

    adb_mutex_lock( &transport_lock );
    while (node) {
        if (node == tracker) {
            *pnode = node->next;
            break;
        }
        pnode = &node->next;
        node  = *pnode;
    }
    adb_mutex_unlock( &transport_lock );
}

static void
device_tracker_close( asocket*  socket )
{
    device_tracker*  tracker = (device_tracker*) socket;
    asocket*         peer    = socket->peer;

    D( "device tracker %p removed\n", tracker);
    if (peer) {
        peer->peer = NULL;
        peer->close(peer);
    }
    device_tracker_remove(tracker);
    free(tracker);
}

static int
device_tracker_enqueue( asocket*  socket, apacket*  p )
{
    /* you can't read from a device tracker, close immediately */
    put_apacket(p);
    device_tracker_close(socket);
    return -1;
}

static int device_tracker_send(device_tracker* tracker, const std::string& string) {
    apacket* p = get_apacket();
    asocket* peer = tracker->socket.peer;

    snprintf(reinterpret_cast<char*>(p->data), 5, "%04x", static_cast<int>(string.size()));
    memcpy(&p->data[4], string.data(), string.size());
    p->len = 4 + string.size();
    return peer->enqueue(peer, p);
}

static void device_tracker_ready(asocket* socket) {
    device_tracker* tracker = reinterpret_cast<device_tracker*>(socket);

    // We want to send the device list when the tracker connects
    // for the first time, even if no update occurred.
    if (tracker->update_needed > 0) {
        tracker->update_needed = 0;

        std::string transports = list_transports(false);
        device_tracker_send(tracker, transports);
    }
}

asocket*
create_device_tracker(void)
{
    device_tracker* tracker = reinterpret_cast<device_tracker*>(calloc(1, sizeof(*tracker)));
    if (tracker == nullptr) fatal("cannot allocate device tracker");

    D( "device tracker %p created\n", tracker);

    tracker->socket.enqueue = device_tracker_enqueue;
    tracker->socket.ready   = device_tracker_ready;
    tracker->socket.close   = device_tracker_close;
    tracker->update_needed  = 1;

    tracker->next       = device_tracker_list;
    device_tracker_list = tracker;

    return &tracker->socket;
}


// Call this function each time the transport list has changed.
void update_transports() {
    std::string transports = list_transports(false);

    device_tracker* tracker = device_tracker_list;
    while (tracker != nullptr) {
        device_tracker* next = tracker->next;
        // This may destroy the tracker if the connection is closed.
        device_tracker_send(tracker, transports);
        tracker = next;
    }
}

#else

void update_transports() {
    // Nothing to do on the device side.
}

#endif // ADB_HOST

struct tmsg
{
    atransport *transport;
    int         action;
};

static int
transport_read_action(int  fd, struct tmsg*  m)
{
    char *p   = (char*)m;
    int   len = sizeof(*m);
    int   r;

    while(len > 0) {
        r = adb_read(fd, p, len);
        if(r > 0) {
            len -= r;
            p   += r;
        } else {
            if((r < 0) && (errno == EINTR)) continue;
            D("transport_read_action: on fd %d, error %d: %s\n",
              fd, errno, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static int
transport_write_action(int  fd, struct tmsg*  m)
{
    char *p   = (char*)m;
    int   len = sizeof(*m);
    int   r;

    while(len > 0) {
        r = adb_write(fd, p, len);
        if(r > 0) {
            len -= r;
            p   += r;
        } else {
            if((r < 0) && (errno == EINTR)) continue;
            D("transport_write_action: on fd %d, error %d: %s\n",
              fd, errno, strerror(errno));
            return -1;
        }
    }
    return 0;
}

static void transport_registration_func(int _fd, unsigned ev, void *data)
{
    tmsg m;
    int s[2];
    atransport *t;

    if(!(ev & FDE_READ)) {
        return;
    }

    if(transport_read_action(_fd, &m)) {
        fatal_errno("cannot read transport registration socket");
    }

    t = m.transport;

    if(m.action == 0){
        D("transport: %s removing and free'ing %d\n", t->serial, t->transport_socket);

            /* IMPORTANT: the remove closes one half of the
            ** socket pair.  The close closes the other half.
            */
        fdevent_remove(&(t->transport_fde));
        adb_close(t->fd);

        adb_mutex_lock(&transport_lock);
        transport_list.remove(t);
        adb_mutex_unlock(&transport_lock);

        run_transport_disconnects(t);

        if (t->product)
            free(t->product);
        if (t->serial)
            free(t->serial);
        if (t->model)
            free(t->model);
        if (t->device)
            free(t->device);
        if (t->devpath)
            free(t->devpath);

        delete t;

        update_transports();
        return;
    }

    /* don't create transport threads for inaccessible devices */
    if (t->connection_state != kCsNoPerm) {
        /* initial references are the two threads */
        t->ref_count = 2;

        if (adb_socketpair(s)) {
            fatal_errno("cannot open transport socketpair");
        }

        D("transport: %s socketpair: (%d,%d) starting", t->serial, s[0], s[1]);

        t->transport_socket = s[0];
        t->fd = s[1];

        fdevent_install(&(t->transport_fde),
                        t->transport_socket,
                        transport_socket_events,
                        t);

        fdevent_set(&(t->transport_fde), FDE_READ);

        if (!adb_thread_create(input_thread, t)) {
            fatal_errno("cannot create input thread");
        }

        if (!adb_thread_create(output_thread, t)) {
            fatal_errno("cannot create output thread");
        }
    }

    adb_mutex_lock(&transport_lock);
    pending_list.remove(t);
    transport_list.push_front(t);
    adb_mutex_unlock(&transport_lock);

    t->disconnects.next = t->disconnects.prev = &t->disconnects;

    update_transports();
}

void init_transport_registration(void)
{
    int s[2];

    if(adb_socketpair(s)){
        fatal_errno("cannot open transport registration socketpair");
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    transport_registration_send = s[0];
    transport_registration_recv = s[1];

    fdevent_install(&transport_registration_fde,
                    transport_registration_recv,
                    transport_registration_func,
                    0);

    fdevent_set(&transport_registration_fde, FDE_READ);
}

/* the fdevent select pump is single threaded */
static void register_transport(atransport *transport)
{
    tmsg m;
    m.transport = transport;
    m.action = 1;
    D("transport: %s registered\n", transport->serial);
    if(transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}

static void remove_transport(atransport *transport)
{
    tmsg m;
    m.transport = transport;
    m.action = 0;
    D("transport: %s removed\n", transport->serial);
    if(transport_write_action(transport_registration_send, &m)) {
        fatal_errno("cannot write transport registration socket\n");
    }
}


static void transport_unref_locked(atransport *t)
{
    t->ref_count--;
    if (t->ref_count == 0) {
        D("transport: %s unref (kicking and closing)\n", t->serial);
        if (!t->kicked) {
            t->kicked = 1;
            t->kick(t);
        }
        t->close(t);
        remove_transport(t);
    } else {
        D("transport: %s unref (count=%d)\n", t->serial, t->ref_count);
    }
}

static void transport_unref(atransport *t)
{
    if (t) {
        adb_mutex_lock(&transport_lock);
        transport_unref_locked(t);
        adb_mutex_unlock(&transport_lock);
    }
}

void add_transport_disconnect(atransport*  t, adisconnect*  dis)
{
    adb_mutex_lock(&transport_lock);
    dis->next       = &t->disconnects;
    dis->prev       = dis->next->prev;
    dis->prev->next = dis;
    dis->next->prev = dis;
    adb_mutex_unlock(&transport_lock);
}

void remove_transport_disconnect(atransport*  t, adisconnect*  dis)
{
    dis->prev->next = dis->next;
    dis->next->prev = dis->prev;
    dis->next = dis->prev = dis;
}

static int qual_match(const char *to_test,
                      const char *prefix, const char *qual, bool sanitize_qual)
{
    if (!to_test || !*to_test)
        /* Return true if both the qual and to_test are null strings. */
        return !qual || !*qual;

    if (!qual)
        return 0;

    if (prefix) {
        while (*prefix) {
            if (*prefix++ != *to_test++)
                return 0;
        }
    }

    while (*qual) {
        char ch = *qual++;
        if (sanitize_qual && !isalnum(ch))
            ch = '_';
        if (ch != *to_test++)
            return 0;
    }

    /* Everything matched so far.  Return true if *to_test is a NUL. */
    return !*to_test;
}

atransport* acquire_one_transport(ConnectionState state, TransportType type,
                                  const char* serial, std::string* error_out) {
    atransport *result = NULL;
    int ambiguous = 0;

retry:
    *error_out = serial ? android::base::StringPrintf("device '%s' not found", serial) : "no devices found";

    adb_mutex_lock(&transport_lock);
    for (auto t : transport_list) {
        if (t->connection_state == kCsNoPerm) {
            *error_out = "insufficient permissions for device";
            continue;
        }

        /* check for matching serial number */
        if (serial) {
            if ((t->serial && !strcmp(serial, t->serial)) ||
                (t->devpath && !strcmp(serial, t->devpath)) ||
                qual_match(serial, "product:", t->product, false) ||
                qual_match(serial, "model:", t->model, true) ||
                qual_match(serial, "device:", t->device, false)) {
                if (result) {
                    *error_out = "more than one device";
                    ambiguous = 1;
                    result = NULL;
                    break;
                }
                result = t;
            }
        } else {
            if (type == kTransportUsb && t->type == kTransportUsb) {
                if (result) {
                    *error_out = "more than one device";
                    ambiguous = 1;
                    result = NULL;
                    break;
                }
                result = t;
            } else if (type == kTransportLocal && t->type == kTransportLocal) {
                if (result) {
                    *error_out = "more than one emulator";
                    ambiguous = 1;
                    result = NULL;
                    break;
                }
                result = t;
            } else if (type == kTransportAny) {
                if (result) {
                    *error_out = "more than one device/emulator";
                    ambiguous = 1;
                    result = NULL;
                    break;
                }
                result = t;
            }
        }
    }
    adb_mutex_unlock(&transport_lock);

    if (result) {
        if (result->connection_state == kCsUnauthorized) {
            *error_out = "device unauthorized.\n";
            char* ADB_VENDOR_KEYS = getenv("ADB_VENDOR_KEYS");
            *error_out += "This adbd's $ADB_VENDOR_KEYS is ";
            *error_out += ADB_VENDOR_KEYS ? ADB_VENDOR_KEYS : "not set";
            *error_out += "; try 'adb kill-server' if that seems wrong.\n";
            *error_out += "Otherwise check for a confirmation dialog on your device.";
            result = NULL;
        }

        /* offline devices are ignored -- they are either being born or dying */
        if (result && result->connection_state == kCsOffline) {
            *error_out = "device offline";
            result = NULL;
        }

        /* check for required connection state */
        if (result && state != kCsAny && result->connection_state != state) {
            *error_out = "invalid device state";
            result = NULL;
        }
    }

    if (result) {
        /* found one that we can take */
        *error_out = "success";
    } else if (state != kCsAny && (serial || !ambiguous)) {
        adb_sleep_ms(1000);
        goto retry;
    }

    return result;
}

const char* atransport::connection_state_name() const {
    switch (connection_state) {
    case kCsOffline: return "offline";
    case kCsBootloader: return "bootloader";
    case kCsDevice: return "device";
    case kCsHost: return "host";
    case kCsRecovery: return "recovery";
    case kCsNoPerm: return "no permissions";
    case kCsSideload: return "sideload";
    case kCsUnauthorized: return "unauthorized";
    default: return "unknown";
    }
}

#if ADB_HOST

static void append_transport_info(std::string* result, const char* key,
                                  const char* value, bool sanitize) {
    if (value == nullptr || *value == '\0') {
        return;
    }

    *result += ' ';
    *result += key;

    for (const char* p = value; *p; ++p) {
        result->push_back((!sanitize || isalnum(*p)) ? *p : '_');
    }
}

static void append_transport(const atransport* t, std::string* result,
                             bool long_listing) {
    const char* serial = t->serial;
    if (!serial || !serial[0]) {
        serial = "(no serial number)";
    }

    if (!long_listing) {
        *result += serial;
        *result += '\t';
        *result += t->connection_state_name();
    } else {
        android::base::StringAppendF(result, "%-22s %s", serial, t->connection_state_name());

        append_transport_info(result, "", t->devpath, false);
        append_transport_info(result, "product:", t->product, false);
        append_transport_info(result, "model:", t->model, true);
        append_transport_info(result, "device:", t->device, false);
    }
    *result += '\n';
}

std::string list_transports(bool long_listing) {
    std::string result;
    adb_mutex_lock(&transport_lock);
    for (const auto t : transport_list) {
        append_transport(t, &result, long_listing);
    }
    adb_mutex_unlock(&transport_lock);
    return result;
}

/* hack for osx */
void close_usb_devices() {
    adb_mutex_lock(&transport_lock);
    for (auto t : transport_list) {
        if (!t->kicked) {
            t->kicked = 1;
            t->kick(t);
        }
    }
    adb_mutex_unlock(&transport_lock);
}
#endif // ADB_HOST

int register_socket_transport(int s, const char *serial, int port, int local) {
    atransport* t = new atransport();

    if (!serial) {
        char buf[32];
        snprintf(buf, sizeof(buf), "T-%p", t);
        serial = buf;
    }

    D("transport: %s init'ing for socket %d, on port %d\n", serial, s, port);
    if (init_socket_transport(t, s, port, local) < 0) {
        delete t;
        return -1;
    }

    adb_mutex_lock(&transport_lock);
    for (auto transport : pending_list) {
        if (transport->serial && strcmp(serial, transport->serial) == 0) {
            adb_mutex_unlock(&transport_lock);
            delete t;
            return -1;
        }
    }

    for (auto transport : transport_list) {
        if (transport->serial && strcmp(serial, transport->serial) == 0) {
            adb_mutex_unlock(&transport_lock);
            delete t;
            return -1;
        }
    }

    pending_list.push_front(t);
    t->serial = strdup(serial);
    adb_mutex_unlock(&transport_lock);

    register_transport(t);
    return 0;
}

#if ADB_HOST
atransport *find_transport(const char *serial) {
    atransport* result = nullptr;

    adb_mutex_lock(&transport_lock);
    for (auto t : transport_list) {
        if (t->serial && strcmp(serial, t->serial) == 0) {
            result = t;
            break;
        }
    }
    adb_mutex_unlock(&transport_lock);

    return result;
}

void unregister_transport(atransport *t)
{
    adb_mutex_lock(&transport_lock);
    transport_list.remove(t);
    adb_mutex_unlock(&transport_lock);

    kick_transport(t);
    transport_unref(t);
}

// Unregisters all non-emulator TCP transports.
void unregister_all_tcp_transports() {
    adb_mutex_lock(&transport_lock);
    for (auto it = transport_list.begin(); it != transport_list.end(); ) {
        atransport* t = *it;
        if (t->type == kTransportLocal && t->adb_port == 0) {
            // We cannot call kick_transport when holding transport_lock.
            if (!t->kicked) {
                t->kicked = 1;
                t->kick(t);
            }
            transport_unref_locked(t);

            it = transport_list.erase(it);
        } else {
            ++it;
        }
    }

    adb_mutex_unlock(&transport_lock);
}

#endif

void register_usb_transport(usb_handle* usb, const char* serial,
                            const char* devpath, unsigned writeable) {
    atransport* t = new atransport();

    D("transport: %p init'ing for usb_handle %p (sn='%s')\n", t, usb,
      serial ? serial : "");
    init_usb_transport(t, usb, (writeable ? kCsOffline : kCsNoPerm));
    if(serial) {
        t->serial = strdup(serial);
    }

    if (devpath) {
        t->devpath = strdup(devpath);
    }

    adb_mutex_lock(&transport_lock);
    pending_list.push_front(t);
    adb_mutex_unlock(&transport_lock);

    register_transport(t);
}

// This should only be used for transports with connection_state == kCsNoPerm.
void unregister_usb_transport(usb_handle *usb) {
    adb_mutex_lock(&transport_lock);
    transport_list.remove_if([usb](atransport* t) {
        return t->usb == usb && t->connection_state == kCsNoPerm;
    });
    adb_mutex_unlock(&transport_lock);
}

#undef TRACE_TAG
#define TRACE_TAG  TRACE_RWX

int check_header(apacket *p)
{
    if(p->msg.magic != (p->msg.command ^ 0xffffffff)) {
        D("check_header(): invalid magic\n");
        return -1;
    }

    if(p->msg.data_length > MAX_PAYLOAD) {
        D("check_header(): %d > MAX_PAYLOAD\n", p->msg.data_length);
        return -1;
    }

    return 0;
}

int check_data(apacket *p)
{
    unsigned count, sum;
    unsigned char *x;

    count = p->msg.data_length;
    x = p->data;
    sum = 0;
    while(count-- > 0) {
        sum += *x++;
    }

    if(sum != p->msg.data_check) {
        return -1;
    } else {
        return 0;
    }
}
