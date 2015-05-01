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

#ifndef __ADB_H
#define __ADB_H

#include <limits.h>
#include <sys/types.h>

#include "adb_trace.h"
#include "fdevent.h"

#define MAX_PAYLOAD 4096

#define A_SYNC 0x434e5953
#define A_CNXN 0x4e584e43
#define A_OPEN 0x4e45504f
#define A_OKAY 0x59414b4f
#define A_CLSE 0x45534c43
#define A_WRTE 0x45545257
#define A_AUTH 0x48545541

// ADB protocol version.
#define A_VERSION 0x01000000

// Used for help/version information.
#define ADB_VERSION_MAJOR 1
#define ADB_VERSION_MINOR 0

// Increment this when we want to force users to start a new adb server.
#define ADB_SERVER_VERSION 32

struct atransport;
struct usb_handle;

struct amessage {
    unsigned command;       /* command identifier constant      */
    unsigned arg0;          /* first argument                   */
    unsigned arg1;          /* second argument                  */
    unsigned data_length;   /* length of payload (0 is allowed) */
    unsigned data_check;    /* checksum of data payload         */
    unsigned magic;         /* command ^ 0xffffffff             */
};

struct apacket
{
    apacket *next;

    unsigned len;
    unsigned char *ptr;

    amessage msg;
    unsigned char data[MAX_PAYLOAD];
};

/* An asocket represents one half of a connection between a local and
** remote entity.  A local asocket is bound to a file descriptor.  A
** remote asocket is bound to the protocol engine.
*/
struct asocket {
        /* chain pointers for the local/remote list of
        ** asockets that this asocket lives in
        */
    asocket *next;
    asocket *prev;

        /* the unique identifier for this asocket
        */
    unsigned id;

        /* flag: set when the socket's peer has closed
        ** but packets are still queued for delivery
        */
    int    closing;

        /* flag: quit adbd when both ends close the
        ** local service socket
        */
    int    exit_on_close;

        /* the asocket we are connected to
        */

    asocket *peer;

        /* For local asockets, the fde is used to bind
        ** us to our fd event system.  For remote asockets
        ** these fields are not used.
        */
    fdevent fde;
    int fd;

        /* queue of apackets waiting to be written
        */
    apacket *pkt_first;
    apacket *pkt_last;

        /* enqueue is called by our peer when it has data
        ** for us.  It should return 0 if we can accept more
        ** data or 1 if not.  If we return 1, we must call
        ** peer->ready() when we once again are ready to
        ** receive data.
        */
    int (*enqueue)(asocket *s, apacket *pkt);

        /* ready is called by the peer when it is ready for
        ** us to send data via enqueue again
        */
    void (*ready)(asocket *s);

        /* shutdown is called by the peer before it goes away.
        ** the socket should not do any further calls on its peer.
        ** Always followed by a call to close. Optional, i.e. can be NULL.
        */
    void (*shutdown)(asocket *s);

        /* close is called by the peer when it has gone away.
        ** we are not allowed to make any further calls on the
        ** peer once our close method is called.
        */
    void (*close)(asocket *s);

        /* A socket is bound to atransport */
    atransport *transport;
};


/* the adisconnect structure is used to record a callback that
** will be called whenever a transport is disconnected (e.g. by the user)
** this should be used to cleanup objects that depend on the
** transport (e.g. remote sockets, listeners, etc...)
*/
struct  adisconnect
{
    void        (*func)(void*  opaque, atransport*  t);
    void*         opaque;
    adisconnect*  next;
    adisconnect*  prev;
};


/* a transport object models the connection to a remote device or emulator
** there is one transport per connected device/emulator. a "local transport"
** connects through TCP (for the emulator), while a "usb transport" through
** USB (for real devices)
**
** note that kTransportHost doesn't really correspond to a real transport
** object, it's a special value used to indicate that a client wants to
** connect to a service implemented within the ADB server itself.
*/
enum transport_type {
        kTransportUsb,
        kTransportLocal,
        kTransportAny,
        kTransportHost,
};

#define TOKEN_SIZE 20

struct atransport
{
    atransport *next;
    atransport *prev;

    int (*read_from_remote)(apacket *p, atransport *t);
    int (*write_to_remote)(apacket *p, atransport *t);
    void (*close)(atransport *t);
    void (*kick)(atransport *t);

    int fd;
    int transport_socket;
    fdevent transport_fde;
    int ref_count;
    unsigned sync_token;
    int connection_state;
    int online;
    transport_type type;

        /* usb handle or socket fd as needed */
    usb_handle *usb;
    int sfd;

        /* used to identify transports for clients */
    char *serial;
    char *product;
    char *model;
    char *device;
    char *devpath;
    int adb_port; // Use for emulators (local transport)

        /* a list of adisconnect callbacks called when the transport is kicked */
    int          kicked;
    adisconnect  disconnects;

    void *key;
    unsigned char token[TOKEN_SIZE];
    fdevent auth_fde;
    unsigned failed_auth_attempts;

    const char* connection_state_name() const;
};


/* A listener is an entity which binds to a local port
** and, upon receiving a connection on that port, creates
** an asocket to connect the new local connection to a
** specific remote service.
**
** TODO: some listeners read from the new connection to
** determine what exact service to connect to on the far
** side.
*/
struct alistener
{
    alistener *next;
    alistener *prev;

    fdevent fde;
    int fd;

    char *local_name;
    char *connect_to;
    atransport *transport;
    adisconnect  disconnect;
};


void print_packet(const char *label, apacket *p);

asocket *find_local_socket(unsigned local_id, unsigned remote_id);
void install_local_socket(asocket *s);
void remove_socket(asocket *s);
void close_all_sockets(atransport *t);

asocket *create_local_socket(int fd);
asocket *create_local_service_socket(const char *destination);

asocket *create_remote_socket(unsigned id, atransport *t);
void connect_to_remote(asocket *s, const char *destination);
void connect_to_smartsocket(asocket *s);

void fatal(const char *fmt, ...);
void fatal_errno(const char *fmt, ...);

void handle_packet(apacket *p, atransport *t);

void get_my_path(char *s, size_t maxLen);
int launch_server(int server_port);
int adb_main(int is_daemon, int server_port);

/* initialize a transport object's func pointers and state */
#if ADB_HOST
int get_available_local_transport_index();
#endif
int  init_socket_transport(atransport *t, int s, int port, int local);
void init_usb_transport(atransport *t, usb_handle *usb, int state);

#if ADB_HOST
atransport* find_emulator_transport_by_adb_port(int adb_port);
#endif

int service_to_fd(const char *name);
#if ADB_HOST
asocket *host_service_to_socket(const char*  name, const char *serial);
#endif

#if !ADB_HOST
int       init_jdwp(void);
asocket*  create_jdwp_service_socket();
asocket*  create_jdwp_tracker_service_socket();
int       create_jdwp_connection_fd(int  jdwp_pid);
#endif

int handle_forward_request(const char* service, transport_type ttype, char* serial, int reply_fd);

#if !ADB_HOST
void framebuffer_service(int fd, void *cookie);
void set_verity_enabled_state_service(int fd, void* cookie);
#endif

/* packet allocator */
apacket *get_apacket(void);
void put_apacket(apacket *p);

// Define it if you want to dump packets.
#define DEBUG_PACKETS 0

#if !DEBUG_PACKETS
#define print_packet(tag,p) do {} while (0)
#endif

#if ADB_HOST_ON_TARGET
/* adb and adbd are coexisting on the target, so use 5038 for adb
 * to avoid conflicting with adbd's usage of 5037
 */
#  define DEFAULT_ADB_PORT 5038
#else
#  define DEFAULT_ADB_PORT 5037
#endif

#define DEFAULT_ADB_LOCAL_TRANSPORT_PORT 5555

#define ADB_CLASS              0xff
#define ADB_SUBCLASS           0x42
#define ADB_PROTOCOL           0x1


void local_init(int port);
int  local_connect(int  port);
int  local_connect_arbitrary_ports(int console_port, int adb_port);

/* usb host/client interface */
void usb_init();
void usb_cleanup();
int usb_write(usb_handle *h, const void *data, int len);
int usb_read(usb_handle *h, void *data, int len);
int usb_close(usb_handle *h);
void usb_kick(usb_handle *h);

/* used for USB device detection */
#if ADB_HOST
int is_adb_interface(int vid, int pid, int usb_class, int usb_subclass, int usb_protocol);
#endif

int adb_commandline(int argc, const char **argv);

int connection_state(atransport *t);

#define CS_ANY       -1
#define CS_OFFLINE    0
#define CS_BOOTLOADER 1
#define CS_DEVICE     2
#define CS_HOST       3
#define CS_RECOVERY   4
#define CS_NOPERM     5 /* Insufficient permissions to communicate with the device */
#define CS_SIDELOAD   6
#define CS_UNAUTHORIZED 7

extern const char *adb_device_banner;
extern int HOST;
extern int SHELL_EXIT_NOTIFY_FD;

enum subproc_mode {
    SUBPROC_PTY = 0,
    SUBPROC_RAW = 1,
} ;

#define CHUNK_SIZE (64*1024)

#if !ADB_HOST
#define USB_ADB_PATH     "/dev/android_adb"

#define USB_FFS_ADB_PATH  "/dev/usb-ffs/adb/"
#define USB_FFS_ADB_EP(x) USB_FFS_ADB_PATH#x

#define USB_FFS_ADB_EP0   USB_FFS_ADB_EP(ep0)
#define USB_FFS_ADB_OUT   USB_FFS_ADB_EP(ep1)
#define USB_FFS_ADB_IN    USB_FFS_ADB_EP(ep2)
#endif

int handle_host_request(char *service, transport_type ttype, char* serial, int reply_fd, asocket *s);

void handle_online(atransport *t);
void handle_offline(atransport *t);

void send_connect(atransport *t);

#endif
