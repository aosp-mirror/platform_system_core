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

#define  TRACE_TAG   TRACE_ADB

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_auth.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if !ADB_HOST
#include <private/android_filesystem_config.h>
#include <linux/capability.h>
#include <linux/prctl.h>
#include <sys/mount.h>
#else
#include "usb_vendors.h"
#endif

#if ADB_TRACE
ADB_MUTEX_DEFINE( D_lock );
#endif

int HOST = 0;
int gListenAll = 0;

static int auth_enabled = 0;

#if !ADB_HOST
static const char *adb_device_banner = "device";
#endif

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

int   adb_trace_mask;

/* read a comma/space/colum/semi-column separated list of tags
 * from the ADB_TRACE environment variable and build the trace
 * mask from it. note that '1' and 'all' are special cases to
 * enable all tracing
 */
void  adb_trace_init(void)
{
    const char*  p = getenv("ADB_TRACE");
    const char*  q;

    static const struct {
        const char*  tag;
        int           flag;
    } tags[] = {
        { "1", 0 },
        { "all", 0 },
        { "adb", TRACE_ADB },
        { "sockets", TRACE_SOCKETS },
        { "packets", TRACE_PACKETS },
        { "rwx", TRACE_RWX },
        { "usb", TRACE_USB },
        { "sync", TRACE_SYNC },
        { "sysdeps", TRACE_SYSDEPS },
        { "transport", TRACE_TRANSPORT },
        { "jdwp", TRACE_JDWP },
        { "services", TRACE_SERVICES },
        { "auth", TRACE_AUTH },
        { NULL, 0 }
    };

    if (p == NULL)
            return;

    /* use a comma/column/semi-colum/space separated list */
    while (*p) {
        int  len, tagn;

        q = strpbrk(p, " ,:;");
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        for (tagn = 0; tags[tagn].tag != NULL; tagn++)
        {
            int  taglen = strlen(tags[tagn].tag);

            if (len == taglen && !memcmp(tags[tagn].tag, p, len) )
            {
                int  flag = tags[tagn].flag;
                if (flag == 0) {
                    adb_trace_mask = ~0;
                    return;
                }
                adb_trace_mask |= (1 << flag);
                break;
            }
        }
        p = q;
        if (*p)
            p++;
    }
}

#if !ADB_HOST
/*
 * Implements ADB tracing inside the emulator.
 */

#include <stdarg.h>

/*
 * Redefine open and write for qemu_pipe.h that contains inlined references
 * to those routines. We will redifine them back after qemu_pipe.h inclusion.
 */

#undef open
#undef write
#define open    adb_open
#define write   adb_write
#include <hardware/qemu_pipe.h>
#undef open
#undef write
#define open    ___xxx_open
#define write   ___xxx_write

/* A handle to adb-debug qemud service in the emulator. */
int   adb_debug_qemu = -1;

/* Initializes connection with the adb-debug qemud service in the emulator. */
static int adb_qemu_trace_init(void)
{
    char con_name[32];

    if (adb_debug_qemu >= 0) {
        return 0;
    }

    /* adb debugging QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "qemud:adb-debug");
    adb_debug_qemu = qemu_pipe_open(con_name);
    return (adb_debug_qemu >= 0) ? 0 : -1;
}

void adb_qemu_trace(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char msg[1024];

    if (adb_debug_qemu >= 0) {
        vsnprintf(msg, sizeof(msg), fmt, args);
        adb_write(adb_debug_qemu, msg, strlen(msg));
    }
}
#endif  /* !ADB_HOST */

apacket *get_apacket(void)
{
    apacket *p = malloc(sizeof(apacket));
    if(p == 0) fatal("failed to allocate an apacket");
    memset(p, 0, sizeof(apacket) - MAX_PAYLOAD);
    return p;
}

void put_apacket(apacket *p)
{
    free(p);
}

void handle_online(atransport *t)
{
    D("adb: online\n");
    t->online = 1;
}

void handle_offline(atransport *t)
{
    D("adb: offline\n");
    //Close the associated usb
    t->online = 0;
    run_transport_disconnects(t);
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    char *tag;
    char *x;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    case A_AUTH: tag = "AUTH"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    x = (char*) p->data;
    if(count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while(count-- > 0){
        if((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fputs(tag, stderr);
}
#endif

static void send_ready(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_ready \n");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close \n");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static size_t fill_connect_data(char *buf, size_t bufsize)
{
#if ADB_HOST
    return snprintf(buf, bufsize, "host::") + 1;
#else
    static const char *cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };
    static const int num_cnxn_props = ARRAY_SIZE(cnxn_props);
    int i;
    size_t remaining = bufsize;
    size_t len;

    len = snprintf(buf, remaining, "%s::", adb_device_banner);
    remaining -= len;
    buf += len;
    for (i = 0; i < num_cnxn_props; i++) {
        char value[PROPERTY_VALUE_MAX];
        property_get(cnxn_props[i], value, "");
        len = snprintf(buf, remaining, "%s=%s;", cnxn_props[i], value);
        remaining -= len;
        buf += len;
    }

    return bufsize - remaining + 1;
#endif
}

static void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = MAX_PAYLOAD;
    cp->msg.data_length = fill_connect_data((char *)cp->data,
                                            sizeof(cp->data));
    send_packet(cp, t);
}

static void send_auth_request(atransport *t)
{
    D("Calling send_auth_request\n");
    apacket *p;
    int ret;

    ret = adb_auth_generate_token(t->token, sizeof(t->token));
    if (ret != sizeof(t->token)) {
        D("Error generating token ret=%d\n", ret);
        return;
    }

    p = get_apacket();
    memcpy(p->data, t->token, ret);
    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_TOKEN;
    p->msg.data_length = ret;
    send_packet(p, t);
}

static void send_auth_response(uint8_t *token, size_t token_size, atransport *t)
{
    D("Calling send_auth_response\n");
    apacket *p = get_apacket();
    int ret;

    ret = adb_auth_sign(t->key, token, token_size, p->data);
    if (!ret) {
        D("Error signing the token\n");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_SIGNATURE;
    p->msg.data_length = ret;
    send_packet(p, t);
}

static void send_auth_publickey(atransport *t)
{
    D("Calling send_auth_publickey\n");
    apacket *p = get_apacket();
    int ret;

    ret = adb_auth_get_userkey(p->data, sizeof(p->data));
    if (!ret) {
        D("Failed to get user public key\n");
        put_apacket(p);
        return;
    }

    p->msg.command = A_AUTH;
    p->msg.arg0 = ADB_AUTH_RSAPUBLICKEY;
    p->msg.data_length = ret;
    send_packet(p, t);
}

void adb_auth_verified(atransport *t)
{
    handle_online(t);
    send_connect(t);
}

static char *connection_state_name(atransport *t)
{
    if (t == NULL) {
        return "unknown";
    }

    switch(t->connection_state) {
    case CS_BOOTLOADER:
        return "bootloader";
    case CS_DEVICE:
        return "device";
    case CS_OFFLINE:
        return "offline";
    default:
        return "unknown";
    }
}

/* qual_overwrite is used to overwrite a qualifier string.  dst is a
 * pointer to a char pointer.  It is assumed that if *dst is non-NULL, it
 * was malloc'ed and needs to freed.  *dst will be set to a dup of src.
 */
static void qual_overwrite(char **dst, const char *src)
{
    if (!dst)
        return;

    free(*dst);
    *dst = NULL;

    if (!src || !*src)
        return;

    *dst = strdup(src);
}

void parse_banner(char *banner, atransport *t)
{
    static const char *prop_seps = ";";
    static const char key_val_sep = '=';
    char *cp;
    char *type;

    D("parse_banner: %s\n", banner);
    type = banner;
    cp = strchr(type, ':');
    if (cp) {
        *cp++ = 0;
        /* Nothing is done with second field. */
        cp = strchr(cp, ':');
        if (cp) {
            char *save;
            char *key;
            key = adb_strtok_r(cp + 1, prop_seps, &save);
            while (key) {
                cp = strchr(key, key_val_sep);
                if (cp) {
                    *cp++ = '\0';
                    if (!strcmp(key, "ro.product.name"))
                        qual_overwrite(&t->product, cp);
                    else if (!strcmp(key, "ro.product.model"))
                        qual_overwrite(&t->model, cp);
                    else if (!strcmp(key, "ro.product.device"))
                        qual_overwrite(&t->device, cp);
                }
                key = adb_strtok_r(NULL, prop_seps, &save);
            }
        }
    }

    if(!strcmp(type, "bootloader")){
        D("setting connection_state to CS_BOOTLOADER\n");
        t->connection_state = CS_BOOTLOADER;
        update_transports();
        return;
    }

    if(!strcmp(type, "device")) {
        D("setting connection_state to CS_DEVICE\n");
        t->connection_state = CS_DEVICE;
        update_transports();
        return;
    }

    if(!strcmp(type, "recovery")) {
        D("setting connection_state to CS_RECOVERY\n");
        t->connection_state = CS_RECOVERY;
        update_transports();
        return;
    }

    if(!strcmp(type, "sideload")) {
        D("setting connection_state to CS_SIDELOAD\n");
        t->connection_state = CS_SIDELOAD;
        update_transports();
        return;
    }

    t->connection_state = CS_HOST;
}

void handle_packet(apacket *p, atransport *t)
{
    asocket *s;

    D("handle_packet() %c%c%c%c\n", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);

    switch(p->msg.command){
    case A_SYNC:
        if(p->msg.arg0){
            send_packet(p, t);
            if(HOST) send_connect(t);
        } else {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
            /* XXX verify version, etc */
        if(t->connection_state != CS_OFFLINE) {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
        }

        parse_banner((char*) p->data, t);

        if (HOST || !auth_enabled) {
            handle_online(t);
            if(!HOST) send_connect(t);
        } else {
            send_auth_request(t);
        }
        break;

    case A_AUTH:
        if (p->msg.arg0 == ADB_AUTH_TOKEN) {
            t->key = adb_auth_nextkey(t->key);
            if (t->key) {
                send_auth_response(p->data, p->msg.data_length, t);
            } else {
                /* No more private keys to try, send the public key */
                send_auth_publickey(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_SIGNATURE) {
            if (adb_auth_verify(t->token, p->data, p->msg.data_length)) {
                adb_auth_verified(t);
                t->failed_auth_attempts = 0;
            } else {
                if (t->failed_auth_attempts++ > 10)
                    adb_sleep_ms(1000);
                send_auth_request(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_RSAPUBLICKEY) {
            adb_auth_confirm_key(p->data, p->msg.data_length, t);
        }
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if (t->online) {
            char *name = (char*) p->data;
            name[p->msg.data_length > 0 ? p->msg.data_length - 1 : 0] = 0;
            s = create_local_service_socket(name);
            if(s == 0) {
                send_close(0, p->msg.arg0, t);
            } else {
                s->peer = create_remote_socket(p->msg.arg0, t);
                s->peer->peer = s;
                send_ready(s->id, s->peer->id, t);
                s->ready(s);
            }
        }
        break;

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                if(s->peer == 0) {
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                }
                s->ready(s);
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") */
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                s->close(s);
            }
        }
        break;

    case A_WRTE:
        if (t->online) {
            if((s = find_local_socket(p->msg.arg1))) {
                unsigned rid = p->msg.arg0;
                p->len = p->msg.data_length;

                if(s->enqueue(s, p) == 0) {
                    D("Enqueue the socket\n");
                    send_ready(s->id, rid, t);
                }
                return;
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

alistener listener_list = {
    .next = &listener_list,
    .prev = &listener_list,
};

static void ss_listener_event_func(int _fd, unsigned ev, void *_l)
{
    asocket *s;

    if(ev & FDE_READ) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        fd = adb_socket_accept(_fd, &addr, &alen);
        if(fd < 0) return;

        adb_socket_setbufsize(fd, CHUNK_SIZE);

        s = create_local_socket(fd);
        if(s) {
            connect_to_smartsocket(s);
            return;
        }

        adb_close(fd);
    }
}

static void listener_event_func(int _fd, unsigned ev, void *_l)
{
    alistener *l = _l;
    asocket *s;

    if(ev & FDE_READ) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        fd = adb_socket_accept(_fd, &addr, &alen);
        if(fd < 0) return;

        s = create_local_socket(fd);
        if(s) {
            s->transport = l->transport;
            connect_to_remote(s, l->connect_to);
            return;
        }

        adb_close(fd);
    }
}

static void  free_listener(alistener*  l)
{
    if (l->next) {
        l->next->prev = l->prev;
        l->prev->next = l->next;
        l->next = l->prev = l;
    }

    // closes the corresponding fd
    fdevent_remove(&l->fde);

    if (l->local_name)
        free((char*)l->local_name);

    if (l->connect_to)
        free((char*)l->connect_to);

    if (l->transport) {
        remove_transport_disconnect(l->transport, &l->disconnect);
    }
    free(l);
}

static void listener_disconnect(void*  _l, atransport*  t)
{
    alistener*  l = _l;

    free_listener(l);
}

int local_name_to_fd(const char *name)
{
    int port;

    if(!strncmp("tcp:", name, 4)){
        int  ret;
        port = atoi(name + 4);

        if (gListenAll > 0) {
            ret = socket_inaddr_any_server(port, SOCK_STREAM);
        } else {
            ret = socket_loopback_server(port, SOCK_STREAM);
        }

        return ret;
    }
#ifndef HAVE_WIN32_IPC  /* no Unix-domain sockets on Win32 */
    // It's non-sensical to support the "reserved" space on the adb host side
    if(!strncmp(name, "local:", 6)) {
        return socket_local_server(name + 6,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localabstract:", 14)) {
        return socket_local_server(name + 14,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localfilesystem:", 16)) {
        return socket_local_server(name + 16,
                ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
    }

#endif
    printf("unknown local portname '%s'\n", name);
    return -1;
}

// Write a single line describing a listener to a user-provided buffer.
// Appends a trailing zero, even in case of truncation, but the function
// returns the full line length.
// If |buffer| is NULL, does not write but returns required size.
static int format_listener(alistener* l, char* buffer, size_t buffer_len) {
    // Format is simply:
    //
    //  <device-serial> " " <local-name> " " <remote-name> "\n"
    //
    int local_len = strlen(l->local_name);
    int connect_len = strlen(l->connect_to);
    int serial_len = strlen(l->transport->serial);

    if (buffer != NULL) {
        snprintf(buffer, buffer_len, "%s %s %s\n",
                l->transport->serial, l->local_name, l->connect_to);
    }
    // NOTE: snprintf() on Windows returns -1 in case of truncation, so
    // return the computed line length instead.
    return local_len + connect_len + serial_len + 3;
}

// Write the list of current listeners (network redirections) into a
// user-provided buffer. Appends a trailing zero, even in case of
// trunctaion, but return the full size in bytes.
// If |buffer| is NULL, does not write but returns required size.
static int format_listeners(char* buf, size_t buflen)
{
    alistener* l;
    int result = 0;
    for (l = listener_list.next; l != &listener_list; l = l->next) {
        // Ignore special listeners like those for *smartsocket*
        if (l->connect_to[0] == '*')
          continue;
        int len = format_listener(l, buf, buflen);
        // Ensure there is space for the trailing zero.
        result += len;
        if (buf != NULL) {
          buf += len;
          buflen -= len;
          if (buflen <= 0)
              break;
        }
    }
    return result;
}

static int remove_listener(const char *local_name, atransport* transport)
{
    alistener *l;

    for (l = listener_list.next; l != &listener_list; l = l->next) {
        if (!strcmp(local_name, l->local_name)) {
            listener_disconnect(l, l->transport);
            return 0;
        }
    }
    return -1;
}

static void remove_all_listeners(void)
{
    alistener *l, *l_next;
    for (l = listener_list.next; l != &listener_list; l = l_next) {
        l_next = l->next;
        // Never remove smart sockets.
        if (l->connect_to[0] == '*')
            continue;
        listener_disconnect(l, l->transport);
    }
}

// error/status codes for install_listener.
typedef enum {
  INSTALL_STATUS_OK = 0,
  INSTALL_STATUS_INTERNAL_ERROR = -1,
  INSTALL_STATUS_CANNOT_BIND = -2,
  INSTALL_STATUS_CANNOT_REBIND = -3,
} install_status_t;

static install_status_t install_listener(const char *local_name,
                                         const char *connect_to,
                                         atransport* transport,
                                         int no_rebind)
{
    alistener *l;

    //printf("install_listener('%s','%s')\n", local_name, connect_to);

    for(l = listener_list.next; l != &listener_list; l = l->next){
        if(strcmp(local_name, l->local_name) == 0) {
            char *cto;

                /* can't repurpose a smartsocket */
            if(l->connect_to[0] == '*') {
                return INSTALL_STATUS_INTERNAL_ERROR;
            }

                /* can't repurpose a listener if 'no_rebind' is true */
            if (no_rebind) {
                return INSTALL_STATUS_CANNOT_REBIND;
            }

            cto = strdup(connect_to);
            if(cto == 0) {
                return INSTALL_STATUS_INTERNAL_ERROR;
            }

            //printf("rebinding '%s' to '%s'\n", local_name, connect_to);
            free((void*) l->connect_to);
            l->connect_to = cto;
            if (l->transport != transport) {
                remove_transport_disconnect(l->transport, &l->disconnect);
                l->transport = transport;
                add_transport_disconnect(l->transport, &l->disconnect);
            }
            return INSTALL_STATUS_OK;
        }
    }

    if((l = calloc(1, sizeof(alistener))) == 0) goto nomem;
    if((l->local_name = strdup(local_name)) == 0) goto nomem;
    if((l->connect_to = strdup(connect_to)) == 0) goto nomem;


    l->fd = local_name_to_fd(local_name);
    if(l->fd < 0) {
        free((void*) l->local_name);
        free((void*) l->connect_to);
        free(l);
        printf("cannot bind '%s'\n", local_name);
        return -2;
    }

    close_on_exec(l->fd);
    if(!strcmp(l->connect_to, "*smartsocket*")) {
        fdevent_install(&l->fde, l->fd, ss_listener_event_func, l);
    } else {
        fdevent_install(&l->fde, l->fd, listener_event_func, l);
    }
    fdevent_set(&l->fde, FDE_READ);

    l->next = &listener_list;
    l->prev = listener_list.prev;
    l->next->prev = l;
    l->prev->next = l;
    l->transport = transport;

    if (transport) {
        l->disconnect.opaque = l;
        l->disconnect.func   = listener_disconnect;
        add_transport_disconnect(transport, &l->disconnect);
    }
    return INSTALL_STATUS_OK;

nomem:
    fatal("cannot allocate listener");
    return INSTALL_STATUS_INTERNAL_ERROR;
}

#ifdef HAVE_WIN32_PROC
static BOOL WINAPI ctrlc_handler(DWORD type)
{
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}
#endif

static void adb_cleanup(void)
{
    usb_cleanup();
}

void start_logging(void)
{
#ifdef HAVE_WIN32_PROC
    char    temp[ MAX_PATH ];
    FILE*   fnul;
    FILE*   flog;

    GetTempPath( sizeof(temp) - 8, temp );
    strcat( temp, "adb.log" );

    /* Win32 specific redirections */
    fnul = fopen( "NUL", "rt" );
    if (fnul != NULL)
        stdin[0] = fnul[0];

    flog = fopen( temp, "at" );
    if (flog == NULL)
        flog = fnul;

    setvbuf( flog, NULL, _IONBF, 0 );

    stdout[0] = flog[0];
    stderr[0] = flog[0];
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#else
    int fd;

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);

    fd = unix_open("/tmp/adb.log", O_WRONLY | O_CREAT | O_APPEND, 0640);
    if(fd < 0) {
        fd = unix_open("/dev/null", O_WRONLY);
    }
    dup2(fd, 1);
    dup2(fd, 2);
    adb_close(fd);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#endif
}

#if !ADB_HOST
void start_device_log(void)
{
    int fd;
    char    path[PATH_MAX];
    struct tm now;
    time_t t;
    char value[PROPERTY_VALUE_MAX];

    // read the trace mask from persistent property persist.adb.trace_mask
    // give up if the property is not set or cannot be parsed
    property_get("persist.adb.trace_mask", value, "");
    if (sscanf(value, "%x", &adb_trace_mask) != 1)
        return;

    adb_mkdir("/data/adb", 0775);
    tzset();
    time(&t);
    localtime_r(&t, &now);
    strftime(path, sizeof(path),
                "/data/adb/adb-%Y-%m-%d-%H-%M-%S.txt",
                &now);
    fd = unix_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        return;

    // redirect stdout and stderr to the log file
    dup2(fd, 1);
    dup2(fd, 2);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
    adb_close(fd);

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);
}
#endif

#if ADB_HOST
int launch_server(int server_port)
{
#ifdef HAVE_WIN32_PROC
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    HANDLE                pipe_read, pipe_write;
    HANDLE                stdout_handle, stderr_handle;
    SECURITY_ATTRIBUTES   sa;
    STARTUPINFO           startup;
    PROCESS_INFORMATION   pinfo;
    char                  program_path[ MAX_PATH ];
    int                   ret;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* create pipe, and ensure its read handle isn't inheritable */
    ret = CreatePipe( &pipe_read, &pipe_write, &sa, 0 );
    if (!ret) {
        fprintf(stderr, "CreatePipe() failure, error %ld\n", GetLastError() );
        return -1;
    }

    SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );

    /* Some programs want to launch an adb command and collect its output by
     * calling CreateProcess with inheritable stdout/stderr handles, then
     * using read() to get its output. When this happens, the stdout/stderr
     * handles passed to the adb client process will also be inheritable.
     * When starting the adb server here, care must be taken to reset them
     * to non-inheritable.
     * Otherwise, something bad happens: even if the adb command completes,
     * the calling process is stuck while read()-ing from the stdout/stderr
     * descriptors, because they're connected to corresponding handles in the
     * adb server process (even if the latter never uses/writes to them).
     */
    stdout_handle = GetStdHandle( STD_OUTPUT_HANDLE );
    stderr_handle = GetStdHandle( STD_ERROR_HANDLE );
    if (stdout_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stdout_handle, HANDLE_FLAG_INHERIT, 0 );
    }
    if (stderr_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stderr_handle, HANDLE_FLAG_INHERIT, 0 );
    }

    ZeroMemory( &startup, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
    startup.hStdOutput = pipe_write;
    startup.hStdError  = GetStdHandle( STD_ERROR_HANDLE );
    startup.dwFlags    = STARTF_USESTDHANDLES;

    ZeroMemory( &pinfo, sizeof(pinfo) );

    /* get path of current program */
    GetModuleFileName( NULL, program_path, sizeof(program_path) );

    ret = CreateProcess(
            program_path,                              /* program path  */
            "adb fork-server server",
                                    /* the fork-server argument will set the
                                       debug = 2 in the child           */
            NULL,                   /* process handle is not inheritable */
            NULL,                    /* thread handle is not inheritable */
            TRUE,                          /* yes, inherit some handles */
            DETACHED_PROCESS, /* the new process doesn't have a console */
            NULL,                     /* use parent's environment block */
            NULL,                    /* use parent's starting directory */
            &startup,                 /* startup info, i.e. std handles */
            &pinfo );

    CloseHandle( pipe_write );

    if (!ret) {
        fprintf(stderr, "CreateProcess failure, error %ld\n", GetLastError() );
        CloseHandle( pipe_read );
        return -1;
    }

    CloseHandle( pinfo.hProcess );
    CloseHandle( pinfo.hThread );

    /* wait for the "OK\n" message */
    {
        char  temp[3];
        DWORD  count;

        ret = ReadFile( pipe_read, temp, 3, &count, NULL );
        CloseHandle( pipe_read );
        if ( !ret ) {
            fprintf(stderr, "could not read ok from ADB Server, error = %ld\n", GetLastError() );
            return -1;
        }
        if (count != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }
    }
#elif defined(HAVE_FORKEXEC)
    char    path[PATH_MAX];
    int     fd[2];

    // set up a pipe so the child can tell us when it is ready.
    // fd[0] will be parent's end, and fd[1] will get mapped to stderr in the child.
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }
    get_my_path(path, PATH_MAX);
    pid_t pid = fork();
    if(pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        // redirect stderr to the pipe
        // we use stderr instead of stdout due to stdout's buffering behavior.
        adb_close(fd[0]);
        dup2(fd[1], STDERR_FILENO);
        adb_close(fd[1]);

        char str_port[30];
        snprintf(str_port, sizeof(str_port), "%d",  server_port);
        // child process
        int result = execl(path, "adb", "-P", str_port, "fork-server", "server", NULL);
        // this should not return
        fprintf(stderr, "OOPS! execl returned %d, errno: %d\n", result, errno);
    } else  {
        // parent side of the fork

        char  temp[3];

        temp[0] = 'A'; temp[1] = 'B'; temp[2] = 'C';
        // wait for the "OK\n" message
        adb_close(fd[1]);
        int ret = adb_read(fd[0], temp, 3);
        int saved_errno = errno;
        adb_close(fd[0]);
        if (ret < 0) {
            fprintf(stderr, "could not read ok from ADB Server, errno = %d\n", saved_errno);
            return -1;
        }
        if (ret != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }

        setsid();
    }
#else
#error "cannot implement background server start on this platform"
#endif
    return 0;
}
#endif

/* Constructs a local name of form tcp:port.
 * target_str points to the target string, it's content will be overwritten.
 * target_size is the capacity of the target string.
 * server_port is the port number to use for the local name.
 */
void build_local_name(char* target_str, size_t target_size, int server_port)
{
  snprintf(target_str, target_size, "tcp:%d", server_port);
}

#if !ADB_HOST
static int should_drop_privileges() {
#ifndef ALLOW_ADBD_ROOT
    return 1;
#else /* ALLOW_ADBD_ROOT */
    int secure = 0;
    char value[PROPERTY_VALUE_MAX];

   /* run adbd in secure mode if ro.secure is set and
    ** we are not in the emulator
    */
    property_get("ro.kernel.qemu", value, "");
    if (strcmp(value, "1") != 0) {
        property_get("ro.secure", value, "1");
        if (strcmp(value, "1") == 0) {
            // don't run as root if ro.secure is set...
            secure = 1;

            // ... except we allow running as root in userdebug builds if the
            // service.adb.root property has been set by the "adb root" command
            property_get("ro.debuggable", value, "");
            if (strcmp(value, "1") == 0) {
                property_get("service.adb.root", value, "");
                if (strcmp(value, "1") == 0) {
                    secure = 0;
                }
            }
        }
    }
    return secure;
#endif /* ALLOW_ADBD_ROOT */
}
#endif /* !ADB_HOST */

int adb_main(int is_daemon, int server_port)
{
#if !ADB_HOST
    int port;
    char value[PROPERTY_VALUE_MAX];

    umask(000);
#endif

    atexit(adb_cleanup);
#ifdef HAVE_WIN32_PROC
    SetConsoleCtrlHandler( ctrlc_handler, TRUE );
#elif defined(HAVE_FORKEXEC)
    // No SIGCHLD. Let the service subproc handle its children.
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

#if ADB_HOST
    HOST = 1;
    usb_vendors_init();
    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    char local_name[30];
    build_local_name(local_name, sizeof(local_name), server_port);
    if(install_listener(local_name, "*smartsocket*", NULL, 0)) {
        exit(1);
    }
#else
    property_get("ro.adb.secure", value, "0");
    auth_enabled = !strcmp(value, "1");
    if (auth_enabled)
        adb_auth_init();

    // Our external storage path may be different than apps, since
    // we aren't able to bind mount after dropping root.
    const char* adb_external_storage = getenv("ADB_EXTERNAL_STORAGE");
    if (NULL != adb_external_storage) {
        setenv("EXTERNAL_STORAGE", adb_external_storage, 1);
    } else {
        D("Warning: ADB_EXTERNAL_STORAGE is not set.  Leaving EXTERNAL_STORAGE"
          " unchanged.\n");
    }

    /* don't listen on a port (default 5037) if running in secure mode */
    /* don't run as root if we are running in secure mode */
    if (should_drop_privileges()) {
        struct __user_cap_header_struct header;
        struct __user_cap_data_struct cap[2];

        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
            exit(1);
        }

        /* add extra groups:
        ** AID_ADB to access the USB driver
        ** AID_LOG to read system logs (adb logcat)
        ** AID_INPUT to diagnose input issues (getevent)
        ** AID_INET to diagnose network issues (netcfg, ping)
        ** AID_GRAPHICS to access the frame buffer
        ** AID_NET_BT and AID_NET_BT_ADMIN to diagnose bluetooth (hcidump)
        ** AID_SDCARD_R to allow reading from the SD card
        ** AID_SDCARD_RW to allow writing to the SD card
        ** AID_MOUNT to allow unmounting the SD card before rebooting
        ** AID_NET_BW_STATS to read out qtaguid statistics
        */
        gid_t groups[] = { AID_ADB, AID_LOG, AID_INPUT, AID_INET, AID_GRAPHICS,
                           AID_NET_BT, AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                           AID_MOUNT, AID_NET_BW_STATS };
        if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) != 0) {
            exit(1);
        }

        /* then switch user and group to "shell" */
        if (setgid(AID_SHELL) != 0) {
            exit(1);
        }
        if (setuid(AID_SHELL) != 0) {
            exit(1);
        }

        memset(&header, 0, sizeof(header));
        memset(cap, 0, sizeof(cap));

        /* set CAP_SYS_BOOT capability, so "adb reboot" will succeed */
        header.version = _LINUX_CAPABILITY_VERSION_3;
        header.pid = 0;
        cap[CAP_TO_INDEX(CAP_SYS_BOOT)].effective |= CAP_TO_MASK(CAP_SYS_BOOT);
        cap[CAP_TO_INDEX(CAP_SYS_BOOT)].permitted |= CAP_TO_MASK(CAP_SYS_BOOT);
        capset(&header, cap);

        D("Local port disabled\n");
    } else {
        char local_name[30];
        build_local_name(local_name, sizeof(local_name), server_port);
        if(install_listener(local_name, "*smartsocket*", NULL, 0)) {
            exit(1);
        }
    }

    int usb = 0;
    if (access(USB_ADB_PATH, F_OK) == 0 || access(USB_FFS_ADB_EP0, F_OK) == 0) {
        // listen on USB
        usb_init();
        usb = 1;
    }

    // If one of these properties is set, also listen on that port
    // If one of the properties isn't set and we couldn't listen on usb,
    // listen on the default port.
    property_get("service.adb.tcp.port", value, "");
    if (!value[0]) {
        property_get("persist.adb.tcp.port", value, "");
    }
    if (sscanf(value, "%d", &port) == 1 && port > 0) {
        printf("using port=%d\n", port);
        // listen on TCP port specified by service.adb.tcp.port property
        local_init(port);
    } else if (!usb) {
        // listen on default port
        local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    }

    D("adb_main(): pre init_jdwp()\n");
    init_jdwp();
    D("adb_main(): post init_jdwp()\n");
#endif

    if (is_daemon)
    {
        // inform our parent that we are up and running.
#ifdef HAVE_WIN32_PROC
        DWORD  count;
        WriteFile( GetStdHandle( STD_OUTPUT_HANDLE ), "OK\n", 3, &count, NULL );
#elif defined(HAVE_FORKEXEC)
        fprintf(stderr, "OK\n");
#endif
        start_logging();
    }
    D("Event loop starting\n");

    fdevent_loop();

    usb_cleanup();

    return 0;
}

#if ADB_HOST
void connect_device(char* host, char* buffer, int buffer_size)
{
    int port, fd;
    char* portstr = strchr(host, ':');
    char hostbuf[100];
    char serial[100];

    strncpy(hostbuf, host, sizeof(hostbuf) - 1);
    if (portstr) {
        if (portstr - host >= (ptrdiff_t)sizeof(hostbuf)) {
            snprintf(buffer, buffer_size, "bad host name %s", host);
            return;
        }
        // zero terminate the host at the point we found the colon
        hostbuf[portstr - host] = 0;
        if (sscanf(portstr + 1, "%d", &port) == 0) {
            snprintf(buffer, buffer_size, "bad port number %s", portstr);
            return;
        }
    } else {
        port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    }

    snprintf(serial, sizeof(serial), "%s:%d", hostbuf, port);
    if (find_transport(serial)) {
        snprintf(buffer, buffer_size, "already connected to %s", serial);
        return;
    }

    fd = socket_network_client(hostbuf, port, SOCK_STREAM);
    if (fd < 0) {
        snprintf(buffer, buffer_size, "unable to connect to %s:%d", host, port);
        return;
    }

    D("client: connected on remote on fd %d\n", fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);
    register_socket_transport(fd, serial, port, 0);
    snprintf(buffer, buffer_size, "connected to %s", serial);
}

void connect_emulator(char* port_spec, char* buffer, int buffer_size)
{
    char* port_separator = strchr(port_spec, ',');
    if (!port_separator) {
        snprintf(buffer, buffer_size,
                "unable to parse '%s' as <console port>,<adb port>",
                port_spec);
        return;
    }

    // Zero-terminate console port and make port_separator point to 2nd port.
    *port_separator++ = 0;
    int console_port = strtol(port_spec, NULL, 0);
    int adb_port = strtol(port_separator, NULL, 0);
    if (!(console_port > 0 && adb_port > 0)) {
        *(port_separator - 1) = ',';
        snprintf(buffer, buffer_size,
                "Invalid port numbers: Expected positive numbers, got '%s'",
                port_spec);
        return;
    }

    /* Check if the emulator is already known.
     * Note: There's a small but harmless race condition here: An emulator not
     * present just yet could be registered by another invocation right
     * after doing this check here. However, local_connect protects
     * against double-registration too. From here, a better error message
     * can be produced. In the case of the race condition, the very specific
     * error message won't be shown, but the data doesn't get corrupted. */
    atransport* known_emulator = find_emulator_transport_by_adb_port(adb_port);
    if (known_emulator != NULL) {
        snprintf(buffer, buffer_size,
                "Emulator on port %d already registered.", adb_port);
        return;
    }

    /* Check if more emulators can be registered. Similar unproblematic
     * race condition as above. */
    int candidate_slot = get_available_local_transport_index();
    if (candidate_slot < 0) {
        snprintf(buffer, buffer_size, "Cannot accept more emulators.");
        return;
    }

    /* Preconditions met, try to connect to the emulator. */
    if (!local_connect_arbitrary_ports(console_port, adb_port)) {
        snprintf(buffer, buffer_size,
                "Connected to emulator on ports %d,%d", console_port, adb_port);
    } else {
        snprintf(buffer, buffer_size,
                "Could not connect to emulator on ports %d,%d",
                console_port, adb_port);
    }
}
#endif

int handle_host_request(char *service, transport_type ttype, char* serial, int reply_fd, asocket *s)
{
    atransport *transport = NULL;
    char buf[4096];

    if(!strcmp(service, "kill")) {
        fprintf(stderr,"adb server killed by remote request\n");
        fflush(stdout);
        adb_write(reply_fd, "OKAY", 4);
        usb_cleanup();
        exit(0);
    }

#if ADB_HOST
    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        char* error_string = "unknown failure";
        transport_type type = kTransportAny;

        if (!strncmp(service, "transport-usb", strlen("transport-usb"))) {
            type = kTransportUsb;
        } else if (!strncmp(service, "transport-local", strlen("transport-local"))) {
            type = kTransportLocal;
        } else if (!strncmp(service, "transport-any", strlen("transport-any"))) {
            type = kTransportAny;
        } else if (!strncmp(service, "transport:", strlen("transport:"))) {
            service += strlen("transport:");
            serial = service;
        }

        transport = acquire_one_transport(CS_ANY, type, serial, &error_string);

        if (transport) {
            s->transport = transport;
            adb_write(reply_fd, "OKAY", 4);
        } else {
            sendfailmsg(reply_fd, error_string);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strncmp(service, "devices", 7)) {
        char buffer[4096];
        int use_long = !strcmp(service+7, "-l");
        if (use_long || service[7] == 0) {
            memset(buf, 0, sizeof(buf));
            memset(buffer, 0, sizeof(buffer));
            D("Getting device list \n");
            list_transports(buffer, sizeof(buffer), use_long);
            snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer),buffer);
            D("Wrote device list \n");
            writex(reply_fd, buf, strlen(buf));
            return 0;
        }
    }

    // add a new TCP transport, device or emulator
    if (!strncmp(service, "connect:", 8)) {
        char buffer[4096];
        char* host = service + 8;
        if (!strncmp(host, "emu:", 4)) {
            connect_emulator(host + 4, buffer, sizeof(buffer));
        } else {
            connect_device(host, buffer, sizeof(buffer));
        }
        // Send response for emulator and device
        snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer), buffer);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        char* serial = service + 11;
        if (serial[0] == 0) {
            // disconnect from all TCP devices
            unregister_all_tcp_transports();
        } else {
            char hostbuf[100];
            // assume port 5555 if no port is specified
            if (!strchr(serial, ':')) {
                snprintf(hostbuf, sizeof(hostbuf) - 1, "%s:5555", serial);
                serial = hostbuf;
            }
            atransport *t = find_transport(serial);

            if (t) {
                unregister_transport(t);
            } else {
                snprintf(buffer, sizeof(buffer), "No such device %s", serial);
            }
        }

        snprintf(buf, sizeof(buf), "OKAY%04x%s",(unsigned)strlen(buffer), buffer);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    // returns our value for ADB_SERVER_VERSION
    if (!strcmp(service, "version")) {
        char version[12];
        snprintf(version, sizeof version, "%04x", ADB_SERVER_VERSION);
        snprintf(buf, sizeof buf, "OKAY%04x%s", (unsigned)strlen(version), version);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }

    if(!strncmp(service,"get-serialno",strlen("get-serialno"))) {
        char *out = "unknown";
         transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
       if (transport && transport->serial) {
            out = transport->serial;
        }
        snprintf(buf, sizeof buf, "OKAY%04x%s",(unsigned)strlen(out),out);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }
    if(!strncmp(service,"get-devpath",strlen("get-devpath"))) {
        char *out = "unknown";
         transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
       if (transport && transport->devpath) {
            out = transport->devpath;
        }
        snprintf(buf, sizeof buf, "OKAY%04x%s",(unsigned)strlen(out),out);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }
    // indicates a new emulator instance has started
    if (!strncmp(service,"emulator:",9)) {
        int  port = atoi(service+9);
        local_connect(port);
        /* we don't even need to send a reply */
        return 0;
    }
#endif // ADB_HOST

    if(!strcmp(service,"list-forward")) {
        // Create the list of forward redirections.
        char header[9];
        int buffer_size = format_listeners(NULL, 0);
        // Add one byte for the trailing zero.
        char* buffer = malloc(buffer_size+1);
        (void) format_listeners(buffer, buffer_size+1);
        snprintf(header, sizeof header, "OKAY%04x", buffer_size);
        writex(reply_fd, header, 8);
        writex(reply_fd, buffer, buffer_size);
        free(buffer);
        return 0;
    }

    if (!strcmp(service,"killforward-all")) {
        remove_all_listeners();
        adb_write(reply_fd, "OKAYOKAY", 8);
        return 0;
    }

    if(!strncmp(service,"forward:",8) ||
       !strncmp(service,"killforward:",12)) {
        char *local, *remote, *err;
        int r;
        atransport *transport;

        int createForward = strncmp(service,"kill",4);
        int no_rebind = 0;

        local = strchr(service, ':') + 1;

        // Handle forward:norebind:<local>... here
        if (createForward && !strncmp(local, "norebind:", 9)) {
            no_rebind = 1;
            local = strchr(local, ':') + 1;
        }

        remote = strchr(local,';');

        if (createForward) {
            // Check forward: parameter format: '<local>;<remote>'
            if(remote == 0) {
                sendfailmsg(reply_fd, "malformed forward spec");
                return 0;
            }

            *remote++ = 0;
            if((local[0] == 0) || (remote[0] == 0) || (remote[0] == '*')){
                sendfailmsg(reply_fd, "malformed forward spec");
                return 0;
            }
        } else {
            // Check killforward: parameter format: '<local>'
            if (local[0] == 0) {
                sendfailmsg(reply_fd, "malformed forward spec");
                return 0;
            }
        }

        transport = acquire_one_transport(CS_ANY, ttype, serial, &err);
        if (!transport) {
            sendfailmsg(reply_fd, err);
            return 0;
        }

        if (createForward) {
            r = install_listener(local, remote, transport, no_rebind);
        } else {
            r = remove_listener(local, transport);
        }
        if(r == 0) {
                /* 1st OKAY is connect, 2nd OKAY is status */
            writex(reply_fd, "OKAYOKAY", 8);
            return 0;
        }

        if (createForward) {
            const char* message;
            switch (r) {
              case INSTALL_STATUS_CANNOT_BIND:
                message = "cannot bind to socket";
                break;
              case INSTALL_STATUS_CANNOT_REBIND:
                message = "cannot rebind existing socket";
                break;
              default:
                message = "internal error";
            }
            sendfailmsg(reply_fd, message);
        } else {
            sendfailmsg(reply_fd, "cannot remove listener");
        }
        return 0;
    }

    if(!strncmp(service,"get-state",strlen("get-state"))) {
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        char *state = connection_state_name(transport);
        snprintf(buf, sizeof buf, "OKAY%04x%s",(unsigned)strlen(state),state);
        writex(reply_fd, buf, strlen(buf));
        return 0;
    }
    return -1;
}

#if !ADB_HOST
int recovery_mode = 0;
#endif

int main(int argc, char **argv)
{
#if ADB_HOST
    adb_sysdeps_init();
    adb_trace_init();
    D("Handling commandline()\n");
    return adb_commandline(argc - 1, argv + 1);
#else
    /* If adbd runs inside the emulator this will enable adb tracing via
     * adb-debug qemud service in the emulator. */
    adb_qemu_trace_init();
    if((argc > 1) && (!strcmp(argv[1],"recovery"))) {
        adb_device_banner = "recovery";
        recovery_mode = 1;
    }

    start_device_log();
    D("Handling main()\n");
    return adb_main(0, DEFAULT_ADB_PORT);
#endif
}
