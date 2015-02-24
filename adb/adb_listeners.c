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

#include "adb_listeners.h"

#include <stdio.h>

#include "sysdeps.h"

int gListenAll = 0; /* Not static because it is used in commandline.c. */

alistener listener_list = {
    .next = &listener_list,
    .prev = &listener_list,
};

void ss_listener_event_func(int _fd, unsigned ev, void *_l)
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

void listener_event_func(int _fd, unsigned ev, void *_l)
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

void listener_disconnect(void*  _l, atransport*  t)
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
int format_listeners(char* buf, size_t buflen)
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

int remove_listener(const char *local_name, atransport* transport)
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

void remove_all_listeners(void)
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

install_status_t install_listener(const char *local_name,
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
