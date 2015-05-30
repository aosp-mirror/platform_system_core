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
#include <stdlib.h>

#include <base/stringprintf.h>

#include "sysdeps.h"
#include "transport.h"

int gListenAll = 0; /* Not static because it is used in commandline.c. */

static alistener listener_list = {
    .next = &listener_list,
    .prev = &listener_list,
};

static void ss_listener_event_func(int _fd, unsigned ev, void *_l) {
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

static void listener_event_func(int _fd, unsigned ev, void* _l)
{
    alistener* listener = reinterpret_cast<alistener*>(_l);
    asocket *s;

    if (ev & FDE_READ) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        fd = adb_socket_accept(_fd, &addr, &alen);
        if (fd < 0) {
            return;
        }

        s = create_local_socket(fd);
        if (s) {
            s->transport = listener->transport;
            connect_to_remote(s, listener->connect_to);
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

static void listener_disconnect(void* listener, atransport* t) {
    free_listener(reinterpret_cast<alistener*>(listener));
}

static int local_name_to_fd(const char* name) {
    if (!strncmp("tcp:", name, 4)) {
        int port = atoi(name + 4);
        if (gListenAll > 0) {
            return socket_inaddr_any_server(port, SOCK_STREAM);
        } else {
            return socket_loopback_server(port, SOCK_STREAM);
        }
    }
#ifndef HAVE_WIN32_IPC  /* no Unix-domain sockets on Win32 */
    // It's nonsensical to support the "reserved" space on the adb host side
    if (!strncmp(name, "local:", 6)) {
        return socket_local_server(name + 6, ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if (!strncmp(name, "localabstract:", 14)) {
        return socket_local_server(name + 14, ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if (!strncmp(name, "localfilesystem:", 16)) {
        return socket_local_server(name + 16, ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
    }

#endif
    printf("unknown local portname '%s'\n", name);
    return -1;
}

// Write the list of current listeners (network redirections) into a string.
std::string format_listeners() {
    std::string result;
    for (alistener* l = listener_list.next; l != &listener_list; l = l->next) {
        // Ignore special listeners like those for *smartsocket*
        if (l->connect_to[0] == '*') {
            continue;
        }
        //  <device-serial> " " <local-name> " " <remote-name> "\n"
        android::base::StringAppendF(&result, "%s %s %s\n",
                                     l->transport->serial, l->local_name, l->connect_to);
    }
    return result;
}

InstallStatus remove_listener(const char *local_name, atransport* transport) {
    alistener *l;

    for (l = listener_list.next; l != &listener_list; l = l->next) {
        if (!strcmp(local_name, l->local_name)) {
            listener_disconnect(l, l->transport);
            return INSTALL_STATUS_OK;
        }
    }
    return INSTALL_STATUS_LISTENER_NOT_FOUND;
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

InstallStatus install_listener(const std::string& local_name,
                                  const char *connect_to,
                                  atransport* transport,
                                  int no_rebind)
{
    for (alistener* l = listener_list.next; l != &listener_list; l = l->next) {
        if (local_name == l->local_name) {
            char* cto;

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

    alistener* listener = reinterpret_cast<alistener*>(
        calloc(1, sizeof(alistener)));
    if (listener == nullptr) {
        goto nomem;
    }

    listener->local_name = strdup(local_name.c_str());
    if (listener->local_name == nullptr) {
        goto nomem;
    }

    listener->connect_to = strdup(connect_to);
    if (listener->connect_to == nullptr) {
        goto nomem;
    }

    listener->fd = local_name_to_fd(listener->local_name);
    if (listener->fd < 0) {
        printf("cannot bind '%s': %s\n", listener->local_name, strerror(errno));
        free(listener->local_name);
        free(listener->connect_to);
        free(listener);
        return INSTALL_STATUS_CANNOT_BIND;
    }

    close_on_exec(listener->fd);
    if (!strcmp(listener->connect_to, "*smartsocket*")) {
        fdevent_install(&listener->fde, listener->fd, ss_listener_event_func,
                        listener);
    } else {
        fdevent_install(&listener->fde, listener->fd, listener_event_func,
                        listener);
    }
    fdevent_set(&listener->fde, FDE_READ);

    listener->next = &listener_list;
    listener->prev = listener_list.prev;
    listener->next->prev = listener;
    listener->prev->next = listener;
    listener->transport = transport;

    if (transport) {
        listener->disconnect.opaque = listener;
        listener->disconnect.func   = listener_disconnect;
        add_transport_disconnect(transport, &listener->disconnect);
    }
    return INSTALL_STATUS_OK;

nomem:
    fatal("cannot allocate listener");
    return INSTALL_STATUS_INTERNAL_ERROR;
}
