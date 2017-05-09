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

#include <algorithm>
#include <list>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/thread_annotations.h>
#include <cutils/sockets.h>

#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

// A listener is an entity which binds to a local port and, upon receiving a connection on that
// port, creates an asocket to connect the new local connection to a specific remote service.
//
// TODO: some listeners read from the new connection to determine what exact service to connect to
// on the far side.
class alistener {
  public:
    alistener(const std::string& _local_name, const std::string& _connect_to);
    ~alistener();

    fdevent fde;
    int fd = -1;

    std::string local_name;
    std::string connect_to;
    atransport* transport = nullptr;
    adisconnect disconnect;

  private:
    DISALLOW_COPY_AND_ASSIGN(alistener);
};

alistener::alistener(const std::string& _local_name, const std::string& _connect_to)
    : local_name(_local_name), connect_to(_connect_to) {
}

alistener::~alistener() {
    // Closes the corresponding fd.
    fdevent_remove(&fde);

    if (transport) {
        transport->RemoveDisconnect(&disconnect);
    }
}

// listener_list retains ownership of all created alistener objects. Removing an alistener from
// this list will cause it to be deleted.
static auto& listener_list_mutex = *new std::mutex();
typedef std::list<std::unique_ptr<alistener>> ListenerList;
static ListenerList& listener_list GUARDED_BY(listener_list_mutex) = *new ListenerList();

static void ss_listener_event_func(int _fd, unsigned ev, void *_l) {
    if (ev & FDE_READ) {
        int fd = adb_socket_accept(_fd, nullptr, nullptr);
        if (fd < 0) return;

        int rcv_buf_size = CHUNK_SIZE;
        adb_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_buf_size, sizeof(rcv_buf_size));

        asocket* s = create_local_socket(fd);
        if (s) {
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
        int fd = adb_socket_accept(_fd, nullptr, nullptr);
        if (fd < 0) {
            return;
        }

        s = create_local_socket(fd);
        if (s) {
            s->transport = listener->transport;
            connect_to_remote(s, listener->connect_to.c_str());
            return;
        }

        adb_close(fd);
    }
}

// Called as a transport disconnect function. |arg| is the raw alistener*.
static void listener_disconnect(void* arg, atransport*) EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    for (auto iter = listener_list.begin(); iter != listener_list.end(); ++iter) {
        if (iter->get() == arg) {
            (*iter)->transport = nullptr;
            listener_list.erase(iter);
            return;
        }
    }
}

// Write the list of current listeners (network redirections) into a string.
std::string format_listeners() EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    std::string result;
    for (auto& l : listener_list) {
        // Ignore special listeners like those for *smartsocket*
        if (l->connect_to[0] == '*') {
            continue;
        }
        //  <device-serial> " " <local-name> " " <remote-name> "\n"
        // Entries from "adb reverse" have no serial.
        android::base::StringAppendF(&result, "%s %s %s\n",
                                     l->transport->serial ? l->transport->serial : "(reverse)",
                                     l->local_name.c_str(), l->connect_to.c_str());
    }
    return result;
}

InstallStatus remove_listener(const char* local_name, atransport* transport)
    EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    for (auto iter = listener_list.begin(); iter != listener_list.end(); ++iter) {
        if (local_name == (*iter)->local_name) {
            listener_list.erase(iter);
            return INSTALL_STATUS_OK;
        }
    }
    return INSTALL_STATUS_LISTENER_NOT_FOUND;
}

void remove_all_listeners() EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    auto iter = listener_list.begin();
    while (iter != listener_list.end()) {
        // Never remove smart sockets.
        if ((*iter)->connect_to[0] == '*') {
            ++iter;
        } else {
            iter = listener_list.erase(iter);
        }
    }
}

void close_smartsockets() EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    auto pred = [](const std::unique_ptr<alistener>& listener) {
        return listener->local_name == "*smartsocket*";
    };
    listener_list.erase(std::remove_if(listener_list.begin(), listener_list.end(), pred));
}

InstallStatus install_listener(const std::string& local_name, const char* connect_to,
                               atransport* transport, int no_rebind, int* resolved_tcp_port,
                               std::string* error) EXCLUDES(listener_list_mutex) {
    std::lock_guard<std::mutex> lock(listener_list_mutex);
    for (auto& l : listener_list) {
        if (local_name == l->local_name) {
            // Can't repurpose a smartsocket.
            if(l->connect_to[0] == '*') {
                *error = "cannot repurpose smartsocket";
                return INSTALL_STATUS_INTERNAL_ERROR;
            }

            // Can't repurpose a listener if 'no_rebind' is true.
            if (no_rebind) {
                *error = "cannot rebind";
                return INSTALL_STATUS_CANNOT_REBIND;
            }

            l->connect_to = connect_to;
            if (l->transport != transport) {
                l->transport->RemoveDisconnect(&l->disconnect);
                l->transport = transport;
                l->transport->AddDisconnect(&l->disconnect);
            }
            return INSTALL_STATUS_OK;
        }
    }

    std::unique_ptr<alistener> listener(new alistener(local_name, connect_to));

    int resolved = 0;
    listener->fd = socket_spec_listen(listener->local_name, error, &resolved);
    if (listener->fd < 0) {
        return INSTALL_STATUS_CANNOT_BIND;
    }

    // If the caller requested port 0, update the listener name with the resolved port.
    if (resolved != 0) {
        listener->local_name = android::base::StringPrintf("tcp:%d", resolved);
        if (resolved_tcp_port) {
            *resolved_tcp_port = resolved;
        }
    }

    close_on_exec(listener->fd);
    if (listener->connect_to == "*smartsocket*") {
        fdevent_install(&listener->fde, listener->fd, ss_listener_event_func, listener.get());
    } else {
        fdevent_install(&listener->fde, listener->fd, listener_event_func, listener.get());
    }
    fdevent_set(&listener->fde, FDE_READ);

    listener->transport = transport;

    if (transport) {
        listener->disconnect.opaque = listener.get();
        listener->disconnect.func = listener_disconnect;
        transport->AddDisconnect(&listener->disconnect);
    }

    listener_list.push_back(std::move(listener));
    return INSTALL_STATUS_OK;
}
