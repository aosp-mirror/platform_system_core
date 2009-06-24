/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "DhcpListener"
#include <cutils/log.h>

#include <DhcpListener.h>
#include "IDhcpEventHandlers.h"
#include "DhcpState.h"
#include "DhcpEvent.h"
#include "Controller.h"

DhcpListener::DhcpListener(Controller *c, int socket, IDhcpEventHandlers *handlers) :
              SocketListener(socket, false) {
    mHandlers = handlers;
    mController = c;
}

DhcpListener::~DhcpListener() {
}

bool DhcpListener::onDataAvailable(SocketClient *cli) {
    char buffer[255];
    int rc;

    if ((rc = read(cli->getSocket(), buffer, sizeof(buffer))) < 0) {
        LOGW("Error reading dhcp status msg (%s)", strerror(errno));
        return true;
    }

    if (!strncmp(buffer, "STATE:", 6)) {
        char *next = buffer;
        char *tmp;
        int i;

        for (i = 0; i < 2; i++) {
            if (!(tmp = strsep(&next, ":"))) {
                LOGW("Error parsing state '%s'", buffer);
                return true;
            }
        }

        int st = DhcpState::parseString(tmp);
        mHandlers->onDhcpStateChanged(mController, st);
    } else if (!strncmp(buffer, "ADDRINFO:", 9)) {
        char *next = buffer + 9;
	struct in_addr ipaddr, netmask, gateway, broadcast, dns1, dns2;

        if (!inet_aton(strsep(&next, ":"), &ipaddr)) {
            LOGW("Malformatted IP specified");
        }
        if (!inet_aton(strsep(&next, ":"), &netmask)) {
            LOGW("Malformatted netmask specified");
        }
        if (!inet_aton(strsep(&next, ":"), &broadcast)) {
            LOGW("Malformatted broadcast specified");
        }
        if (!inet_aton(strsep(&next, ":"), &gateway)) {
            LOGW("Malformatted gateway specified");
        }
        if (!inet_aton(strsep(&next, ":"), &dns1)) {
            LOGW("Malformatted dns1 specified");
        }
        if (!inet_aton(strsep(&next, ":"), &dns2)) {
            LOGW("Malformatted dns2 specified");
        }
        mHandlers->onDhcpLeaseUpdated(mController, &ipaddr, &netmask,
                                      &broadcast, &gateway, &dns1, &dns2);
 
    } else if (!strncmp(buffer, "EVENT:", 6)) {
        char *next = buffer;
        char *tmp;
        int i;

        for (i = 0; i < 2; i++) {
            if (!(tmp = strsep(&next, ":"))) {
                LOGW("Error parsing event '%s'", buffer);
                return true;
            }
        }

        int ev = DhcpEvent::parseString(tmp);
        mHandlers->onDhcpEvent(mController, ev);
  
    } else {
        LOGW("Unknown DHCP monitor msg '%s'", buffer);
    }

    return true;
}
