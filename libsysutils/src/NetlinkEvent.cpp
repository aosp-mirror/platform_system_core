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
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "NetlinkEvent"
#include <cutils/log.h>

#include <sysutils/NetlinkListener.h>
#include <sysutils/NetlinkEvent.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if.h>

const int NetlinkEvent::NlActionUnknown = 0;
const int NetlinkEvent::NlActionAdd = 1;
const int NetlinkEvent::NlActionRemove = 2;
const int NetlinkEvent::NlActionChange = 3;
const int NetlinkEvent::NlActionLinkUp = 4;
const int NetlinkEvent::NlActionLinkDown = 5;

NetlinkEvent::NetlinkEvent() {
    mAction = NlActionUnknown;
    memset(mParams, 0, sizeof(mParams));
    mPath = NULL;
    mSubsystem = NULL;
}

NetlinkEvent::~NetlinkEvent() {
    int i;
    if (mPath)
        free(mPath);
    if (mSubsystem)
        free(mSubsystem);
    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        free(mParams[i]);
    }
}

void NetlinkEvent::dump() {
    int i;

    for (i = 0; i < NL_PARAMS_MAX; i++) {
        if (!mParams[i])
            break;
        SLOGD("NL param '%s'\n", mParams[i]);
    }
}

/*
 * Parse an binary message from a NETLINK_ROUTE netlink socket.
 */
bool NetlinkEvent::parseBinaryNetlinkMessage(char *buffer, int size) {
    size_t sz = size;
    struct nlmsghdr *nh = (struct nlmsghdr *) buffer;

    while (NLMSG_OK(nh, sz) && (nh->nlmsg_type != NLMSG_DONE)) {
        if (nh->nlmsg_type == RTM_NEWLINK) {
            int len = nh->nlmsg_len - sizeof(*nh);
            struct ifinfomsg *ifi;

            if (sizeof(*ifi) <= (size_t) len) {
                ifi = (ifinfomsg *)NLMSG_DATA(nh);

                if ((ifi->ifi_flags & IFF_LOOPBACK) == 0) {
                    struct rtattr *rta = (struct rtattr *)
                      ((char *) ifi + NLMSG_ALIGN(sizeof(*ifi)));
                    len = NLMSG_PAYLOAD(nh, sizeof(*ifi));

                    while(RTA_OK(rta, len)) {
                        switch(rta->rta_type) {
                        case IFLA_IFNAME:
                            char buffer[16 + IFNAMSIZ];
                            snprintf(buffer, sizeof(buffer), "INTERFACE=%s",
                                     (char *) RTA_DATA(rta));
                            mParams[0] = strdup(buffer);
                            mAction = (ifi->ifi_flags & IFF_LOWER_UP) ?
                              NlActionLinkUp : NlActionLinkDown;
                            mSubsystem = strdup("net");
                            break;
                        }

                        rta = RTA_NEXT(rta, len);
                    }
                }
            }
        }

        nh = NLMSG_NEXT(nh, size);
    }

    return true;
}

/*
 * Parse an ASCII-formatted message from a NETLINK_KOBJECT_UEVENT
 * netlink socket.
 */
bool NetlinkEvent::parseAsciiNetlinkMessage(char *buffer, int size) {
    char *s = buffer;
    char *end;
    int param_idx = 0;
    int i;
    int first = 1;

    end = s + size;
    while (s < end) {
        if (first) {
            char *p;
            for (p = s; *p != '@'; p++);
            p++;
            mPath = strdup(p);
            first = 0;
        } else {
            if (!strncmp(s, "ACTION=", strlen("ACTION="))) {
                char *a = s + strlen("ACTION=");
                if (!strcmp(a, "add"))
                    mAction = NlActionAdd;
                else if (!strcmp(a, "remove"))
                    mAction = NlActionRemove;
                else if (!strcmp(a, "change"))
                    mAction = NlActionChange;
            } else if (!strncmp(s, "SEQNUM=", strlen("SEQNUM=")))
                mSeq = atoi(s + strlen("SEQNUM="));
            else if (!strncmp(s, "SUBSYSTEM=", strlen("SUBSYSTEM=")))
                mSubsystem = strdup(s + strlen("SUBSYSTEM="));
            else
                mParams[param_idx++] = strdup(s);
        }
        s+= strlen(s) + 1;
    }
    return true;
}

bool NetlinkEvent::decode(char *buffer, int size, int format) {
  if (format == NetlinkListener::NETLINK_FORMAT_BINARY) {
    return parseBinaryNetlinkMessage(buffer, size);
  } else {
    return parseAsciiNetlinkMessage(buffer, size);
  }
}

const char *NetlinkEvent::findParam(const char *paramName) {
    size_t len = strlen(paramName);
    for (int i = 0; mParams[i] && i < NL_PARAMS_MAX; ++i) {
        const char *ptr = mParams[i] + len;
        if (!strncmp(mParams[i], paramName, len) && *ptr == '=')
            return ++ptr;
    }

    SLOGE("NetlinkEvent::FindParam(): Parameter '%s' not found", paramName);
    return NULL;
}
