/*
 * Copyright (c) 2009-2013, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include <dns_sd.h>
#include <cutils/properties.h>
#include <unistd.h>

#include "debug.h"
#include "network_discovery.h"
#include "utils.h"

#define MDNS_SERVICE_NAME "mdnsd"
#define MDNS_SERVICE_STATUS "init.svc.mdnsd"
#define FASTBOOTD_TYPE "_fastbootd._tcp"
#define FASTBOOTD_DOMAIN "local."
#define FASTBOOTD_NAME "fastbootd"


static void reg_reply(DNSServiceRef sdref, const DNSServiceFlags flags, DNSServiceErrorType errorCode,
    const char *name, const char *regtype, const char *domain, void *context)
{
    (void)sdref;    // Unused
    (void)flags;    // Unused
    (void)context;  // Unused
    if (errorCode == kDNSServiceErr_ServiceNotRunning) {
        fprintf(stderr, "Error code %d\n", errorCode);
    }


    printf("Got a reply for service %s.%s%s: ", name, regtype, domain);

    if (errorCode == kDNSServiceErr_NoError)
    {
        if (flags & kDNSServiceFlagsAdd)
            printf("Name now registered and active\n");
        else
            printf("Name registration removed\n");
        if (errorCode == kDNSServiceErr_NameConflict)
            printf("Name in use, please choose another\n");
        else
            printf("Error %d\n", errorCode);

        if (!(flags & kDNSServiceFlagsMoreComing)) fflush(stdout);
    }
}

static int register_service() {
    DNSServiceRef sdref = NULL;
    const char *domain = FASTBOOTD_DOMAIN;
    const char *type = FASTBOOTD_TYPE;
    const char *host = NULL;
    char name[PROP_VALUE_MAX];
    uint16_t port = 22;
    int flags = 0;
    DNSServiceErrorType result;
    property_get("ro.serialno", name, "");
    if (!strcmp(name, "")) {
        D(ERR, "No property serialno");
        return -1;
    }

    result = DNSServiceRegister(&sdref, flags, kDNSServiceInterfaceIndexAny,
                       name, type, domain, host, port,
                       0, NULL, reg_reply, NULL);
    if (result != kDNSServiceErr_NoError) {
        D(ERR, "Unable to register service");
        return -1;
    }
    return 0;
}


int network_discovery_init()
{
    D(INFO, "Starting discovery");
    if (service_start(MDNS_SERVICE_NAME)) {
        D(ERR, "Unable to start discovery");
        return -1;
    }

    if (register_service()) {
        D(ERR, "Unable to register service");
        return -1;
    }

    return 0;
}

