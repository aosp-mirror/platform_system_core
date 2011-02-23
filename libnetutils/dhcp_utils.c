/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

/* Utilities for managing the dhcpcd DHCP client daemon */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cutils/properties.h>

static const char DAEMON_NAME[]        = "dhcpcd";
static const char DAEMON_PROP_NAME[]   = "init.svc.dhcpcd";
static const char HOSTNAME_PROP_NAME[] = "net.hostname";
static const char DHCP_PROP_NAME_PREFIX[]  = "dhcp";
static const char DAEMON_NAME_RENEW[]  = "dhcpcd_renew";
static const char DAEMON_PROP_NAME_RENEW[]  = "init.svc.dhcpcd_renew";
static const char DHCP_PROP_NAME_RENEW_PREFIX[]  = "dhcp_renew";
static const int  NAP_TIME = 1;   /* wait for 1 second at a time */
                                  /* when polling for property values */
static char errmsg[100];

/*
 * Wait for a system property to be assigned a specified value.
 * If desired_value is NULL, then just wait for the property to
 * be created with any value. maxwait is the maximum amount of
 * time in seconds to wait before giving up.
 */
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = maxwait / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- > 0) {
        usleep(1000000);
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL || 
                    strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
    }
    return -1; /* failure */
}

static void fill_ip_info(const char *interface,
                     in_addr_t *ipaddr,
                     in_addr_t *gateway,
                     in_addr_t *mask,
                     in_addr_t *dns1,
                     in_addr_t *dns2,
                     in_addr_t *server,
                     uint32_t  *lease)
{
    char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];
    struct in_addr addr;
    in_addr_t iaddr;

    snprintf(prop_name, sizeof(prop_name), "%s.%s.ipaddress", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *ipaddr = addr.s_addr;
    } else {
        *ipaddr = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.gateway", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *gateway = addr.s_addr;
    } else {
        *gateway = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.mask", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *mask = addr.s_addr;
    } else {
        *mask = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.dns1", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *dns1 = addr.s_addr;
    } else {
        *dns1 = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.dns2", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *dns2 = addr.s_addr;
    } else {
        *dns2 = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.server", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL) && inet_aton(prop_value, &addr)) {
        *server = addr.s_addr;
    } else {
        *server = 0;
    }
    snprintf(prop_name, sizeof(prop_name), "%s.%s.leasetime", DHCP_PROP_NAME_PREFIX, interface);
    if (property_get(prop_name, prop_value, NULL)) {
        *lease = atol(prop_value);
    }
}

/*
 * Start the dhcp client daemon, and wait for it to finish
 * configuring the interface.
 */
int dhcp_do_request(const char *interface,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    in_addr_t *mask,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the daemon and wait until it's ready */
    if (property_get(HOSTNAME_PROP_NAME, prop_value, NULL) && (prop_value[0] != '\0'))
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:-h %s %s", DAEMON_NAME, interface,
                 prop_value, interface);
    else
        snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME, interface, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for dhcpcd to start");
        return -1;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP result property was not set");
        return -1;
    }
    if (strcmp(prop_value, "ok") == 0) {
        fill_ip_info(interface, ipaddr, gateway, mask, dns1, dns2, server, lease);
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP result was %s", prop_value);
        return -1;
    }
}

/**
 * Stop the DHCP client daemon.
 */
int dhcp_stop(const char *interface)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_PREFIX,
            interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            interface);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, interface);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    property_set(result_prop_name, "failed");
    return 0;
}

/**
 * Release the current DHCP client lease.
 */
int dhcp_release_lease(const char *interface)
{
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.stop";
    const char *desired_status = "stopped";

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME,
            interface);

    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s", DAEMON_NAME, interface);

    /* Stop the daemon and wait until it's reported to be stopped */
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 5) < 0) {
        return -1;
    }
    return 0;
}

char *dhcp_get_errmsg() {
    return errmsg;
}

/**
 * Run WiMAX dhcp renew service.
 * "wimax_renew" service shoud be included in init.rc.
 */
int dhcp_do_request_renew(const char *interface,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    in_addr_t *mask,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease)
{
    char result_prop_name[PROPERTY_KEY_MAX];
    char daemon_prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[PROPERTY_VALUE_MAX * 2];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";

    snprintf(result_prop_name, sizeof(result_prop_name), "%s.%s.result",
            DHCP_PROP_NAME_RENEW_PREFIX,
            interface);

    snprintf(daemon_prop_name, sizeof(daemon_prop_name), "%s_%s",
            DAEMON_PROP_NAME_RENEW,
            interface);

    /* Erase any previous setting of the dhcp result property */
    property_set(result_prop_name, "");

    /* Start the renew daemon and wait until it's ready */
    snprintf(daemon_cmd, sizeof(daemon_cmd), "%s_%s:%s", DAEMON_NAME_RENEW, interface, interface);
    memset(prop_value, '\0', PROPERTY_VALUE_MAX);
    property_set(ctrl_prop, daemon_cmd);
    if (wait_for_property(daemon_prop_name, desired_status, 10) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for dhcpcd Renew to start");
        return -1;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(result_prop_name, NULL, 30) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for DHCP Renew to finish");
        return -1;
    }

    if (!property_get(result_prop_name, prop_value, NULL)) {
        /* shouldn't ever happen, given the success of wait_for_property() */
        snprintf(errmsg, sizeof(errmsg), "%s", "DHCP Renew result property was not set");
        return -1;
    }
    if (strcmp(prop_value, "ok") == 0) {
        fill_ip_info(interface, ipaddr, gateway, mask, dns1, dns2, server, lease);
        return 0;
    } else {
        snprintf(errmsg, sizeof(errmsg), "DHCP Renew result was %s", prop_value);
        return -1;
    }
}