/*
 * Copyright (C) 2013 The Android Open Source Project
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

#define LOG_TAG "healthd"
#define KLOG_LEVEL 6

#include "healthd.h"
#include "BatteryMonitor.h"

#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <cutils/uevent.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <utils/Errors.h>

using namespace android;

// Periodic chores intervals in seconds
#define DEFAULT_PERIODIC_CHORES_INTERVAL_FAST (60 * 1)
#define DEFAULT_PERIODIC_CHORES_INTERVAL_SLOW (60 * 10)

static struct healthd_config healthd_config = {
    .periodic_chores_interval_fast = DEFAULT_PERIODIC_CHORES_INTERVAL_FAST,
    .periodic_chores_interval_slow = DEFAULT_PERIODIC_CHORES_INTERVAL_SLOW,
    .batteryStatusPath = String8(String8::kEmptyString),
    .batteryHealthPath = String8(String8::kEmptyString),
    .batteryPresentPath = String8(String8::kEmptyString),
    .batteryCapacityPath = String8(String8::kEmptyString),
    .batteryVoltagePath = String8(String8::kEmptyString),
    .batteryTemperaturePath = String8(String8::kEmptyString),
    .batteryTechnologyPath = String8(String8::kEmptyString),
    .batteryCurrentNowPath = String8(String8::kEmptyString),
    .batteryCurrentAvgPath = String8(String8::kEmptyString),
    .batteryChargeCounterPath = String8(String8::kEmptyString),
    .energyCounter = NULL,
    .boot_min_cap = 0,
    .screen_on = NULL,
};

static int eventct;
static int epollfd;

#define POWER_SUPPLY_SUBSYSTEM "power_supply"

// epoll_create() parameter is actually unused
#define MAX_EPOLL_EVENTS 40
static int uevent_fd;
static int wakealarm_fd;

// -1 for no epoll timeout
static int awake_poll_interval = -1;

static int wakealarm_wake_interval = DEFAULT_PERIODIC_CHORES_INTERVAL_FAST;

static BatteryMonitor* gBatteryMonitor;

struct healthd_mode_ops *healthd_mode_ops;

// Android mode

extern void healthd_mode_android_init(struct healthd_config *config);
extern int healthd_mode_android_preparetowait(void);
extern void healthd_mode_android_battery_update(
    struct android::BatteryProperties *props);

// Charger mode

extern void healthd_mode_charger_init(struct healthd_config *config);
extern int healthd_mode_charger_preparetowait(void);
extern void healthd_mode_charger_heartbeat(void);
extern void healthd_mode_charger_battery_update(
    struct android::BatteryProperties *props);

// NOPs for modes that need no special action

static void healthd_mode_nop_init(struct healthd_config *config);
static int healthd_mode_nop_preparetowait(void);
static void healthd_mode_nop_heartbeat(void);
static void healthd_mode_nop_battery_update(
    struct android::BatteryProperties *props);

static struct healthd_mode_ops android_ops = {
    .init = healthd_mode_android_init,
    .preparetowait = healthd_mode_android_preparetowait,
    .heartbeat = healthd_mode_nop_heartbeat,
    .battery_update = healthd_mode_android_battery_update,
};

static struct healthd_mode_ops charger_ops = {
    .init = healthd_mode_charger_init,
    .preparetowait = healthd_mode_charger_preparetowait,
    .heartbeat = healthd_mode_charger_heartbeat,
    .battery_update = healthd_mode_charger_battery_update,
};

static struct healthd_mode_ops recovery_ops = {
    .init = healthd_mode_nop_init,
    .preparetowait = healthd_mode_nop_preparetowait,
    .heartbeat = healthd_mode_nop_heartbeat,
    .battery_update = healthd_mode_nop_battery_update,
};

static void healthd_mode_nop_init(struct healthd_config* /*config*/) {
}

static int healthd_mode_nop_preparetowait(void) {
    return -1;
}

static void healthd_mode_nop_heartbeat(void) {
}

static void healthd_mode_nop_battery_update(
    struct android::BatteryProperties* /*props*/) {
}

int healthd_register_event(int fd, void (*handler)(uint32_t)) {
    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLWAKEUP;
    ev.data.ptr = (void *)handler;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        KLOG_ERROR(LOG_TAG,
                   "epoll_ctl failed; errno=%d\n", errno);
        return -1;
    }

    eventct++;
    return 0;
}

static void wakealarm_set_interval(int interval) {
    struct itimerspec itval;

    if (wakealarm_fd == -1)
            return;

    wakealarm_wake_interval = interval;

    if (interval == -1)
        interval = 0;

    itval.it_interval.tv_sec = interval;
    itval.it_interval.tv_nsec = 0;
    itval.it_value.tv_sec = interval;
    itval.it_value.tv_nsec = 0;

    if (timerfd_settime(wakealarm_fd, 0, &itval, NULL) == -1)
        KLOG_ERROR(LOG_TAG, "wakealarm_set_interval: timerfd_settime failed\n");
}

status_t healthd_get_property(int id, struct BatteryProperty *val) {
    return gBatteryMonitor->getProperty(id, val);
}

void healthd_battery_update(void) {
    // Fast wake interval when on charger (watch for overheat);
    // slow wake interval when on battery (watch for drained battery).

   int new_wake_interval = gBatteryMonitor->update() ?
       healthd_config.periodic_chores_interval_fast :
           healthd_config.periodic_chores_interval_slow;

    if (new_wake_interval != wakealarm_wake_interval)
            wakealarm_set_interval(new_wake_interval);

    // During awake periods poll at fast rate.  If wake alarm is set at fast
    // rate then just use the alarm; if wake alarm is set at slow rate then
    // poll at fast rate while awake and let alarm wake up at slow rate when
    // asleep.

    if (healthd_config.periodic_chores_interval_fast == -1)
        awake_poll_interval = -1;
    else
        awake_poll_interval =
            new_wake_interval == healthd_config.periodic_chores_interval_fast ?
                -1 : healthd_config.periodic_chores_interval_fast * 1000;
}

void healthd_dump_battery_state(int fd) {
    gBatteryMonitor->dumpState(fd);
    fsync(fd);
}

static void periodic_chores() {
    healthd_battery_update();
}

#define UEVENT_MSG_LEN 2048
static void uevent_event(uint32_t /*epevents*/) {
    char msg[UEVENT_MSG_LEN+2];
    char *cp;
    int n;

    n = uevent_kernel_multicast_recv(uevent_fd, msg, UEVENT_MSG_LEN);
    if (n <= 0)
        return;
    if (n >= UEVENT_MSG_LEN)   /* overflow -- discard */
        return;

    msg[n] = '\0';
    msg[n+1] = '\0';
    cp = msg;

    while (*cp) {
        if (!strcmp(cp, "SUBSYSTEM=" POWER_SUPPLY_SUBSYSTEM)) {
            healthd_battery_update();
            break;
        }

        /* advance to after the next \0 */
        while (*cp++)
            ;
    }
}

static void uevent_init(void) {
    uevent_fd = uevent_open_socket(64*1024, true);

    if (uevent_fd < 0) {
        KLOG_ERROR(LOG_TAG, "uevent_init: uevent_open_socket failed\n");
        return;
    }

    fcntl(uevent_fd, F_SETFL, O_NONBLOCK);
    if (healthd_register_event(uevent_fd, uevent_event))
        KLOG_ERROR(LOG_TAG,
                   "register for uevent events failed\n");
}

static void wakealarm_event(uint32_t /*epevents*/) {
    unsigned long long wakeups;

    if (read(wakealarm_fd, &wakeups, sizeof(wakeups)) == -1) {
        KLOG_ERROR(LOG_TAG, "wakealarm_event: read wakealarm fd failed\n");
        return;
    }

    periodic_chores();
}

static void wakealarm_init(void) {
    wakealarm_fd = timerfd_create(CLOCK_BOOTTIME_ALARM, TFD_NONBLOCK);
    if (wakealarm_fd == -1) {
        KLOG_ERROR(LOG_TAG, "wakealarm_init: timerfd_create failed\n");
        return;
    }

    if (healthd_register_event(wakealarm_fd, wakealarm_event))
        KLOG_ERROR(LOG_TAG,
                   "Registration of wakealarm event failed\n");

    wakealarm_set_interval(healthd_config.periodic_chores_interval_fast);
}

static void healthd_mainloop(void) {
    while (1) {
        struct epoll_event events[eventct];
        int nevents;
        int timeout = awake_poll_interval;
        int mode_timeout;

        mode_timeout = healthd_mode_ops->preparetowait();
        if (timeout < 0 || (mode_timeout > 0 && mode_timeout < timeout))
            timeout = mode_timeout;
        nevents = epoll_wait(epollfd, events, eventct, timeout);

        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            KLOG_ERROR(LOG_TAG, "healthd_mainloop: epoll_wait failed\n");
            break;
        }

        for (int n = 0; n < nevents; ++n) {
            if (events[n].data.ptr)
                (*(void (*)(int))events[n].data.ptr)(events[n].events);
        }

        if (!nevents)
            periodic_chores();

        healthd_mode_ops->heartbeat();
    }

    return;
}

static int healthd_init() {
    epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if (epollfd == -1) {
        KLOG_ERROR(LOG_TAG,
                   "epoll_create failed; errno=%d\n",
                   errno);
        return -1;
    }

    healthd_board_init(&healthd_config);
    healthd_mode_ops->init(&healthd_config);
    wakealarm_init();
    uevent_init();
    gBatteryMonitor = new BatteryMonitor();
    gBatteryMonitor->init(&healthd_config);
    return 0;
}

int main(int argc, char **argv) {
    int ch;
    int ret;

    klog_set_level(KLOG_LEVEL);
    healthd_mode_ops = &android_ops;

    if (!strcmp(basename(argv[0]), "charger")) {
        healthd_mode_ops = &charger_ops;
    } else {
        while ((ch = getopt(argc, argv, "cr")) != -1) {
            switch (ch) {
            case 'c':
                healthd_mode_ops = &charger_ops;
                break;
            case 'r':
                healthd_mode_ops = &recovery_ops;
                break;
            case '?':
            default:
                KLOG_ERROR(LOG_TAG, "Unrecognized healthd option: %c\n",
                           optopt);
                exit(1);
            }
        }
    }

    ret = healthd_init();
    if (ret) {
        KLOG_ERROR("Initialization failed, exiting\n");
        exit(2);
    }

    healthd_mainloop();
    KLOG_ERROR("Main loop terminated, exiting\n");
    return 3;
}
