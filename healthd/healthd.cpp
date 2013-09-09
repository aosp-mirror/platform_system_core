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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <batteryservice/BatteryService.h>
#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <cutils/klog.h>
#include <cutils/uevent.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

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
    .batteryChargeCounterPath = String8(String8::kEmptyString),
};

#define POWER_SUPPLY_SUBSYSTEM "power_supply"

// epoll events: uevent, wakealarm, binder
#define MAX_EPOLL_EVENTS 3
static int uevent_fd;
static int wakealarm_fd;
static int binder_fd;

// -1 for no epoll timeout
static int awake_poll_interval = -1;

static int wakealarm_wake_interval = DEFAULT_PERIODIC_CHORES_INTERVAL_FAST;

static BatteryMonitor* gBatteryMonitor;

static bool nosvcmgr;

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

static void battery_update(void) {
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

static void periodic_chores() {
    battery_update();
}

static void uevent_init(void) {
    uevent_fd = uevent_open_socket(64*1024, true);

    if (uevent_fd >= 0)
        fcntl(uevent_fd, F_SETFL, O_NONBLOCK);
    else
        KLOG_ERROR(LOG_TAG, "uevent_init: uevent_open_socket failed\n");
}

#define UEVENT_MSG_LEN 1024
static void uevent_event(void) {
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
            battery_update();
            break;
        }

        /* advance to after the next \0 */
        while (*cp++)
            ;
    }
}

static void wakealarm_init(void) {
    wakealarm_fd = timerfd_create(CLOCK_BOOTTIME_ALARM, TFD_NONBLOCK);
    if (wakealarm_fd == -1) {
        KLOG_ERROR(LOG_TAG, "wakealarm_init: timerfd_create failed\n");
        return;
    }

    wakealarm_set_interval(healthd_config.periodic_chores_interval_fast);
}

static void wakealarm_event(void) {
    unsigned long long wakeups;

    if (read(wakealarm_fd, &wakeups, sizeof(wakeups)) == -1) {
        KLOG_ERROR(LOG_TAG, "wakealarm_event: read wakealarm_fd failed\n");
        return;
    }

    periodic_chores();
}

static void binder_init(void) {
    ProcessState::self()->setThreadPoolMaxThreadCount(0);
    IPCThreadState::self()->disableBackgroundScheduling(true);
    IPCThreadState::self()->setupPolling(&binder_fd);
}

static void binder_event(void) {
    IPCThreadState::self()->handlePolledCommands();
}

static void healthd_mainloop(void) {
    struct epoll_event ev;
    int epollfd;
    int maxevents = 0;

    epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if (epollfd == -1) {
        KLOG_ERROR(LOG_TAG,
                   "healthd_mainloop: epoll_create failed; errno=%d\n",
                   errno);
        return;
    }

    if (uevent_fd >= 0) {
        ev.events = EPOLLIN | EPOLLWAKEUP;
        ev.data.ptr = (void *)uevent_event;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, uevent_fd, &ev) == -1)
            KLOG_ERROR(LOG_TAG,
                       "healthd_mainloop: epoll_ctl for uevent_fd failed; errno=%d\n",
                       errno);
        else
            maxevents++;
    }

    if (wakealarm_fd >= 0) {
        ev.events = EPOLLIN | EPOLLWAKEUP;
        ev.data.ptr = (void *)wakealarm_event;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, wakealarm_fd, &ev) == -1)
            KLOG_ERROR(LOG_TAG,
                       "healthd_mainloop: epoll_ctl for wakealarm_fd failed; errno=%d\n",
                       errno);
        else
            maxevents++;
   }

    if (binder_fd >= 0) {
        ev.events = EPOLLIN | EPOLLWAKEUP;
        ev.data.ptr= (void *)binder_event;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, binder_fd, &ev) == -1)
            KLOG_ERROR(LOG_TAG,
                       "healthd_mainloop: epoll_ctl for binder_fd failed; errno=%d\n",
                       errno);
        else
            maxevents++;
   }

    while (1) {
        struct epoll_event events[maxevents];
        int nevents;

        IPCThreadState::self()->flushCommands();
        nevents = epoll_wait(epollfd, events, maxevents, awake_poll_interval);

        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            KLOG_ERROR(LOG_TAG, "healthd_mainloop: epoll_wait failed\n");
            break;
        }

        for (int n = 0; n < nevents; ++n) {
            if (events[n].data.ptr)
                (*(void (*)())events[n].data.ptr)();
        }

        if (!nevents)
            periodic_chores();
    }

    return;
}

int main(int argc, char **argv) {
    int ch;

    klog_set_level(KLOG_LEVEL);

    while ((ch = getopt(argc, argv, "n")) != -1) {
        switch (ch) {
        case 'n':
            nosvcmgr = true;
            break;
        case '?':
        default:
            KLOG_WARNING(LOG_TAG, "Unrecognized healthd option: %c\n", ch);
        }
    }

    healthd_board_init(&healthd_config);
    wakealarm_init();
    uevent_init();
    binder_init();
    gBatteryMonitor = new BatteryMonitor();
    gBatteryMonitor->init(&healthd_config, nosvcmgr);

    healthd_mainloop();
    return 0;
}
