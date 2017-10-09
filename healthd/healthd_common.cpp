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

#define LOG_TAG "healthd-common"
#define KLOG_LEVEL 6

#include <healthd/healthd.h>
#include <healthd/BatteryMonitor.h>

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

#ifdef HEALTHD_USE_HEALTH_2_0
#include <health2/Health.h>
#endif

using namespace android;

#ifndef BOARD_PERIODIC_CHORES_INTERVAL_FAST
  // Periodic chores fast interval in seconds
  #define DEFAULT_PERIODIC_CHORES_INTERVAL_FAST (60 * 1)
#else
  #define DEFAULT_PERIODIC_CHORES_INTERVAL_FAST (BOARD_PERIODIC_CHORES_INTERVAL_FAST)
#endif

#ifndef BOARD_PERIODIC_CHORES_INTERVAL_SLOW
  // Periodic chores fast interval in seconds
  #define DEFAULT_PERIODIC_CHORES_INTERVAL_SLOW (60 * 10)
#else
  #define DEFAULT_PERIODIC_CHORES_INTERVAL_SLOW (BOARD_PERIODIC_CHORES_INTERVAL_SLOW)
#endif

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
    .batteryFullChargePath = String8(String8::kEmptyString),
    .batteryCycleCountPath = String8(String8::kEmptyString),
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

#ifndef HEALTHD_USE_HEALTH_2_0
static BatteryMonitor* gBatteryMonitor = nullptr;
#else
extern sp<::android::hardware::health::V2_0::IHealth> gHealth;
#endif

struct healthd_mode_ops *healthd_mode_ops = nullptr;

int healthd_register_event(int fd, void (*handler)(uint32_t), EventWakeup wakeup) {
    struct epoll_event ev;

    ev.events = EPOLLIN;

    if (wakeup == EVENT_WAKEUP_FD)
        ev.events |= EPOLLWAKEUP;

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

#ifdef HEALTHD_USE_HEALTH_2_0
status_t convertStatus(android::hardware::health::V2_0::Result r) {
    using android::hardware::health::V2_0::Result;
    switch(r) {
        case Result::SUCCESS:       return OK;
        case Result::NOT_SUPPORTED: return BAD_VALUE;
        case Result::NOT_FOUND:     return NAME_NOT_FOUND;
        case Result::CALLBACK_DIED: return DEAD_OBJECT;
        case Result::UNKNOWN: // fallthrough
        default:
            return UNKNOWN_ERROR;
    }
}
#endif

status_t healthd_get_property(int id, struct BatteryProperty *val) {
#ifndef HEALTHD_USE_HEALTH_2_0
    return gBatteryMonitor->getProperty(id, val);
#else
    using android::hardware::health::V1_0::BatteryStatus;
    using android::hardware::health::V2_0::Result;
    val->valueInt64 = INT64_MIN;
    status_t err = UNKNOWN_ERROR;
    switch (id) {
        case BATTERY_PROP_CHARGE_COUNTER: {
            gHealth->getChargeCounter([&](Result r, int32_t v) {
                err = convertStatus(r);
                val->valueInt64 = v;
            });
            break;
        }
        case BATTERY_PROP_CURRENT_NOW: {
            gHealth->getCurrentNow([&](Result r, int32_t v) {
                err = convertStatus(r);
                val->valueInt64 = v;
            });
            break;
        }
        case BATTERY_PROP_CURRENT_AVG: {
            gHealth->getCurrentAverage([&](Result r, int32_t v) {
                err = convertStatus(r);
                val->valueInt64 = v;
            });
            break;
        }
        case BATTERY_PROP_CAPACITY: {
            gHealth->getCapacity([&](Result r, int32_t v) {
                err = convertStatus(r);
                val->valueInt64 = v;
            });
            break;
        }
        case BATTERY_PROP_ENERGY_COUNTER: {
            gHealth->getEnergyCounter([&](Result r, int64_t v) {
                err = convertStatus(r);
                val->valueInt64 = v;
            });
            break;
        }
        case BATTERY_PROP_BATTERY_STATUS: {
            gHealth->getChargeStatus([&](Result r, BatteryStatus v) {
                err = convertStatus(r);
                val->valueInt64 = static_cast<int64_t>(v);
            });
            break;
        }
        default: {
            err = BAD_VALUE;
            break;
        }
    }
    return err;
#endif
}

void healthd_battery_update_internal(bool charger_online) {
    // Fast wake interval when on charger (watch for overheat);
    // slow wake interval when on battery (watch for drained battery).

    int new_wake_interval = charger_online ? healthd_config.periodic_chores_interval_fast
                                           : healthd_config.periodic_chores_interval_slow;

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

void healthd_battery_update(void) {
#ifndef HEALTHD_USE_HEALTH_2_0
    healthd_battery_update_internal(gBatteryMonitor->update());
#else
    gHealth->update();
#endif
}

void healthd_dump_battery_state(int fd) {
#ifndef HEALTHD_USE_HEALTH_2_0
    gBatteryMonitor->dumpState(fd);
#else
    native_handle_t* nativeHandle = native_handle_create(1, 0);
    nativeHandle->data[0] = fd;
    ::android::hardware::hidl_handle handle;
    handle.setTo(nativeHandle, true /* shouldOwn */);
    gHealth->debug(handle, {} /* options */);
#endif

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
    if (healthd_register_event(uevent_fd, uevent_event, EVENT_WAKEUP_FD))
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

    if (healthd_register_event(wakealarm_fd, wakealarm_event, EVENT_WAKEUP_FD))
        KLOG_ERROR(LOG_TAG,
                   "Registration of wakealarm event failed\n");

    wakealarm_set_interval(healthd_config.periodic_chores_interval_fast);
}

static void healthd_mainloop(void) {
    int nevents = 0;
    while (1) {
        struct epoll_event events[eventct];
        int timeout = awake_poll_interval;
        int mode_timeout;

        /* Don't wait for first timer timeout to run periodic chores */
        if (!nevents)
            periodic_chores();

        healthd_mode_ops->heartbeat();

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

#ifndef HEALTHD_USE_HEALTH_2_0
    healthd_board_init(&healthd_config);
#else
    // healthd_board_* functions are removed in health@2.0
#endif

    healthd_mode_ops->init(&healthd_config);
    wakealarm_init();
    uevent_init();

#ifndef HEALTHD_USE_HEALTH_2_0
    gBatteryMonitor = new BatteryMonitor();
    gBatteryMonitor->init(&healthd_config);
#endif

    return 0;
}

int healthd_main() {
    int ret;

    klog_set_level(KLOG_LEVEL);

    if (!healthd_mode_ops) {
        KLOG_ERROR("healthd ops not set, exiting\n");
        exit(1);
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
