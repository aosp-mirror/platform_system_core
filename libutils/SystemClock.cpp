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


/*
 * System clock functions.
 */

#if defined(__ANDROID__)
#include <linux/ioctl.h>
#include <linux/rtc.h>
#include <utils/Atomic.h>
#include <linux/android_alarm.h>
#endif

#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>

#include <utils/SystemClock.h>
#include <utils/Timers.h>

#define LOG_TAG "SystemClock"
#include <utils/Log.h>

namespace android {

/*
 * native public static long uptimeMillis();
 */
int64_t uptimeMillis()
{
    int64_t when = systemTime(SYSTEM_TIME_MONOTONIC);
    return (int64_t) nanoseconds_to_milliseconds(when);
}

/*
 * native public static long elapsedRealtime();
 */
int64_t elapsedRealtime()
{
	return nanoseconds_to_milliseconds(elapsedRealtimeNano());
}

/*
 * native public static long elapsedRealtimeNano();
 */
int64_t elapsedRealtimeNano()
{
#if defined(__ANDROID__)
    static int s_fd = -1;

    if (s_fd == -1) {
        int fd = open("/dev/alarm", O_RDONLY);
        if (android_atomic_cmpxchg(-1, fd, &s_fd)) {
            close(fd);
        }
    }

    struct timespec ts;
    if (ioctl(s_fd, ANDROID_ALARM_GET_TIME(ANDROID_ALARM_ELAPSED_REALTIME), &ts) == 0) {
        return seconds_to_nanoseconds(ts.tv_sec) + ts.tv_nsec;
    }

    // /dev/alarm doesn't exist, fallback to CLOCK_BOOTTIME
    if (clock_gettime(CLOCK_BOOTTIME, &ts) == 0) {
        return seconds_to_nanoseconds(ts.tv_sec) + ts.tv_nsec;
    }

    // XXX: there was an error, probably because the driver didn't
    // exist ... this should return
    // a real error, like an exception!
    return systemTime(SYSTEM_TIME_MONOTONIC);
#else
    return systemTime(SYSTEM_TIME_MONOTONIC);
#endif
}

}; // namespace android
