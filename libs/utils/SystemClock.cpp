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

#ifdef HAVE_ANDROID_OS
#include <linux/ioctl.h>
#include <linux/rtc.h>
#include <utils/Atomic.h>
#include <linux/android_alarm.h>
#endif

#include <sys/time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <utils/SystemClock.h>
#include <utils/Timers.h>

#define LOG_TAG "SystemClock"
#include "utils/Log.h"

namespace android {

/*
 * Set the current time.  This only works when running as root.
 */
int setCurrentTimeMillis(int64_t millis)
{
#if WIN32
    // not implemented
    return -1;
#else
    struct timeval tv;
#ifdef HAVE_ANDROID_OS
    struct timespec ts;
    int fd;
    int res;
#endif
    int ret = 0;

    if (millis <= 0 || millis / 1000LL >= INT_MAX) {
        return -1;
    }

    tv.tv_sec = (time_t) (millis / 1000LL);
    tv.tv_usec = (suseconds_t) ((millis % 1000LL) * 1000LL);

    ALOGD("Setting time of day to sec=%d\n", (int) tv.tv_sec);

#ifdef HAVE_ANDROID_OS
    fd = open("/dev/alarm", O_RDWR);
    if(fd < 0) {
        ALOGW("Unable to open alarm driver: %s\n", strerror(errno));
        return -1;
    }
    ts.tv_sec = tv.tv_sec;
    ts.tv_nsec = tv.tv_usec * 1000;
    res = ioctl(fd, ANDROID_ALARM_SET_RTC, &ts);
    if(res < 0) {
        ALOGW("Unable to set rtc to %ld: %s\n", tv.tv_sec, strerror(errno));
        ret = -1;
    }
    close(fd);
#else
    if (settimeofday(&tv, NULL) != 0) {
        ALOGW("Unable to set clock to %d.%d: %s\n",
            (int) tv.tv_sec, (int) tv.tv_usec, strerror(errno));
        ret = -1;
    }
#endif

    return ret;
#endif // WIN32
}

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

#define METHOD_CLOCK_GETTIME    0
#define METHOD_IOCTL            1
#define METHOD_SYSTEMTIME       2

static const char *gettime_method_names[] = {
    "clock_gettime",
    "ioctl",
    "systemTime",
};

static inline void checkTimeStamps(int64_t timestamp,
                                   int64_t volatile *prevTimestampPtr,
                                   int volatile *prevMethodPtr,
                                   int curMethod)
{
    /*
     * Disable the check for SDK since the prebuilt toolchain doesn't contain
     * gettid, and int64_t is different on the ARM platform
     * (ie long vs long long).
     */
#ifdef ARCH_ARM
    int64_t prevTimestamp = *prevTimestampPtr;
    int prevMethod = *prevMethodPtr;

    if (timestamp < prevTimestamp) {
        ALOGW("time going backwards: prev %lld(%s) vs now %lld(%s), tid=%d",
              prevTimestamp, gettime_method_names[prevMethod],
              timestamp, gettime_method_names[curMethod],
              gettid());
    }
    // NOTE - not atomic and may generate spurious warnings if the 64-bit
    // write is interrupted or not observed as a whole.
    *prevTimestampPtr = timestamp;
    *prevMethodPtr = curMethod;
#endif
}

/*
 * native public static long elapsedRealtimeNano();
 */
int64_t elapsedRealtimeNano()
{
#ifdef HAVE_ANDROID_OS
    struct timespec ts;
    int result;
    int64_t timestamp;
    static volatile int64_t prevTimestamp;
    static volatile int prevMethod;

#if 0
    /*
     * b/7100774
     * clock_gettime appears to have clock skews and can sometimes return
     * backwards values. Disable its use until we find out what's wrong.
     */
    result = clock_gettime(CLOCK_BOOTTIME, &ts);
    if (result == 0) {
        timestamp = seconds_to_nanoseconds(ts.tv_sec) + ts.tv_nsec;
        checkTimeStamps(timestamp, &prevTimestamp, &prevMethod,
                        METHOD_CLOCK_GETTIME);
        return timestamp;
    }
#endif

    // CLOCK_BOOTTIME doesn't exist, fallback to /dev/alarm
    static int s_fd = -1;

    if (s_fd == -1) {
        int fd = open("/dev/alarm", O_RDONLY);
        if (android_atomic_cmpxchg(-1, fd, &s_fd)) {
            close(fd);
        }
    }

    result = ioctl(s_fd,
            ANDROID_ALARM_GET_TIME(ANDROID_ALARM_ELAPSED_REALTIME), &ts);

    if (result == 0) {
        timestamp = seconds_to_nanoseconds(ts.tv_sec) + ts.tv_nsec;
        checkTimeStamps(timestamp, &prevTimestamp, &prevMethod, METHOD_IOCTL);
        return timestamp;
    }

    // XXX: there was an error, probably because the driver didn't
    // exist ... this should return
    // a real error, like an exception!
    timestamp = systemTime(SYSTEM_TIME_MONOTONIC);
    checkTimeStamps(timestamp, &prevTimestamp, &prevMethod,
                    METHOD_SYSTEMTIME);
    return timestamp;
#else
    return systemTime(SYSTEM_TIME_MONOTONIC);
#endif
}

}; // namespace android
