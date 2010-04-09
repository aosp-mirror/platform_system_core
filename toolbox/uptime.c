/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <sys/time.h>
#include <linux/ioctl.h>
#include <linux/rtc.h>
#include <linux/android_alarm.h>
#include <fcntl.h>
#include <stdio.h>


static void format_time(int time, char* buffer) {
    int seconds, minutes, hours, days;

    seconds = time % 60;
    time /= 60;
    minutes = time % 60;
    time /= 60;
    hours = time % 24;
    days = time / 24;

    if (days > 0)
        sprintf(buffer, "%d days, %02d:%02d:%02d", days, hours, minutes, seconds);
    else
        sprintf(buffer, "%02d:%02d:%02d", hours, minutes, seconds);
}

int64_t elapsedRealtime()
{
    struct timespec ts;
    int fd, result;

    fd = open("/dev/alarm", O_RDONLY);
    if (fd < 0)
        return fd;

   result = ioctl(fd, ANDROID_ALARM_GET_TIME(ANDROID_ALARM_ELAPSED_REALTIME), &ts);
   close(fd);

    if (result == 0)
        return ts.tv_sec;
    return -1;
}

int uptime_main(int argc, char *argv[])
{
    float up_time, idle_time;
    char up_string[100], idle_string[100], sleep_string[100];
    int elapsed;

    FILE* file = fopen("/proc/uptime", "r");
    if (!file) {
        fprintf(stderr, "Could not open /proc/uptime\n");
        return -1;
    }
    if (fscanf(file, "%f %f", &up_time, &idle_time) != 2) {
        fprintf(stderr, "Could not parse /proc/uptime\n");
        fclose(file);
        return -1;
    }
    fclose(file);

    elapsed = elapsedRealtime();
    if (elapsed < 0) {
        fprintf(stderr, "elapsedRealtime failed\n");
        return -1;
    }

    format_time(elapsed, up_string);
    format_time((int)idle_time, idle_string);
    format_time((int)(elapsed - up_time), sleep_string);
    printf("up time: %s, idle time: %s, sleep time: %s\n", up_string, idle_string, sleep_string);

    return 0;
}
