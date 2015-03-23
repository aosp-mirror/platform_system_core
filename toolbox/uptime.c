/*
 * Copyright (c) 2010, The Android Open Source Project
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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void format_time(int time, char* buffer) {
    int seconds = time % 60;
    time /= 60;
    int minutes = time % 60;
    time /= 60;
    int hours = time % 24;
    int days = time / 24;

    if (days > 0) {
        sprintf(buffer, "%d day%s, %02d:%02d:%02d", days, (days == 1) ? "" : "s", hours, minutes, seconds);
    } else {
        sprintf(buffer, "%02d:%02d:%02d", hours, minutes, seconds);
    }
}

int uptime_main(int argc __attribute__((unused)), char *argv[] __attribute__((unused))) {
    FILE* file = fopen("/proc/uptime", "r");
    if (!file) {
        fprintf(stderr, "Could not open /proc/uptime\n");
        return -1;
    }
    float idle_time;
    if (fscanf(file, "%*f %f", &idle_time) != 1) {
        fprintf(stderr, "Could not parse /proc/uptime\n");
        fclose(file);
        return -1;
    }
    fclose(file);

    struct timespec up_timespec;
    if (clock_gettime(CLOCK_MONOTONIC, &up_timespec) == -1) {
        fprintf(stderr, "Could not get monotonic time: %s\n", strerror(errno));
	return -1;
    }
    float up_time = up_timespec.tv_sec + up_timespec.tv_nsec / 1e9;

    struct timespec elapsed_timespec;
    if (clock_gettime(CLOCK_BOOTTIME, &elapsed_timespec) == -1) {
        fprintf(stderr, "Could not get boot time: %s\n", strerror(errno));
        return -1;
    }
    int elapsed = elapsed_timespec.tv_sec;

    char up_string[100], idle_string[100], sleep_string[100];
    format_time(elapsed, up_string);
    format_time((int)idle_time, idle_string);
    format_time((int)(elapsed - up_time), sleep_string);
    printf("up time: %s, idle time: %s, sleep time: %s\n", up_string, idle_string, sleep_string);

    return 0;
}
