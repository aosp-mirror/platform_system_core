/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "storaged"
#define KLOG_LEVEL 6

#include <fcntl.h>
#include <getopt.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include <android-base/macros.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <cutils/android_get_control_file.h>
#include <cutils/sched_policy.h>
#include <private/android_filesystem_config.h>

#include <storaged.h>
#include <storaged_service.h>
#include <storaged_utils.h>

sp<storaged_t> storaged;

// Function of storaged's main thread
void* storaged_main(void* /* unused */) {
    storaged = new storaged_t();

    storaged->init_battery_service();
    storaged->report_storage_info();

    LOG_TO(SYSTEM, INFO) << "storaged: Start";

    for (;;) {
        storaged->event_checked();
        storaged->pause();
    }
    return NULL;
}

static void help_message(void) {
    printf("usage: storaged [OPTION]\n");
    printf("  -u    --uid                   Dump uid I/O usage to stdout\n");
    printf("  -s    --start                 Start storaged (default)\n");
    fflush(stdout);
}

int main(int argc, char** argv) {
    int flag_main_service = 0;
    int flag_dump_uid = 0;
    int opt;

    for (;;) {
        int opt_idx = 0;
        static struct option long_options[] = {
            {"start",       no_argument,        0, 's'},
            {"kill",        no_argument,        0, 'k'},
            {"uid",         no_argument,        0, 'u'},
            {"help",        no_argument,        0, 'h'}
        };
        opt = getopt_long(argc, argv, ":skdhu0", long_options, &opt_idx);
        if (opt == -1) {
            break;
        }

        switch (opt) {
        case 's':
            flag_main_service = 1;
            break;
        case 'u':
            flag_dump_uid = 1;
            break;
        case 'h':
            help_message();
            return 0;
        case '?':
        default:
            fprintf(stderr, "no supported option\n");
            help_message();
            return -1;
        }
    }

    if (argc == 1) {
        flag_main_service = 1;
    }

    if (flag_main_service && flag_dump_uid) {
        fprintf(stderr, "Invalid arguments. Option \"start\" and \"dump\" cannot be used together.\n");
        help_message();
        return -1;
    }

    if (flag_main_service) { // start main thread
        // Start the main thread of storaged
        pthread_t storaged_main_thread;
        errno = pthread_create(&storaged_main_thread, NULL, storaged_main, NULL);
        if (errno != 0) {
            PLOG_TO(SYSTEM, ERROR) << "Failed to create main thread";
            return -1;
        }

        defaultServiceManager()->addService(String16("storaged"), new Storaged());
        android::ProcessState::self()->startThreadPool();
        IPCThreadState::self()->joinThreadPool();
        pthread_join(storaged_main_thread, NULL);

        return 0;
    }

    if (flag_dump_uid) {
        sp<IStoraged> storaged_service = get_storaged_service();
        if (storaged_service == NULL) {
            fprintf(stderr, "Cannot find storaged service.\nMaybe run storaged --start first?\n");
            return -1;
        }
        std::vector<struct uid_info> res = storaged_service->dump_uids(NULL);

        if (res.size() == 0) {
            fprintf(stderr, "UID I/O is not readable in this version of kernel.\n");
            return 0;
        }

        sort_running_uids_info(res);
        log_console_running_uids_info(res);

        return 0;
    }

    return 0;
}
