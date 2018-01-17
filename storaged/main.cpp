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
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/resource.h>
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

using namespace std;
using namespace android;

sp<storaged_t> storaged_sp;

// Function of storaged's main thread
void* storaged_main(void* /* unused */) {
    storaged_sp = new storaged_t();

    storaged_sp->init();
    storaged_sp->report_storage_info();

    LOG_TO(SYSTEM, INFO) << "storaged: Start";

    for (;;) {
        storaged_sp->event_checked();
        storaged_sp->pause();
    }
    return NULL;
}

void help_message(void) {
    printf("usage: storaged [OPTION]\n");
    printf("  -u    --uid                   Dump uid I/O usage to stdout\n");
    printf("  -t    --task                  Dump task I/O usage to stdout\n");
    printf("  -p    --perf                  Dump I/O perf history to stdout\n");
    printf("  -s    --start                 Start storaged (default)\n");
    fflush(stdout);
}

int main(int argc, char** argv) {
    bool flag_main_service = false;
    bool flag_dump_uid = false;
    bool flag_dump_task = false;
    bool flag_dump_perf = false;
    int opt;

    for (;;) {
        int opt_idx = 0;
        static struct option long_options[] = {
            {"perf",        no_argument,    nullptr, 'p'},
            {"start",       no_argument,    nullptr, 's'},
            {"task",        no_argument,    nullptr, 't'},
            {"uid",         no_argument,    nullptr, 'u'},
            {nullptr,       0,              nullptr,  0}
        };
        opt = getopt_long(argc, argv, ":pstu", long_options, &opt_idx);
        if (opt == -1) {
            break;
        }

        switch (opt) {
        case 'p':
            flag_dump_perf = true;
            break;
        case 's':
            flag_main_service = true;
            break;
        case 't':
            flag_dump_task = true;
            break;
        case 'u':
            flag_dump_uid = true;
            break;
        default:
            help_message();
            return 0;
        }
    }

    if (argc == 1) {
        flag_main_service = true;
    }

    if (flag_main_service && (flag_dump_uid || flag_dump_task)) {
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

        if (StoragedService::start() != android::OK ||
            StoragedPrivateService::start() != android::OK) {
            PLOG_TO(SYSTEM, ERROR) << "Failed to start storaged service";
            return -1;
        }

        android::ProcessState::self()->startThreadPool();
        IPCThreadState::self()->joinThreadPool();
        pthread_join(storaged_main_thread, NULL);

        return 0;
    }

    sp<IStoragedPrivate> storaged_service = get_storaged_pri_service();
    if (storaged_service == NULL) {
        fprintf(stderr, "Cannot find storaged service.\nMaybe run storaged --start first?\n");
        return -1;
    }

    if (flag_dump_uid || flag_dump_task) {
        vector<UidInfo> uid_io;
        binder::Status status = storaged_service->dumpUids(&uid_io);
        if (!status.isOk() || uid_io.size() == 0) {
            fprintf(stderr, "UID I/O info is not available.\n");
            return 0;
        }

        sort_running_uids_info(uid_io);
        log_console_running_uids_info(uid_io, flag_dump_task);
    }

    if (flag_dump_perf) {
        vector<int> perf_history;
        binder::Status status = storaged_service->dumpPerfHistory(&perf_history);
        if (!status.isOk() || perf_history.size() == 0) {
            fprintf(stderr, "I/O perf history is not available.\n");
            return 0;
        }

        log_console_perf_history(perf_history);
    }

    return 0;
}
