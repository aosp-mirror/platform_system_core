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
#include <android-base/stringprintf.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <cutils/android_get_control_file.h>
#include <cutils/klog.h>
#include <cutils/sched_policy.h>
#include <private/android_filesystem_config.h>

#include <storaged.h>
#include <storaged_service.h>
#include <storaged_utils.h>

storaged_t storaged;

static int drop_privs() {
    // privilege setting
    struct sched_param param;
    memset(&param, 0, sizeof(param));

    if (set_sched_policy(0, SP_BACKGROUND) < 0) return -1;

    if (sched_setscheduler((pid_t) 0, SCHED_BATCH, &param) < 0) return -1;

    if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) return -1;

    if (prctl(PR_SET_KEEPCAPS, 1) < 0) return -1;

    std::unique_ptr<struct _cap_struct, int(*)(void *)> caps(cap_init(), cap_free);
    if (cap_clear(caps.get()) < 0) return -1;
    cap_value_t cap_value[] = {
        CAP_SETGID,
        CAP_SETUID,
        CAP_SYS_PTRACE // allow access to proc/<pid>/io as non-root user
    };
    if (cap_set_flag(caps.get(), CAP_PERMITTED,
                     arraysize(cap_value), cap_value,
                     CAP_SET) < 0) return -1;
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE,
                     arraysize(cap_value), cap_value,
                     CAP_SET) < 0) return -1;
    if (cap_set_proc(caps.get()) < 0)
        return -1;

    gid_t groups[] = { AID_READPROC };

    if (setgroups(sizeof(groups) / sizeof(groups[0]), groups) == -1) return -1;

    if (setgid(AID_SYSTEM) != 0) return -1;

    if (setuid(AID_SYSTEM) != 0) return -1;

    if (cap_set_flag(caps.get(), CAP_PERMITTED, 2, cap_value, CAP_CLEAR) < 0) return -1;
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, 2, cap_value, CAP_CLEAR) < 0) return -1;
    if (cap_set_proc(caps.get()) < 0)
        return -1;

    return 0;
}

// Function of storaged's main thread
extern int fd_dmesg;
void* storaged_main(void* s) {
    storaged_t* storaged = (storaged_t*)s;

    if (fd_dmesg >= 0) {
        static const char start_message[] = {KMSG_PRIORITY(LOG_INFO),
            's', 't', 'o', 'r', 'a', 'g', 'e', 'd', ':', ' ', 'S', 't', 'a', 'r', 't', '\n'};
        write(fd_dmesg, start_message, sizeof(start_message));
    }

    for (;;) {
        storaged->event();
        storaged->pause();
    }
    return NULL;
}

static void help_message(void) {
    printf("usage: storaged [OPTION]\n");
    printf("  -d    --dump                  Dump task I/O usage to stdout\n");
    printf("  -s    --start                 Start storaged (default)\n");
    printf("        --emmc=INTERVAL         Set publish interval of emmc lifetime information (in days)\n");
    printf("        --diskstats=INTERVAL    Set publish interval of diskstats (in hours)\n");
    printf("        --unit=INTERVAL         Set storaged's refresh interval (in seconds)\n");
    fflush(stdout);
}

#define HOUR_TO_SEC ( 3600 )
#define DAY_TO_SEC ( 3600 * 24 )

int main(int argc, char** argv) {
    klog_set_level(KLOG_LEVEL);
    int flag_main_service = 0;
    int flag_dump_task = 0;
    int flag_config = 0;
    int unit_interval = DEFAULT_PERIODIC_CHORES_INTERVAL_UNIT;
    int diskstats_interval = DEFAULT_PERIODIC_CHORES_INTERVAL_DISK_STATS_PUBLISH;
    int emmc_interval = DEFAULT_PERIODIC_CHORES_INTERVAL_EMMC_INFO_PUBLISH;
    int fd_emmc = -1;
    int opt;

    for (;;) {
        int opt_idx = 0;
        static struct option long_options[] = {
            {"start",       no_argument,        0, 's'},
            {"kill",        no_argument,        0, 'k'},
            {"dump",        no_argument,        0, 'd'},
            {"help",        no_argument,        0, 'h'},
            {"unit",        required_argument,  0,  0 },
            {"diskstats",   required_argument,  0,  0 },
            {"emmc",        required_argument,  0,  0 }
        };
        opt = getopt_long(argc, argv, ":skdh0", long_options, &opt_idx);
        if (opt == -1) {
            break;
        }

        switch (opt) {
        case 0:
            printf("option %s", long_options[opt_idx].name);
            if (optarg) {
                printf(" with arg %s", optarg);
                if (strcmp(long_options[opt_idx].name, "unit") == 0) {
                    unit_interval = atoi(optarg);
                    if (unit_interval == 0) {
                        fprintf(stderr, "Invalid argument. Option %s requires an integer argument greater than 0.\n",
                                long_options[opt_idx].name);
                        help_message();
                        return -1;
                    }
                } else if (strcmp(long_options[opt_idx].name, "diskstats") == 0) {
                    diskstats_interval = atoi(optarg) * HOUR_TO_SEC;
                    if (diskstats_interval == 0) {
                        fprintf(stderr, "Invalid argument. Option %s requires an integer argument greater than 0.\n",
                                long_options[opt_idx].name);
                        help_message();
                        return -1;
                    }

                } else if (strcmp(long_options[opt_idx].name, "emmc") == 0) {
                    emmc_interval = atoi(optarg) * DAY_TO_SEC;
                    if (diskstats_interval == 0) {
                        fprintf(stderr, "Invalid argument. Option %s requires an integer argument greater than 0.\n",
                                long_options[opt_idx].name);
                        help_message();
                        return -1;
                    }
                }
                flag_config = 1;
            } else {
                fprintf(stderr, "Invalid argument. Option %s requires an argument.\n",
                        long_options[opt_idx].name);
                help_message();
                return -1;
            }
            printf("\n");
            break;
        case 's':
            flag_main_service = 1;
            break;
        case 'd':
            flag_dump_task = 1;
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

    if (flag_main_service && flag_dump_task) {
        fprintf(stderr, "Invalid arguments. Option \"start\" and \"dump\" cannot be used together.\n");
        help_message();
        return -1;
    }

    if (flag_config && flag_dump_task) {
        fprintf(stderr, "Invalid arguments. Cannot set configs in \'dump\' option.\n");
        help_message();
        return -1;
    }

    if (flag_main_service) { // start main thread
        static const char dev_kmsg[] = "/dev/kmsg";
        fd_dmesg = android_get_control_file(dev_kmsg);
        if (fd_dmesg < 0)
            fd_dmesg = TEMP_FAILURE_RETRY(open(dev_kmsg, O_WRONLY));

        static const char mmc0_ext_csd[] = "/d/mmc0/mmc0:0001/ext_csd";
        fd_emmc = android_get_control_file(mmc0_ext_csd);
        if (fd_emmc < 0)
            fd_emmc = TEMP_FAILURE_RETRY(open(mmc0_ext_csd, O_RDONLY));

        if (drop_privs() != 0) {
            return -1;
        }

        storaged.set_privileged_fds(fd_emmc);

        if (flag_config) {
            storaged.set_unit_interval(unit_interval);
            storaged.set_diskstats_interval(diskstats_interval);
            storaged.set_emmc_interval(emmc_interval);
        }

        // Start the main thread of storaged
        pthread_t storaged_main_thread;
        if (pthread_create(&storaged_main_thread, NULL, storaged_main, &storaged)) {
            if (fd_dmesg >= 0) {
                std::string error_message = android::base::StringPrintf(
                    "%s Failed to create main thread\n", kmsg_error_prefix);
                write(fd_dmesg, error_message.c_str(), error_message.length());
            }
            return -1;
        }

        defaultServiceManager()->addService(String16("storaged"), new Storaged());
        android::ProcessState::self()->startThreadPool();
        IPCThreadState::self()->joinThreadPool();
        pthread_join(storaged_main_thread, NULL);

        close(fd_dmesg);
        close(fd_emmc);

        return 0;
    }

    if (flag_dump_task) {
        sp<IStoraged> storaged_service = get_storaged_service();
        if (storaged_service == NULL) {
            fprintf(stderr, "Cannot find storaged service.\nMaybe run storaged --start first?\n");
            return -1;
        }
        std::vector<struct task_info> res = storaged_service->dump_tasks(NULL);

        if (res.size() == 0) {
            fprintf(stderr, "Task I/O is not readable in this version of kernel.\n");
            return 0;
        }

        time_t starttime = storaged.get_starttime();

        if (starttime == (time_t)-1) {
            fprintf(stderr, "Unknown start time\n");
        } else {
            char* time_str = ctime(&starttime);
            printf("Application I/O was collected by storaged since %s", time_str);
        }

        sort_running_tasks_info(res);
        log_console_running_tasks_info(res);


        return 0;
    }

    return 0;
}