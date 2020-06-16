/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/klog.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <memory>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <cutils/android_get_control_file.h>
#include <cutils/sockets.h>
#include <log/event_tag_map.h>
#include <packagelistparser/packagelistparser.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>
#include <processgroup/sched_policy.h>
#include <utils/threads.h>

#include "ChattyLogBuffer.h"
#include "CommandListener.h"
#include "LogAudit.h"
#include "LogBuffer.h"
#include "LogKlog.h"
#include "LogListener.h"
#include "LogReader.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogUtils.h"
#include "SerializedLogBuffer.h"
#include "SimpleLogBuffer.h"

#define KMSG_PRIORITY(PRI)                                 \
    '<', '0' + LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(PRI)) / 10, \
        '0' + LOG_MAKEPRI(LOG_DAEMON, LOG_PRI(PRI)) % 10, '>'

// The service is designed to be run by init, it does not respond well to starting up manually. Init
// has a 'sigstop' feature that sends SIGSTOP to a service immediately before calling exec().  This
// allows debuggers, etc to be attached to logd at the very beginning, while still having init
// handle the user, groups, capabilities, files, etc setup.
static int drop_privs(bool klogd, bool auditd) {
    sched_param param = {};

    if (set_sched_policy(0, SP_BACKGROUND) < 0) {
        PLOG(ERROR) << "failed to set background scheduling policy";
        return -1;
    }

    if (sched_setscheduler((pid_t)0, SCHED_BATCH, &param) < 0) {
        PLOG(ERROR) << "failed to set batch scheduler";
        return -1;
    }

    if (!__android_logger_property_get_bool("ro.debuggable", BOOL_DEFAULT_FALSE) &&
        prctl(PR_SET_DUMPABLE, 0) == -1) {
        PLOG(ERROR) << "failed to clear PR_SET_DUMPABLE";
        return -1;
    }

    std::unique_ptr<struct _cap_struct, int (*)(void*)> caps(cap_init(), cap_free);
    if (cap_clear(caps.get()) < 0) {
        return -1;
    }
    std::vector<cap_value_t> cap_value;
    if (klogd) {
        cap_value.emplace_back(CAP_SYSLOG);
    }
    if (auditd) {
        cap_value.emplace_back(CAP_AUDIT_CONTROL);
    }

    if (cap_set_flag(caps.get(), CAP_PERMITTED, cap_value.size(), cap_value.data(), CAP_SET) < 0) {
        return -1;
    }
    if (cap_set_flag(caps.get(), CAP_EFFECTIVE, cap_value.size(), cap_value.data(), CAP_SET) < 0) {
        return -1;
    }
    if (cap_set_proc(caps.get()) < 0) {
        PLOG(ERROR) << "failed to set CAP_SYSLOG or CAP_AUDIT_CONTROL";
        return -1;
    }

    return 0;
}

char* android::uidToName(uid_t u) {
    struct Userdata {
        uid_t uid;
        char* name;
    } userdata = {
            .uid = u,
            .name = nullptr,
    };

    packagelist_parse(
            [](pkg_info* info, void* callback_parameter) {
                auto userdata = reinterpret_cast<Userdata*>(callback_parameter);
                bool result = true;
                if (info->uid == userdata->uid) {
                    userdata->name = strdup(info->name);
                    // false to stop processing
                    result = false;
                }
                packagelist_free(info);
                return result;
            },
            &userdata);

    return userdata.name;
}

static void readDmesg(LogAudit* al, LogKlog* kl) {
    if (!al && !kl) {
        return;
    }

    int rc = klogctl(KLOG_SIZE_BUFFER, nullptr, 0);
    if (rc <= 0) {
        return;
    }

    // Margin for additional input race or trailing nul
    ssize_t len = rc + 1024;
    std::unique_ptr<char[]> buf(new char[len]);

    rc = klogctl(KLOG_READ_ALL, buf.get(), len);
    if (rc <= 0) {
        return;
    }

    if (rc < len) {
        len = rc + 1;
    }
    buf[--len] = '\0';

    ssize_t sublen;
    for (char *ptr = nullptr, *tok = buf.get();
         (rc >= 0) && !!(tok = android::log_strntok_r(tok, len, ptr, sublen));
         tok = nullptr) {
        if ((sublen <= 0) || !*tok) continue;
        if (al) {
            rc = al->log(tok, sublen);
        }
        if (kl) {
            rc = kl->log(tok, sublen);
        }
    }
}

static int issueReinit() {
    int sock = TEMP_FAILURE_RETRY(socket_local_client(
        "logd", ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM));
    if (sock < 0) return -errno;

    static const char reinitStr[] = "reinit";
    ssize_t ret = TEMP_FAILURE_RETRY(write(sock, reinitStr, sizeof(reinitStr)));
    if (ret < 0) return -errno;

    struct pollfd p;
    memset(&p, 0, sizeof(p));
    p.fd = sock;
    p.events = POLLIN;
    ret = TEMP_FAILURE_RETRY(poll(&p, 1, 1000));
    if (ret < 0) return -errno;
    if ((ret == 0) || !(p.revents & POLLIN)) return -ETIME;

    static const char success[] = "success";
    char buffer[sizeof(success) - 1];
    memset(buffer, 0, sizeof(buffer));
    ret = TEMP_FAILURE_RETRY(read(sock, buffer, sizeof(buffer)));
    if (ret < 0) return -errno;

    return strncmp(buffer, success, sizeof(success) - 1) != 0;
}

// Foreground waits for exit of the main persistent threads
// that are started here. The threads are created to manage
// UNIX domain client sockets for writing, reading and
// controlling the user space logger, and for any additional
// logging plugins like auditd and restart control. Additional
// transitory per-client threads are created for each reader.
int main(int argc, char* argv[]) {
    // logd is written under the assumption that the timezone is UTC.
    // If TZ is not set, persist.sys.timezone is looked up in some time utility
    // libc functions, including mktime. It confuses the logd time handling,
    // so here explicitly set TZ to UTC, which overrides the property.
    setenv("TZ", "UTC", 1);
    // issue reinit command. KISS argument parsing.
    if ((argc > 1) && argv[1] && !strcmp(argv[1], "--reinit")) {
        return issueReinit();
    }

    android::base::InitLogging(
            argv, [](android::base::LogId log_id, android::base::LogSeverity severity,
                     const char* tag, const char* file, unsigned int line, const char* message) {
                if (tag && strcmp(tag, "logd") != 0) {
                    auto prefixed_message = android::base::StringPrintf("%s: %s", tag, message);
                    android::base::KernelLogger(log_id, severity, "logd", file, line,
                                                prefixed_message.c_str());
                } else {
                    android::base::KernelLogger(log_id, severity, "logd", file, line, message);
                }
            });

    static const char dev_kmsg[] = "/dev/kmsg";
    int fdDmesg = android_get_control_file(dev_kmsg);
    if (fdDmesg < 0) {
        fdDmesg = TEMP_FAILURE_RETRY(open(dev_kmsg, O_WRONLY | O_CLOEXEC));
    }

    int fdPmesg = -1;
    bool klogd = __android_logger_property_get_bool(
        "ro.logd.kernel",
        BOOL_DEFAULT_TRUE | BOOL_DEFAULT_FLAG_ENG | BOOL_DEFAULT_FLAG_SVELTE);
    if (klogd) {
        static const char proc_kmsg[] = "/proc/kmsg";
        fdPmesg = android_get_control_file(proc_kmsg);
        if (fdPmesg < 0) {
            fdPmesg = TEMP_FAILURE_RETRY(
                open(proc_kmsg, O_RDONLY | O_NDELAY | O_CLOEXEC));
        }
        if (fdPmesg < 0) PLOG(ERROR) << "Failed to open " << proc_kmsg;
    }

    bool auditd = __android_logger_property_get_bool("ro.logd.auditd", BOOL_DEFAULT_TRUE);
    if (drop_privs(klogd, auditd) != 0) {
        return EXIT_FAILURE;
    }

    // A cache of event log tags
    LogTags log_tags;

    // Pruning configuration.
    PruneList prune_list;

    // Partial (required for chatty) or full logging statistics.
    bool enable_full_log_statistics = __android_logger_property_get_bool(
            "logd.statistics", BOOL_DEFAULT_TRUE | BOOL_DEFAULT_FLAG_PERSIST |
                                       BOOL_DEFAULT_FLAG_ENG | BOOL_DEFAULT_FLAG_SVELTE);
    LogStatistics log_statistics(enable_full_log_statistics);

    // Serves the purpose of managing the last logs times read on a
    // socket connection, and as a reader lock on a range of log
    // entries.
    LogReaderList reader_list;

    // LogBuffer is the object which is responsible for holding all log entries.
    LogBuffer* logBuf;
    if (true) {
        logBuf = new ChattyLogBuffer(&reader_list, &log_tags, &prune_list, &log_statistics);
    } else {
        logBuf = new SimpleLogBuffer(&reader_list, &log_tags, &log_statistics);
    }

    // LogReader listens on /dev/socket/logdr. When a client
    // connects, log entries in the LogBuffer are written to the client.
    LogReader* reader = new LogReader(logBuf, &reader_list);
    if (reader->startListener()) {
        return EXIT_FAILURE;
    }

    // LogListener listens on /dev/socket/logdw for client
    // initiated log messages. New log entries are added to LogBuffer
    // and LogReader is notified to send updates to connected clients.
    LogListener* swl = new LogListener(logBuf);
    if (!swl->StartListener()) {
        return EXIT_FAILURE;
    }

    // Command listener listens on /dev/socket/logd for incoming logd
    // administrative commands.
    CommandListener* cl = new CommandListener(logBuf, &log_tags, &prune_list, &log_statistics);
    if (cl->startListener()) {
        return EXIT_FAILURE;
    }

    // LogAudit listens on NETLINK_AUDIT socket for selinux
    // initiated log messages. New log entries are added to LogBuffer
    // and LogReader is notified to send updates to connected clients.
    LogAudit* al = nullptr;
    if (auditd) {
        int dmesg_fd = __android_logger_property_get_bool("ro.logd.auditd.dmesg", BOOL_DEFAULT_TRUE)
                               ? fdDmesg
                               : -1;
        al = new LogAudit(logBuf, dmesg_fd, &log_statistics);
    }

    LogKlog* kl = nullptr;
    if (klogd) {
        kl = new LogKlog(logBuf, fdDmesg, fdPmesg, al != nullptr, &log_statistics);
    }

    readDmesg(al, kl);

    // failure is an option ... messages are in dmesg (required by standard)
    if (kl && kl->startListener()) {
        delete kl;
    }

    if (al && al->startListener()) {
        delete al;
    }

    TEMP_FAILURE_RETRY(pause());

    return EXIT_SUCCESS;
}
