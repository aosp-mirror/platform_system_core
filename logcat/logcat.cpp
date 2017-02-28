/*
 * Copyright (C) 2006-2017 The Android Open Source Project
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

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sched_policy.h>
#include <cutils/sockets.h>
#include <log/event_tag_map.h>
#include <log/logcat.h>
#include <log/logprint.h>
#include <private/android_logger.h>
#include <system/thread_defs.h>

#include <pcrecpp.h>

#define DEFAULT_MAX_ROTATED_LOGS 4

struct android_logcat_context_internal {
    // status
    volatile std::atomic_int retval;  // valid if thread_stopped set
    // Arguments passed in, or copies and storage thereof if a thread.
    int argc;
    char* const* argv;
    char* const* envp;
    std::vector<std::string> args;
    std::vector<const char*> argv_hold;
    std::vector<std::string> envs;
    std::vector<const char*> envp_hold;
    int output_fd; // duplication of fileno(output) (below)
    int error_fd;  // duplication of fileno(error) (below)

    // library
    int fds[2];    // From popen call
    FILE* output;  // everything writes to fileno(output), buffer unused
    FILE* error;   // unless error == output.
    pthread_t thr;
    volatile std::atomic_bool stop;  // quick exit flag
    volatile std::atomic_bool thread_stopped;
    bool stderr_null;    // shell "2>/dev/null"
    bool stderr_stdout;  // shell "2>&1"

    // global variables
    AndroidLogFormat* logformat;
    const char* outputFileName;
    // 0 means "no log rotation"
    size_t logRotateSizeKBytes;
    // 0 means "unbounded"
    size_t maxRotatedLogs;
    size_t outByteCount;
    int printBinary;
    int devCount;  // >1 means multiple
    pcrecpp::RE* regex;
    // 0 means "infinite"
    size_t maxCount;
    size_t printCount;
    bool printItAnyways;
    bool debug;

    // static variables
    bool hasOpenedEventTagMap;
    EventTagMap* eventTagMap;
};

// Creates a context associated with this logcat instance
android_logcat_context create_android_logcat() {
    android_logcat_context_internal* context;

    context = (android_logcat_context_internal*)calloc(
        1, sizeof(android_logcat_context_internal));
    if (!context) return NULL;

    context->fds[0] = -1;
    context->fds[1] = -1;
    context->output_fd = -1;
    context->error_fd = -1;
    context->maxRotatedLogs = DEFAULT_MAX_ROTATED_LOGS;

    context->argv_hold.clear();
    context->args.clear();
    context->envp_hold.clear();
    context->envs.clear();

    return (android_logcat_context)context;
}

// logd prefixes records with a length field
#define RECORD_LENGTH_FIELD_SIZE_BYTES sizeof(uint32_t)

struct log_device_t {
    const char* device;
    bool binary;
    struct logger* logger;
    struct logger_list* logger_list;
    bool printed;

    log_device_t* next;

    log_device_t(const char* d, bool b) {
        device = d;
        binary = b;
        next = NULL;
        printed = false;
        logger = NULL;
        logger_list = NULL;
    }
};

namespace android {

enum helpType { HELP_FALSE, HELP_TRUE, HELP_FORMAT };

// if showHelp is set, newline required in fmt statement to transition to usage
static void logcat_panic(android_logcat_context_internal* context,
                         enum helpType showHelp, const char* fmt, ...)
    __printflike(3, 4);

static int openLogFile(const char* pathname) {
    return open(pathname, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
}

static void close_output(android_logcat_context_internal* context) {
    // split output_from_error
    if (context->error == context->output) {
        context->output = NULL;
        context->output_fd = -1;
    }
    if (context->error && (context->output_fd == fileno(context->error))) {
        context->output_fd = -1;
    }
    if (context->output_fd == context->error_fd) {
        context->output_fd = -1;
    }
    // close output channel
    if (context->output) {
        if (context->output != stdout) {
            if (context->output_fd == fileno(context->output)) {
                context->output_fd = -1;
            }
            if (context->fds[1] == fileno(context->output)) {
                context->fds[1] = -1;
            }
            fclose(context->output);
        }
        context->output = NULL;
    }
    if (context->output_fd >= 0) {
        if (context->output_fd != fileno(stdout)) {
            if (context->fds[1] == context->output_fd) {
                context->fds[1] = -1;
            }
            close(context->output_fd);
        }
        context->output_fd = -1;
    }
}

static void close_error(android_logcat_context_internal* context) {
    // split error_from_output
    if (context->output == context->error) {
        context->error = NULL;
        context->error_fd = -1;
    }
    if (context->output && (context->error_fd == fileno(context->output))) {
        context->error_fd = -1;
    }
    if (context->error_fd == context->output_fd) {
        context->error_fd = -1;
    }
    // close error channel
    if (context->error) {
        if ((context->error != stderr) && (context->error != stdout)) {
            if (context->error_fd == fileno(context->error)) {
                context->error_fd = -1;
            }
            if (context->fds[1] == fileno(context->error)) {
                context->fds[1] = -1;
            }
            fclose(context->error);
        }
        context->error = NULL;
    }
    if (context->error_fd >= 0) {
        if ((context->error_fd != fileno(stdout)) &&
            (context->error_fd != fileno(stderr))) {
            if (context->fds[1] == context->error_fd) {
                context->fds[1] = -1;
            }
            close(context->error_fd);
        }
        context->error_fd = -1;
    }
}

static void rotateLogs(android_logcat_context_internal* context) {
    int err;

    // Can't rotate logs if we're not outputting to a file
    if (context->outputFileName == NULL) {
        return;
    }

    close_output(context);

    // Compute the maximum number of digits needed to count up to
    // maxRotatedLogs in decimal.  eg:
    // maxRotatedLogs == 30
    //   -> log10(30) == 1.477
    //   -> maxRotationCountDigits == 2
    int maxRotationCountDigits =
        (context->maxRotatedLogs > 0)
            ? (int)(floor(log10(context->maxRotatedLogs) + 1))
            : 0;

    for (int i = context->maxRotatedLogs; i > 0; i--) {
        std::string file1 = android::base::StringPrintf(
            "%s.%.*d", context->outputFileName, maxRotationCountDigits, i);

        std::string file0;
        if (i - 1 == 0) {
            file0 = android::base::StringPrintf("%s", context->outputFileName);
        } else {
            file0 =
                android::base::StringPrintf("%s.%.*d", context->outputFileName,
                                            maxRotationCountDigits, i - 1);
        }

        if ((file0.length() == 0) || (file1.length() == 0)) {
            perror("while rotating log files");
            break;
        }

        err = rename(file0.c_str(), file1.c_str());

        if (err < 0 && errno != ENOENT) {
            perror("while rotating log files");
        }
    }

    context->output_fd = openLogFile(context->outputFileName);

    if (context->output_fd < 0) {
        logcat_panic(context, HELP_FALSE, "couldn't open output file");
        return;
    }
    context->output = fdopen(context->output_fd, "web");
    if (context->output == NULL) {
        logcat_panic(context, HELP_FALSE, "couldn't fdopen output file");
        return;
    }
    if (context->stderr_stdout) {
        close_error(context);
        context->error = context->output;
        context->error_fd = context->output_fd;
    }

    context->outByteCount = 0;
}

void printBinary(android_logcat_context_internal* context, struct log_msg* buf) {
    size_t size = buf->len();

    TEMP_FAILURE_RETRY(write(context->output_fd, buf, size));
}

static bool regexOk(android_logcat_context_internal* context,
                    const AndroidLogEntry& entry) {
    if (!context->regex) {
        return true;
    }

    std::string messageString(entry.message, entry.messageLen);

    return context->regex->PartialMatch(messageString);
}

static void processBuffer(android_logcat_context_internal* context,
                          log_device_t* dev, struct log_msg* buf) {
    int bytesWritten = 0;
    int err;
    AndroidLogEntry entry;
    char binaryMsgBuf[1024];

    if (dev->binary) {
        if (!context->eventTagMap && !context->hasOpenedEventTagMap) {
            context->eventTagMap = android_openEventTagMap(NULL);
            context->hasOpenedEventTagMap = true;
        }
        err = android_log_processBinaryLogBuffer(
            &buf->entry_v1, &entry, context->eventTagMap, binaryMsgBuf,
            sizeof(binaryMsgBuf));
        // printf(">>> pri=%d len=%d msg='%s'\n",
        //    entry.priority, entry.messageLen, entry.message);
    } else {
        err = android_log_processLogBuffer(&buf->entry_v1, &entry);
    }
    if ((err < 0) && !context->debug) {
        return;
    }

    if (android_log_shouldPrintLine(
            context->logformat, std::string(entry.tag, entry.tagLen).c_str(),
            entry.priority)) {
        bool match = regexOk(context, entry);

        context->printCount += match;
        if (match || context->printItAnyways) {
            bytesWritten = android_log_printLogLine(context->logformat,
                                                    context->output_fd, &entry);

            if (bytesWritten < 0) {
                logcat_panic(context, HELP_FALSE, "output error");
                return;
            }
        }
    }

    context->outByteCount += bytesWritten;

    if (context->logRotateSizeKBytes > 0 &&
        (context->outByteCount / 1024) >= context->logRotateSizeKBytes) {
        rotateLogs(context);
    }
}

static void maybePrintStart(android_logcat_context_internal* context,
                            log_device_t* dev, bool printDividers) {
    if (!dev->printed || printDividers) {
        if (context->devCount > 1 && !context->printBinary) {
            char buf[1024];
            snprintf(buf, sizeof(buf), "--------- %s %s\n",
                     dev->printed ? "switch to" : "beginning of", dev->device);
            if (write(context->output_fd, buf, strlen(buf)) < 0) {
                logcat_panic(context, HELP_FALSE, "output error");
                return;
            }
        }
        dev->printed = true;
    }
}

static void setupOutputAndSchedulingPolicy(
    android_logcat_context_internal* context, bool blocking) {
    if (context->outputFileName == NULL) return;

    if (blocking) {
        // Lower priority and set to batch scheduling if we are saving
        // the logs into files and taking continuous content.
        if ((set_sched_policy(0, SP_BACKGROUND) < 0) && context->error) {
            fprintf(context->error,
                    "failed to set background scheduling policy\n");
        }

        struct sched_param param;
        memset(&param, 0, sizeof(param));
        if (sched_setscheduler((pid_t)0, SCHED_BATCH, &param) < 0) {
            fprintf(stderr, "failed to set to batch scheduler\n");
        }

        if ((setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) &&
            context->error) {
            fprintf(context->error, "failed set to priority\n");
        }
    }

    close_output(context);

    context->output_fd = openLogFile(context->outputFileName);

    if (context->output_fd < 0) {
        logcat_panic(context, HELP_FALSE, "couldn't open output file");
        return;
    }

    struct stat statbuf;
    if (fstat(context->output_fd, &statbuf) == -1) {
        close_output(context);
        logcat_panic(context, HELP_FALSE, "couldn't get output file stat\n");
        return;
    }

    if ((size_t)statbuf.st_size > SIZE_MAX || statbuf.st_size < 0) {
        close_output(context);
        logcat_panic(context, HELP_FALSE, "invalid output file stat\n");
        return;
    }

    context->output = fdopen(context->output_fd, "web");

    context->outByteCount = statbuf.st_size;
}

// clang-format off
static void show_help(android_logcat_context_internal* context) {
    if (!context->error) return;

    const char* cmd = strrchr(context->argv[0], '/');
    cmd = cmd ? cmd + 1 : context->argv[0];

    fprintf(context->error, "Usage: %s [options] [filterspecs]\n", cmd);

    fprintf(context->error, "options include:\n"
                    "  -s              Set default filter to silent. Equivalent to filterspec '*:S'\n"
                    "  -f <file>, --file=<file>               Log to file. Default is stdout\n"
                    "  -r <kbytes>, --rotate-kbytes=<kbytes>\n"
                    "                  Rotate log every kbytes. Requires -f option\n"
                    "  -n <count>, --rotate-count=<count>\n"
                    "                  Sets max number of rotated logs to <count>, default 4\n"
                    "  --id=<id>       If the signature id for logging to file changes, then clear\n"
                    "                  the fileset and continue\n"
                    "  -v <format>, --format=<format>\n"
                    "                  Sets log print format verb and adverbs, where <format> is:\n"
                    "                    brief help long process raw tag thread threadtime time\n"
                    "                  and individually flagged modifying adverbs can be added:\n"
                    "                    color descriptive epoch monotonic printable uid\n"
                    "                    usec UTC year zone\n"
                    // private and undocumented nsec, no signal, too much noise
                    // useful for -T or -t <timestamp> accurate testing though.
                    "  -D, --dividers  Print dividers between each log buffer\n"
                    "  -c, --clear     Clear (flush) the entire log and exit\n"
                    "                  if Log to File specified, clear fileset instead\n"
                    "  -d              Dump the log and then exit (don't block)\n"
                    "  -e <expr>, --regex=<expr>\n"
                    "                  Only print lines where the log message matches <expr>\n"
                    "                  where <expr> is a regular expression\n"
                    // Leave --head undocumented as alias for -m
                    "  -m <count>, --max-count=<count>\n"
                    "                  Quit after printing <count> lines. This is meant to be\n"
                    "                  paired with --regex, but will work on its own.\n"
                    "  --print         Paired with --regex and --max-count to let content bypass\n"
                    "                  regex filter but still stop at number of matches.\n"
                    // Leave --tail undocumented as alias for -t
                    "  -t <count>      Print only the most recent <count> lines (implies -d)\n"
                    "  -t '<time>'     Print most recent lines since specified time (implies -d)\n"
                    "  -T <count>      Print only the most recent <count> lines (does not imply -d)\n"
                    "  -T '<time>'     Print most recent lines since specified time (not imply -d)\n"
                    "                  count is pure numerical, time is 'MM-DD hh:mm:ss.mmm...'\n"
                    "                  'YYYY-MM-DD hh:mm:ss.mmm...' or 'sssss.mmm...' format\n"
                    "  -g, --buffer-size                      Get the size of the ring buffer.\n"
                    "  -G <size>, --buffer-size=<size>\n"
                    "                  Set size of log ring buffer, may suffix with K or M.\n"
                    "  -L, --last      Dump logs from prior to last reboot\n"
                    // Leave security (Device Owner only installations) and
                    // kernel (userdebug and eng) buffers undocumented.
                    "  -b <buffer>, --buffer=<buffer>         Request alternate ring buffer, 'main',\n"
                    "                  'system', 'radio', 'events', 'crash', 'default' or 'all'.\n"
                    "                  Multiple -b parameters or comma separated list of buffers are\n"
                    "                  allowed. Buffers interleaved. Default -b main,system,crash.\n"
                    "  -B, --binary    Output the log in binary.\n"
                    "  -S, --statistics                       Output statistics.\n"
                    "  -p, --prune     Print prune white and ~black list. Service is specified as\n"
                    "                  UID, UID/PID or /PID. Weighed for quicker pruning if prefix\n"
                    "                  with ~, otherwise weighed for longevity if unadorned. All\n"
                    "                  other pruning activity is oldest first. Special case ~!\n"
                    "                  represents an automatic quicker pruning for the noisiest\n"
                    "                  UID as determined by the current statistics.\n"
                    "  -P '<list> ...', --prune='<list> ...'\n"
                    "                  Set prune white and ~black list, using same format as\n"
                    "                  listed above. Must be quoted.\n"
                    "  --pid=<pid>     Only prints logs from the given pid.\n"
                    // Check ANDROID_LOG_WRAP_DEFAULT_TIMEOUT value for match to 2 hours
                    "  --wrap          Sleep for 2 hours or when buffer about to wrap whichever\n"
                    "                  comes first. Improves efficiency of polling by providing\n"
                    "                  an about-to-wrap wakeup.\n");

    fprintf(context->error, "\nfilterspecs are a series of \n"
                   "  <tag>[:priority]\n\n"
                   "where <tag> is a log component tag (or * for all) and priority is:\n"
                   "  V    Verbose (default for <tag>)\n"
                   "  D    Debug (default for '*')\n"
                   "  I    Info\n"
                   "  W    Warn\n"
                   "  E    Error\n"
                   "  F    Fatal\n"
                   "  S    Silent (suppress all output)\n"
                   "\n'*' by itself means '*:D' and <tag> by itself means <tag>:V.\n"
                   "If no '*' filterspec or -s on command line, all filter defaults to '*:V'.\n"
                   "eg: '*:S <tag>' prints only <tag>, '<tag>:S' suppresses all <tag> log messages.\n"
                   "\nIf not specified on the command line, filterspec is set from ANDROID_LOG_TAGS.\n"
                   "\nIf not specified with -v on command line, format is set from ANDROID_PRINTF_LOG\n"
                   "or defaults to \"threadtime\"\n\n");
}

static void show_format_help(android_logcat_context_internal* context) {
    if (!context->error) return;
    fprintf(context->error,
        "-v <format>, --format=<format> options:\n"
        "  Sets log print format verb and adverbs, where <format> is:\n"
        "    brief long process raw tag thread threadtime time\n"
        "  and individually flagged modifying adverbs can be added:\n"
        "    color descriptive epoch monotonic printable uid usec UTC year zone\n"
        "\nSingle format verbs:\n"
        "  brief      — Display priority/tag and PID of the process issuing the message.\n"
        "  long       — Display all metadata fields, separate messages with blank lines.\n"
        "  process    — Display PID only.\n"
        "  raw        — Display the raw log message, with no other metadata fields.\n"
        "  tag        — Display the priority/tag only.\n"
        "  threadtime — Display the date, invocation time, priority, tag, and the PID\n"
        "               and TID of the thread issuing the message. (the default format).\n"
        "  time       — Display the date, invocation time, priority/tag, and PID of the\n"
        "             process issuing the message.\n"
        "\nAdverb modifiers can be used in combination:\n"
        "  color       — Display in highlighted color to match priority. i.e. \x1B[38;5;231mVERBOSE\n"
        "                \x1B[38;5;75mDEBUG \x1B[38;5;40mINFO \x1B[38;5;166mWARNING \x1B[38;5;196mERROR FATAL\x1B[0m\n"
        "  descriptive — events logs only, descriptions from event-log-tags database.\n"
        "  epoch       — Display time as seconds since Jan 1 1970.\n"
        "  monotonic   — Display time as cpu seconds since last boot.\n"
        "  printable   — Ensure that any binary logging content is escaped.\n"
        "  uid         — If permitted, display the UID or Android ID of logged process.\n"
        "  usec        — Display time down the microsecond precision.\n"
        "  UTC         — Display time as UTC.\n"
        "  year        — Add the year to the displayed time.\n"
        "  zone        — Add the local timezone to the displayed time.\n"
        "  \"<zone>\"    — Print using this public named timezone (experimental).\n\n"
    );
}
// clang-format on

static int setLogFormat(android_logcat_context_internal* context,
                        const char* formatString) {
    AndroidLogPrintFormat format;

    format = android_log_formatFromString(formatString);

    if (format == FORMAT_OFF) {
        // FORMAT_OFF means invalid string
        return -1;
    }

    return android_log_setPrintFormat(context->logformat, format);
}

static const char multipliers[][2] = { { "" }, { "K" }, { "M" }, { "G" } };

static unsigned long value_of_size(unsigned long value) {
    for (unsigned i = 0;
         (i < sizeof(multipliers) / sizeof(multipliers[0])) && (value >= 1024);
         value /= 1024, ++i)
        ;
    return value;
}

static const char* multiplier_of_size(unsigned long value) {
    unsigned i;
    for (i = 0;
         (i < sizeof(multipliers) / sizeof(multipliers[0])) && (value >= 1024);
         value /= 1024, ++i)
        ;
    return multipliers[i];
}

// String to unsigned int, returns -1 if it fails
static bool getSizeTArg(const char* ptr, size_t* val, size_t min = 0,
                        size_t max = SIZE_MAX) {
    if (!ptr) {
        return false;
    }

    char* endp;
    errno = 0;
    size_t ret = (size_t)strtoll(ptr, &endp, 0);

    if (endp[0] || errno) {
        return false;
    }

    if ((ret > max) || (ret < min)) {
        return false;
    }

    *val = ret;
    return true;
}

static void logcat_panic(android_logcat_context_internal* context,
                         enum helpType showHelp, const char* fmt, ...) {
    context->retval = EXIT_FAILURE;
    if (!context->error) {
        context->stop = true;
        return;
    }

    va_list args;
    va_start(args, fmt);
    vfprintf(context->error, fmt, args);
    va_end(args);

    switch (showHelp) {
        case HELP_TRUE:
            show_help(context);
            break;
        case HELP_FORMAT:
            show_format_help(context);
            break;
        case HELP_FALSE:
        default:
            break;
    }

    context->stop = true;
}

static char* parseTime(log_time& t, const char* cp) {
    char* ep = t.strptime(cp, "%m-%d %H:%M:%S.%q");
    if (ep) {
        return ep;
    }
    ep = t.strptime(cp, "%Y-%m-%d %H:%M:%S.%q");
    if (ep) {
        return ep;
    }
    return t.strptime(cp, "%s.%q");
}

// Find last logged line in <outputFileName>, or <outputFileName>.1
static log_time lastLogTime(char* outputFileName) {
    log_time retval(log_time::EPOCH);
    if (!outputFileName) {
        return retval;
    }

    std::string directory;
    char* file = strrchr(outputFileName, '/');
    if (!file) {
        directory = ".";
        file = outputFileName;
    } else {
        *file = '\0';
        directory = outputFileName;
        *file = '/';
        ++file;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(directory.c_str()),
                                            closedir);
    if (!dir.get()) {
        return retval;
    }

    log_time now(android_log_clockid());

    size_t len = strlen(file);
    log_time modulo(0, NS_PER_SEC);
    struct dirent* dp;

    while ((dp = readdir(dir.get())) != NULL) {
        if ((dp->d_type != DT_REG) || (strncmp(dp->d_name, file, len) != 0) ||
            (dp->d_name[len] && ((dp->d_name[len] != '.') ||
                                 (strtoll(dp->d_name + 1, NULL, 10) != 1)))) {
            continue;
        }

        std::string file_name = directory;
        file_name += "/";
        file_name += dp->d_name;
        std::string file;
        if (!android::base::ReadFileToString(file_name, &file)) {
            continue;
        }

        bool found = false;
        for (const auto& line : android::base::Split(file, "\n")) {
            log_time t(log_time::EPOCH);
            char* ep = parseTime(t, line.c_str());
            if (!ep || (*ep != ' ')) {
                continue;
            }
            // determine the time precision of the logs (eg: msec or usec)
            for (unsigned long mod = 1UL; mod < modulo.tv_nsec; mod *= 10) {
                if (t.tv_nsec % (mod * 10)) {
                    modulo.tv_nsec = mod;
                    break;
                }
            }
            // We filter any times later than current as we may not have the
            // year stored with each log entry. Also, since it is possible for
            // entries to be recorded out of order (very rare) we select the
            // maximum we find just in case.
            if ((t < now) && (t > retval)) {
                retval = t;
                found = true;
            }
        }
        // We count on the basename file to be the definitive end, so stop here.
        if (!dp->d_name[len] && found) {
            break;
        }
    }
    if (retval == log_time::EPOCH) {
        return retval;
    }
    // tail_time prints matching or higher, round up by the modulo to prevent
    // a replay of the last entry we have just checked.
    retval += modulo;
    return retval;
}

const char* getenv(android_logcat_context_internal* context, const char* name) {
    if (!context->envp || !name || !*name) return NULL;

    for (size_t len = strlen(name), i = 0; context->envp[i]; ++i) {
        if (strncmp(context->envp[i], name, len)) continue;
        if (context->envp[i][len] == '=') return &context->envp[i][len + 1];
    }
    return NULL;
}

}  // namespace android

void reportErrorName(const char** current, const char* name,
                     bool blockSecurity) {
    if (*current) {
        return;
    }
    if (blockSecurity && (android_name_to_log_id(name) == LOG_ID_SECURITY)) {
        return;
    }
    *current = name;
}

static int __logcat(android_logcat_context_internal* context) {
    using namespace android;
    int err;
    int hasSetLogFormat = 0;
    bool clearLog = false;
    bool allSelected = false;
    bool getLogSize = false;
    bool getPruneList = false;
    bool printStatistics = false;
    bool printDividers = false;
    unsigned long setLogSize = 0;
    char* setPruneList = NULL;
    char* setId = NULL;
    int mode = ANDROID_LOG_RDONLY;
    std::string forceFilters;
    log_device_t* devices = NULL;
    log_device_t* dev;
    struct logger_list* logger_list;
    size_t tail_lines = 0;
    log_time tail_time(log_time::EPOCH);
    size_t pid = 0;
    bool got_t = false;

    // object instantiations before goto's can happen
    log_device_t unexpected("unexpected", false);
    const char* openDeviceFail = NULL;
    const char* clearFail = NULL;
    const char* setSizeFail = NULL;
    const char* getSizeFail = NULL;
    int argc = context->argc;
    char* const* argv = context->argv;

    context->output = stdout;
    context->error = stderr;

    for (int i = 0; i < argc; ++i) {
        // Simulate shell stderr redirect parsing
        if ((argv[i][0] != '2') || (argv[i][1] != '>')) continue;

        // Append to file not implemented, just open file
        size_t skip = (argv[i][2] == '>') + 2;
        if (!strcmp(&argv[i][skip], "/dev/null")) {
            context->stderr_null = true;
        } else if (!strcmp(&argv[i][skip], "&1")) {
            context->stderr_stdout = true;
        } else {
            // stderr file redirections are not supported
            fprintf(context->stderr_stdout ? stdout : stderr,
                    "stderr redirection to file %s unsupported, skipping\n",
                    &argv[i][skip]);
        }
        // Only the first one
        break;
    }

    const char* filename = NULL;
    for (int i = 0; i < argc; ++i) {
        // Simulate shell stdout redirect parsing
        if (argv[i][0] != '>') continue;

        // Append to file not implemented, just open file
        filename = &argv[i][(argv[i][1] == '>') + 1];
        // Only the first one
        break;
    }

    // Deal with setting up file descriptors and FILE pointers
    if (context->error_fd >= 0) { // Is an error file descriptor supplied?
        if (context->error_fd == context->output_fd) {
            context->stderr_stdout = true;
        } else if (context->stderr_null) { // redirection told us to close it
            close(context->error_fd);
            context->error_fd = -1;
        } else { // All Ok, convert error to a FILE pointer
            context->error = fdopen(context->error_fd, "web");
            if (!context->error) {
                context->retval = -errno;
                fprintf(context->stderr_stdout ? stdout : stderr,
                        "Failed to fdopen(error_fd=%d) %s\n", context->error_fd,
                        strerror(errno));
                goto exit;
            }
        }
    }
    if (context->output_fd >= 0) { // Is an output file descriptor supplied?
        if (filename) { // redirect to file, close the supplied file descriptor.
            close(context->output_fd);
            context->output_fd = -1;
        } else { // All Ok, convert output to a FILE pointer
            context->output = fdopen(context->output_fd, "web");
            if (!context->output) {
                context->retval = -errno;
                fprintf(context->stderr_stdout ? stdout : context->error,
                        "Failed to fdopen(output_fd=%d) %s\n",
                        context->output_fd, strerror(errno));
                goto exit;
            }
        }
    }
    if (filename) { // We supplied an output file redirected in command line
        context->output = fopen(filename, "web");
    }
    // Deal with 2>&1
    if (context->stderr_stdout) context->error = context->output;
    // Deal with 2>/dev/null
    if (context->stderr_null) {
        context->error_fd = -1;
        context->error = NULL;
    }
    // Only happens if output=stdout or output=filename
    if ((context->output_fd < 0) && context->output) {
        context->output_fd = fileno(context->output);
    }
    // Only happens if error=stdout || error=stderr
    if ((context->error_fd < 0) && context->error) {
        context->error_fd = fileno(context->error);
    }

    context->logformat = android_log_format_new();

    if (argc == 2 && 0 == strcmp(argv[1], "--help")) {
        show_help(context);
        context->retval = EXIT_SUCCESS;
        goto exit;
    }

    // danger: getopt is _not_ reentrant
    optind = 1;
    for (;;) {
        int ret;

        int option_index = 0;
        // list of long-argument only strings for later comparison
        static const char pid_str[] = "pid";
        static const char debug_str[] = "debug";
        static const char id_str[] = "id";
        static const char wrap_str[] = "wrap";
        static const char print_str[] = "print";
        // clang-format off
        static const struct option long_options[] = {
          { "binary",        no_argument,       NULL,   'B' },
          { "buffer",        required_argument, NULL,   'b' },
          { "buffer-size",   optional_argument, NULL,   'g' },
          { "clear",         no_argument,       NULL,   'c' },
          { debug_str,       no_argument,       NULL,   0 },
          { "dividers",      no_argument,       NULL,   'D' },
          { "file",          required_argument, NULL,   'f' },
          { "format",        required_argument, NULL,   'v' },
          // hidden and undocumented reserved alias for --regex
          { "grep",          required_argument, NULL,   'e' },
          // hidden and undocumented reserved alias for --max-count
          { "head",          required_argument, NULL,   'm' },
          { id_str,          required_argument, NULL,   0 },
          { "last",          no_argument,       NULL,   'L' },
          { "max-count",     required_argument, NULL,   'm' },
          { pid_str,         required_argument, NULL,   0 },
          { print_str,       no_argument,       NULL,   0 },
          { "prune",         optional_argument, NULL,   'p' },
          { "regex",         required_argument, NULL,   'e' },
          { "rotate-count",  required_argument, NULL,   'n' },
          { "rotate-kbytes", required_argument, NULL,   'r' },
          { "statistics",    no_argument,       NULL,   'S' },
          // hidden and undocumented reserved alias for -t
          { "tail",          required_argument, NULL,   't' },
          // support, but ignore and do not document, the optional argument
          { wrap_str,        optional_argument, NULL,   0 },
          { NULL,            0,                 NULL,   0 }
        };
        // clang-format on

        ret = getopt_long(argc, argv,
                          ":cdDLt:T:gG:sQf:r:n:v:b:BSpP:m:e:", long_options,
                          &option_index);

        if (ret < 0) {
            break;
        }

        switch (ret) {
            case 0:
                // only long options
                if (long_options[option_index].name == pid_str) {
                    // ToDo: determine runtime PID_MAX?
                    if (!getSizeTArg(optarg, &pid, 1)) {
                        logcat_panic(context, HELP_TRUE, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                        goto exit;
                    }
                    break;
                }
                if (long_options[option_index].name == wrap_str) {
                    mode |= ANDROID_LOG_WRAP | ANDROID_LOG_RDONLY |
                            ANDROID_LOG_NONBLOCK;
                    // ToDo: implement API that supports setting a wrap timeout
                    size_t dummy = ANDROID_LOG_WRAP_DEFAULT_TIMEOUT;
                    if (optarg && !getSizeTArg(optarg, &dummy, 1)) {
                        logcat_panic(context, HELP_TRUE, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                        goto exit;
                    }
                    if ((dummy != ANDROID_LOG_WRAP_DEFAULT_TIMEOUT) &&
                        context->error) {
                        fprintf(context->error,
                                "WARNING: %s %u seconds, ignoring %zu\n",
                                long_options[option_index].name,
                                ANDROID_LOG_WRAP_DEFAULT_TIMEOUT, dummy);
                    }
                    break;
                }
                if (long_options[option_index].name == print_str) {
                    context->printItAnyways = true;
                    break;
                }
                if (long_options[option_index].name == debug_str) {
                    context->debug = true;
                    break;
                }
                if (long_options[option_index].name == id_str) {
                    setId = optarg && optarg[0] ? optarg : NULL;
                    break;
                }
                break;

            case 's':
                // default to all silent
                android_log_addFilterRule(context->logformat, "*:s");
                break;

            case 'c':
                clearLog = true;
                mode |= ANDROID_LOG_WRONLY;
                break;

            case 'L':
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_PSTORE |
                        ANDROID_LOG_NONBLOCK;
                break;

            case 'd':
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
                break;

            case 't':
                got_t = true;
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
            // FALLTHRU
            case 'T':
                if (strspn(optarg, "0123456789") != strlen(optarg)) {
                    char* cp = parseTime(tail_time, optarg);
                    if (!cp) {
                        logcat_panic(context, HELP_FALSE,
                                     "-%c \"%s\" not in time format\n", ret,
                                     optarg);
                        goto exit;
                    }
                    if (*cp) {
                        char c = *cp;
                        *cp = '\0';
                        if (context->error) {
                            fprintf(
                                context->error,
                                "WARNING: -%c \"%s\"\"%c%s\" time truncated\n",
                                ret, optarg, c, cp + 1);
                        }
                        *cp = c;
                    }
                } else {
                    if (!getSizeTArg(optarg, &tail_lines, 1)) {
                        if (context->error) {
                            fprintf(context->error,
                                    "WARNING: -%c %s invalid, setting to 1\n",
                                    ret, optarg);
                        }
                        tail_lines = 1;
                    }
                }
                break;

            case 'D':
                printDividers = true;
                break;

            case 'e':
                context->regex = new pcrecpp::RE(optarg);
                break;

            case 'm': {
                char* end = NULL;
                if (!getSizeTArg(optarg, &context->maxCount)) {
                    logcat_panic(context, HELP_FALSE,
                                 "-%c \"%s\" isn't an "
                                 "integer greater than zero\n",
                                 ret, optarg);
                    goto exit;
                }
            } break;

            case 'g':
                if (!optarg) {
                    getLogSize = true;
                    break;
                }
            // FALLTHRU

            case 'G': {
                char* cp;
                if (strtoll(optarg, &cp, 0) > 0) {
                    setLogSize = strtoll(optarg, &cp, 0);
                } else {
                    setLogSize = 0;
                }

                switch (*cp) {
                    case 'g':
                    case 'G':
                        setLogSize *= 1024;
                    // FALLTHRU
                    case 'm':
                    case 'M':
                        setLogSize *= 1024;
                    // FALLTHRU
                    case 'k':
                    case 'K':
                        setLogSize *= 1024;
                    // FALLTHRU
                    case '\0':
                        break;

                    default:
                        setLogSize = 0;
                }

                if (!setLogSize) {
                    logcat_panic(context, HELP_FALSE,
                                 "ERROR: -G <num><multiplier>\n");
                    goto exit;
                }
            } break;

            case 'p':
                if (!optarg) {
                    getPruneList = true;
                    break;
                }
            // FALLTHRU

            case 'P':
                setPruneList = optarg;
                break;

            case 'b': {
                unsigned idMask = 0;
                while ((optarg = strtok(optarg, ",:; \t\n\r\f")) != NULL) {
                    if (strcmp(optarg, "default") == 0) {
                        idMask |= (1 << LOG_ID_MAIN) | (1 << LOG_ID_SYSTEM) |
                                  (1 << LOG_ID_CRASH);
                    } else if (strcmp(optarg, "all") == 0) {
                        allSelected = true;
                        idMask = (unsigned)-1;
                    } else {
                        log_id_t log_id = android_name_to_log_id(optarg);
                        const char* name = android_log_id_to_name(log_id);

                        if (strcmp(name, optarg) != 0) {
                            logcat_panic(context, HELP_TRUE,
                                         "unknown buffer %s\n", optarg);
                            goto exit;
                        }
                        if (log_id == LOG_ID_SECURITY) allSelected = false;
                        idMask |= (1 << log_id);
                    }
                    optarg = NULL;
                }

                for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
                    const char* name = android_log_id_to_name((log_id_t)i);
                    log_id_t log_id = android_name_to_log_id(name);

                    if (log_id != (log_id_t)i) {
                        continue;
                    }
                    if ((idMask & (1 << i)) == 0) {
                        continue;
                    }

                    bool found = false;
                    for (dev = devices; dev; dev = dev->next) {
                        if (!strcmp(name, dev->device)) {
                            found = true;
                            break;
                        }
                        if (!dev->next) {
                            break;
                        }
                    }
                    if (found) {
                        continue;
                    }

                    bool binary =
                        !strcmp(name, "events") || !strcmp(name, "security");
                    log_device_t* d = new log_device_t(name, binary);

                    if (dev) {
                        dev->next = d;
                        dev = d;
                    } else {
                        devices = dev = d;
                    }
                    context->devCount++;
                }
            } break;

            case 'B':
                context->printBinary = 1;
                break;

            case 'f':
                if ((tail_time == log_time::EPOCH) && (tail_lines == 0)) {
                    tail_time = lastLogTime(optarg);
                }
                // redirect output to a file
                context->outputFileName = optarg;
                break;

            case 'r':
                if (!getSizeTArg(optarg, &context->logRotateSizeKBytes, 1)) {
                    logcat_panic(context, HELP_TRUE,
                                 "Invalid parameter \"%s\" to -r\n", optarg);
                    goto exit;
                }
                break;

            case 'n':
                if (!getSizeTArg(optarg, &context->maxRotatedLogs, 1)) {
                    logcat_panic(context, HELP_TRUE,
                                 "Invalid parameter \"%s\" to -n\n", optarg);
                    goto exit;
                }
                break;

            case 'v':
                if (!strcmp(optarg, "help") || !strcmp(optarg, "--help")) {
                    show_format_help(context);
                    context->retval = EXIT_SUCCESS;
                    goto exit;
                }
                err = setLogFormat(context, optarg);
                if (err < 0) {
                    logcat_panic(context, HELP_FORMAT,
                                 "Invalid parameter \"%s\" to -v\n", optarg);
                    goto exit;
                }
                hasSetLogFormat |= err;
                break;

            case 'Q':
#define KERNEL_OPTION "androidboot.logcat="
#define CONSOLE_OPTION "androidboot.console="
                // This is a *hidden* option used to start a version of logcat
                // in an emulated device only.  It basically looks for
                // androidboot.logcat= on the kernel command line.  If
                // something is found, it extracts a log filter and uses it to
                // run the program.  If nothing is found, the program should
                // quit immediately.
                {
                    std::string cmdline;
                    android::base::ReadFileToString("/proc/cmdline", &cmdline);

                    const char* logcat = strstr(cmdline.c_str(), KERNEL_OPTION);
                    // if nothing found or invalid filters, exit quietly
                    if (!logcat) {
                        context->retval = EXIT_SUCCESS;
                        goto exit;
                    }

                    const char* p = logcat + strlen(KERNEL_OPTION);
                    const char* q = strpbrk(p, " \t\n\r");
                    if (!q) q = p + strlen(p);
                    forceFilters = std::string(p, q);

                    // redirect our output to the emulator console
                    const char* console =
                        strstr(cmdline.c_str(), CONSOLE_OPTION);
                    if (!console) break;

                    p = console + strlen(CONSOLE_OPTION);
                    q = strpbrk(p, " \t\n\r");
                    int len = q ? q - p : strlen(p);
                    std::string devname = "/dev/" + std::string(p, len);
                    cmdline.erase();

                    if (context->error) {
                        fprintf(context->error, "logcat using %s\n",
                                devname.c_str());
                    }

                    FILE* fp = fopen(devname.c_str(), "web");
                    devname.erase();
                    if (!fp) break;

                    // close output and error channels, replace with console
                    android::close_output(context);
                    android::close_error(context);
                    context->stderr_stdout = true;
                    context->output = fp;
                    context->output_fd = fileno(fp);
                    if (context->stderr_null) break;
                    context->stderr_stdout = true;
                    context->error = fp;
                    context->error_fd = fileno(fp);
                }
                break;

            case 'S':
                printStatistics = true;
                break;

            case ':':
                logcat_panic(context, HELP_TRUE,
                             "Option -%c needs an argument\n", optopt);
                goto exit;

            default:
                logcat_panic(context, HELP_TRUE, "Unrecognized Option %c\n",
                             optopt);
                goto exit;
        }
    }

    if (context->maxCount && got_t) {
        logcat_panic(context, HELP_TRUE,
                     "Cannot use -m (--max-count) and -t together\n");
        goto exit;
    }
    if (context->printItAnyways && (!context->regex || !context->maxCount)) {
        // One day it would be nice if --print -v color and --regex <expr>
        // could play with each other and show regex highlighted content.
        // clang-format off
        if (context->error) {
            fprintf(context->error, "WARNING: "
                            "--print ignored, to be used in combination with\n"
                                "         "
                            "--regex <expr> and --max-count <N>\n");
        }
        context->printItAnyways = false;
    }

    if (!devices) {
        dev = devices = new log_device_t("main", false);
        context->devCount = 1;
        if (android_name_to_log_id("system") == LOG_ID_SYSTEM) {
            dev = dev->next = new log_device_t("system", false);
            context->devCount++;
        }
        if (android_name_to_log_id("crash") == LOG_ID_CRASH) {
            dev = dev->next = new log_device_t("crash", false);
            context->devCount++;
        }
    }

    if (context->logRotateSizeKBytes != 0 && context->outputFileName == NULL) {
        logcat_panic(context, HELP_TRUE, "-r requires -f as well\n");
        goto exit;
    }

    if (setId != NULL) {
        if (context->outputFileName == NULL) {
            logcat_panic(context, HELP_TRUE,
                         "--id='%s' requires -f as well\n", setId);
            goto exit;
        }

        std::string file_name = android::base::StringPrintf(
                                        "%s.id", context->outputFileName);
        std::string file;
        bool file_ok = android::base::ReadFileToString(file_name, &file);
        android::base::WriteStringToFile(setId, file_name, S_IRUSR | S_IWUSR,
                                         getuid(), getgid());
        if (!file_ok || (file.compare(setId) == 0)) {
            setId = NULL;
        }
    }

    if (hasSetLogFormat == 0) {
        const char* logFormat = android::getenv(context, "ANDROID_PRINTF_LOG");

        if (logFormat != NULL) {
            err = setLogFormat(context, logFormat);
            if ((err < 0) && context->error) {
                fprintf(context->error,
                        "invalid format in ANDROID_PRINTF_LOG '%s'\n",
                        logFormat);
            }
        } else {
            setLogFormat(context, "threadtime");
        }
    }

    if (forceFilters.size()) {
        err = android_log_addFilterString(context->logformat,
                                          forceFilters.c_str());
        if (err < 0) {
            logcat_panic(context, HELP_FALSE,
                         "Invalid filter expression in logcat args\n");
            goto exit;
        }
    } else if (argc == optind) {
        // Add from environment variable
        const char* env_tags_orig = android::getenv(context, "ANDROID_LOG_TAGS");

        if (env_tags_orig != NULL) {
            err = android_log_addFilterString(context->logformat,
                                              env_tags_orig);

            if (err < 0) {
                logcat_panic(context, HELP_TRUE,
                            "Invalid filter expression in ANDROID_LOG_TAGS\n");
                goto exit;
            }
        }
    } else {
        // Add from commandline
        for (int i = optind ; i < argc ; i++) {
            // skip stderr redirections of _all_ kinds
            if ((argv[i][0] == '2') && (argv[i][1] == '>')) continue;
            // skip stdout redirections of _all_ kinds
            if (argv[i][0] == '>') continue;

            err = android_log_addFilterString(context->logformat, argv[i]);
            if (err < 0) {
                logcat_panic(context, HELP_TRUE,
                             "Invalid filter expression '%s'\n", argv[i]);
                goto exit;
            }
        }
    }

    dev = devices;
    if (tail_time != log_time::EPOCH) {
        logger_list = android_logger_list_alloc_time(mode, tail_time, pid);
    } else {
        logger_list = android_logger_list_alloc(mode, tail_lines, pid);
    }
    // We have three orthogonal actions below to clear, set log size and
    // get log size. All sharing the same iteration loop.
    while (dev) {
        dev->logger_list = logger_list;
        dev->logger = android_logger_open(logger_list,
                                          android_name_to_log_id(dev->device));
        if (!dev->logger) {
            reportErrorName(&openDeviceFail, dev->device, allSelected);
            dev = dev->next;
            continue;
        }

        if (clearLog || setId) {
            if (context->outputFileName) {
                int maxRotationCountDigits =
                    (context->maxRotatedLogs > 0) ?
                        (int)(floor(log10(context->maxRotatedLogs) + 1)) :
                        0;

                for (int i = context->maxRotatedLogs ; i >= 0 ; --i) {
                    std::string file;

                    if (i == 0) {
                        file = android::base::StringPrintf(
                            "%s", context->outputFileName);
                    } else {
                        file = android::base::StringPrintf("%s.%.*d",
                            context->outputFileName, maxRotationCountDigits, i);
                    }

                    if (file.length() == 0) {
                        perror("while clearing log files");
                        reportErrorName(&clearFail, dev->device, allSelected);
                        break;
                    }

                    err = unlink(file.c_str());

                    if (err < 0 && errno != ENOENT && clearFail == NULL) {
                        perror("while clearing log files");
                        reportErrorName(&clearFail, dev->device, allSelected);
                    }
                }
            } else if (android_logger_clear(dev->logger)) {
                reportErrorName(&clearFail, dev->device, allSelected);
            }
        }

        if (setLogSize) {
            if (android_logger_set_log_size(dev->logger, setLogSize)) {
                reportErrorName(&setSizeFail, dev->device, allSelected);
            }
        }

        if (getLogSize) {
            long size = android_logger_get_log_size(dev->logger);
            long readable = android_logger_get_log_readable_size(dev->logger);

            if ((size < 0) || (readable < 0)) {
                reportErrorName(&getSizeFail, dev->device, allSelected);
            } else {
                std::string str = android::base::StringPrintf(
                       "%s: ring buffer is %ld%sb (%ld%sb consumed),"
                         " max entry is %db, max payload is %db\n",
                       dev->device,
                       value_of_size(size), multiplier_of_size(size),
                       value_of_size(readable), multiplier_of_size(readable),
                       (int)LOGGER_ENTRY_MAX_LEN,
                       (int)LOGGER_ENTRY_MAX_PAYLOAD);
                TEMP_FAILURE_RETRY(write(context->output_fd,
                                         str.data(), str.length()));
            }
        }

        dev = dev->next;
    }

    context->retval = EXIT_SUCCESS;

    // report any errors in the above loop and exit
    if (openDeviceFail) {
        logcat_panic(context, HELP_FALSE,
                     "Unable to open log device '%s'\n", openDeviceFail);
        goto close;
    }
    if (clearFail) {
        logcat_panic(context, HELP_FALSE,
                     "failed to clear the '%s' log\n", clearFail);
        goto close;
    }
    if (setSizeFail) {
        logcat_panic(context, HELP_FALSE,
                     "failed to set the '%s' log size\n", setSizeFail);
        goto close;
    }
    if (getSizeFail) {
        logcat_panic(context, HELP_FALSE,
                     "failed to get the readable '%s' log size", getSizeFail);
        goto close;
    }

    if (setPruneList) {
        size_t len = strlen(setPruneList);
        // extra 32 bytes are needed by android_logger_set_prune_list
        size_t bLen = len + 32;
        char* buf = NULL;
        if (asprintf(&buf, "%-*s", (int)(bLen - 1), setPruneList) > 0) {
            buf[len] = '\0';
            if (android_logger_set_prune_list(logger_list, buf, bLen)) {
                logcat_panic(context, HELP_FALSE,
                             "failed to set the prune list");
            }
            free(buf);
        } else {
            logcat_panic(context, HELP_FALSE,
                         "failed to set the prune list (alloc)");
        }
        goto close;
    }

    if (printStatistics || getPruneList) {
        size_t len = 8192;
        char* buf;

        for (int retry = 32; (retry >= 0) && ((buf = new char[len]));
             delete[] buf, buf = NULL, --retry) {
            if (getPruneList) {
                android_logger_get_prune_list(logger_list, buf, len);
            } else {
                android_logger_get_statistics(logger_list, buf, len);
            }
            buf[len - 1] = '\0';
            if (atol(buf) < 3) {
                delete[] buf;
                buf = NULL;
                break;
            }
            size_t ret = atol(buf) + 1;
            if (ret <= len) {
                len = ret;
                break;
            }
            len = ret;
        }

        if (!buf) {
            logcat_panic(context, HELP_FALSE, "failed to read data");
            goto close;
        }

        // remove trailing FF
        char* cp = buf + len - 1;
        *cp = '\0';
        bool truncated = *--cp != '\f';
        if (!truncated) {
            *cp = '\0';
        }

        // squash out the byte count
        cp = buf;
        if (!truncated) {
            while (isdigit(*cp)) {
                ++cp;
            }
            if (*cp == '\n') {
                ++cp;
            }
        }

        len = strlen(cp);
        TEMP_FAILURE_RETRY(write(context->output_fd, cp, len));
        delete[] buf;
        goto close;
    }

    if (getLogSize || setLogSize || clearLog) {
        goto close;
    }

    setupOutputAndSchedulingPolicy(context, (mode & ANDROID_LOG_NONBLOCK) == 0);
    if (context->stop) goto close;

    // LOG_EVENT_INT(10, 12345);
    // LOG_EVENT_LONG(11, 0x1122334455667788LL);
    // LOG_EVENT_STRING(0, "whassup, doc?");

    dev = NULL;

    while (!context->stop &&
           (!context->maxCount || (context->printCount < context->maxCount))) {
        struct log_msg log_msg;
        int ret = android_logger_list_read(logger_list, &log_msg);
        if (ret == 0) {
            logcat_panic(context, HELP_FALSE, "read: unexpected EOF!\n");
            break;
        }

        if (ret < 0) {
            if (ret == -EAGAIN) {
                break;
            }

            if (ret == -EIO) {
                logcat_panic(context, HELP_FALSE, "read: unexpected EOF!\n");
                break;
            }
            if (ret == -EINVAL) {
                logcat_panic(context, HELP_FALSE, "read: unexpected length.\n");
                break;
            }
            logcat_panic(context, HELP_FALSE, "logcat read failure");
            break;
        }

        log_device_t* d;
        for (d = devices; d; d = d->next) {
            if (android_name_to_log_id(d->device) == log_msg.id()) {
                break;
            }
        }
        if (!d) {
            context->devCount = 2; // set to Multiple
            d = &unexpected;
            d->binary = log_msg.id() == LOG_ID_EVENTS;
        }

        if (dev != d) {
            dev = d;
            maybePrintStart(context, dev, printDividers);
            if (context->stop) break;
        }
        if (context->printBinary) {
            printBinary(context, &log_msg);
        } else {
            processBuffer(context, dev, &log_msg);
        }
    }

close:
    android_logger_list_free(logger_list);

exit:
    // close write end of pipe to help things along
    if (context->output_fd == context->fds[1]) {
        android::close_output(context);
    }
    if (context->error_fd == context->fds[1]) {
        android::close_error(context);
    }
    if (context->fds[1] >= 0) {
        // NB: should be closed by the above
        int save_errno = errno;
        close(context->fds[1]);
        errno = save_errno;
        context->fds[1] = -1;
    }
    context->thread_stopped = true;
    return context->retval;
}

// Can block
int android_logcat_run_command(android_logcat_context ctx,
                               int output, int error,
                               int argc, char* const* argv,
                               char* const* envp) {
    android_logcat_context_internal* context = ctx;

    context->output_fd = output;
    context->error_fd = error;
    context->argc = argc;
    context->argv = argv;
    context->envp = envp;
    context->stop = false;
    context->thread_stopped = false;
    return __logcat(context);
}

// starts a thread, opens a pipe, returns reading end.
int android_logcat_run_command_thread(android_logcat_context ctx,
                                      int argc, char* const* argv,
                                      char* const* envp) {
    android_logcat_context_internal* context = ctx;

    int save_errno = EBUSY;
    if ((context->fds[0] >= 0) || (context->fds[1] >= 0)) {
        goto exit;
    }

    if (pipe(context->fds) < 0) {
        save_errno = errno;
        goto exit;
    }

    pthread_attr_t attr;
    if (pthread_attr_init(&attr)) {
        save_errno = errno;
        goto close_exit;
    }

    struct sched_param param;
    memset(&param, 0, sizeof(param));
    pthread_attr_setschedparam(&attr, &param);
    pthread_attr_setschedpolicy(&attr, SCHED_BATCH);
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
        int save_errno = errno;
        goto pthread_attr_exit;
    }

    context->stop = false;
    context->thread_stopped = false;
    context->output_fd = context->fds[1];
    // save off arguments so they remain while thread is active.
    for (int i = 0; i < argc; ++i) {
        context->args.push_back(std::string(argv[i]));
    }
    // save off environment so they remain while thread is active.
    if (envp) for (size_t i = 0; envp[i]; ++i) {
        context->envs.push_back(std::string(envp[i]));
    }

    for (auto& str : context->args) {
        context->argv_hold.push_back(str.c_str());
    }
    context->argv_hold.push_back(NULL);
    for (auto& str : context->envs) {
        context->envp_hold.push_back(str.c_str());
    }
    context->envp_hold.push_back(NULL);

    context->argc = context->argv_hold.size() - 1;
    context->argv = (char* const*)&context->argv_hold[0];
    context->envp = (char* const*)&context->envp_hold[0];

#ifdef DEBUG
    fprintf(stderr, "argv[%d] = {", context->argc);
    for (auto str : context->argv_hold) {
        fprintf(stderr, " \"%s\"", str ?: "NULL");
    }
    fprintf(stderr, " }\n");
    fflush(stderr);
#endif
    context->retval = EXIT_SUCCESS;
    if (pthread_create(&context->thr, &attr,
                       (void*(*)(void*))__logcat, context)) {
        int save_errno = errno;
        goto argv_exit;
    }
    pthread_attr_destroy(&attr);

    return context->fds[0];

argv_exit:
    context->argv_hold.clear();
    context->args.clear();
    context->envp_hold.clear();
    context->envs.clear();
pthread_attr_exit:
    pthread_attr_destroy(&attr);
close_exit:
    close(context->fds[0]);
    context->fds[0] = -1;
    close(context->fds[1]);
    context->fds[1] = -1;
exit:
    errno = save_errno;
    context->stop = true;
    context->thread_stopped = true;
    context->retval = EXIT_FAILURE;
    return -1;
}

// test if the thread is still doing 'stuff'
int android_logcat_run_command_thread_running(android_logcat_context ctx) {
    android_logcat_context_internal* context = ctx;

    return context->thread_stopped == false;
}

// Finished with context
int android_logcat_destroy(android_logcat_context* ctx) {
    android_logcat_context_internal* context = *ctx;

    *ctx = NULL;

    context->stop = true;

    while (context->thread_stopped == false) {
        sched_yield();
    }

    delete context->regex;
    context->argv_hold.clear();
    context->args.clear();
    context->envp_hold.clear();
    context->envs.clear();
    if (context->fds[0] >= 0) {
        close(context->fds[0]);
        context->fds[0] = -1;
    }
    android::close_output(context);
    android::close_error(context);
    if (context->fds[1] >= 0) {
        // NB: could be closed by the above fclose(s), ignore error.
        int save_errno = errno;
        close(context->fds[1]);
        errno = save_errno;
        context->fds[1] = -1;
    }

    android_closeEventTagMap(context->eventTagMap);

    int retval = context->retval;

    free(context);

    return retval;
}
