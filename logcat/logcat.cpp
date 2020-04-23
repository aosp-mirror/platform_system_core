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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <memory>
#include <regex>
#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <log/event_tag_map.h>
#include <log/log_id.h>
#include <log/log_read.h>
#include <log/logprint.h>
#include <private/android_logger.h>
#include <processgroup/sched_policy.h>
#include <system/thread_defs.h>

#define DEFAULT_MAX_ROTATED_LOGS 4

using android::base::Join;
using android::base::ParseByteCount;
using android::base::ParseUint;
using android::base::Split;
using android::base::StringPrintf;

class Logcat {
  public:
    int Run(int argc, char** argv);

  private:
    void RotateLogs();
    void ProcessBuffer(struct log_msg* buf);
    void PrintDividers(log_id_t log_id, bool print_dividers);
    void SetupOutputAndSchedulingPolicy(bool blocking);
    int SetLogFormat(const char* format_string);

    // Used for all options
    android::base::unique_fd output_fd_{dup(STDOUT_FILENO)};
    std::unique_ptr<AndroidLogFormat, decltype(&android_log_format_free)> logformat_{
            android_log_format_new(), &android_log_format_free};

    // For logging to a file and log rotation
    const char* output_file_name_ = nullptr;
    size_t log_rotate_size_kb_ = 0;                       // 0 means "no log rotation"
    size_t max_rotated_logs_ = DEFAULT_MAX_ROTATED_LOGS;  // 0 means "unbounded"
    size_t out_byte_count_ = 0;

    // For binary log buffers
    int print_binary_ = 0;
    std::unique_ptr<EventTagMap, decltype(&android_closeEventTagMap)> event_tag_map_{
            nullptr, &android_closeEventTagMap};
    bool has_opened_event_tag_map_ = false;

    // For the related --regex, --max-count, --print
    std::unique_ptr<std::regex> regex_;
    size_t max_count_ = 0;  // 0 means "infinite"
    size_t print_count_ = 0;
    bool print_it_anyways_ = false;

    // For PrintDividers()
    log_id_t last_printed_id_ = LOG_ID_MAX;
    bool printed_start_[LOG_ID_MAX] = {};

    bool debug_ = false;
};

#ifndef F2FS_IOC_SET_PIN_FILE
#define F2FS_IOCTL_MAGIC       0xf5
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#endif

static int openLogFile(const char* pathname, size_t sizeKB) {
    int fd = open(pathname, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        return fd;
    }

    // no need to check errors
    __u32 set = 1;
    ioctl(fd, F2FS_IOC_SET_PIN_FILE, &set);
    fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, (sizeKB << 10));
    return fd;
}

static void closeLogFile(const char* pathname) {
    int fd = open(pathname, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        return;
    }

    // no need to check errors
    __u32 set = 0;
    ioctl(fd, F2FS_IOC_SET_PIN_FILE, &set);
    close(fd);
}

void Logcat::RotateLogs() {
    // Can't rotate logs if we're not outputting to a file
    if (!output_file_name_) return;

    output_fd_.reset();

    // Compute the maximum number of digits needed to count up to
    // maxRotatedLogs in decimal.  eg:
    // maxRotatedLogs == 30
    //   -> log10(30) == 1.477
    //   -> maxRotationCountDigits == 2
    int max_rotation_count_digits =
            max_rotated_logs_ > 0 ? (int)(floor(log10(max_rotated_logs_) + 1)) : 0;

    for (int i = max_rotated_logs_; i > 0; i--) {
        std::string file1 =
                StringPrintf("%s.%.*d", output_file_name_, max_rotation_count_digits, i);

        std::string file0;
        if (!(i - 1)) {
            file0 = output_file_name_;
        } else {
            file0 = StringPrintf("%s.%.*d", output_file_name_, max_rotation_count_digits, i - 1);
        }

        if (!file0.length() || !file1.length()) {
            perror("while rotating log files");
            break;
        }

        closeLogFile(file0.c_str());

        int err = rename(file0.c_str(), file1.c_str());

        if (err < 0 && errno != ENOENT) {
            perror("while rotating log files");
        }
    }

    output_fd_.reset(openLogFile(output_file_name_, log_rotate_size_kb_));

    if (!output_fd_.ok()) {
        error(EXIT_FAILURE, errno, "Couldn't open output file");
    }

    out_byte_count_ = 0;
}

void Logcat::ProcessBuffer(struct log_msg* buf) {
    int bytesWritten = 0;
    int err;
    AndroidLogEntry entry;
    char binaryMsgBuf[1024];

    bool is_binary =
            buf->id() == LOG_ID_EVENTS || buf->id() == LOG_ID_STATS || buf->id() == LOG_ID_SECURITY;

    if (is_binary) {
        if (!event_tag_map_ && !has_opened_event_tag_map_) {
            event_tag_map_.reset(android_openEventTagMap(nullptr));
            has_opened_event_tag_map_ = true;
        }
        err = android_log_processBinaryLogBuffer(&buf->entry, &entry, event_tag_map_.get(),
                                                 binaryMsgBuf, sizeof(binaryMsgBuf));
        // printf(">>> pri=%d len=%d msg='%s'\n",
        //    entry.priority, entry.messageLen, entry.message);
    } else {
        err = android_log_processLogBuffer(&buf->entry, &entry);
    }
    if (err < 0 && !debug_) return;

    if (android_log_shouldPrintLine(logformat_.get(), std::string(entry.tag, entry.tagLen).c_str(),
                                    entry.priority)) {
        bool match = !regex_ ||
                     std::regex_search(entry.message, entry.message + entry.messageLen, *regex_);

        print_count_ += match;
        if (match || print_it_anyways_) {
            bytesWritten = android_log_printLogLine(logformat_.get(), output_fd_.get(), &entry);

            if (bytesWritten < 0) {
                error(EXIT_FAILURE, 0, "Output error.");
            }
        }
    }

    out_byte_count_ += bytesWritten;

    if (log_rotate_size_kb_ > 0 && (out_byte_count_ / 1024) >= log_rotate_size_kb_) {
        RotateLogs();
    }
}

void Logcat::PrintDividers(log_id_t log_id, bool print_dividers) {
    if (log_id == last_printed_id_ || print_binary_) {
        return;
    }
    if (!printed_start_[log_id] || print_dividers) {
        if (dprintf(output_fd_.get(), "--------- %s %s\n",
                    printed_start_[log_id] ? "switch to" : "beginning of",
                    android_log_id_to_name(log_id)) < 0) {
            error(EXIT_FAILURE, errno, "Output error");
        }
    }
    last_printed_id_ = log_id;
    printed_start_[log_id] = true;
}

void Logcat::SetupOutputAndSchedulingPolicy(bool blocking) {
    if (!output_file_name_) return;

    if (blocking) {
        // Lower priority and set to batch scheduling if we are saving
        // the logs into files and taking continuous content.
        if (set_sched_policy(0, SP_BACKGROUND) < 0) {
            fprintf(stderr, "failed to set background scheduling policy\n");
        }

        struct sched_param param = {};
        if (sched_setscheduler((pid_t)0, SCHED_BATCH, &param) < 0) {
            fprintf(stderr, "failed to set to batch scheduler\n");
        }

        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
            fprintf(stderr, "failed set to priority\n");
        }
    }

    output_fd_.reset(openLogFile(output_file_name_, log_rotate_size_kb_));

    if (!output_fd_.ok()) {
        error(EXIT_FAILURE, errno, "Couldn't open output file");
    }

    struct stat statbuf;
    if (fstat(output_fd_.get(), &statbuf) == -1) {
        error(EXIT_FAILURE, errno, "Couldn't get output file stat");
    }

    if ((size_t)statbuf.st_size > SIZE_MAX || statbuf.st_size < 0) {
        error(EXIT_FAILURE, 0, "Invalid output file stat.");
    }

    out_byte_count_ = statbuf.st_size;
}

// clang-format off
static void show_help() {
    const char* cmd = getprogname();

    fprintf(stderr, "Usage: %s [options] [filterspecs]\n", cmd);

    fprintf(stderr, R"init(
General options:
  -b, --buffer=<buffer>       Request alternate ring buffer(s):
                                main system radio events crash default all
                              Additionally, 'kernel' for userdebug and eng builds, and
                              'security' for Device Owner installations.
                              Multiple -b parameters or comma separated list of buffers are
                              allowed. Buffers are interleaved.
                              Default -b main,system,crash,kernel.
  -L, --last                  Dump logs from prior to last reboot from pstore.
  -c, --clear                 Clear (flush) the entire log and exit.
                              if -f is specified, clear the specified file and its related rotated
                              log files instead.
                              if -L is specified, clear pstore log instead.
  -d                          Dump the log and then exit (don't block).
  --pid=<pid>                 Only print logs from the given pid.
  --wrap                      Sleep for 2 hours or when buffer about to wrap whichever
                              comes first. Improves efficiency of polling by providing
                              an about-to-wrap wakeup.

Formatting:
  -v, --format=<format>       Sets log print format verb and adverbs, where <format> is one of:
                                brief help long process raw tag thread threadtime time
                              Modifying adverbs can be added:
                                color descriptive epoch monotonic printable uid usec UTC year zone
                              Multiple -v parameters or comma separated list of format and format
                              modifiers are allowed.
  -D, --dividers              Print dividers between each log buffer.
  -B, --binary                Output the log in binary.

Outfile files:
  -f, --file=<file>           Log to file instead of stdout.
  -r, --rotate-kbytes=<n>     Rotate log every <n> kbytes. Requires -f option.
  -n, --rotate-count=<count>  Sets max number of rotated logs to <count>, default 4.
  --id=<id>                   If the signature <id> for logging to file changes, then clear the
                              associated files and continue.

Logd control:
 These options send a control message to the logd daemon on device, print its return message if
 applicable, then exit. They are incompatible with -L, as these attributes do not apply to pstore.
  -g, --buffer-size           Get the size of the ring buffers within logd.
  -G, --buffer-size=<size>    Set size of a ring buffer in logd. May suffix with K or M.
                              This can individually control each buffer's size with -b.
  -S, --statistics            Output statistics.
                              --pid can be used to provide pid specific stats.
  -p, --prune                 Print prune white and ~black list. Service is specified as UID,
                              UID/PID or /PID. Weighed for quicker pruning if prefix with ~,
                              otherwise weighed for longevity if unadorned. All other pruning
                              activity is oldest first. Special case ~! represents an automatic
                              quicker pruning for the noisiest UID as determined by the current
                              statistics.
  -P, --prune='<list> ...'    Set prune white and ~black list, using same format as listed above.
                              Must be quoted.

Filtering:
  -s                          Set default filter to silent. Equivalent to filterspec '*:S'
  -e, --regex=<expr>          Only print lines where the log message matches <expr> where <expr> is
                              an ECMAScript regular expression.
  -m, --max-count=<count>     Quit after printing <count> lines. This is meant to be paired with
                              --regex, but will work on its own.
  --print                     This option is only applicable when --regex is set and only useful if
                              --max-count is also provided.
                              With --print, logcat will print all messages even if they do not
                              match the regex. Logcat will quit after printing the max-count number
                              of lines that match the regex.
  -t <count>                  Print only the most recent <count> lines (implies -d).
  -t '<time>'                 Print the lines since specified time (implies -d).
  -T <count>                  Print only the most recent <count> lines (does not imply -d).
  -T '<time>'                 Print the lines since specified time (not imply -d).
                              count is pure numerical, time is 'MM-DD hh:mm:ss.mmm...'
                              'YYYY-MM-DD hh:mm:ss.mmm...' or 'sssss.mmm...' format.
)init");

    fprintf(stderr, "\nfilterspecs are a series of \n"
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

static void show_format_help() {
    fprintf(stderr,
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
        "  thread     — Display priority, PID and TID of process issuing the message.\n"
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

int Logcat::SetLogFormat(const char* format_string) {
    AndroidLogPrintFormat format = android_log_formatFromString(format_string);

    // invalid string?
    if (format == FORMAT_OFF) return -1;

    return android_log_setPrintFormat(logformat_.get(), format);
}

static std::pair<unsigned long, const char*> format_of_size(unsigned long value) {
    static const char multipliers[][3] = {{""}, {"Ki"}, {"Mi"}, {"Gi"}};
    size_t i;
    for (i = 0;
         (i < sizeof(multipliers) / sizeof(multipliers[0])) && (value >= 1024);
         value /= 1024, ++i)
        ;
    return std::make_pair(value, multipliers[i]);
}

static char* parseTime(log_time& t, const char* cp) {
    char* ep = t.strptime(cp, "%m-%d %H:%M:%S.%q");
    if (ep) return ep;
    ep = t.strptime(cp, "%Y-%m-%d %H:%M:%S.%q");
    if (ep) return ep;
    return t.strptime(cp, "%s.%q");
}

// Find last logged line in <outputFileName>, or <outputFileName>.1
static log_time lastLogTime(const char* outputFileName) {
    log_time retval(log_time::EPOCH);
    if (!outputFileName) return retval;

    std::string directory;
    const char* file = strrchr(outputFileName, '/');
    if (!file) {
        directory = ".";
        file = outputFileName;
    } else {
        directory = std::string(outputFileName, file - outputFileName);
        ++file;
    }

    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(directory.c_str()),
                                            closedir);
    if (!dir.get()) return retval;

    log_time now(android_log_clockid());

    size_t len = strlen(file);
    log_time modulo(0, NS_PER_SEC);
    struct dirent* dp;

    while (!!(dp = readdir(dir.get()))) {
        if ((dp->d_type != DT_REG) || !!strncmp(dp->d_name, file, len) ||
            (dp->d_name[len] && ((dp->d_name[len] != '.') ||
                                 (strtoll(dp->d_name + 1, nullptr, 10) != 1)))) {
            continue;
        }

        std::string file_name = directory;
        file_name += "/";
        file_name += dp->d_name;
        std::string file;
        if (!android::base::ReadFileToString(file_name, &file)) continue;

        bool found = false;
        for (const auto& line : android::base::Split(file, "\n")) {
            log_time t(log_time::EPOCH);
            char* ep = parseTime(t, line.c_str());
            if (!ep || (*ep != ' ')) continue;
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
        if (!dp->d_name[len] && found) break;
    }
    if (retval == log_time::EPOCH) return retval;
    // tail_time prints matching or higher, round up by the modulo to prevent
    // a replay of the last entry we have just checked.
    retval += modulo;
    return retval;
}

void ReportErrorName(const std::string& name, bool allow_security,
                     std::vector<std::string>* errors) {
    if (allow_security || name != "security") {
        errors->emplace_back(name);
    }
}

int Logcat::Run(int argc, char** argv) {
    bool hasSetLogFormat = false;
    bool clearLog = false;
    bool security_buffer_selected =
            false;  // Do not report errors on the security buffer unless it is explicitly named.
    bool getLogSize = false;
    bool getPruneList = false;
    bool printStatistics = false;
    bool printDividers = false;
    unsigned long setLogSize = 0;
    const char* setPruneList = nullptr;
    const char* setId = nullptr;
    int mode = 0;
    std::string forceFilters;
    size_t tail_lines = 0;
    log_time tail_time(log_time::EPOCH);
    size_t pid = 0;
    bool got_t = false;
    unsigned id_mask = 0;

    if (argc == 2 && !strcmp(argv[1], "--help")) {
        show_help();
        return EXIT_SUCCESS;
    }

    // meant to catch comma-delimited values, but cast a wider
    // net for stability dealing with possible mistaken inputs.
    static const char delimiters[] = ",:; \t\n\r\f";

    optind = 0;
    while (true) {
        int option_index = 0;
        // list of long-argument only strings for later comparison
        static const char pid_str[] = "pid";
        static const char debug_str[] = "debug";
        static const char id_str[] = "id";
        static const char wrap_str[] = "wrap";
        static const char print_str[] = "print";
        // clang-format off
        static const struct option long_options[] = {
          { "binary",        no_argument,       nullptr, 'B' },
          { "buffer",        required_argument, nullptr, 'b' },
          { "buffer-size",   optional_argument, nullptr, 'g' },
          { "clear",         no_argument,       nullptr, 'c' },
          { debug_str,       no_argument,       nullptr, 0 },
          { "dividers",      no_argument,       nullptr, 'D' },
          { "file",          required_argument, nullptr, 'f' },
          { "format",        required_argument, nullptr, 'v' },
          // hidden and undocumented reserved alias for --regex
          { "grep",          required_argument, nullptr, 'e' },
          // hidden and undocumented reserved alias for --max-count
          { "head",          required_argument, nullptr, 'm' },
          { "help",          no_argument,       nullptr, 'h' },
          { id_str,          required_argument, nullptr, 0 },
          { "last",          no_argument,       nullptr, 'L' },
          { "max-count",     required_argument, nullptr, 'm' },
          { pid_str,         required_argument, nullptr, 0 },
          { print_str,       no_argument,       nullptr, 0 },
          { "prune",         optional_argument, nullptr, 'p' },
          { "regex",         required_argument, nullptr, 'e' },
          { "rotate-count",  required_argument, nullptr, 'n' },
          { "rotate-kbytes", required_argument, nullptr, 'r' },
          { "statistics",    no_argument,       nullptr, 'S' },
          // hidden and undocumented reserved alias for -t
          { "tail",          required_argument, nullptr, 't' },
          // support, but ignore and do not document, the optional argument
          { wrap_str,        optional_argument, nullptr, 0 },
          { nullptr,         0,                 nullptr, 0 }
        };
        // clang-format on

        int c = getopt_long(argc, argv, ":cdDhLt:T:gG:sQf:r:n:v:b:BSpP:m:e:", long_options,
                            &option_index);
        if (c == -1) break;

        switch (c) {
            case 0:
                // only long options
                if (long_options[option_index].name == pid_str) {
                    if (pid != 0) {
                        error(EXIT_FAILURE, 0, "Only one --pid argument can be provided.");
                    }

                    if (!ParseUint(optarg, &pid) || pid < 1) {
                        error(EXIT_FAILURE, 0, "%s %s out of range.",
                              long_options[option_index].name, optarg);
                    }
                    break;
                }
                if (long_options[option_index].name == wrap_str) {
                    mode |= ANDROID_LOG_WRAP | ANDROID_LOG_NONBLOCK;
                    // ToDo: implement API that supports setting a wrap timeout
                    size_t dummy = ANDROID_LOG_WRAP_DEFAULT_TIMEOUT;
                    if (optarg && (!ParseUint(optarg, &dummy) || dummy < 1)) {
                        error(EXIT_FAILURE, 0, "%s %s out of range.",
                              long_options[option_index].name, optarg);
                    }
                    if (dummy != ANDROID_LOG_WRAP_DEFAULT_TIMEOUT) {
                        fprintf(stderr, "WARNING: %s %u seconds, ignoring %zu\n",
                                long_options[option_index].name, ANDROID_LOG_WRAP_DEFAULT_TIMEOUT,
                                dummy);
                    }
                    break;
                }
                if (long_options[option_index].name == print_str) {
                    print_it_anyways_ = true;
                    break;
                }
                if (long_options[option_index].name == debug_str) {
                    debug_ = true;
                    break;
                }
                if (long_options[option_index].name == id_str) {
                    setId = (optarg && optarg[0]) ? optarg : nullptr;
                }
                break;

            case 's':
                // default to all silent
                android_log_addFilterRule(logformat_.get(), "*:s");
                break;

            case 'c':
                clearLog = true;
                break;

            case 'L':
                mode |= ANDROID_LOG_PSTORE | ANDROID_LOG_NONBLOCK;
                break;

            case 'd':
                mode |= ANDROID_LOG_NONBLOCK;
                break;

            case 't':
                got_t = true;
                mode |= ANDROID_LOG_NONBLOCK;
                FALLTHROUGH_INTENDED;
            case 'T':
                if (strspn(optarg, "0123456789") != strlen(optarg)) {
                    char* cp = parseTime(tail_time, optarg);
                    if (!cp) {
                        error(EXIT_FAILURE, 0, "-%c '%s' not in time format.", c, optarg);
                    }
                    if (*cp) {
                        char ch = *cp;
                        *cp = '\0';
                        fprintf(stderr, "WARNING: -%c '%s' '%c%s' time truncated\n", c, optarg, ch,
                                cp + 1);
                        *cp = ch;
                    }
                } else {
                    if (!ParseUint(optarg, &tail_lines) || tail_lines < 1) {
                        fprintf(stderr, "WARNING: -%c %s invalid, setting to 1\n", c, optarg);
                        tail_lines = 1;
                    }
                }
                break;

            case 'D':
                printDividers = true;
                break;

            case 'e':
                regex_.reset(new std::regex(optarg));
                break;

            case 'm': {
                if (!ParseUint(optarg, &max_count_) || max_count_ < 1) {
                    error(EXIT_FAILURE, 0, "-%c '%s' isn't an integer greater than zero.", c,
                          optarg);
                }
            } break;

            case 'g':
                if (!optarg) {
                    getLogSize = true;
                    break;
                }
                FALLTHROUGH_INTENDED;

            case 'G': {
                if (!ParseByteCount(optarg, &setLogSize) || setLogSize < 1) {
                    error(EXIT_FAILURE, 0, "-G must be specified as <num><multiplier>.");
                }
            } break;

            case 'p':
                if (!optarg) {
                    getPruneList = true;
                    break;
                }
                FALLTHROUGH_INTENDED;

            case 'P':
                setPruneList = optarg;
                break;

            case 'b':
                for (const auto& buffer : Split(optarg, delimiters)) {
                    if (buffer == "default") {
                        id_mask |= (1 << LOG_ID_MAIN) | (1 << LOG_ID_SYSTEM) | (1 << LOG_ID_CRASH);
                    } else if (buffer == "all") {
                        id_mask = -1;
                    } else {
                        log_id_t log_id = android_name_to_log_id(buffer.c_str());
                        if (log_id >= LOG_ID_MAX) {
                            error(EXIT_FAILURE, 0, "Unknown buffer '%s' listed for -b.",
                                  buffer.c_str());
                        }
                        if (log_id == LOG_ID_SECURITY) {
                            security_buffer_selected = true;
                        }
                        id_mask |= (1 << log_id);
                    }
                }
                break;

            case 'B':
                print_binary_ = 1;
                break;

            case 'f':
                if ((tail_time == log_time::EPOCH) && !tail_lines) {
                    tail_time = lastLogTime(optarg);
                }
                // redirect output to a file
                output_file_name_ = optarg;
                break;

            case 'r':
                if (!ParseUint(optarg, &log_rotate_size_kb_) || log_rotate_size_kb_ < 1) {
                    error(EXIT_FAILURE, 0, "Invalid parameter '%s' to -r.", optarg);
                }
                break;

            case 'n':
                if (!ParseUint(optarg, &max_rotated_logs_) || max_rotated_logs_ < 1) {
                    error(EXIT_FAILURE, 0, "Invalid parameter '%s' to -n.", optarg);
                }
                break;

            case 'v':
                if (!strcmp(optarg, "help") || !strcmp(optarg, "--help")) {
                    show_format_help();
                    return EXIT_SUCCESS;
                }
                for (const auto& arg : Split(optarg, delimiters)) {
                    int err = SetLogFormat(arg.c_str());
                    if (err < 0) {
                        error(EXIT_FAILURE, 0, "Invalid parameter '%s' to -v.", arg.c_str());
                    }
                    if (err) hasSetLogFormat = true;
                }
                break;

            case 'Q':
#define LOGCAT_FILTER "androidboot.logcat="
#define CONSOLE_PIPE_OPTION "androidboot.consolepipe="
#define CONSOLE_OPTION "androidboot.console="
#define QEMU_PROPERTY "ro.kernel.qemu"
#define QEMU_CMDLINE "qemu.cmdline"
                // This is a *hidden* option used to start a version of logcat
                // in an emulated device only.  It basically looks for
                // androidboot.logcat= on the kernel command line.  If
                // something is found, it extracts a log filter and uses it to
                // run the program. The logcat output will go to consolepipe if
                // androiboot.consolepipe (e.g. qemu_pipe) is given, otherwise,
                // it goes to androidboot.console (e.g. tty)
                {
                    // if not in emulator, exit quietly
                    if (false == android::base::GetBoolProperty(QEMU_PROPERTY, false)) {
                        return EXIT_SUCCESS;
                    }

                    std::string cmdline = android::base::GetProperty(QEMU_CMDLINE, "");
                    if (cmdline.empty()) {
                        android::base::ReadFileToString("/proc/cmdline", &cmdline);
                    }

                    const char* logcatFilter = strstr(cmdline.c_str(), LOGCAT_FILTER);
                    // if nothing found or invalid filters, exit quietly
                    if (!logcatFilter) {
                        return EXIT_SUCCESS;
                    }

                    const char* p = logcatFilter + strlen(LOGCAT_FILTER);
                    const char* q = strpbrk(p, " \t\n\r");
                    if (!q) q = p + strlen(p);
                    forceFilters = std::string(p, q);

                    // redirect our output to the emulator console pipe or console
                    const char* consolePipe =
                        strstr(cmdline.c_str(), CONSOLE_PIPE_OPTION);
                    const char* console =
                        strstr(cmdline.c_str(), CONSOLE_OPTION);

                    if (consolePipe) {
                        p = consolePipe + strlen(CONSOLE_PIPE_OPTION);
                    } else if (console) {
                        p = console + strlen(CONSOLE_OPTION);
                    } else {
                        return EXIT_FAILURE;
                    }

                    q = strpbrk(p, " \t\n\r");
                    int len = q ? q - p : strlen(p);
                    std::string devname = "/dev/" + std::string(p, len);
                    std::string pipePurpose("pipe:logcat");
                    if (consolePipe) {
                        // example: "qemu_pipe,pipe:logcat"
                        // upon opening of /dev/qemu_pipe, the "pipe:logcat"
                        // string with trailing '\0' should be written to the fd
                        size_t pos = devname.find(',');
                        if (pos != std::string::npos) {
                            pipePurpose = devname.substr(pos + 1);
                            devname = devname.substr(0, pos);
                        }
                    }

                    fprintf(stderr, "logcat using %s\n", devname.c_str());

                    int fd = open(devname.c_str(), O_WRONLY | O_CLOEXEC);
                    if (fd < 0) {
                        break;
                    }

                    if (consolePipe) {
                        // need the trailing '\0'
                        if (!android::base::WriteFully(fd, pipePurpose.c_str(),
                                                       pipePurpose.size() + 1)) {
                            close(fd);
                            return EXIT_FAILURE;
                        }
                    }
                    // close output and error channels, replace with console
                    dup2(fd, output_fd_.get());
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                }
                break;

            case 'S':
                printStatistics = true;
                break;

            case ':':
                error(EXIT_FAILURE, 0, "Option '%s' needs an argument.", argv[optind - 1]);
                break;

            case 'h':
                show_help();
                show_format_help();
                return EXIT_SUCCESS;

            case '?':
                error(EXIT_FAILURE, 0, "Unknown option '%s'.", argv[optind - 1]);
                break;

            default:
                error(EXIT_FAILURE, 0, "Unknown getopt_long() result '%c'.", c);
        }
    }

    if (max_count_ && got_t) {
        error(EXIT_FAILURE, 0, "Cannot use -m (--max-count) and -t together.");
    }
    if (print_it_anyways_ && (!regex_ || !max_count_)) {
        // One day it would be nice if --print -v color and --regex <expr>
        // could play with each other and show regex highlighted content.
        fprintf(stderr,
                "WARNING: "
                "--print ignored, to be used in combination with\n"
                "         "
                "--regex <expr> and --max-count <N>\n");
        print_it_anyways_ = false;
    }

    // If no buffers are specified, default to using these buffers.
    if (id_mask == 0) {
        id_mask = (1 << LOG_ID_MAIN) | (1 << LOG_ID_SYSTEM) | (1 << LOG_ID_CRASH) |
                  (1 << LOG_ID_KERNEL);
    }

    if (log_rotate_size_kb_ != 0 && !output_file_name_) {
        error(EXIT_FAILURE, 0, "-r requires -f as well.");
    }

    if (setId != 0) {
        if (!output_file_name_) {
            error(EXIT_FAILURE, 0, "--id='%s' requires -f as well.", setId);
        }

        std::string file_name = StringPrintf("%s.id", output_file_name_);
        std::string file;
        bool file_ok = android::base::ReadFileToString(file_name, &file);
        android::base::WriteStringToFile(setId, file_name, S_IRUSR | S_IWUSR,
                                         getuid(), getgid());
        if (!file_ok || !file.compare(setId)) setId = nullptr;
    }

    if (!hasSetLogFormat) {
        const char* logFormat = getenv("ANDROID_PRINTF_LOG");

        if (!!logFormat) {
            for (const auto& arg : Split(logFormat, delimiters)) {
                int err = SetLogFormat(arg.c_str());
                // environment should not cause crash of logcat
                if (err < 0) {
                    fprintf(stderr, "invalid format in ANDROID_PRINTF_LOG '%s'\n", arg.c_str());
                }
                if (err > 0) hasSetLogFormat = true;
            }
        }
        if (!hasSetLogFormat) {
            SetLogFormat("threadtime");
        }
    }

    if (forceFilters.size()) {
        int err = android_log_addFilterString(logformat_.get(), forceFilters.c_str());
        if (err < 0) {
            error(EXIT_FAILURE, 0, "Invalid filter expression in logcat args.");
        }
    } else if (argc == optind) {
        // Add from environment variable
        const char* env_tags_orig = getenv("ANDROID_LOG_TAGS");

        if (!!env_tags_orig) {
            int err = android_log_addFilterString(logformat_.get(), env_tags_orig);

            if (err < 0) {
                error(EXIT_FAILURE, 0, "Invalid filter expression in ANDROID_LOG_TAGS.");
            }
        }
    } else {
        // Add from commandline
        for (int i = optind ; i < argc ; i++) {
            int err = android_log_addFilterString(logformat_.get(), argv[i]);
            if (err < 0) {
                error(EXIT_FAILURE, 0, "Invalid filter expression '%s'.", argv[i]);
            }
        }
    }

    if (mode & ANDROID_LOG_PSTORE) {
        if (output_file_name_) {
            error(EXIT_FAILURE, 0, "-c is ambiguous with both -f and -L specified.");
        }
        if (setLogSize || getLogSize || printStatistics || getPruneList || setPruneList) {
            error(EXIT_FAILURE, 0, "-L is incompatible with -g/-G, -S, and -p/-P.");
        }
        if (clearLog) {
            unlink("/sys/fs/pstore/pmsg-ramoops-0");
            return EXIT_SUCCESS;
        }
    }

    if (output_file_name_) {
        if (setLogSize || getLogSize || printStatistics || getPruneList || setPruneList) {
            error(EXIT_FAILURE, 0, "-f is incompatible with -g/-G, -S, and -p/-P.");
        }

        if (clearLog || setId) {
            int max_rotation_count_digits =
                    max_rotated_logs_ > 0 ? (int)(floor(log10(max_rotated_logs_) + 1)) : 0;

            for (int i = max_rotated_logs_; i >= 0; --i) {
                std::string file;

                if (!i) {
                    file = output_file_name_;
                } else {
                    file = StringPrintf("%s.%.*d", output_file_name_, max_rotation_count_digits, i);
                }

                int err = unlink(file.c_str());

                if (err < 0 && errno != ENOENT) {
                    fprintf(stderr, "failed to delete log file '%s': %s\n", file.c_str(),
                            strerror(errno));
                }
            }
        }

        if (clearLog) {
            return EXIT_SUCCESS;
        }
    }

    std::unique_ptr<logger_list, decltype(&android_logger_list_free)> logger_list{
            nullptr, &android_logger_list_free};
    if (tail_time != log_time::EPOCH) {
        logger_list.reset(android_logger_list_alloc_time(mode, tail_time, pid));
    } else {
        logger_list.reset(android_logger_list_alloc(mode, tail_lines, pid));
    }
    // We have three orthogonal actions below to clear, set log size and
    // get log size. All sharing the same iteration loop.
    std::vector<std::string> open_device_failures;
    std::vector<std::string> clear_failures;
    std::vector<std::string> set_size_failures;
    std::vector<std::string> get_size_failures;

    for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
        if (!(id_mask & (1 << i))) continue;
        const char* buffer_name = android_log_id_to_name(static_cast<log_id_t>(i));

        auto logger = android_logger_open(logger_list.get(), static_cast<log_id_t>(i));
        if (logger == nullptr) {
            ReportErrorName(buffer_name, security_buffer_selected, &open_device_failures);
            continue;
        }

        if (clearLog) {
            if (android_logger_clear(logger)) {
                ReportErrorName(buffer_name, security_buffer_selected, &clear_failures);
            }
        }

        if (setLogSize) {
            if (android_logger_set_log_size(logger, setLogSize)) {
                ReportErrorName(buffer_name, security_buffer_selected, &set_size_failures);
            }
        }

        if (getLogSize) {
            long size = android_logger_get_log_size(logger);
            long readable = android_logger_get_log_readable_size(logger);

            if (size < 0 || readable < 0) {
                ReportErrorName(buffer_name, security_buffer_selected, &get_size_failures);
            } else {
                auto size_format = format_of_size(size);
                auto readable_format = format_of_size(readable);
                std::string str = android::base::StringPrintf(
                        "%s: ring buffer is %lu %sB (%lu %sB consumed),"
                        " max entry is %d B, max payload is %d B\n",
                        buffer_name, size_format.first, size_format.second, readable_format.first,
                        readable_format.second, (int)LOGGER_ENTRY_MAX_LEN,
                        (int)LOGGER_ENTRY_MAX_PAYLOAD);
                TEMP_FAILURE_RETRY(write(output_fd_.get(), str.data(), str.length()));
            }
        }
    }

    // report any errors in the above loop and exit
    if (!open_device_failures.empty()) {
        error(EXIT_FAILURE, 0, "Unable to open log device%s '%s'.",
              open_device_failures.size() > 1 ? "s" : "", Join(open_device_failures, ",").c_str());
    }
    if (!clear_failures.empty()) {
        error(EXIT_FAILURE, 0, "failed to clear the '%s' log%s.", Join(clear_failures, ",").c_str(),
              clear_failures.size() > 1 ? "s" : "");
    }
    if (!set_size_failures.empty()) {
        error(EXIT_FAILURE, 0, "failed to set the '%s' log size%s.",
              Join(set_size_failures, ",").c_str(), set_size_failures.size() > 1 ? "s" : "");
    }
    if (!get_size_failures.empty()) {
        error(EXIT_FAILURE, 0, "failed to get the readable '%s' log size%s.",
              Join(get_size_failures, ",").c_str(), get_size_failures.size() > 1 ? "s" : "");
    }

    if (setPruneList) {
        size_t len = strlen(setPruneList);
        if (android_logger_set_prune_list(logger_list.get(), setPruneList, len)) {
            error(EXIT_FAILURE, 0, "Failed to set the prune list.");
        }
        return EXIT_SUCCESS;
    }

    if (printStatistics || getPruneList) {
        std::string buf(8192, '\0');
        size_t ret_length = 0;
        int retry = 32;

        for (; retry >= 0; --retry) {
            if (getPruneList) {
                android_logger_get_prune_list(logger_list.get(), buf.data(), buf.size());
            } else {
                android_logger_get_statistics(logger_list.get(), buf.data(), buf.size());
            }

            ret_length = atol(buf.c_str());
            if (ret_length < 3) {
                error(EXIT_FAILURE, 0, "Failed to read data.");
            }

            if (ret_length < buf.size()) {
                break;
            }

            buf.resize(ret_length + 1);
        }

        if (retry < 0) {
            error(EXIT_FAILURE, 0, "Failed to read data.");
        }

        buf.resize(ret_length);
        if (buf.back() == '\f') {
            buf.pop_back();
        }

        // Remove the byte count prefix
        const char* cp = buf.c_str();
        while (isdigit(*cp)) ++cp;
        if (*cp == '\n') ++cp;

        size_t len = strlen(cp);
        TEMP_FAILURE_RETRY(write(output_fd_.get(), cp, len));
        return EXIT_SUCCESS;
    }

    if (getLogSize || setLogSize || clearLog) return EXIT_SUCCESS;

    SetupOutputAndSchedulingPolicy(!(mode & ANDROID_LOG_NONBLOCK));

    while (!max_count_ || print_count_ < max_count_) {
        struct log_msg log_msg;
        int ret = android_logger_list_read(logger_list.get(), &log_msg);
        if (!ret) {
            error(EXIT_FAILURE, 0, R"init(Unexpected EOF!

This means that either the device shut down, logd crashed, or this instance of logcat was unable to read log
messages as quickly as they were being produced.

If you have enabled significant logging, look into using the -G option to increase log buffer sizes.)init");
        }

        if (ret < 0) {
            if (ret == -EAGAIN) break;

            if (ret == -EIO) {
                error(EXIT_FAILURE, 0, "Unexpected EOF!");
            }
            if (ret == -EINVAL) {
                error(EXIT_FAILURE, 0, "Unexpected length.");
            }
            error(EXIT_FAILURE, errno, "Logcat read failure");
        }

        if (log_msg.id() > LOG_ID_MAX) {
            error(EXIT_FAILURE, 0, "Unexpected log id (%d) over LOG_ID_MAX (%d).", log_msg.id(),
                  LOG_ID_MAX);
        }

        PrintDividers(log_msg.id(), printDividers);

        if (print_binary_) {
            TEMP_FAILURE_RETRY(write(output_fd_.get(), &log_msg, log_msg.len()));
        } else {
            ProcessBuffer(&log_msg);
        }
    }
    return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
    Logcat logcat;
    return logcat.Run(argc, argv);
}
