// Copyright 2006-2015 The Android Open Source Project

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
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

#include <memory>
#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sched_policy.h>
#include <cutils/sockets.h>
#include <log/event_tag_map.h>
#include <log/logprint.h>
#include <private/android_logger.h>
#include <system/thread_defs.h>

#include <pcrecpp.h>

#define DEFAULT_MAX_ROTATED_LOGS 4

static AndroidLogFormat * g_logformat;

/* logd prefixes records with a length field */
#define RECORD_LENGTH_FIELD_SIZE_BYTES sizeof(uint32_t)

struct log_device_t {
    const char* device;
    bool binary;
    struct logger *logger;
    struct logger_list *logger_list;
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

/* Global Variables */

static const char * g_outputFileName;
// 0 means "no log rotation"
static size_t g_logRotateSizeKBytes;
// 0 means "unbounded"
static size_t g_maxRotatedLogs = DEFAULT_MAX_ROTATED_LOGS;
static int g_outFD = -1;
static size_t g_outByteCount;
static int g_printBinary;
static int g_devCount;                              // >1 means multiple
static pcrecpp::RE* g_regex;
// 0 means "infinite"
static size_t g_maxCount;
static size_t g_printCount;
static bool g_printItAnyways;
static bool g_debug;

enum helpType {
    HELP_FALSE,
    HELP_TRUE,
    HELP_FORMAT
};

// if showHelp is set, newline required in fmt statement to transition to usage
__noreturn static void logcat_panic(enum helpType showHelp, const char *fmt, ...) __printflike(2,3);

static int openLogFile (const char *pathname)
{
    return open(pathname, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
}

static void rotateLogs()
{
    int err;

    // Can't rotate logs if we're not outputting to a file
    if (g_outputFileName == NULL) {
        return;
    }

    close(g_outFD);

    // Compute the maximum number of digits needed to count up to g_maxRotatedLogs in decimal.
    // eg: g_maxRotatedLogs == 30 -> log10(30) == 1.477 -> maxRotationCountDigits == 2
    int maxRotationCountDigits =
            (g_maxRotatedLogs > 0) ? (int) (floor(log10(g_maxRotatedLogs) + 1)) : 0;

    for (int i = g_maxRotatedLogs ; i > 0 ; i--) {
        std::string file1 = android::base::StringPrintf(
            "%s.%.*d", g_outputFileName, maxRotationCountDigits, i);

        std::string file0;
        if (i - 1 == 0) {
            file0 = android::base::StringPrintf("%s", g_outputFileName);
        } else {
            file0 = android::base::StringPrintf(
                "%s.%.*d", g_outputFileName, maxRotationCountDigits, i - 1);
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

    g_outFD = openLogFile(g_outputFileName);

    if (g_outFD < 0) {
        logcat_panic(HELP_FALSE, "couldn't open output file");
    }

    g_outByteCount = 0;

}

void printBinary(struct log_msg *buf)
{
    size_t size = buf->len();

    TEMP_FAILURE_RETRY(write(g_outFD, buf, size));
}

static bool regexOk(const AndroidLogEntry& entry)
{
    if (!g_regex) {
        return true;
    }

    std::string messageString(entry.message, entry.messageLen);

    return g_regex->PartialMatch(messageString);
}

static void processBuffer(log_device_t* dev, struct log_msg *buf)
{
    int bytesWritten = 0;
    int err;
    AndroidLogEntry entry;
    char binaryMsgBuf[1024];

    if (dev->binary) {
        static bool hasOpenedEventTagMap = false;
        static EventTagMap *eventTagMap = NULL;

        if (!eventTagMap && !hasOpenedEventTagMap) {
            eventTagMap = android_openEventTagMap(NULL);
            hasOpenedEventTagMap = true;
        }
        err = android_log_processBinaryLogBuffer(&buf->entry_v1, &entry,
                                                 eventTagMap,
                                                 binaryMsgBuf,
                                                 sizeof(binaryMsgBuf));
        //printf(">>> pri=%d len=%d msg='%s'\n",
        //    entry.priority, entry.messageLen, entry.message);
    } else {
        err = android_log_processLogBuffer(&buf->entry_v1, &entry);
    }
    if ((err < 0) && !g_debug) {
        goto error;
    }

    if (android_log_shouldPrintLine(g_logformat,
                                    std::string(entry.tag, entry.tagLen).c_str(),
                                    entry.priority)) {
        bool match = regexOk(entry);

        g_printCount += match;
        if (match || g_printItAnyways) {
            bytesWritten = android_log_printLogLine(g_logformat, g_outFD, &entry);

            if (bytesWritten < 0) {
                logcat_panic(HELP_FALSE, "output error");
            }
        }
    }

    g_outByteCount += bytesWritten;

    if (g_logRotateSizeKBytes > 0
        && (g_outByteCount / 1024) >= g_logRotateSizeKBytes
    ) {
        rotateLogs();
    }

error:
    return;
}

static void maybePrintStart(log_device_t* dev, bool printDividers) {
    if (!dev->printed || printDividers) {
        if (g_devCount > 1 && !g_printBinary) {
            char buf[1024];
            snprintf(buf, sizeof(buf), "--------- %s %s\n",
                     dev->printed ? "switch to" : "beginning of",
                     dev->device);
            if (write(g_outFD, buf, strlen(buf)) < 0) {
                logcat_panic(HELP_FALSE, "output error");
            }
        }
        dev->printed = true;
    }
}

static void setupOutputAndSchedulingPolicy(bool blocking) {
    if (g_outputFileName == NULL) {
        g_outFD = STDOUT_FILENO;
        return;
    }

    if (blocking) {
        // Lower priority and set to batch scheduling if we are saving
        // the logs into files and taking continuous content.
        if (set_sched_policy(0, SP_BACKGROUND) < 0) {
            fprintf(stderr, "failed to set background scheduling policy\n");
        }

        struct sched_param param;
        memset(&param, 0, sizeof(param));
        if (sched_setscheduler((pid_t) 0, SCHED_BATCH, &param) < 0) {
            fprintf(stderr, "failed to set to batch scheduler\n");
        }

        if (setpriority(PRIO_PROCESS, 0, ANDROID_PRIORITY_BACKGROUND) < 0) {
            fprintf(stderr, "failed set to priority\n");
        }
    }

    g_outFD = openLogFile (g_outputFileName);

    if (g_outFD < 0) {
        logcat_panic(HELP_FALSE, "couldn't open output file");
    }

    struct stat statbuf;
    if (fstat(g_outFD, &statbuf) == -1) {
        close(g_outFD);
        logcat_panic(HELP_FALSE, "couldn't get output file stat\n");
    }

    if ((size_t) statbuf.st_size > SIZE_MAX || statbuf.st_size < 0) {
        close(g_outFD);
        logcat_panic(HELP_FALSE, "invalid output file stat\n");
    }

    g_outByteCount = statbuf.st_size;
}

static void show_help(const char *cmd)
{
    fprintf(stderr,"Usage: %s [options] [filterspecs]\n", cmd);

    fprintf(stderr, "options include:\n"
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

    fprintf(stderr,"\nfilterspecs are a series of \n"
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

static void show_format_help()
{
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

static int setLogFormat(const char * formatString)
{
    static AndroidLogPrintFormat format;

    format = android_log_formatFromString(formatString);

    if (format == FORMAT_OFF) {
        // FORMAT_OFF means invalid string
        return -1;
    }

    return android_log_setPrintFormat(g_logformat, format);
}

static const char multipliers[][2] = {
    { "" },
    { "K" },
    { "M" },
    { "G" }
};

static unsigned long value_of_size(unsigned long value)
{
    for (unsigned i = 0;
            (i < sizeof(multipliers)/sizeof(multipliers[0])) && (value >= 1024);
            value /= 1024, ++i) ;
    return value;
}

static const char *multiplier_of_size(unsigned long value)
{
    unsigned i;
    for (i = 0;
            (i < sizeof(multipliers)/sizeof(multipliers[0])) && (value >= 1024);
            value /= 1024, ++i) ;
    return multipliers[i];
}

/*String to unsigned int, returns -1 if it fails*/
static bool getSizeTArg(const char *ptr, size_t *val, size_t min = 0,
                        size_t max = SIZE_MAX)
{
    if (!ptr) {
        return false;
    }

    char *endp;
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

static void logcat_panic(enum helpType showHelp, const char *fmt, ...)
{
    va_list  args;
    va_start(args, fmt);
    vfprintf(stderr, fmt,  args);
    va_end(args);

    switch (showHelp) {
    case HELP_TRUE:
       show_help(getprogname());
       break;
    case HELP_FORMAT:
       show_format_help();
       break;
    case HELP_FALSE:
    default:
      break;
    }

    exit(EXIT_FAILURE);
}

static char *parseTime(log_time &t, const char *cp) {

    char *ep = t.strptime(cp, "%m-%d %H:%M:%S.%q");
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
static log_time lastLogTime(char *outputFileName) {
    log_time retval(log_time::EPOCH);
    if (!outputFileName) {
        return retval;
    }

    std::string directory;
    char *file = strrchr(outputFileName, '/');
    if (!file) {
        directory = ".";
        file = outputFileName;
    } else {
        *file = '\0';
        directory = outputFileName;
        *file = '/';
        ++file;
    }

    std::unique_ptr<DIR, int(*)(DIR*)>
            dir(opendir(directory.c_str()), closedir);
    if (!dir.get()) {
        return retval;
    }

    log_time now(android_log_clockid());

    size_t len = strlen(file);
    log_time modulo(0, NS_PER_SEC);
    struct dirent *dp;

    while ((dp = readdir(dir.get())) != NULL) {
        if ((dp->d_type != DT_REG) ||
                (strncmp(dp->d_name, file, len) != 0) ||
                (dp->d_name[len] &&
                     ((dp->d_name[len] != '.') ||
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
            char *ep = parseTime(t, line.c_str());
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

} /* namespace android */

void reportErrorName(const char **current,
                     const char* name,
                     bool blockSecurity) {
    if (*current) {
       return;
    }
    if (blockSecurity && (android_name_to_log_id(name) == LOG_ID_SECURITY)) {
       return;
    }
    *current = name;
}

int main(int argc, char **argv)
{
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
    char *setPruneList = NULL;
    char *setId = NULL;
    int mode = ANDROID_LOG_RDONLY;
    const char *forceFilters = NULL;
    log_device_t* devices = NULL;
    log_device_t* dev;
    struct logger_list *logger_list;
    size_t tail_lines = 0;
    log_time tail_time(log_time::EPOCH);
    size_t pid = 0;
    bool got_t = false;

    signal(SIGPIPE, exit);

    g_logformat = android_log_format_new();

    if (argc == 2 && 0 == strcmp(argv[1], "--help")) {
        show_help(argv[0]);
        return EXIT_SUCCESS;
    }

    for (;;) {
        int ret;

        int option_index = 0;
        // list of long-argument only strings for later comparison
        static const char pid_str[] = "pid";
        static const char debug_str[] = "debug";
        static const char id_str[] = "id";
        static const char wrap_str[] = "wrap";
        static const char print_str[] = "print";
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

        ret = getopt_long(argc, argv, ":cdDLt:T:gG:sQf:r:n:v:b:BSpP:m:e:",
                          long_options, &option_index);

        if (ret < 0) {
            break;
        }

        switch (ret) {
            case 0:
                // only long options
                if (long_options[option_index].name == pid_str) {
                    // ToDo: determine runtime PID_MAX?
                    if (!getSizeTArg(optarg, &pid, 1)) {
                        logcat_panic(HELP_TRUE, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                    }
                    break;
                }
                if (long_options[option_index].name == wrap_str) {
                    mode |= ANDROID_LOG_WRAP |
                            ANDROID_LOG_RDONLY |
                            ANDROID_LOG_NONBLOCK;
                    // ToDo: implement API that supports setting a wrap timeout
                    size_t dummy = ANDROID_LOG_WRAP_DEFAULT_TIMEOUT;
                    if (optarg && !getSizeTArg(optarg, &dummy, 1)) {
                        logcat_panic(HELP_TRUE, "%s %s out of range\n",
                                     long_options[option_index].name, optarg);
                    }
                    if (dummy != ANDROID_LOG_WRAP_DEFAULT_TIMEOUT) {
                        fprintf(stderr,
                                "WARNING: %s %u seconds, ignoring %zu\n",
                                long_options[option_index].name,
                                ANDROID_LOG_WRAP_DEFAULT_TIMEOUT, dummy);
                    }
                    break;
                }
                if (long_options[option_index].name == print_str) {
                    g_printItAnyways = true;
                    break;
                }
                if (long_options[option_index].name == debug_str) {
                    g_debug = true;
                    break;
                }
                if (long_options[option_index].name == id_str) {
                    setId = optarg && optarg[0] ? optarg : NULL;
                    break;
                }
            break;

            case 's':
                // default to all silent
                android_log_addFilterRule(g_logformat, "*:s");
            break;

            case 'c':
                clearLog = true;
                mode |= ANDROID_LOG_WRONLY;
            break;

            case 'L':
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_PSTORE | ANDROID_LOG_NONBLOCK;
            break;

            case 'd':
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
            break;

            case 't':
                got_t = true;
                mode |= ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
                /* FALLTHRU */
            case 'T':
                if (strspn(optarg, "0123456789") != strlen(optarg)) {
                    char *cp = parseTime(tail_time, optarg);
                    if (!cp) {
                        logcat_panic(HELP_FALSE,
                                     "-%c \"%s\" not in time format\n",
                                     ret, optarg);
                    }
                    if (*cp) {
                        char c = *cp;
                        *cp = '\0';
                        fprintf(stderr,
                                "WARNING: -%c \"%s\"\"%c%s\" time truncated\n",
                                ret, optarg, c, cp + 1);
                        *cp = c;
                    }
                } else {
                    if (!getSizeTArg(optarg, &tail_lines, 1)) {
                        fprintf(stderr,
                                "WARNING: -%c %s invalid, setting to 1\n",
                                ret, optarg);
                        tail_lines = 1;
                    }
                }
            break;

            case 'D':
                printDividers = true;
            break;

            case 'e':
                g_regex = new pcrecpp::RE(optarg);
            break;

            case 'm': {
                char *end = NULL;
                if (!getSizeTArg(optarg, &g_maxCount)) {
                    logcat_panic(HELP_FALSE, "-%c \"%s\" isn't an "
                                 "integer greater than zero\n", ret, optarg);
                }
            }
            break;

            case 'g':
                if (!optarg) {
                    getLogSize = true;
                    break;
                }
                // FALLTHRU

            case 'G': {
                char *cp;
                if (strtoll(optarg, &cp, 0) > 0) {
                    setLogSize = strtoll(optarg, &cp, 0);
                } else {
                    setLogSize = 0;
                }

                switch(*cp) {
                case 'g':
                case 'G':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case 'm':
                case 'M':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case 'k':
                case 'K':
                    setLogSize *= 1024;
                /* FALLTHRU */
                case '\0':
                break;

                default:
                    setLogSize = 0;
                }

                if (!setLogSize) {
                    fprintf(stderr, "ERROR: -G <num><multiplier>\n");
                    return EXIT_FAILURE;
                }
            }
            break;

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
                        idMask |= (1 << LOG_ID_MAIN) |
                                  (1 << LOG_ID_SYSTEM) |
                                  (1 << LOG_ID_CRASH);
                    } else if (strcmp(optarg, "all") == 0) {
                        allSelected = true;
                        idMask = (unsigned)-1;
                    } else {
                        log_id_t log_id = android_name_to_log_id(optarg);
                        const char *name = android_log_id_to_name(log_id);

                        if (strcmp(name, optarg) != 0) {
                            logcat_panic(HELP_TRUE,
                                         "unknown buffer %s\n", optarg);
                        }
                        if (log_id == LOG_ID_SECURITY) allSelected = false;
                        idMask |= (1 << log_id);
                    }
                    optarg = NULL;
                }

                for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
                    const char *name = android_log_id_to_name((log_id_t)i);
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

                    bool binary = !strcmp(name, "events") ||
                                  !strcmp(name, "security");
                    log_device_t* d = new log_device_t(name, binary);

                    if (dev) {
                        dev->next = d;
                        dev = d;
                    } else {
                        devices = dev = d;
                    }
                    g_devCount++;
                }
            }
            break;

            case 'B':
                g_printBinary = 1;
            break;

            case 'f':
                if ((tail_time == log_time::EPOCH) && (tail_lines == 0)) {
                    tail_time = lastLogTime(optarg);
                }
                // redirect output to a file
                g_outputFileName = optarg;
            break;

            case 'r':
                if (!getSizeTArg(optarg, &g_logRotateSizeKBytes, 1)) {
                    logcat_panic(HELP_TRUE,
                                 "Invalid parameter \"%s\" to -r\n", optarg);
                }
            break;

            case 'n':
                if (!getSizeTArg(optarg, &g_maxRotatedLogs, 1)) {
                    logcat_panic(HELP_TRUE,
                                 "Invalid parameter \"%s\" to -n\n", optarg);
                }
            break;

            case 'v':
                if (!strcmp(optarg, "help") || !strcmp(optarg, "--help")) {
                    show_format_help();
                    exit(0);
                }
                err = setLogFormat(optarg);
                if (err < 0) {
                    logcat_panic(HELP_FORMAT,
                                 "Invalid parameter \"%s\" to -v\n", optarg);
                }
                hasSetLogFormat |= err;
            break;

            case 'Q':
                /* this is a *hidden* option used to start a version of logcat                 */
                /* in an emulated device only. it basically looks for androidboot.logcat=      */
                /* on the kernel command line. If something is found, it extracts a log filter */
                /* and uses it to run the program. If nothing is found, the program should     */
                /* quit immediately                                                            */
#define  KERNEL_OPTION  "androidboot.logcat="
#define  CONSOLE_OPTION "androidboot.console="
                {
                    int          fd;
                    char*        logcat;
                    char*        console;
                    int          force_exit = 1;
                    static char  cmdline[1024];

                    fd = open("/proc/cmdline", O_RDONLY);
                    if (fd >= 0) {
                        int  n = read(fd, cmdline, sizeof(cmdline)-1 );
                        if (n < 0) n = 0;
                        cmdline[n] = 0;
                        close(fd);
                    } else {
                        cmdline[0] = 0;
                    }

                    logcat  = strstr( cmdline, KERNEL_OPTION );
                    console = strstr( cmdline, CONSOLE_OPTION );
                    if (logcat != NULL) {
                        char*  p = logcat + sizeof(KERNEL_OPTION)-1;;
                        char*  q = strpbrk( p, " \t\n\r" );;

                        if (q != NULL)
                            *q = 0;

                        forceFilters = p;
                        force_exit   = 0;
                    }
                    /* if nothing found or invalid filters, exit quietly */
                    if (force_exit) {
                        return EXIT_SUCCESS;
                    }

                    /* redirect our output to the emulator console */
                    if (console) {
                        char*  p = console + sizeof(CONSOLE_OPTION)-1;
                        char*  q = strpbrk( p, " \t\n\r" );
                        char   devname[64];
                        int    len;

                        if (q != NULL) {
                            len = q - p;
                        } else
                            len = strlen(p);

                        len = snprintf( devname, sizeof(devname), "/dev/%.*s", len, p );
                        fprintf(stderr, "logcat using %s (%d)\n", devname, len);
                        if (len < (int)sizeof(devname)) {
                            fd = open( devname, O_WRONLY );
                            if (fd >= 0) {
                                dup2(fd, 1);
                                dup2(fd, 2);
                                close(fd);
                            }
                        }
                    }
                }
                break;

            case 'S':
                printStatistics = true;
                break;

            case ':':
                logcat_panic(HELP_TRUE,
                             "Option -%c needs an argument\n", optopt);
                break;

            default:
                logcat_panic(HELP_TRUE,
                             "Unrecognized Option %c\n", optopt);
                break;
        }
    }

    if (g_maxCount && got_t) {
        logcat_panic(HELP_TRUE,
                     "Cannot use -m (--max-count) and -t together\n");
    }
    if (g_printItAnyways && (!g_regex || !g_maxCount)) {
        // One day it would be nice if --print -v color and --regex <expr>
        // could play with each other and show regex highlighted content.
        fprintf(stderr, "WARNING: "
                            "--print ignored, to be used in combination with\n"
                        "         "
                            "--regex <expr> and --max-count <N>\n");
        g_printItAnyways = false;
    }

    if (!devices) {
        dev = devices = new log_device_t("main", false);
        g_devCount = 1;
        if (android_name_to_log_id("system") == LOG_ID_SYSTEM) {
            dev = dev->next = new log_device_t("system", false);
            g_devCount++;
        }
        if (android_name_to_log_id("crash") == LOG_ID_CRASH) {
            dev = dev->next = new log_device_t("crash", false);
            g_devCount++;
        }
    }

    if (g_logRotateSizeKBytes != 0 && g_outputFileName == NULL) {
        logcat_panic(HELP_TRUE, "-r requires -f as well\n");
    }

    if (setId != NULL) {
        if (g_outputFileName == NULL) {
            logcat_panic(HELP_TRUE, "--id='%s' requires -f as well\n", setId);
        }

        std::string file_name = android::base::StringPrintf("%s.id", g_outputFileName);
        std::string file;
        bool file_ok = android::base::ReadFileToString(file_name, &file);
        android::base::WriteStringToFile(setId, file_name,
                                         S_IRUSR | S_IWUSR, getuid(), getgid());
        if (!file_ok || (file.compare(setId) == 0)) {
            setId = NULL;
        }
    }

    if (hasSetLogFormat == 0) {
        const char* logFormat = getenv("ANDROID_PRINTF_LOG");

        if (logFormat != NULL) {
            err = setLogFormat(logFormat);
            if (err < 0) {
                fprintf(stderr, "invalid format in ANDROID_PRINTF_LOG '%s'\n",
                                    logFormat);
            }
        } else {
            setLogFormat("threadtime");
        }
    }

    if (forceFilters) {
        err = android_log_addFilterString(g_logformat, forceFilters);
        if (err < 0) {
            logcat_panic(HELP_FALSE,
                         "Invalid filter expression in logcat args\n");
        }
    } else if (argc == optind) {
        // Add from environment variable
        char *env_tags_orig = getenv("ANDROID_LOG_TAGS");

        if (env_tags_orig != NULL) {
            err = android_log_addFilterString(g_logformat, env_tags_orig);

            if (err < 0) {
                logcat_panic(HELP_TRUE,
                            "Invalid filter expression in ANDROID_LOG_TAGS\n");
            }
        }
    } else {
        // Add from commandline
        for (int i = optind ; i < argc ; i++) {
            err = android_log_addFilterString(g_logformat, argv[i]);

            if (err < 0) {
                logcat_panic(HELP_TRUE,
                             "Invalid filter expression '%s'\n", argv[i]);
            }
        }
    }

    dev = devices;
    if (tail_time != log_time::EPOCH) {
        logger_list = android_logger_list_alloc_time(mode, tail_time, pid);
    } else {
        logger_list = android_logger_list_alloc(mode, tail_lines, pid);
    }
    const char *openDeviceFail = NULL;
    const char *clearFail = NULL;
    const char *setSizeFail = NULL;
    const char *getSizeFail = NULL;
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
            if (g_outputFileName) {
                int maxRotationCountDigits =
                    (g_maxRotatedLogs > 0) ? (int) (floor(log10(g_maxRotatedLogs) + 1)) : 0;

                for (int i = g_maxRotatedLogs ; i >= 0 ; --i) {
                    std::string file;

                    if (i == 0) {
                        file = android::base::StringPrintf("%s", g_outputFileName);
                    } else {
                        file = android::base::StringPrintf("%s.%.*d",
                            g_outputFileName, maxRotationCountDigits, i);
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
                printf("%s: ring buffer is %ld%sb (%ld%sb consumed), "
                       "max entry is %db, max payload is %db\n", dev->device,
                       value_of_size(size), multiplier_of_size(size),
                       value_of_size(readable), multiplier_of_size(readable),
                       (int) LOGGER_ENTRY_MAX_LEN,
                       (int) LOGGER_ENTRY_MAX_PAYLOAD);
            }
        }

        dev = dev->next;
    }
    // report any errors in the above loop and exit
    if (openDeviceFail) {
        logcat_panic(HELP_FALSE,
                     "Unable to open log device '%s'\n", openDeviceFail);
    }
    if (clearFail) {
        logcat_panic(HELP_FALSE,
                     "failed to clear the '%s' log\n", clearFail);
    }
    if (setSizeFail) {
        logcat_panic(HELP_FALSE,
                     "failed to set the '%s' log size\n", setSizeFail);
    }
    if (getSizeFail) {
        logcat_panic(HELP_FALSE,
                     "failed to get the readable '%s' log size", getSizeFail);
    }

    if (setPruneList) {
        size_t len = strlen(setPruneList);
        /*extra 32 bytes are needed by  android_logger_set_prune_list */
        size_t bLen = len + 32;
        char *buf = NULL;
        if (asprintf(&buf, "%-*s", (int)(bLen - 1), setPruneList) > 0) {
            buf[len] = '\0';
            if (android_logger_set_prune_list(logger_list, buf, bLen)) {
                logcat_panic(HELP_FALSE, "failed to set the prune list");
            }
            free(buf);
        } else {
            logcat_panic(HELP_FALSE, "failed to set the prune list (alloc)");
        }
    }

    if (printStatistics || getPruneList) {
        size_t len = 8192;
        char *buf;

        for (int retry = 32;
                (retry >= 0) && ((buf = new char [len]));
                delete [] buf, buf = NULL, --retry) {
            if (getPruneList) {
                android_logger_get_prune_list(logger_list, buf, len);
            } else {
                android_logger_get_statistics(logger_list, buf, len);
            }
            buf[len-1] = '\0';
            if (atol(buf) < 3) {
                delete [] buf;
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
            logcat_panic(HELP_FALSE, "failed to read data");
        }

        // remove trailing FF
        char *cp = buf + len - 1;
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

        printf("%s", cp);
        delete [] buf;
        return EXIT_SUCCESS;
    }

    if (getLogSize) {
        return EXIT_SUCCESS;
    }
    if (setLogSize || setPruneList) {
        return EXIT_SUCCESS;
    }
    if (clearLog) {
        return EXIT_SUCCESS;
    }

    setupOutputAndSchedulingPolicy((mode & ANDROID_LOG_NONBLOCK) == 0);

    //LOG_EVENT_INT(10, 12345);
    //LOG_EVENT_LONG(11, 0x1122334455667788LL);
    //LOG_EVENT_STRING(0, "whassup, doc?");

    dev = NULL;
    log_device_t unexpected("unexpected", false);

    while (!g_maxCount || (g_printCount < g_maxCount)) {
        struct log_msg log_msg;
        log_device_t* d;
        int ret = android_logger_list_read(logger_list, &log_msg);

        if (ret == 0) {
            logcat_panic(HELP_FALSE, "read: unexpected EOF!\n");
        }

        if (ret < 0) {
            if (ret == -EAGAIN) {
                break;
            }

            if (ret == -EIO) {
                logcat_panic(HELP_FALSE, "read: unexpected EOF!\n");
            }
            if (ret == -EINVAL) {
                logcat_panic(HELP_FALSE, "read: unexpected length.\n");
            }
            logcat_panic(HELP_FALSE, "logcat read failure");
        }

        for (d = devices; d; d = d->next) {
            if (android_name_to_log_id(d->device) == log_msg.id()) {
                break;
            }
        }
        if (!d) {
            g_devCount = 2; // set to Multiple
            d = &unexpected;
            d->binary = log_msg.id() == LOG_ID_EVENTS;
        }

        if (dev != d) {
            dev = d;
            maybePrintStart(dev, printDividers);
        }
        if (g_printBinary) {
            printBinary(&log_msg);
        } else {
            processBuffer(dev, &log_msg);
        }
    }

    android_logger_list_free(logger_list);

    return EXIT_SUCCESS;
}
