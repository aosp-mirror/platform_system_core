/*
 * Copyright (C) 2013 The Android Open Source Project
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
 *
 * This flex program reads /var/log/messages as it grows and saves kernel
 * warnings to files.  It keeps track of warnings it has seen (based on
 * file/line only, ignoring differences in the stack trace), and reports only
 * the first warning of each kind, but maintains a count of all warnings by
 * using their hashes as buckets in a UMA sparse histogram.  It also invokes
 * the crash collector, which collects the warnings and prepares them for later
 * shipment to the crash server.
 */

%option noyywrap

%{
#include <fcntl.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdarg.h>
#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "metrics/c_metrics_library.h"

int WarnStart(void);
void WarnEnd(void);
void WarnInput(char *buf, yy_size_t *result, size_t max_size);

#define YY_INPUT(buf, result, max_size) WarnInput(buf, &result, max_size)

%}

/* Define a few useful regular expressions. */

D               [0-9]
PREFIX          .*" kernel: [ "*{D}+"."{D}+"]"
CUT_HERE        {PREFIX}" ------------[ cut here".*
WARNING         {PREFIX}" WARNING: at "
END_TRACE       {PREFIX}" ---[ end trace".*

/* Use exclusive start conditions. */
%x PRE_WARN WARN

%%
 /* The scanner itself. */

^{CUT_HERE}\n{WARNING}          BEGIN(PRE_WARN);
.|\n                            /* ignore all other input in state 0 */
<PRE_WARN>[^ ]+.[^ ]+\n         if (WarnStart()) {
                                  /* yytext is
                                     "file:line func+offset/offset()\n" */
                                  BEGIN(WARN); ECHO;
                                } else {
                                  BEGIN(0);
                                }

 /* Assume the warning ends at the "end trace" line */
<WARN>^{END_TRACE}\n            ECHO; BEGIN(0); WarnEnd();
<WARN>^.*\n                     ECHO;

%%

#define HASH_BITMAP_SIZE        (1 << 15)  /* size in bits */
#define HASH_BITMAP_MASK        (HASH_BITMAP_SIZE - 1)

const char warn_hist_name[] = "Platform.KernelWarningHashes";
uint32_t hash_bitmap[HASH_BITMAP_SIZE / 32];
CMetricsLibrary metrics_library;

const char *prog_name;          /* the name of this program */
int yyin_fd;                    /* instead of FILE *yyin to avoid buffering */
int i_fd;                       /* for inotify, to detect file changes */
int testing;                    /* 1 if running test */
int filter;                     /* 1 when using as filter (for development) */
int fifo;                       /* 1 when reading from fifo (for devel) */
int draining;                   /* 1 when draining renamed log file */

const char *msg_path = "/var/log/messages";
const char warn_dump_dir[]  = "/var/run/kwarn";
const char *warn_dump_path = "/var/run/kwarn/warning";
const char *crash_reporter_command;

__attribute__((__format__(__printf__, 1, 2)))
static void Die(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  fprintf(stderr, "%s: ", prog_name);
  vfprintf(stderr, format, ap);
  exit(1);
}

static void RunCrashReporter(void) {
  int status = system(crash_reporter_command);
  if (status != 0)
    Die("%s exited with status %d\n", crash_reporter_command, status);
}

static uint32_t StringHash(const char *string) {
  uint32_t hash = 0;
  while (*string != '\0') {
    hash = (hash << 5) + hash + *string++;
  }
  return hash;
}

/* We expect only a handful of different warnings per boot session, so the
 * probability of a collision is very low, and statistically it won't matter
 * (unless warnings with the same hash also happens in tandem, which is even
 * rarer).
 */
static int HashSeen(uint32_t hash) {
  int word_index = (hash & HASH_BITMAP_MASK) / 32;
  int bit_index = (hash & HASH_BITMAP_MASK) % 32;
  return hash_bitmap[word_index] & 1 << bit_index;
}

static void SetHashSeen(uint32_t hash) {
  int word_index = (hash & HASH_BITMAP_MASK) / 32;
  int bit_index = (hash & HASH_BITMAP_MASK) % 32;
  hash_bitmap[word_index] |= 1 << bit_index;
}

#pragma GCC diagnostic ignored "-Wwrite-strings"
int WarnStart(void) {
  uint32_t hash;
  char *spacep;

  if (filter)
    return 1;

  hash = StringHash(yytext);
  if (!(testing || fifo || filter)) {
    CMetricsLibrarySendSparseToUMA(metrics_library, warn_hist_name, (int) hash);
  }
  if (HashSeen(hash))
    return 0;
  SetHashSeen(hash);

  yyout = fopen(warn_dump_path, "w");
  if (yyout == NULL)
    Die("fopen %s failed: %s\n", warn_dump_path, strerror(errno));
  spacep = strchr(yytext, ' ');
  if (spacep == NULL || spacep[1] == '\0')
    spacep = "unknown-function";
  fprintf(yyout, "%08x-%s\n", hash, spacep + 1);
  return 1;
}

void WarnEnd(void) {
  if (filter)
    return;
  fclose(yyout);
  yyout = stdout;               /* for debugging */
  RunCrashReporter();
}

static void WarnOpenInput(const char *path) {
  yyin_fd = open(path, O_RDONLY);
  if (yyin_fd < 0)
    Die("could not open %s: %s\n", path, strerror(errno));
  if (!fifo) {
    /* Go directly to the end of the file.  We don't want to parse the same
     * warnings multiple times on reboot/restart.  We might miss some
     * warnings, but so be it---it's too hard to keep track reliably of the
     * last parsed position in the syslog.
     */
    if (lseek(yyin_fd, 0, SEEK_END) < 0)
      Die("could not lseek %s: %s\n", path, strerror(errno));
    /* Set up notification of file growth and rename. */
    i_fd = inotify_init();
    if (i_fd < 0)
      Die("inotify_init: %s\n", strerror(errno));
    if (inotify_add_watch(i_fd, path, IN_MODIFY | IN_MOVE_SELF) < 0)
      Die("inotify_add_watch: %s\n", strerror(errno));
  }
}

/* We replace the default YY_INPUT() for the following reasons:
 *
 * 1.  We want to read data as soon as it becomes available, but the default
 * YY_INPUT() uses buffered I/O.
 *
 * 2.  We want to block on end of input and wait for the file to grow.
 *
 * 3.  We want to detect log rotation, and reopen the input file as needed.
 */
void WarnInput(char *buf, yy_size_t *result, size_t max_size) {
  while (1) {
    ssize_t ret = read(yyin_fd, buf, max_size);
    if (ret < 0)
      Die("read: %s", strerror(errno));
    *result = ret;
    if (*result > 0 || fifo || filter)
      return;
    if (draining) {
      /* Assume we're done with this log, and move to next
       * log.  Rsyslogd may keep writing to the old log file
       * for a while, but we don't care since we don't have
       * to be exact.
       */
      close(yyin_fd);
      if (YYSTATE == WARN) {
        /* Be conservative in case we lose the warn
         * terminator during the switch---or we may
         * collect personally identifiable information.
         */
        WarnEnd();
      }
      BEGIN(0);        /* see above comment */
      sleep(1);        /* avoid race with log rotator */
      WarnOpenInput(msg_path);
      draining = 0;
      continue;
    }
    /* Nothing left to read, so we must wait. */
    struct inotify_event event;
    while (1) {
      int n = read(i_fd, &event, sizeof(event));
      if (n <= 0) {
        if (errno == EINTR)
          continue;
        else
          Die("inotify: %s\n", strerror(errno));
      } else
        break;
    }
    if (event.mask & IN_MOVE_SELF) {
      /* The file has been renamed.  Before switching
       * to the new one, we process any remaining
       * content of this file.
       */
      draining = 1;
    }
  }
}

int main(int argc, char **argv) {
  int result;
  struct passwd *user;
  prog_name = argv[0];

  if (argc == 2 && strcmp(argv[1], "--test") == 0)
    testing = 1;
  else if (argc == 2 && strcmp(argv[1], "--filter") == 0)
    filter = 1;
  else if (argc == 2 && strcmp(argv[1], "--fifo") == 0) {
    fifo = 1;
  } else if (argc != 1) {
    fprintf(stderr,
            "usage: %s [single-flag]\n"
            "flags (for testing only):\n"
            "--fifo\tinput is fifo \"fifo\", output is stdout\n"
            "--filter\tinput is stdin, output is stdout\n"
            "--test\trun self-test\n",
            prog_name);
    exit(1);
  }

  metrics_library = CMetricsLibraryNew();
  CMetricsLibraryInit(metrics_library);

  crash_reporter_command = testing ?
    "./warn_collector_test_reporter.sh" :
    "/sbin/crash_reporter --kernel_warning";

  /* When filtering with --filter (for development) use stdin for input.
   * Otherwise read input from a file or a fifo.
   */
  yyin_fd = fileno(stdin);
  if (testing) {
    msg_path = "messages";
    warn_dump_path = "warning";
  }
  if (fifo) {
    msg_path = "fifo";
  }
  if (!filter) {
    WarnOpenInput(msg_path);
  }

  /* Create directory for dump file.  Still need to be root here. */
  unlink(warn_dump_path);
  if (!testing && !fifo && !filter) {
    rmdir(warn_dump_dir);
    result = mkdir(warn_dump_dir, 0755);
    if (result < 0)
      Die("could not create %s: %s\n",
          warn_dump_dir, strerror(errno));
  }

  if (0) {
    /* TODO(semenzato): put this back in once we decide it's safe
     * to make /var/spool/crash rwxrwxrwx root, or use a different
     * owner and setuid for the crash reporter as well.
     */

    /* Get low privilege uid, gid. */
    user = getpwnam("chronos");
    if (user == NULL)
      Die("getpwnam failed\n");

    /* Change dump directory ownership. */
    if (chown(warn_dump_dir, user->pw_uid, user->pw_gid) < 0)
      Die("chown: %s\n", strerror(errno));

    /* Drop privileges. */
    if (setuid(user->pw_uid) < 0) {
      Die("setuid: %s\n", strerror(errno));
    }
  }

  /* Go! */
  return yylex();
}

/* Flex should really know not to generate these functions.
 */
void UnusedFunctionWarningSuppressor(void) {
  yyunput(0, 0);
}
