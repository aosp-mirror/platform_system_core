// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_library.h"

#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

#define READ_WRITE_ALL_FILE_FLAGS \
  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

static const char kAutotestPath[] = "/var/log/metrics/autotest-events";
static const char kUMAEventsPath[] = "/var/log/metrics/uma-events";
static const char kConsentFile[] = "/home/chronos/Consent To Send Stats";
static const int32_t kBufferSize = 1024;

time_t MetricsLibrary::cached_enabled_time_ = 0;
bool MetricsLibrary::cached_enabled_ = false;

using std::string;

// TODO(sosa@chromium.org) - use Chromium logger instead of stderr
static void PrintError(const char* message, const char* file,
                       int code) {
  static const char kProgramName[] = "libmetrics";
  if (code == 0) {
    fprintf(stderr, "%s: %s\n", kProgramName, message);
  } else if (file == NULL) {
    fprintf(stderr, "%s: ", kProgramName);
    perror(message);
  } else {
    fprintf(stderr, "%s: %s: ", kProgramName, file);
    perror(message);
  }
}

MetricsLibrary::MetricsLibrary()
    : uma_events_file_(NULL),
      consent_file_(kConsentFile) {}

// We take buffer and buffer_size as parameters in order to simplify testing
// of various alignments of the |device_name| with |buffer_size|.
bool MetricsLibrary::IsDeviceMounted(const char* device_name,
                                     const char* mounts_file,
                                     char* buffer,
                                     int buffer_size,
                                     bool* result) {
  if (buffer == NULL || buffer_size < 1)
    return false;
  int mounts_fd = open(mounts_file, O_RDONLY);
  if (mounts_fd < 0)
    return false;
  // match_offset describes:
  //   -1 -- not beginning of line
  //   0..strlen(device_name)-1 -- this offset in device_name is next to match
  //   strlen(device_name) -- matched full name, just need a space.
  int match_offset = 0;
  bool match = false;
  while (!match) {
    int read_size = read(mounts_fd, buffer, buffer_size);
    if (read_size <= 0) {
      if (errno == -EINTR)
        continue;
      break;
    }
    for (int i = 0; i < read_size; ++i) {
      if (buffer[i] == '\n') {
        match_offset = 0;
        continue;
      }
      if (match_offset < 0) {
        continue;
      }
      if (device_name[match_offset] == '\0') {
        if (buffer[i] == ' ') {
          match = true;
          break;
        }
        match_offset = -1;
        continue;
      }

      if (buffer[i] == device_name[match_offset]) {
        ++match_offset;
      } else {
        match_offset = -1;
      }
    }
  }
  close(mounts_fd);
  *result = match;
  return true;
}

bool MetricsLibrary::IsGuestMode() {
  char buffer[256];
  bool result = false;
  if (!IsDeviceMounted("guestfs",
                       "/proc/mounts",
                       buffer,
                       sizeof(buffer),
                       &result)) {
    return false;
  }
  return result;
}

bool MetricsLibrary::AreMetricsEnabled() {
  static struct stat stat_buffer;
  time_t this_check_time = time(NULL);

  if (this_check_time != cached_enabled_time_) {
    cached_enabled_time_ = this_check_time;
    if (stat(consent_file_, &stat_buffer) >= 0 &&
        !IsGuestMode())
      cached_enabled_ = true;
    else
      cached_enabled_ = false;
  }
  return cached_enabled_;
}

bool MetricsLibrary::SendMessageToChrome(int32_t length, const char* message) {
  if (!AreMetricsEnabled())
    return true;

  int chrome_fd = open(uma_events_file_,
                       O_WRONLY | O_APPEND | O_CREAT,
                       READ_WRITE_ALL_FILE_FLAGS);
  // If we failed to open it, return.
  if (chrome_fd < 0) {
    PrintError("open", uma_events_file_, errno);
    return false;
  }

  // Need to chmod because open flags are anded with umask. Ignore the
  // exit code -- a chronos process may fail chmoding because the file
  // has been created by a root process but that should be OK.
  fchmod(chrome_fd, READ_WRITE_ALL_FILE_FLAGS);

  // Grab an exclusive lock to protect Chrome from truncating
  // underneath us. Keep the file locked as briefly as possible.
  if (flock(chrome_fd, LOCK_EX) < 0) {
    PrintError("flock", uma_events_file_, errno);
    close(chrome_fd);
    return false;
  }

  bool success = true;
  if (write(chrome_fd, message, length) != length) {
    PrintError("write", uma_events_file_, errno);
    success = false;
  }

  // Release the file lock and close file.
  if (flock(chrome_fd, LOCK_UN) < 0) {
    PrintError("unlock", uma_events_file_, errno);
    success = false;
  }
  close(chrome_fd);
  return success;
}

int32_t MetricsLibrary::FormatChromeMessage(int32_t buffer_size, char* buffer,
                                            const char* format, ...) {
  int32_t message_length;
  size_t len_size = sizeof(message_length);

  // Format the non-LENGTH contents in the buffer by leaving space for
  // LENGTH at the start of the buffer.
  va_list args;
  va_start(args, format);
  message_length = vsnprintf(&buffer[len_size], buffer_size - len_size,
                             format, args);
  va_end(args);

  if (message_length < 0) {
    PrintError("chrome message format error", NULL, 0);
    return -1;
  }

  // +1 to account for the trailing \0.
  message_length += len_size + 1;
  if (message_length > buffer_size) {
    PrintError("chrome message too long", NULL, 0);
    return -1;
  }

  // Prepend LENGTH to the message.
  memcpy(buffer, &message_length, len_size);
  return message_length;
}

void MetricsLibrary::Init() {
  uma_events_file_ = kUMAEventsPath;
}

bool MetricsLibrary::SendToAutotest(const string& name, int value) {
  FILE* autotest_file = fopen(kAutotestPath, "a+");
  if (autotest_file == NULL) {
    PrintError("fopen", kAutotestPath, errno);
    return false;
  }

  fprintf(autotest_file, "%s=%d\n", name.c_str(), value);
  fclose(autotest_file);
  return true;
}

bool MetricsLibrary::SendToUMA(const string& name, int sample,
                               int min, int max, int nbuckets) {
  // Format the message.
  char message[kBufferSize];
  int32_t message_length =
      FormatChromeMessage(kBufferSize, message,
                          "histogram%c%s %d %d %d %d", '\0',
                          name.c_str(), sample, min, max, nbuckets);

  if (message_length < 0)
    return false;

  // Send the message.
  return SendMessageToChrome(message_length, message);
}

bool MetricsLibrary::SendEnumToUMA(const std::string& name, int sample,
                                   int max) {
  // Format the message.
  char message[kBufferSize];
  int32_t message_length =
      FormatChromeMessage(kBufferSize, message,
                          "linearhistogram%c%s %d %d", '\0',
                          name.c_str(), sample, max);

  if (message_length < 0)
    return false;

  // Send the message.
  return SendMessageToChrome(message_length, message);
}
