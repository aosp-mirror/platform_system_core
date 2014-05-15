// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_library.h"

#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

// HANDLE_EINTR macro, no libbase required.
#include <base/posix/eintr_wrapper.h>

#include "policy/device_policy.h"

#define READ_WRITE_ALL_FILE_FLAGS \
  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static const char kAutotestPath[] = "/var/log/metrics/autotest-events";
static const char kUMAEventsPath[] = "/var/log/metrics/uma-events";
static const char kNewUMAEventsPath[] = "/var/run/metrics/uma-events";
static const char kConsentFile[] = "/home/chronos/Consent To Send Stats";
static const int32_t kBufferSize = 1024;
static const char kCrosEventHistogramName[] = "Platform.CrOSEvent";
static const int kCrosEventHistogramMax = 100;

/* Add new cros events here.
 *
 * The index of the event is sent in the message, so please do not
 * reorder the names.
 */
static const char *kCrosEventNames[] = {
  "ModemManagerCommandSendFailure",  // 0
  "HwWatchdogReboot",  // 1
  "Cras.NoCodecsFoundAtBoot",  // 2
  "Chaps.DatabaseCorrupted",  // 3
  "Chaps.DatabaseRepairFailure",  // 4
  "Chaps.DatabaseCreateFailure",  // 5
  "Attestation.OriginSpecificExhausted",  // 6
  "SpringPowerSupply.Original.High",  // 7
  "SpringPowerSupply.Other.High",  // 8
  "SpringPowerSupply.Original.Low",  // 9
  "SpringPowerSupply.ChargerIdle",  // 10
  "TPM.NonZeroDictionaryAttackCounter",  // 11
};

time_t MetricsLibrary::cached_enabled_time_ = 0;
bool MetricsLibrary::cached_enabled_ = false;

// Copied from libbase to avoid pulling in all of libbase just for libmetrics.
static int WriteFileDescriptor(const int fd, const char* data, int size) {
  // Allow for partial writes.
  ssize_t bytes_written_total = 0;
  for (ssize_t bytes_written_partial = 0; bytes_written_total < size;
       bytes_written_total += bytes_written_partial) {
    bytes_written_partial =
        HANDLE_EINTR(write(fd, data + bytes_written_total,
                           size - bytes_written_total));
    if (bytes_written_partial < 0)
      return -1;
  }

  return bytes_written_total;
}

MetricsLibrary::MetricsLibrary() : consent_file_(kConsentFile) {}
MetricsLibrary::~MetricsLibrary() {}

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
  return result && (access("/var/run/state/logged-in", F_OK) == 0);
}

bool MetricsLibrary::AreMetricsEnabled() {
  static struct stat stat_buffer;
  time_t this_check_time = time(NULL);
  if (this_check_time != cached_enabled_time_) {
    cached_enabled_time_ = this_check_time;

    if (!policy_provider_.get())
      policy_provider_.reset(new policy::PolicyProvider());
    policy_provider_->Reload();
    // We initialize with the default value which is false and will be preserved
    // if the policy is not set.
    bool enabled = false;
    bool has_policy = false;
    if (policy_provider_->device_policy_is_loaded()) {
      has_policy =
          policy_provider_->GetDevicePolicy().GetMetricsEnabled(&enabled);
    }
    // If policy couldn't be loaded or the metrics policy is not set we should
    // still respect the consent file if it is present for migration purposes.
    // TODO(pastarmovj)
    if (!has_policy) {
      enabled = stat(consent_file_.c_str(), &stat_buffer) >= 0;
    }

    if (enabled && !IsGuestMode())
      cached_enabled_ = true;
    else
      cached_enabled_ = false;
  }
  return cached_enabled_;
}

bool MetricsLibrary::StoreMessageInFile(const std::string& message,
                                        const std::string& events_file) {
  int size = static_cast<int>(message.size());
  if (size > kBufferSize) {
    LOG(ERROR) << "chrome message too big (" << size << " bytes)";
    return false;
  }
  // Use libc here instead of chromium base classes because we need a UNIX fd
  // for flock.
  int chrome_fd = HANDLE_EINTR(open(events_file.c_str(),
                                    O_WRONLY | O_APPEND | O_CREAT,
                                    READ_WRITE_ALL_FILE_FLAGS));
  // If we failed to open it, return.
  if (chrome_fd < 0) {
    PLOG(ERROR) << events_file << ": open";
    return false;
  }

  // Need to chmod because open flags are anded with umask. Ignore the
  // exit code -- a chronos process may fail chmoding because the file
  // has been created by a root process but that should be OK.
  fchmod(chrome_fd, READ_WRITE_ALL_FILE_FLAGS);

  // Grab an exclusive lock to protect Chrome from truncating
  // underneath us.
  if (HANDLE_EINTR(flock(chrome_fd, LOCK_EX)) < 0) {
    PLOG(ERROR) << events_file << ": flock";
    IGNORE_EINTR(close(chrome_fd));
    return false;
  }

  bool success = true;
  if (WriteFileDescriptor(chrome_fd, message.c_str(), size) != size) {
    PLOG(ERROR) << events_file << ": write";
    success = false;
  }

  // Close the file and release the lock.
  IGNORE_EINTR(close(chrome_fd));
  return success;
}

bool MetricsLibrary::SendMessageToChrome(const std::string& message) {
  // TEMPORARY: store to both new and old file, to facilitate change if the
  // Chrome side is out of sync with this.  See crbug.com/373833.

  // If one store fails, we'll be cool... hey man it's OK, you know, whatever.
  // If both stores fail, then definitely something is wrong.
  bool success = StoreMessageInFile(message, uma_events_file_);
  success |= StoreMessageInFile(message, new_uma_events_file_);
  return success;
}

const std::string MetricsLibrary::FormatChromeMessage(
    const std::string& name,
    const std::string& value) {
  uint32 message_length =
      sizeof(message_length) + name.size() + 1 + value.size() + 1;
  std::string result;
  result.reserve(message_length);
  // Marshal the total message length in the native byte order.
  result.assign(reinterpret_cast<char*>(&message_length),
                sizeof(message_length));
  result += name + '\0' + value + '\0';
  return result;
}

void MetricsLibrary::Init() {
  uma_events_file_ = kUMAEventsPath;
  new_uma_events_file_ = kNewUMAEventsPath;
}

bool MetricsLibrary::SendToAutotest(const std::string& name, int value) {
  FILE* autotest_file = fopen(kAutotestPath, "a+");
  if (autotest_file == NULL) {
    PLOG(ERROR) << kAutotestPath << ": fopen";
    return false;
  }

  fprintf(autotest_file, "%s=%d\n", name.c_str(), value);
  fclose(autotest_file);
  return true;
}

bool MetricsLibrary::SendToUMA(const std::string& name,
                               int sample,
                               int min,
                               int max,
                               int nbuckets) {
  // Format the message.
  std::string value = base::StringPrintf("%s %d %d %d %d",
      name.c_str(), sample, min, max, nbuckets);
  std::string message = FormatChromeMessage("histogram", value);
  // Send the message.
  return SendMessageToChrome(message);
}

bool MetricsLibrary::SendEnumToUMA(const std::string& name, int sample,
                                   int max) {
  // Format the message.
  std::string value = base::StringPrintf("%s %d %d", name.c_str(), sample, max);
  std::string message = FormatChromeMessage("linearhistogram", value);
  // Send the message.
  return SendMessageToChrome(message);
}

bool MetricsLibrary::SendSparseToUMA(const std::string& name, int sample) {
  // Format the message.
  std::string value = base::StringPrintf("%s %d", name.c_str(), sample);
  std::string message = FormatChromeMessage("sparsehistogram", value);
  // Send the message.
  return SendMessageToChrome(message);
}

bool MetricsLibrary::SendUserActionToUMA(const std::string& action) {
  // Format the message.
  std::string message = FormatChromeMessage("useraction", action);
  // Send the message.
  return SendMessageToChrome(message);
}

bool MetricsLibrary::SendCrashToUMA(const char *crash_kind) {
  // Format the message.
  std::string message = FormatChromeMessage("crash", crash_kind);
  // Send the message.
  return SendMessageToChrome(message);
}

void MetricsLibrary::SetPolicyProvider(policy::PolicyProvider* provider) {
  policy_provider_.reset(provider);
}

bool MetricsLibrary::SendCrosEventToUMA(const std::string& event) {
  for (size_t i = 0; i < ARRAY_SIZE(kCrosEventNames); i++) {
    if (strcmp(event.c_str(), kCrosEventNames[i]) == 0) {
      return SendEnumToUMA(kCrosEventHistogramName, i, kCrosEventHistogramMax);
    }
  }
  return false;
}
