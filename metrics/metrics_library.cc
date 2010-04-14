// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * metrics_library.cc
 *
 *  Created on: Dec 1, 2009
 *      Author: sosa
 */

#include "metrics_library.h"

#include <errno.h>
#include <sys/file.h>
#include <string.h>
#include <stdio.h>

#define READ_WRITE_ALL_FILE_FLAGS \
  (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH)

static const char kAutotestPath[] = "/tmp/.chromeos-metrics-autotest";
static const char kChromePath[] = "/tmp/.chromeos-metrics";
static const int kBufferSize = 4096;

using namespace std;

// TODO(sosa@chromium.org) - use Chromium logger instead of stderr
void MetricsLibrary::PrintError(const char *message, const char *file,
                               int code) {
  const char *kProgramName = "metrics_library";
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

void MetricsLibrary::SendToAutotest(string name, string value) {
  FILE *autotest_file = fopen(kAutotestPath, "a+");
  if (autotest_file == NULL) {
    PrintError("fopen", kAutotestPath, errno);
    return;
  }

  fprintf(autotest_file, "%s=%s\n", name.c_str(), value.c_str());
  fclose(autotest_file);
}

void MetricsLibrary::SendToChrome(string name, string value) {
  int chrome_fd = open(kChromePath,
                       O_WRONLY | O_APPEND | O_CREAT,
                       READ_WRITE_ALL_FILE_FLAGS);
  // If we failed to open it, return
  if (chrome_fd < 0) {
    PrintError("open", kChromePath, errno);
    return;
  }

  // Need to chmod because open flags are anded with umask.
  if (fchmod(chrome_fd, READ_WRITE_ALL_FILE_FLAGS) < 0) {
    PrintError("fchmod", kChromePath, errno);
    close(chrome_fd);
    return;
  }

  // Grab an exclusive lock to protect Chrome from truncating underneath us
  if (flock(chrome_fd, LOCK_EX) < 0) {
    PrintError("flock", kChromePath, errno);
    close(chrome_fd);
    return;
  }

  // Message format is: LENGTH (binary), NAME, VALUE
  char message[kBufferSize];
  char *curr_ptr = message;
  int32_t message_length =
      name.length() + value.length() + 2 + sizeof(message_length);
  if (message_length > static_cast<int32_t>(sizeof(message)))
    PrintError("name/value too long", NULL, 0);

  // Make sure buffer is blanked
  memset(message, 0, sizeof(message));
  memcpy(curr_ptr, &message_length, sizeof(message_length));
  curr_ptr += sizeof(message_length);
  strncpy(curr_ptr, name.c_str(), name.length());
  curr_ptr += name.length() + 1;
  strncpy(curr_ptr, value.c_str(), value.length());
  if (write(chrome_fd, message, message_length) != message_length)
    PrintError("write", kChromePath, errno);

  // Release the file lock and close file
  if (flock(chrome_fd, LOCK_UN) < 0)
    PrintError("unlock", kChromePath, errno);
  close(chrome_fd);
}
