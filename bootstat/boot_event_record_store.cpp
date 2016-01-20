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

#include "boot_event_record_store.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <utime.h>
#include <cstdlib>
#include <android-base/file.h>
#include <android-base/logging.h>

namespace {

const char BOOTSTAT_DATA_DIR[] = "/data/misc/bootstat/";

// Given a boot even record file at |path|, extracts the event's relative time
// from the record into |uptime|.
bool ParseRecordEventTime(const std::string& path, int32_t* uptime) {
  DCHECK_NE(static_cast<int32_t*>(nullptr), uptime);

  struct stat file_stat;
  if (stat(path.c_str(), &file_stat) == -1) {
    PLOG(ERROR) << "Failed to read " << path;
    return false;
  }

  *uptime = file_stat.st_mtime;
  return true;
}

}  // namespace

BootEventRecordStore::BootEventRecordStore() {
  SetStorePath(BOOTSTAT_DATA_DIR);
}

void BootEventRecordStore::AddBootEvent(const std::string& name) {
  std::string uptime_str;
  if (!android::base::ReadFileToString("/proc/uptime", &uptime_str)) {
    LOG(ERROR) << "Failed to read /proc/uptime";
  }

  std::string record_path = GetBootEventPath(name);
  if (creat(record_path.c_str(), S_IRUSR | S_IWUSR) == -1) {
    PLOG(ERROR) << "Failed to create " << record_path;
  }

  struct stat file_stat;
  if (stat(record_path.c_str(), &file_stat) == -1) {
    PLOG(ERROR) << "Failed to read " << record_path;
  }

  // Cast intentionally rounds down.
  time_t uptime = static_cast<time_t>(strtod(uptime_str.c_str(), NULL));
  struct utimbuf times = {file_stat.st_atime, uptime};
  if (utime(record_path.c_str(), &times) == -1) {
    PLOG(ERROR) << "Failed to set mtime for " << record_path;
  }
}

std::vector<BootEventRecordStore::BootEventRecord> BootEventRecordStore::
    GetAllBootEvents() const {
  std::vector<BootEventRecord> events;

  std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(store_path_.c_str()), closedir);

  // This case could happen due to external manipulation of the filesystem,
  // so crash out if the record store doesn't exist.
  CHECK_NE(static_cast<DIR*>(nullptr), dir.get());

  struct dirent* entry;
  while ((entry = readdir(dir.get())) != NULL) {
    // Only parse regular files.
    if (entry->d_type != DT_REG) {
      continue;
    }

    const std::string event = entry->d_name;
    const std::string record_path = GetBootEventPath(event);
    int32_t uptime;
    if (!ParseRecordEventTime(record_path, &uptime)) {
      LOG(ERROR) << "Failed to parse boot time record: " << record_path;
      continue;
    }

    events.push_back(std::make_pair(event, uptime));
  }

  return events;
}

void BootEventRecordStore::SetStorePath(const std::string& path) {
  DCHECK_EQ('/', path.back());
  store_path_ = path;
}

std::string BootEventRecordStore::GetBootEventPath(
    const std::string& event) const {
  DCHECK_EQ('/', store_path_.back());
  return store_path_ + event;
}
