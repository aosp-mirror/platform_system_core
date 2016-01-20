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

#ifndef BOOT_EVENT_RECORD_STORE_H_
#define BOOT_EVENT_RECORD_STORE_H_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <android-base/macros.h>
#include <gtest/gtest_prod.h>

// BootEventRecordStore manages the persistence of boot events to the record
// store and the retrieval of all boot event records from the store.
class BootEventRecordStore {
 public:
  // A BootEventRecord consists of the event name and the timestamp the event
  // occurred.
  typedef std::pair<std::string, int32_t> BootEventRecord;

  BootEventRecordStore();

  // Persists the boot event named |name| in the record store.
  void AddBootEvent(const std::string& name);

  // Returns a list of all of the boot events persisted in the record store.
  std::vector<BootEventRecord> GetAllBootEvents() const;

 private:
  // The tests call SetStorePath to override the default store location with a
  // more test-friendly path.
  FRIEND_TEST(BootEventRecordStoreTest, AddSingleBootEvent);
  FRIEND_TEST(BootEventRecordStoreTest, AddMultipleBootEvents);

  // Sets the filesystem path of the record store.
  void SetStorePath(const std::string& path);

  // Constructs the full path of the given boot |event|.
  std::string GetBootEventPath(const std::string& event) const;

  // The filesystem path of the record store.
  std::string store_path_;

  DISALLOW_COPY_AND_ASSIGN(BootEventRecordStore);
};

#endif  // BOOT_EVENT_RECORD_STORE_H_