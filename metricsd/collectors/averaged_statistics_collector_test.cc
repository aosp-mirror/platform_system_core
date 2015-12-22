/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "averaged_statistics_collector.h"

#include <memory>

#include <inttypes.h>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>


static const char kFakeDiskStatsFormat[] =
    "    1793     1788    %" PRIu64 "   105580    "
    "    196      175     %" PRIu64 "    30290    "
    "    0    44060   135850\n";
static const uint64_t kFakeReadSectors[] = {80000, 100000};
static const uint64_t kFakeWriteSectors[] = {3000, 4000};


class AveragedStatisticsTest : public testing::Test {
 protected:
  std::string kFakeDiskStats0;
  std::string kFakeDiskStats1;

  virtual void SetUp() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    disk_stats_path_ = temp_dir_.path().Append("disk_stats");
    collector_.reset(new AveragedStatisticsCollector(
        &metrics_lib_, disk_stats_path_.value(), ""));

    kFakeDiskStats0 = base::StringPrintf(kFakeDiskStatsFormat,
                                         kFakeReadSectors[0],
                                         kFakeWriteSectors[0]);
    kFakeDiskStats1 = base::StringPrintf(kFakeDiskStatsFormat,
                                         kFakeReadSectors[1],
                                         kFakeWriteSectors[1]);

    CreateFakeDiskStatsFile(kFakeDiskStats0);
  }

  // Creates or overwrites an input file containing fake disk stats.
  void CreateFakeDiskStatsFile(const std::string& fake_stats) {
    EXPECT_EQ(base::WriteFile(disk_stats_path_,
                              fake_stats.data(), fake_stats.size()),
              fake_stats.size());
  }

  // Collector used for tests.
  std::unique_ptr<AveragedStatisticsCollector> collector_;

  // Temporary directory used for tests.
  base::ScopedTempDir temp_dir_;

  // Path for the fake files.
  base::FilePath disk_stats_path_;

  MetricsLibrary metrics_lib_;
};

TEST_F(AveragedStatisticsTest, ParseDiskStats) {
  uint64_t read_sectors_now, write_sectors_now;
  CreateFakeDiskStatsFile(kFakeDiskStats0);
  ASSERT_TRUE(collector_->DiskStatsReadStats(&read_sectors_now,
                                             &write_sectors_now));
  EXPECT_EQ(read_sectors_now, kFakeReadSectors[0]);
  EXPECT_EQ(write_sectors_now, kFakeWriteSectors[0]);

  CreateFakeDiskStatsFile(kFakeDiskStats1);
  ASSERT_TRUE(collector_->DiskStatsReadStats(&read_sectors_now,
                                             &write_sectors_now));
  EXPECT_EQ(read_sectors_now, kFakeReadSectors[1]);
  EXPECT_EQ(write_sectors_now, kFakeWriteSectors[1]);
}

TEST_F(AveragedStatisticsTest, ParseVmStats) {
  static char kVmStats[] = "pswpin 1345\npswpout 8896\n"
    "foo 100\nbar 200\npgmajfault 42\netcetc 300\n";
  struct AveragedStatisticsCollector::VmstatRecord stats;
  EXPECT_TRUE(collector_->VmStatsParseStats(kVmStats, &stats));
  EXPECT_EQ(stats.page_faults, 42);
  EXPECT_EQ(stats.swap_in, 1345);
  EXPECT_EQ(stats.swap_out, 8896);
}
