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

#include <chrono>
#include <deque>
#include <fcntl.h>
#include <random>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <healthhalutils/HealthHalUtils.h>
#include <storaged.h>               // data structures
#include <storaged_utils.h>         // functions to test

#define MMC_DISK_STATS_PATH "/sys/block/mmcblk0/stat"
#define SDA_DISK_STATS_PATH "/sys/block/sda/stat"

using namespace std;
using namespace chrono;
using namespace storaged_proto;

namespace {

void write_and_pause(uint32_t sec) {
    const char* path = "/cache/test";
    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    ASSERT_LT(-1, fd);
    char buffer[2048];
    memset(buffer, 1, sizeof(buffer));
    int loop_size = 100;
    for (int i = 0; i < loop_size; ++i) {
        ASSERT_EQ(2048, write(fd, buffer, sizeof(buffer)));
    }
    fsync(fd);
    close(fd);

    fd = open(path, O_RDONLY);
    ASSERT_LT(-1, fd);
    for (int i = 0; i < loop_size; ++i) {
        ASSERT_EQ(2048, read(fd, buffer, sizeof(buffer)));
    }
    close(fd);

    sleep(sec);
}

} // namespace

// the return values of the tested functions should be the expected ones
const char* DISK_STATS_PATH;
TEST(storaged_test, retvals) {
    struct disk_stats stats;
    memset(&stats, 0, sizeof(struct disk_stats));

    if (access(MMC_DISK_STATS_PATH, R_OK) >= 0) {
        DISK_STATS_PATH = MMC_DISK_STATS_PATH;
    } else if (access(SDA_DISK_STATS_PATH, R_OK) >= 0) {
        DISK_STATS_PATH = SDA_DISK_STATS_PATH;
    } else {
        return;
    }

    EXPECT_TRUE(parse_disk_stats(DISK_STATS_PATH, &stats));

    struct disk_stats old_stats;
    memset(&old_stats, 0, sizeof(struct disk_stats));
    old_stats = stats;

    const char wrong_path[] = "/this/is/wrong";
    EXPECT_FALSE(parse_disk_stats(wrong_path, &stats));

    // reading a wrong path should not damage the output structure
    EXPECT_EQ(stats, old_stats);
}

TEST(storaged_test, disk_stats) {
    struct disk_stats stats = {};
    ASSERT_TRUE(parse_disk_stats(DISK_STATS_PATH, &stats));

    // every entry of stats (except io_in_flight) should all be greater than 0
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        if (i == 8) continue; // skip io_in_flight which can be 0
        EXPECT_LT((uint64_t)0, *((uint64_t*)&stats + i));
    }

    // accumulation of the increments should be the same with the overall increment
    struct disk_stats base = {}, tmp = {}, curr, acc = {}, inc[5];
    for (uint i = 0; i < 5; ++i) {
        ASSERT_TRUE(parse_disk_stats(DISK_STATS_PATH, &curr));
        if (i == 0) {
            base = curr;
            tmp = curr;
            sleep(5);
            continue;
        }
        get_inc_disk_stats(&tmp, &curr, &inc[i]);
        add_disk_stats(&inc[i], &acc);
        tmp = curr;
        write_and_pause(5);
    }
    struct disk_stats overall_inc = {};
    get_inc_disk_stats(&base, &curr, &overall_inc);

    EXPECT_EQ(overall_inc, acc);
}

double mean(std::deque<uint32_t> nums) {
    double sum = 0.0;
    for (uint32_t i : nums) {
    sum += i;
    }
    return sum / nums.size();
}

double standard_deviation(std::deque<uint32_t> nums) {
    double sum = 0.0;
    double avg = mean(nums);
    for (uint32_t i : nums) {
    sum += ((double)i - avg) * ((double)i - avg);
    }
    return sqrt(sum / nums.size());
}

TEST(storaged_test, stream_stats) {
    // 100 random numbers
    std::vector<uint32_t> data = {8147,9058,1270,9134,6324,975,2785,5469,9575,9649,1576,9706,9572,4854,8003,1419,4218,9157,7922,9595,6557,357,8491,9340,6787,7577,7431,3922,6555,1712,7060,318,2769,462,971,8235,6948,3171,9502,344,4387,3816,7655,7952,1869,4898,4456,6463,7094,7547,2760,6797,6551,1626,1190,4984,9597,3404,5853,2238,7513,2551,5060,6991,8909,9593,5472,1386,1493,2575,8407,2543,8143,2435,9293,3500,1966,2511,6160,4733,3517,8308,5853,5497,9172,2858,7572,7537,3804,5678,759,540,5308,7792,9340,1299,5688,4694,119,3371};
    std::deque<uint32_t> test_data;
    stream_stats sstats;
    for (uint32_t i : data) {
        test_data.push_back(i);
        sstats.add(i);

        EXPECT_EQ((int)standard_deviation(test_data), (int)sstats.get_std());
        EXPECT_EQ((int)mean(test_data), (int)sstats.get_mean());
    }

    for (uint32_t i : data) {
        test_data.pop_front();
        sstats.evict(i);

        EXPECT_EQ((int)standard_deviation(test_data), (int)sstats.get_std());
        EXPECT_EQ((int)mean(test_data), (int)sstats.get_mean());
    }

    // some real data
    std::vector<uint32_t> another_data = {113875,81620,103145,28327,86855,207414,96526,52567,28553,250311};
    test_data.clear();
    uint32_t window_size = 2;
    uint32_t idx;
    stream_stats sstats1;
    for (idx = 0; idx < window_size; ++idx) {
        test_data.push_back(another_data[idx]);
        sstats1.add(another_data[idx]);
    }
    EXPECT_EQ((int)standard_deviation(test_data), (int)sstats1.get_std());
    EXPECT_EQ((int)mean(test_data), (int)sstats1.get_mean());
    for (;idx < another_data.size(); ++idx) {
        test_data.pop_front();
        sstats1.evict(another_data[idx - window_size]);
        test_data.push_back(another_data[idx]);
        sstats1.add(another_data[idx]);
        EXPECT_EQ((int)standard_deviation(test_data), (int)sstats1.get_std());
        EXPECT_EQ((int)mean(test_data), (int)sstats1.get_mean());
    }
}

struct disk_perf disk_perf_multiply(struct disk_perf perf, double mul) {
    struct disk_perf retval;
    retval.read_perf = (double)perf.read_perf * mul;
    retval.read_ios = (double)perf.read_ios * mul;
    retval.write_perf = (double)perf.write_perf * mul;
    retval.write_ios = (double)perf.write_ios * mul;
    retval.queue = (double)perf.queue * mul;

    return retval;
}

struct disk_stats disk_stats_add(struct disk_stats stats1, struct disk_stats stats2) {
    struct disk_stats retval;
    retval.read_ios = stats1.read_ios + stats2.read_ios;
    retval.read_merges = stats1.read_merges + stats2.read_merges;
    retval.read_sectors = stats1.read_sectors + stats2.read_sectors;
    retval.read_ticks = stats1.read_ticks + stats2.read_ticks;
    retval.write_ios = stats1.write_ios + stats2.write_ios;
    retval.write_merges = stats1.write_merges + stats2.write_merges;
    retval.write_sectors = stats1.write_sectors + stats2.write_sectors;
    retval.write_ticks = stats1.write_ticks + stats2.write_ticks;
    retval.io_in_flight = stats1.io_in_flight + stats2.io_in_flight;
    retval.io_ticks = stats1.io_ticks + stats2.io_ticks;
    retval.io_in_queue = stats1.io_in_queue + stats2.io_in_queue;
    retval.end_time = stats1.end_time + stats2.end_time;

    return retval;
}

void expect_increasing(struct disk_stats stats1, struct disk_stats stats2) {
    EXPECT_LE(stats1.read_ios, stats2.read_ios);
    EXPECT_LE(stats1.read_merges, stats2.read_merges);
    EXPECT_LE(stats1.read_sectors, stats2.read_sectors);
    EXPECT_LE(stats1.read_ticks, stats2.read_ticks);
    EXPECT_LE(stats1.write_ios, stats2.write_ios);
    EXPECT_LE(stats1.write_merges, stats2.write_merges);
    EXPECT_LE(stats1.write_sectors, stats2.write_sectors);
    EXPECT_LE(stats1.write_ticks, stats2.write_ticks);
    EXPECT_LE(stats1.io_ticks, stats2.io_ticks);
    EXPECT_LE(stats1.io_in_queue, stats2.io_in_queue);

    EXPECT_TRUE(stats1.read_ios < stats2.read_ios ||
        stats1.read_merges < stats2.read_merges ||
        stats1.read_sectors < stats2.read_sectors ||
        stats1.read_ticks < stats2.read_ticks ||
        stats1.write_ios < stats2.write_ios ||
        stats1.write_merges < stats2.write_merges ||
        stats1.write_sectors < stats2.write_sectors ||
        stats1.write_ticks < stats2.write_ticks ||
        stats1.io_ticks < stats2.io_ticks ||
        stats1.io_in_queue < stats2.io_in_queue);
}

TEST(storaged_test, disk_stats_monitor) {
    using android::hardware::health::V2_0::get_health_service;

    auto healthService = get_health_service();

    // asserting that there is one file for diskstats
    ASSERT_TRUE(healthService != nullptr || access(MMC_DISK_STATS_PATH, R_OK) >= 0 ||
                access(SDA_DISK_STATS_PATH, R_OK) >= 0);

    // testing if detect() will return the right value
    disk_stats_monitor dsm_detect{healthService};
    ASSERT_TRUE(dsm_detect.enabled());
    // feed monitor with constant perf data for io perf baseline
    // using constant perf is reasonable since the functionality of stream_stats
    // has already been tested
    struct disk_perf norm_perf = {
        .read_perf = 10 * 1024,
        .read_ios = 50,
        .write_perf = 5 * 1024,
        .write_ios = 25,
        .queue = 5
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> rand(0.8, 1.2);

    for (uint i = 0; i < dsm_detect.mWindow; ++i) {
        struct disk_perf perf = disk_perf_multiply(norm_perf, rand(gen));

        dsm_detect.add(&perf);
        dsm_detect.mBuffer.push(perf);
        EXPECT_EQ(dsm_detect.mBuffer.size(), (uint64_t)i + 1);
    }

    dsm_detect.mValid = true;
    dsm_detect.update_mean();
    dsm_detect.update_std();

    for (double i = 0; i < 2 * dsm_detect.mSigma; i += 0.5) {
        struct disk_perf test_perf;
        struct disk_perf test_mean = dsm_detect.mMean;
        struct disk_perf test_std = dsm_detect.mStd;

        test_perf.read_perf = (double)test_mean.read_perf - i * test_std.read_perf;
        test_perf.read_ios = (double)test_mean.read_ios - i * test_std.read_ios;
        test_perf.write_perf = (double)test_mean.write_perf - i * test_std.write_perf;
        test_perf.write_ios = (double)test_mean.write_ios - i * test_std.write_ios;
        test_perf.queue = (double)test_mean.queue + i * test_std.queue;

        EXPECT_EQ((i > dsm_detect.mSigma), dsm_detect.detect(&test_perf));
    }

    // testing if stalled disk_stats can be correctly accumulated in the monitor
    disk_stats_monitor dsm_acc{healthService};
    struct disk_stats norm_inc = {
        .read_ios = 200,
        .read_merges = 0,
        .read_sectors = 200,
        .read_ticks = 200,
        .write_ios = 100,
        .write_merges = 0,
        .write_sectors = 100,
        .write_ticks = 100,
        .io_in_flight = 0,
        .io_ticks = 600,
        .io_in_queue = 300,
        .start_time = 0,
        .end_time = 100,
        .counter = 0,
        .io_avg = 0
    };

    struct disk_stats stall_inc = {
        .read_ios = 200,
        .read_merges = 0,
        .read_sectors = 20,
        .read_ticks = 200,
        .write_ios = 100,
        .write_merges = 0,
        .write_sectors = 10,
        .write_ticks = 100,
        .io_in_flight = 0,
        .io_ticks = 600,
        .io_in_queue = 1200,
        .start_time = 0,
        .end_time = 100,
        .counter = 0,
        .io_avg = 0
    };

    struct disk_stats stats_base = {};
    int loop_size = 100;
    for (int i = 0; i < loop_size; ++i) {
        stats_base = disk_stats_add(stats_base, norm_inc);
        dsm_acc.update(&stats_base);
        EXPECT_EQ(dsm_acc.mValid, (uint32_t)i >= dsm_acc.mWindow);
        EXPECT_FALSE(dsm_acc.mStall);
    }

    stats_base = disk_stats_add(stats_base, stall_inc);
    dsm_acc.update(&stats_base);
    EXPECT_TRUE(dsm_acc.mValid);
    EXPECT_TRUE(dsm_acc.mStall);

    for (int i = 0; i < 10; ++i) {
        stats_base = disk_stats_add(stats_base, norm_inc);
        dsm_acc.update(&stats_base);
        EXPECT_TRUE(dsm_acc.mValid);
        EXPECT_FALSE(dsm_acc.mStall);
    }

    struct disk_stats stats_prev = {};
    loop_size = 10;
    write_and_pause(5);
    for (int i = 0; i < loop_size; ++i) {
        dsm_detect.update();
        expect_increasing(stats_prev, dsm_detect.mPrevious);
        stats_prev = dsm_detect.mPrevious;
        write_and_pause(5);
    }
}

TEST(storaged_test, storage_info_t) {
    storage_info_t si;
    time_point<steady_clock> tp;
    time_point<system_clock> stp;

    // generate perf history [least_recent  ------> most recent]
    // day 1:   5,  10,  15,  20            | daily average 12
    // day 2:  25,  30,  35,  40,  45       | daily average 35
    // day 3:  50,  55,  60,  65,  70       | daily average 60
    // day 4:  75,  80,  85,  90,  95       | daily average 85
    // day 5: 100, 105, 110, 115,           | daily average 107
    // day 6: 120, 125, 130, 135, 140       | daily average 130
    // day 7: 145, 150, 155, 160, 165       | daily average 155
    // end of week 1:                       | weekly average 83
    // day 1: 170, 175, 180, 185, 190       | daily average 180
    // day 2: 195, 200, 205, 210, 215       | daily average 205
    // day 3: 220, 225, 230, 235            | daily average 227
    // day 4: 240, 245, 250, 255, 260       | daily average 250
    // day 5: 265, 270, 275, 280, 285       | daily average 275
    // day 6: 290, 295, 300, 305, 310       | daily average 300
    // day 7: 315, 320, 325, 330, 335       | daily average 325
    // end of week 2:                       | weekly average 251
    // day 1: 340, 345, 350, 355            | daily average 347
    // day 2: 360, 365, 370, 375
    si.day_start_tp = {};
    for (int i = 0; i < 75; i++) {
        tp += hours(5);
        stp = {};
        stp += duration_cast<chrono::seconds>(tp.time_since_epoch());
        si.update_perf_history((i + 1) * 5, stp);
    }

    vector<int> history = si.get_perf_history();
    EXPECT_EQ(history.size(), 66UL);
    size_t i = 0;
    EXPECT_EQ(history[i++], 4);
    EXPECT_EQ(history[i++], 7);    // 7 days
    EXPECT_EQ(history[i++], 52);   // 52 weeks
    // last 24 hours
    EXPECT_EQ(history[i++], 375);
    EXPECT_EQ(history[i++], 370);
    EXPECT_EQ(history[i++], 365);
    EXPECT_EQ(history[i++], 360);
    // daily average of last 7 days
    EXPECT_EQ(history[i++], 347);
    EXPECT_EQ(history[i++], 325);
    EXPECT_EQ(history[i++], 300);
    EXPECT_EQ(history[i++], 275);
    EXPECT_EQ(history[i++], 250);
    EXPECT_EQ(history[i++], 227);
    EXPECT_EQ(history[i++], 205);
    // weekly average of last 52 weeks
    EXPECT_EQ(history[i++], 251);
    EXPECT_EQ(history[i++], 83);
    for (; i < history.size(); i++) {
        EXPECT_EQ(history[i], 0);
    }
}

TEST(storaged_test, storage_info_t_proto) {
    storage_info_t si;
    si.day_start_tp = {};

    IOPerfHistory proto;
    proto.set_nr_samples(10);
    proto.set_day_start_sec(0);
    si.load_perf_history_proto(proto);

    // Skip ahead > 1 day, with no data points in the previous day.
    time_point<system_clock> stp;
    stp += hours(36);
    si.update_perf_history(100, stp);

    vector<int> history = si.get_perf_history();
    EXPECT_EQ(history.size(), 63UL);
    EXPECT_EQ(history[0], 1);
    EXPECT_EQ(history[1], 7);
    EXPECT_EQ(history[2], 52);
    EXPECT_EQ(history[3], 100);
    for (size_t i = 4; i < history.size(); i++) {
        EXPECT_EQ(history[i], 0);
    }
}

TEST(storaged_test, uid_monitor) {
    uid_monitor uidm;
    auto& io_history = uidm.io_history();

    io_history[200] = {
        .start_ts = 100,
        .entries = {
            { "app1", {
                .user_id = 0,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON] = 1000,
              }
            },
            { "app2", {
                .user_id = 0,
                .uid_ios.bytes[READ][FOREGROUND][CHARGER_OFF] = 1000,
              }
            },
            { "app1", {
                .user_id = 1,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON] = 1000,
                .uid_ios.bytes[READ][FOREGROUND][CHARGER_ON] = 1000,
              }
            },
        },
    };

    io_history[300] = {
        .start_ts = 200,
        .entries = {
            { "app1", {
                .user_id = 1,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_OFF] = 1000,
              }
            },
            { "app3", {
                .user_id = 0,
                .uid_ios.bytes[READ][BACKGROUND][CHARGER_OFF] = 1000,
              }
            },
        },
    };

    unordered_map<int, StoragedProto> protos;

    uidm.update_uid_io_proto(&protos);

    EXPECT_EQ(protos.size(), 2U);
    EXPECT_EQ(protos.count(0), 1UL);
    EXPECT_EQ(protos.count(1), 1UL);

    EXPECT_EQ(protos[0].uid_io_usage().uid_io_items_size(), 2);
    const UidIOItem& user_0_item_0 = protos[0].uid_io_usage().uid_io_items(0);
    EXPECT_EQ(user_0_item_0.end_ts(), 200UL);
    EXPECT_EQ(user_0_item_0.records().start_ts(), 100UL);
    EXPECT_EQ(user_0_item_0.records().entries_size(), 2);
    EXPECT_EQ(user_0_item_0.records().entries(0).uid_name(), "app1");
    EXPECT_EQ(user_0_item_0.records().entries(0).user_id(), 0UL);
    EXPECT_EQ(user_0_item_0.records().entries(0).uid_io().wr_fg_chg_on(), 1000UL);
    EXPECT_EQ(user_0_item_0.records().entries(1).uid_name(), "app2");
    EXPECT_EQ(user_0_item_0.records().entries(1).user_id(), 0UL);
    EXPECT_EQ(user_0_item_0.records().entries(1).uid_io().rd_fg_chg_off(), 1000UL);
    const UidIOItem& user_0_item_1 = protos[0].uid_io_usage().uid_io_items(1);
    EXPECT_EQ(user_0_item_1.end_ts(), 300UL);
    EXPECT_EQ(user_0_item_1.records().start_ts(), 200UL);
    EXPECT_EQ(user_0_item_1.records().entries_size(), 1);
    EXPECT_EQ(user_0_item_1.records().entries(0).uid_name(), "app3");
    EXPECT_EQ(user_0_item_1.records().entries(0).user_id(), 0UL);
    EXPECT_EQ(user_0_item_1.records().entries(0).uid_io().rd_bg_chg_off(), 1000UL);

    EXPECT_EQ(protos[1].uid_io_usage().uid_io_items_size(), 2);
    const UidIOItem& user_1_item_0 = protos[1].uid_io_usage().uid_io_items(0);
    EXPECT_EQ(user_1_item_0.end_ts(), 200UL);
    EXPECT_EQ(user_1_item_0.records().start_ts(), 100UL);
    EXPECT_EQ(user_1_item_0.records().entries_size(), 1);
    EXPECT_EQ(user_1_item_0.records().entries(0).uid_name(), "app1");
    EXPECT_EQ(user_1_item_0.records().entries(0).user_id(), 1UL);
    EXPECT_EQ(user_1_item_0.records().entries(0).uid_io().rd_fg_chg_on(), 1000UL);
    EXPECT_EQ(user_1_item_0.records().entries(0).uid_io().wr_fg_chg_on(), 1000UL);
    const UidIOItem& user_1_item_1 = protos[1].uid_io_usage().uid_io_items(1);
    EXPECT_EQ(user_1_item_1.end_ts(), 300UL);
    EXPECT_EQ(user_1_item_1.records().start_ts(), 200UL);
    EXPECT_EQ(user_1_item_1.records().entries_size(), 1);
    EXPECT_EQ(user_1_item_1.records().entries(0).uid_name(), "app1");
    EXPECT_EQ(user_1_item_1.records().entries(0).user_id(), 1UL);
    EXPECT_EQ(user_1_item_1.records().entries(0).uid_io().wr_fg_chg_off(), 1000UL);

    io_history.clear();

    io_history[300] = {
        .start_ts = 200,
        .entries = {
            { "app1", {
                .user_id = 0,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON] = 1000,
              }
            },
        },
    };

    io_history[400] = {
        .start_ts = 300,
        .entries = {
            { "app1", {
                .user_id = 0,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON] = 1000,
              }
            },
        },
    };

    uidm.load_uid_io_proto(0, protos[0].uid_io_usage());
    uidm.load_uid_io_proto(1, protos[1].uid_io_usage());

    EXPECT_EQ(io_history.size(), 3UL);
    EXPECT_EQ(io_history.count(200), 1UL);
    EXPECT_EQ(io_history.count(300), 1UL);
    EXPECT_EQ(io_history.count(400), 1UL);

    EXPECT_EQ(io_history[200].start_ts, 100UL);
    const vector<struct uid_record>& entries_0 = io_history[200].entries;
    EXPECT_EQ(entries_0.size(), 3UL);
    EXPECT_EQ(entries_0[0].name, "app1");
    EXPECT_EQ(entries_0[0].ios.user_id, 0UL);
    EXPECT_EQ(entries_0[0].ios.uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);
    EXPECT_EQ(entries_0[1].name, "app2");
    EXPECT_EQ(entries_0[1].ios.user_id, 0UL);
    EXPECT_EQ(entries_0[1].ios.uid_ios.bytes[READ][FOREGROUND][CHARGER_OFF], 1000UL);
    EXPECT_EQ(entries_0[2].name, "app1");
    EXPECT_EQ(entries_0[2].ios.user_id, 1UL);
    EXPECT_EQ(entries_0[2].ios.uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);
    EXPECT_EQ(entries_0[2].ios.uid_ios.bytes[READ][FOREGROUND][CHARGER_ON], 1000UL);

    EXPECT_EQ(io_history[300].start_ts, 200UL);
    const vector<struct uid_record>& entries_1 = io_history[300].entries;
    EXPECT_EQ(entries_1.size(), 3UL);
    EXPECT_EQ(entries_1[0].name, "app1");
    EXPECT_EQ(entries_1[0].ios.user_id, 0UL);
    EXPECT_EQ(entries_1[0].ios.uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);
    EXPECT_EQ(entries_1[1].name, "app3");
    EXPECT_EQ(entries_1[1].ios.user_id, 0UL);
    EXPECT_EQ(entries_1[1].ios.uid_ios.bytes[READ][BACKGROUND][CHARGER_OFF], 1000UL);
    EXPECT_EQ(entries_1[2].name, "app1");
    EXPECT_EQ(entries_1[2].ios.user_id, 1UL);
    EXPECT_EQ(entries_1[2].ios.uid_ios.bytes[WRITE][FOREGROUND][CHARGER_OFF], 1000UL);

    EXPECT_EQ(io_history[400].start_ts, 300UL);
    const vector<struct uid_record>& entries_2 = io_history[400].entries;
    EXPECT_EQ(entries_2.size(), 1UL);
    EXPECT_EQ(entries_2[0].name, "app1");
    EXPECT_EQ(entries_2[0].ios.user_id, 0UL);
    EXPECT_EQ(entries_2[0].ios.uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);

    map<string, io_usage> merged_entries_0 = merge_io_usage(entries_0);
    EXPECT_EQ(merged_entries_0.size(), 2UL);
    EXPECT_EQ(merged_entries_0.count("app1"), 1UL);
    EXPECT_EQ(merged_entries_0.count("app2"), 1UL);
    EXPECT_EQ(merged_entries_0["app1"].bytes[READ][FOREGROUND][CHARGER_ON], 1000UL);
    EXPECT_EQ(merged_entries_0["app1"].bytes[WRITE][FOREGROUND][CHARGER_ON], 2000UL);
    EXPECT_EQ(merged_entries_0["app2"].bytes[READ][FOREGROUND][CHARGER_OFF], 1000UL);

    map<string, io_usage> merged_entries_1 = merge_io_usage(entries_1);
    EXPECT_EQ(merged_entries_1.size(), 2UL);
    EXPECT_EQ(merged_entries_1.count("app1"), 1UL);
    EXPECT_EQ(merged_entries_1.count("app3"), 1UL);
    EXPECT_EQ(merged_entries_1["app1"].bytes[WRITE][FOREGROUND][CHARGER_OFF], 1000UL);
    EXPECT_EQ(merged_entries_1["app1"].bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);
    EXPECT_EQ(merged_entries_1["app3"].bytes[READ][BACKGROUND][CHARGER_OFF], 1000UL);

    map<string, io_usage> merged_entries_2 = merge_io_usage(entries_2);
    EXPECT_EQ(merged_entries_2.size(), 1UL);
    EXPECT_EQ(merged_entries_2.count("app1"), 1UL);
    EXPECT_EQ(merged_entries_2["app1"].bytes[WRITE][FOREGROUND][CHARGER_ON], 1000UL);

    uidm.clear_user_history(0);

    EXPECT_EQ(uidm.io_history_.size(), 2UL);
    EXPECT_EQ(uidm.io_history_.count(200), 1UL);
    EXPECT_EQ(uidm.io_history_.count(300), 1UL);

    EXPECT_EQ(uidm.io_history_[200].entries.size(), 1UL);
    EXPECT_EQ(uidm.io_history_[300].entries.size(), 1UL);

    uidm.clear_user_history(1);

    EXPECT_EQ(uidm.io_history_.size(), 0UL);
}

TEST(storaged_test, load_uid_io_proto) {
    uid_monitor uidm;

    uidm.io_history_[200] = {
        .start_ts = 100,
        .entries = {
            { "app1", {
                .user_id = 0,
                .uid_ios.bytes[WRITE][FOREGROUND][CHARGER_ON] = 1000,
              }
            },
            { "app2", {
                .user_id = 0,
                .uid_ios.bytes[READ][FOREGROUND][CHARGER_OFF] = 2000,
              }
            },
            { "app3", {
                .user_id = 0,
                .uid_ios.bytes[READ][FOREGROUND][CHARGER_OFF] = 3000,
              }
            },
        },
    };

    unordered_map<int, StoragedProto> protos;
    uidm.update_uid_io_proto(&protos);
    ASSERT_EQ(protos.size(), size_t(1));

    // Loading the same proto many times should not add duplicate entries.
    const UidIOUsage& user_0 = protos[0].uid_io_usage();
    for (size_t i = 0; i < 10000; i++) {
        uidm.load_uid_io_proto(0, user_0);
    }
    ASSERT_EQ(uidm.io_history_.size(), size_t(1));
    ASSERT_EQ(uidm.io_history_[200].entries.size(), size_t(3));
}
