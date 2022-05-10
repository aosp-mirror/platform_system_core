/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _STORAGED_DISKSTATS_H_
#define _STORAGED_DISKSTATS_H_

#include <stdint.h>

#include <aidl/android/hardware/health/IHealth.h>

// number of attributes diskstats has
#define DISK_STATS_SIZE ( 11 )

#define MMC_DISK_STATS_PATH "/sys/block/mmcblk0/stat"
#define SDA_DISK_STATS_PATH "/sys/block/sda/stat"

struct disk_stats {
    /* It will be extremely unlikely for any of the following entries to overflow.
     * For read_bytes(which will be greater than any of the following entries), it
     * will take 27 years to overflow uint64_t at the reading rate of 20GB/s, which
     * is the peak memory transfer rate for current memory.
     * The diskstats entries (first 11) need to be at top in this structure _after_
     * compiler's optimization.
     */
    uint64_t read_ios;       // number of read I/Os processed
    uint64_t read_merges;    // number of read I/Os merged with in-queue I/Os
    uint64_t read_sectors;   // number of sectors read
    uint64_t read_ticks;     // total wait time for read requests
    uint64_t write_ios;      // number of write I/Os processed
    uint64_t write_merges;   // number of write I/Os merged with in-queue I/Os
    uint64_t write_sectors;  // number of sectors written
    uint64_t write_ticks;    // total wait time for write requests
    uint64_t io_in_flight;   // number of I/Os currently in flight
    uint64_t io_ticks;       // total time this block device has been active
    uint64_t io_in_queue;    // total wait time for all requests

    uint64_t start_time;     // monotonic time accounting starts
    uint64_t end_time;       // monotonic time accounting ends
    uint32_t counter;        // private counter for accumulate calculations
    double   io_avg;         // average io_in_flight for accumulate calculations

    bool is_zero() {
        return read_ios == 0 && write_ios == 0 &&
               io_in_flight == 0 && io_ticks == 0 && io_in_queue == 0;
    }

    friend disk_stats operator- (disk_stats curr, const disk_stats& prev) {
        curr.read_ios -= prev.read_ios;
        curr.read_merges -= prev.read_merges;
        curr.read_sectors -= prev.read_sectors;
        curr.read_ticks -= prev.read_ticks;
        curr.write_ios -= prev.write_ios;
        curr.write_merges -= prev.write_merges;
        curr.write_sectors -= prev.write_sectors;
        curr.write_ticks -= prev.write_ticks;
        /* skips io_in_flight, use current value */
        curr.io_ticks -= prev.io_ticks;
        curr.io_in_queue -= prev.io_in_queue;
        return curr;
    }

    friend bool operator== (const disk_stats& a, const disk_stats& b) {
        return a.read_ios == b.read_ios &&
               a.read_merges == b.read_merges &&
               a.read_sectors == b.read_sectors &&
               a.read_ticks == b.read_ticks &&
               a.write_ios == b.write_ios &&
               a.write_merges == b.write_merges &&
               a.write_sectors == b.write_sectors &&
               a.write_ticks == b.write_ticks &&
               /* skips io_in_flight */
               a.io_ticks == b.io_ticks &&
               a.io_in_queue == b.io_in_queue;
    }

    disk_stats& operator+= (const disk_stats& stats) {
        read_ios += stats.read_ios;
        read_merges += stats.read_merges;
        read_sectors += stats.read_sectors;
        read_ticks += stats.read_ticks;
        write_ios += stats.write_ios;
        write_merges += stats.write_merges;
        write_sectors += stats.write_sectors;
        write_ticks += stats.write_ticks;
        /* skips io_in_flight, use current value */
        io_ticks += stats.io_ticks;
        io_in_queue += stats.io_in_queue;
        return *this;
    }
};

struct disk_perf {
    uint32_t read_perf;         // read speed (kbytes/s)
    uint32_t read_ios;          // read I/Os per second
    uint32_t write_perf;        // write speed (kbytes/s)
    uint32_t write_ios;         // write I/Os per second
    uint32_t queue;             // I/Os in queue
    bool is_zero() {
        return read_perf == 0 && read_ios == 0 &&
               write_perf == 0 && write_ios == 0 && queue == 0;
    }
};

class stream_stats {
private:
    double mSum;
    double mSquareSum;
    uint32_t mCnt;
public:
    stream_stats() : mSum(0), mSquareSum(0), mCnt(0) {};
    ~stream_stats() {};
    double get_mean() {
        return mSum / mCnt;
    }
    double get_std() {
        return sqrt(mSquareSum / mCnt - mSum * mSum / (mCnt * mCnt));
    }
    void add(uint32_t num) {
        mSum += (double)num;
        mSquareSum += (double)num * (double)num;
        mCnt++;
    }
    void evict(uint32_t num) {
        if (mSum < num || mSquareSum < (double)num * (double)num) return;
        mSum -= (double)num;
        mSquareSum -= (double)num * (double)num;
        mCnt--;
    }
};

class disk_stats_monitor {
private:
    FRIEND_TEST(storaged_test, disk_stats_monitor);
    const char* const DISK_STATS_PATH;
    struct disk_stats mPrevious;
    struct disk_stats mAccumulate;      /* reset after stall */
    struct disk_stats mAccumulate_pub;  /* reset after publish */
    bool mStall;
    std::queue<struct disk_perf> mBuffer;
    struct {
        stream_stats read_perf;           // read speed (bytes/s)
        stream_stats read_ios;            // read I/Os per second
        stream_stats write_perf;          // write speed (bytes/s)
        stream_stats write_ios;           // write I/O per second
        stream_stats queue;               // I/Os in queue
    } mStats;
    bool mValid;
    const uint32_t mWindow;
    const double mSigma;
    struct disk_perf mMean;
    struct disk_perf mStd;
    std::shared_ptr<aidl::android::hardware::health::IHealth> mHealth;

    void update_mean();
    void update_std();
    void add(struct disk_perf* perf);
    void evict(struct disk_perf* perf);
    bool detect(struct disk_perf* perf);

    void update(struct disk_stats* stats);

public:
  disk_stats_monitor(const std::shared_ptr<aidl::android::hardware::health::IHealth>& healthService,
                     uint32_t window_size = 5, double sigma = 1.0)
      : DISK_STATS_PATH(
                healthService != nullptr
                        ? nullptr
                        : (access(MMC_DISK_STATS_PATH, R_OK) == 0
                                   ? MMC_DISK_STATS_PATH
                                   : (access(SDA_DISK_STATS_PATH, R_OK) == 0 ? SDA_DISK_STATS_PATH
                                                                             : nullptr))),
        mPrevious(),
        mAccumulate(),
        mAccumulate_pub(),
        mStall(false),
        mValid(false),
        mWindow(window_size),
        mSigma(sigma),
        mMean(),
        mStd(),
        mHealth(healthService) {}
  bool enabled() { return mHealth != nullptr || DISK_STATS_PATH != nullptr; }
  void update(void);
  void publish(void);
};

#endif /* _STORAGED_DISKSTATS_H_ */
