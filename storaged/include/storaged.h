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

#ifndef _STORAGED_H_
#define _STORAGED_H_

#include <semaphore.h>
#include <stdint.h>
#include <time.h>

#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include <batteryservice/IBatteryPropertiesListener.h>

#include "storaged_uid_monitor.h"

using namespace android;

#define FRIEND_TEST(test_case_name, test_name) \
friend class test_case_name##_##test_name##_Test

/* For debug */
#ifdef DEBUG
#define debuginfo(fmt, ...) \
 do {printf("%s():\t" fmt "\t[%s:%d]\n", __FUNCTION__, ##__VA_ARGS__, __FILE__, __LINE__);} \
 while(0)
#else
#define debuginfo(...)
#endif

#define SECTOR_SIZE ( 512 )
#define SEC_TO_MSEC ( 1000 )
#define MSEC_TO_USEC ( 1000 )
#define USEC_TO_NSEC ( 1000 )
#define SEC_TO_USEC ( 1000000 )
#define HOUR_TO_SEC ( 3600 )
#define DAY_TO_SEC ( 3600 * 24 )

// number of attributes diskstats has
#define DISK_STATS_SIZE ( 11 )
// maximum size limit of a stats file
#define DISK_STATS_FILE_MAX_SIZE ( 256 )
#define DISK_STATS_IO_IN_FLIGHT_IDX ( 8 )
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
};

#define MMC_VER_STR_LEN ( 9 )   // maximum length of the MMC version string, including NULL terminator
// minimum size of a ext_csd file
#define EXT_CSD_FILE_MIN_SIZE ( 1024 )
struct emmc_info {
    int eol;                        // pre-eol (end of life) information
    int lifetime_a;                 // device life time estimation (type A)
    int lifetime_b;                 // device life time estimation (type B)
    char mmc_ver[MMC_VER_STR_LEN];  // device version string
};

struct disk_perf {
    uint32_t read_perf;         // read speed (kbytes/s)
    uint32_t read_ios;          // read I/Os per second
    uint32_t write_perf;        // write speed (kbytes/s)
    uint32_t write_ios;         // write I/Os per second
    uint32_t queue;             // I/Os in queue
};

#define CMD_MAX_LEN ( 64 )
struct task_info {
    uint32_t pid;                   // task id
    uint64_t rchar;                 // characters read
    uint64_t wchar;                 // characters written
    uint64_t syscr;                 // read syscalls
    uint64_t syscw;                 // write syscalls
    uint64_t read_bytes;            // bytes read (from storage layer)
    uint64_t write_bytes;           // bytes written (to storage layer)
    uint64_t cancelled_write_bytes; // cancelled write byte by truncate

    uint64_t starttime;             // start time of task

    char cmd[CMD_MAX_LEN];          // filename of the executable
};

class lock_t {
    sem_t* mSem;
public:
    lock_t(sem_t* sem) {
        mSem = sem;
        sem_wait(mSem);
    }
    ~lock_t() {
        sem_post(mSem);
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

#define MMC_DISK_STATS_PATH "/sys/block/mmcblk0/stat"
#define SDA_DISK_STATS_PATH "/sys/block/sda/stat"
#define EMMC_ECSD_PATH "/d/mmc0/mmc0:0001/ext_csd"
#define UID_IO_STATS_PATH "/proc/uid_io/stats"

class disk_stats_monitor {
private:
    FRIEND_TEST(storaged_test, disk_stats_monitor);
    const char* DISK_STATS_PATH;
    struct disk_stats mPrevious;
    struct disk_stats mAccumulate;
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

    void update_mean();
    void update_std();
    void add(struct disk_perf* perf);
    void evict(struct disk_perf* perf);
    bool detect(struct disk_perf* perf);

    void update(struct disk_stats* stats);

public:
    disk_stats_monitor(uint32_t window_size = 5, double sigma = 1.0) :
            mStall(false),
            mValid(false),
            mWindow(window_size),
            mSigma(sigma) {
        memset(&mPrevious, 0, sizeof(mPrevious));
        memset(&mMean, 0, sizeof(mMean));
        memset(&mStd, 0, sizeof(mStd));

        if (access(MMC_DISK_STATS_PATH, R_OK) >= 0) {
            DISK_STATS_PATH = MMC_DISK_STATS_PATH;
        } else {
            DISK_STATS_PATH = SDA_DISK_STATS_PATH;
        }
    }
    void update(void);
};

class disk_stats_publisher {
private:
    FRIEND_TEST(storaged_test, disk_stats_publisher);
    const char* DISK_STATS_PATH;
    struct disk_stats mAccumulate;
    struct disk_stats mPrevious;
public:
    disk_stats_publisher(void) {
        memset(&mAccumulate, 0, sizeof(struct disk_stats));
        memset(&mPrevious, 0, sizeof(struct disk_stats));

        if (access(MMC_DISK_STATS_PATH, R_OK) >= 0) {
            DISK_STATS_PATH = MMC_DISK_STATS_PATH;
        } else {
            DISK_STATS_PATH = SDA_DISK_STATS_PATH;
        }
    }

    ~disk_stats_publisher(void) {}
    void publish(void);
    void update(void);
};

class emmc_info_t {
private:
    struct emmc_info mInfo;
    bool mValid;
    int mFdEmmc;
public:
    emmc_info_t(void) :
            mValid(false),
            mFdEmmc(-1) {
        memset(&mInfo, 0, sizeof(struct emmc_info));
    }
    ~emmc_info_t(void) {}

    void publish(void);
    void update(void);
    void set_emmc_fd(int fd) {
        mFdEmmc = fd;
    }
};

// Periodic chores intervals in seconds
#define DEFAULT_PERIODIC_CHORES_INTERVAL_UNIT ( 60 )
#define DEFAULT_PERIODIC_CHORES_INTERVAL_DISK_STATS_PUBLISH ( 3600 )
#define DEFAULT_PERIODIC_CHORES_INTERVAL_EMMC_INFO_PUBLISH ( 86400 )
#define DEFAULT_PERIODIC_CHORES_INTERVAL_UID_IO ( 3600 )
#define DEFAULT_PERIODIC_CHORES_INTERVAL_UID_IO_LIMIT (300)

// UID IO threshold in bytes
#define DEFAULT_PERIODIC_CHORES_UID_IO_THRESHOLD ( 1024 * 1024 * 1024ULL )

struct storaged_config {
    int periodic_chores_interval_unit;
    int periodic_chores_interval_disk_stats_publish;
    int periodic_chores_interval_emmc_info_publish;
    int periodic_chores_interval_uid_io;
    bool proc_uid_io_available;      // whether uid_io is accessible
    bool emmc_available;        // whether eMMC est_csd file is readable
    bool diskstats_available;   // whether diskstats is accessible
    int event_time_check_usec;  // check how much cputime spent in event loop
};

class storaged_t : public BnBatteryPropertiesListener {
private:
    time_t mTimer;
    storaged_config mConfig;
    disk_stats_publisher mDiskStats;
    disk_stats_monitor mDsm;
    emmc_info_t mEmmcInfo;
    uid_monitor mUidm;
    time_t mStarttime;
public:
    storaged_t(void);
    ~storaged_t() {}
    void event(void);
    void event_checked(void);
    void pause(void) {
        sleep(mConfig.periodic_chores_interval_unit);
    }
    void set_privileged_fds(int fd_emmc) {
        mEmmcInfo.set_emmc_fd(fd_emmc);
    }

    time_t get_starttime(void) {
        return mStarttime;
    }

    std::unordered_map<uint32_t, struct uid_info> get_uids(void) {
        return mUidm.get_uid_io_stats();
    }
    std::map<uint64_t, std::vector<struct uid_record>> get_uid_records(
            double hours, uint64_t threshold, bool force_report) {
        return mUidm.dump(hours, threshold, force_report);
    }
    void update_uid_io_interval(int interval) {
        if (interval >= DEFAULT_PERIODIC_CHORES_INTERVAL_UID_IO_LIMIT) {
            mConfig.periodic_chores_interval_uid_io = interval;
        }
    }

    void init_battery_service();
    virtual void batteryPropertiesChanged(struct BatteryProperties props);
};

// Eventlog tag
// The content must match the definition in EventLogTags.logtags
#define EVENTLOGTAG_DISKSTATS ( 2732 )
#define EVENTLOGTAG_EMMCINFO ( 2733 )
#define EVENTLOGTAG_UID_IO_ALERT ( 2734 )

#endif /* _STORAGED_H_ */
