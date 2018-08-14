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

#define LOG_TAG "storaged"

#include <stdint.h>
#include <stdlib.h>

#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <log/log_event_list.h>

#include "storaged.h"
#include "storaged_diskstats.h"

namespace {

using android::sp;
using android::hardware::health::V2_0::DiskStats;
using android::hardware::health::V2_0::IHealth;
using android::hardware::health::V2_0::Result;
using android::hardware::health::V2_0::toString;

#ifdef DEBUG
void log_debug_disk_perf(struct disk_perf* perf, const char* type) {
    // skip if the input structure are all zeros
    if (perf == NULL || perf->is_zero()) return;

    LOG_TO(SYSTEM, INFO) << "disk_perf " << type
              << " rd: " << perf->read_perf << " kbps, " << perf->read_ios << " iops"
              << " wr: " << perf->write_perf << " kbps, " << perf->write_ios << " iops"
              << " q: " << perf->queue;
}
#else
void log_debug_disk_perf(struct disk_perf* perf, const char* type) {}
#endif

void log_event_disk_stats(struct disk_stats* stats, const char* type) {
    // skip if the input structure are all zeros
    if (stats == NULL || stats->is_zero()) return;

    android_log_event_list(EVENTLOGTAG_DISKSTATS)
        << type << stats->start_time << stats->end_time
        << stats->read_ios << stats->read_merges
        << stats->read_sectors << stats->read_ticks
        << stats->write_ios << stats->write_merges
        << stats->write_sectors << stats->write_ticks
        << (uint64_t)stats->io_avg << stats->io_ticks << stats->io_in_queue
        << LOG_ID_EVENTS;
}

} // namespace

bool get_time(struct timespec* ts) {
    // Use monotonic to exclude suspend time so that we measure IO bytes/sec
    // when system is running.
    int ret = clock_gettime(CLOCK_MONOTONIC, ts);
    if (ret < 0) {
        PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        return false;
    }
    return true;
}

void init_disk_stats_other(const struct timespec& ts, struct disk_stats* stats) {
    stats->start_time = 0;
    stats->end_time = (uint64_t)ts.tv_sec * SEC_TO_MSEC + ts.tv_nsec / (MSEC_TO_USEC * USEC_TO_NSEC);
    stats->counter = 1;
    stats->io_avg = (double)stats->io_in_flight;
}

bool parse_disk_stats(const char* disk_stats_path, struct disk_stats* stats) {
    // Get time
    struct timespec ts;
    if (!get_time(&ts)) {
        return false;
    }

    std::string buffer;
    if (!android::base::ReadFileToString(disk_stats_path, &buffer)) {
        PLOG_TO(SYSTEM, ERROR) << disk_stats_path << ": ReadFileToString failed.";
        return false;
    }

    // Regular diskstats entries
    std::stringstream ss(buffer);
    for (uint i = 0; i < DISK_STATS_SIZE; ++i) {
        ss >> *((uint64_t*)stats + i);
    }
    // Other entries
    init_disk_stats_other(ts, stats);
    return true;
}

void convert_hal_disk_stats(struct disk_stats* dst, const DiskStats& src) {
    dst->read_ios = src.reads;
    dst->read_merges = src.readMerges;
    dst->read_sectors = src.readSectors;
    dst->read_ticks = src.readTicks;
    dst->write_ios = src.writes;
    dst->write_merges = src.writeMerges;
    dst->write_sectors = src.writeSectors;
    dst->write_ticks = src.writeTicks;
    dst->io_in_flight = src.ioInFlight;
    dst->io_ticks = src.ioTicks;
    dst->io_in_queue = src.ioInQueue;
}

bool get_disk_stats_from_health_hal(const sp<IHealth>& service, struct disk_stats* stats) {
    struct timespec ts;
    if (!get_time(&ts)) {
        return false;
    }

    bool success = false;
    auto ret = service->getDiskStats([&success, stats](auto result, const auto& halStats) {
        if (result != Result::SUCCESS || halStats.size() == 0) {
            LOG_TO(SYSTEM, ERROR) << "getDiskStats failed with result " << toString(result)
                                  << " and size " << halStats.size();
            return;
        }

        convert_hal_disk_stats(stats, halStats[0]);
        success = true;
    });

    if (!ret.isOk()) {
        LOG_TO(SYSTEM, ERROR) << "getDiskStats failed with " << ret.description();
        return false;
    }

    if (!success) {
        return false;
    }

    init_disk_stats_other(ts, stats);
    return true;
}

struct disk_perf get_disk_perf(struct disk_stats* stats)
{
    struct disk_perf perf = {};

    if (stats->io_ticks) {
        if (stats->read_ticks) {
            unsigned long long divisor = stats->read_ticks * stats->io_ticks;
            perf.read_perf = ((unsigned long long)SECTOR_SIZE *
                              stats->read_sectors * stats->io_in_queue +
                              (divisor >> 1)) / divisor;
            perf.read_ios = ((unsigned long long)SEC_TO_MSEC *
                             stats->read_ios * stats->io_in_queue +
                             (divisor >> 1)) / divisor;
        }
        if (stats->write_ticks) {
            unsigned long long divisor = stats->write_ticks * stats->io_ticks;
            perf.write_perf = ((unsigned long long)SECTOR_SIZE *
                               stats->write_sectors * stats->io_in_queue +
                               (divisor >> 1)) / divisor;
            perf.write_ios = ((unsigned long long)SEC_TO_MSEC *
                              stats->write_ios * stats->io_in_queue +
                              (divisor >> 1)) / divisor;
        }
        perf.queue = (stats->io_in_queue + (stats->io_ticks >> 1)) /
                     stats->io_ticks;
    }
    return perf;
}

void get_inc_disk_stats(const struct disk_stats* prev, const struct disk_stats* curr,
                        struct disk_stats* inc)
{
    *inc = *curr - *prev;
    inc->start_time = prev->end_time;
    inc->end_time = curr->end_time;
    inc->io_avg = curr->io_avg;
    inc->counter = 1;
}

// Add src to dst
void add_disk_stats(struct disk_stats* src, struct disk_stats* dst)
{
    if (dst->end_time != 0 && dst->end_time != src->start_time) {
        LOG_TO(SYSTEM, WARNING) << "Two dis-continuous periods of diskstats"
            << " are added. dst end with " << dst->end_time
            << ", src start with " << src->start_time;
    }

    *dst += *src;

    dst->io_in_flight = src->io_in_flight;
    if (dst->counter + src->counter) {
        dst->io_avg =
            ((dst->io_avg * dst->counter) + (src->io_avg * src->counter)) /
            (dst->counter + src->counter);
    }
    dst->counter += src->counter;
    dst->end_time = src->end_time;
    if (dst->start_time == 0) {
        dst->start_time = src->start_time;
    }
}

/* disk_stats_monitor */
void disk_stats_monitor::update_mean()
{
    CHECK(mValid);
    mMean.read_perf = (uint32_t)mStats.read_perf.get_mean();
    mMean.read_ios = (uint32_t)mStats.read_ios.get_mean();
    mMean.write_perf = (uint32_t)mStats.write_perf.get_mean();
    mMean.write_ios = (uint32_t)mStats.write_ios.get_mean();
    mMean.queue = (uint32_t)mStats.queue.get_mean();
}

void disk_stats_monitor::update_std()
{
    CHECK(mValid);
    mStd.read_perf = (uint32_t)mStats.read_perf.get_std();
    mStd.read_ios = (uint32_t)mStats.read_ios.get_std();
    mStd.write_perf = (uint32_t)mStats.write_perf.get_std();
    mStd.write_ios = (uint32_t)mStats.write_ios.get_std();
    mStd.queue = (uint32_t)mStats.queue.get_std();
}

void disk_stats_monitor::add(struct disk_perf* perf)
{
    mStats.read_perf.add(perf->read_perf);
    mStats.read_ios.add(perf->read_ios);
    mStats.write_perf.add(perf->write_perf);
    mStats.write_ios.add(perf->write_ios);
    mStats.queue.add(perf->queue);
}

void disk_stats_monitor::evict(struct disk_perf* perf) {
    mStats.read_perf.evict(perf->read_perf);
    mStats.read_ios.evict(perf->read_ios);
    mStats.write_perf.evict(perf->write_perf);
    mStats.write_ios.evict(perf->write_ios);
    mStats.queue.evict(perf->queue);
}

bool disk_stats_monitor::detect(struct disk_perf* perf)
{
    return ((double)perf->queue >= (double)mMean.queue + mSigma * (double)mStd.queue) &&
        ((double)perf->read_perf < (double)mMean.read_perf - mSigma * (double)mStd.read_perf) &&
        ((double)perf->write_perf < (double)mMean.write_perf - mSigma * (double)mStd.write_perf);
}

void disk_stats_monitor::update(struct disk_stats* curr)
{
    disk_stats inc;
    get_inc_disk_stats(&mPrevious, curr, &inc);
    add_disk_stats(&inc, &mAccumulate_pub);

    struct disk_perf perf = get_disk_perf(&inc);
    log_debug_disk_perf(&perf, "regular");

    add(&perf);
    mBuffer.push(perf);
    if (mBuffer.size() > mWindow) {
        evict(&mBuffer.front());
        mBuffer.pop();
        mValid = true;
    }

    // Update internal data structures
    if (LIKELY(mValid)) {
        CHECK_EQ(mBuffer.size(), mWindow);
        update_mean();
        update_std();
        if (UNLIKELY(detect(&perf))) {
            mStall = true;
            add_disk_stats(&inc, &mAccumulate);
            log_debug_disk_perf(&mMean, "stalled_mean");
            log_debug_disk_perf(&mStd, "stalled_std");
        } else {
            if (mStall) {
                struct disk_perf acc_perf = get_disk_perf(&mAccumulate);
                log_debug_disk_perf(&acc_perf, "stalled");
                log_event_disk_stats(&mAccumulate, "stalled");
                mStall = false;
                memset(&mAccumulate, 0, sizeof(mAccumulate));
            }
        }
    }

    mPrevious = *curr;
}

void disk_stats_monitor::update() {
    disk_stats curr;
    if (mHealth != nullptr) {
        if (!get_disk_stats_from_health_hal(mHealth, &curr)) {
            return;
        }
    } else {
        if (!parse_disk_stats(DISK_STATS_PATH, &curr)) {
            return;
        }
    }

    update(&curr);
}

void disk_stats_monitor::publish(void)
{
    struct disk_perf perf = get_disk_perf(&mAccumulate_pub);
    log_debug_disk_perf(&perf, "regular");
    log_event_disk_stats(&mAccumulate, "regular");
    // Reset global structures
    memset(&mAccumulate_pub, 0, sizeof(struct disk_stats));
}
