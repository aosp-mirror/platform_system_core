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

#define LOG_TAG "storaged"

#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#include <android-base/logging.h>

#include <storaged.h>
#include <storaged_utils.h>

/* disk_stats_publisher */
void disk_stats_publisher::publish(void) {
    // Logging
    log_kernel_disk_stats(&mAccumulate, "regular");
    struct disk_perf perf = get_disk_perf(&mAccumulate);
    log_kernel_disk_perf(&perf, "regular");
    log_event_disk_stats(&mAccumulate, "regular");
    // Reset global structures
    memset(&mAccumulate, 0, sizeof(struct disk_stats));
}

void disk_stats_publisher::update(void) {
    struct disk_stats curr;
    if (parse_disk_stats(DISK_STATS_PATH, &curr)) {
        struct disk_stats inc = get_inc_disk_stats(&mPrevious, &curr);
        add_disk_stats(&inc, &mAccumulate);
        #ifdef DEBUG
//            log_kernel_disk_stats(&mPrevious, "prev stats");
//            log_kernel_disk_stats(&curr, "curr stats");
//            log_kernel_disk_stats(&inc, "inc stats");
//            log_kernel_disk_stats(&mAccumulate, "accumulated stats");
        #endif
        mPrevious = curr;
    }
}

/* disk_stats_monitor */
void disk_stats_monitor::update_mean() {
    CHECK(mValid);
    mMean.read_perf = (uint32_t)mStats.read_perf.get_mean();
    mMean.read_ios = (uint32_t)mStats.read_ios.get_mean();
    mMean.write_perf = (uint32_t)mStats.write_perf.get_mean();
    mMean.write_ios = (uint32_t)mStats.write_ios.get_mean();
    mMean.queue = (uint32_t)mStats.queue.get_mean();
}

void disk_stats_monitor::update_std() {
    CHECK(mValid);
    mStd.read_perf = (uint32_t)mStats.read_perf.get_std();
    mStd.read_ios = (uint32_t)mStats.read_ios.get_std();
    mStd.write_perf = (uint32_t)mStats.write_perf.get_std();
    mStd.write_ios = (uint32_t)mStats.write_ios.get_std();
    mStd.queue = (uint32_t)mStats.queue.get_std();
}

void disk_stats_monitor::add(struct disk_perf* perf) {
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

bool disk_stats_monitor::detect(struct disk_perf* perf) {
    return ((double)perf->queue >= (double)mMean.queue + mSigma * (double)mStd.queue) &&
            ((double)perf->read_perf < (double)mMean.read_perf - mSigma * (double)mStd.read_perf) &&
            ((double)perf->write_perf < (double)mMean.write_perf - mSigma * (double)mStd.write_perf);
}

void disk_stats_monitor::update(struct disk_stats* stats) {
    struct disk_stats inc = get_inc_disk_stats(&mPrevious, stats);
    struct disk_perf perf = get_disk_perf(&inc);
    // Update internal data structures
    if (LIKELY(mValid)) {
        CHECK_EQ(mBuffer.size(), mWindow);

        if (UNLIKELY(detect(&perf))) {
            mStall = true;
            add_disk_stats(&inc, &mAccumulate);
            #ifdef DEBUG
            log_kernel_disk_perf(&mMean, "stalled_mean");
            log_kernel_disk_perf(&mStd, "stalled_std");
            #endif
        } else {
            if (mStall) {
                log_kernel_disk_stats(&mAccumulate, "stalled");
                struct disk_perf acc_perf = get_disk_perf(&mAccumulate);
                log_kernel_disk_perf(&acc_perf, "stalled");

                log_event_disk_stats(&mAccumulate, "stalled");
                mStall = false;
                memset(&mAccumulate, 0, sizeof(mAccumulate));
            }
        }

        evict(&mBuffer.front());
        mBuffer.pop();
        add(&perf);
        mBuffer.push(perf);

        update_mean();
        update_std();

    } else { /* mValid == false */
        CHECK_LT(mBuffer.size(), mWindow);
        add(&perf);
        mBuffer.push(perf);
        if (mBuffer.size() == mWindow) {
            mValid = true;
            update_mean();
            update_std();
        }
    }

    mPrevious = *stats;
}

void disk_stats_monitor::update(void) {
    struct disk_stats curr;
    if (LIKELY(parse_disk_stats(DISK_STATS_PATH, &curr))) {
        update(&curr);
    }
}

/* emmc_info_t */
void emmc_info_t::publish(void) {
    if (mValid) {
        log_kernel_emmc_info(&mInfo);
        log_event_emmc_info(&mInfo);
    }
}

void emmc_info_t::update(void) {
    if (mFdEmmc >= 0) {
        mValid = parse_emmc_ecsd(mFdEmmc, &mInfo);
    }
}

/* storaged_t */
storaged_t::storaged_t(void) {
    mConfig.emmc_available = (access(EMMC_ECSD_PATH, R_OK) >= 0);

    if (access(MMC_DISK_STATS_PATH, R_OK) < 0 && access(SDA_DISK_STATS_PATH, R_OK) < 0) {
        mConfig.diskstats_available = false;
    } else {
        mConfig.diskstats_available = true;
    }

    mConfig.proc_taskio_readable = true;
    const char* test_paths[] = {"/proc/1/io", "/proc/1/comm", "/proc/1/cmdline", "/proc/1/stat"};
    for (uint i = 0; i < sizeof(test_paths) / sizeof(const char*); ++i) {
        if (access(test_paths[i], R_OK) < 0) {
            mConfig.proc_taskio_readable = false;
            break;
        }
    }

    mConfig.periodic_chores_interval_unit = DEFAULT_PERIODIC_CHORES_INTERVAL_UNIT;
    mConfig.periodic_chores_interval_disk_stats_publish = DEFAULT_PERIODIC_CHORES_INTERVAL_DISK_STATS_PUBLISH;
    mConfig.periodic_chores_interval_emmc_info_publish = DEFAULT_PERIODIC_CHORES_INTERVAL_EMMC_INFO_PUBLISH;

    mStarttime = time(NULL);
}

void storaged_t::event(void) {
    if (mConfig.diskstats_available) {
        mDiskStats.update();
        mDsm.update();
        if (mTimer && (mTimer % mConfig.periodic_chores_interval_disk_stats_publish) == 0) {
            mDiskStats.publish();
        }
    }

    if (mConfig.proc_taskio_readable) {
        mTasks.update_running_tasks();
    }

    if (mConfig.emmc_available && mTimer &&
            (mTimer % mConfig.periodic_chores_interval_emmc_info_publish) == 0) {
        mEmmcInfo.update();
        mEmmcInfo.publish();
    }

    mTimer += mConfig.periodic_chores_interval_unit;
}