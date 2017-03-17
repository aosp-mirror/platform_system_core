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
#include <batteryservice/BatteryServiceConstants.h>
#include <batteryservice/IBatteryPropertiesRegistrar.h>
#include <binder/IServiceManager.h>
#include <cutils/properties.h>
#include <log/log.h>

#include <storaged.h>
#include <storaged_utils.h>

/* disk_stats_publisher */
void disk_stats_publisher::publish(void) {
    // Logging
    struct disk_perf perf = get_disk_perf(&mAccumulate);
    log_debug_disk_perf(&perf, "regular");
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

static sp<IBatteryPropertiesRegistrar> get_battery_properties_service() {
    sp<IServiceManager> sm = defaultServiceManager();
    if (sm == NULL) return NULL;

    sp<IBinder> binder = sm->getService(String16("batteryproperties"));
    if (binder == NULL) return NULL;

    sp<IBatteryPropertiesRegistrar> battery_properties =
        interface_cast<IBatteryPropertiesRegistrar>(binder);

    return battery_properties;
}

static inline charger_stat_t is_charger_on(int64_t prop) {
    return (prop == BATTERY_STATUS_CHARGING || prop == BATTERY_STATUS_FULL) ?
        CHARGER_ON : CHARGER_OFF;
}

void storaged_t::batteryPropertiesChanged(struct BatteryProperties props) {
    mUidm.set_charger_state(is_charger_on(props.batteryStatus));
}

void storaged_t::init_battery_service() {
    sp<IBatteryPropertiesRegistrar> battery_properties = get_battery_properties_service();
    if (battery_properties == NULL) {
        LOG_TO(SYSTEM, WARNING) << "failed to find batteryproperties service";
        return;
    }

    struct BatteryProperty val;
    battery_properties->getProperty(BATTERY_PROP_BATTERY_STATUS, &val);
    mUidm.init(is_charger_on(val.valueInt64));

    // register listener after init uid_monitor
    battery_properties->registerListener(this);
}

/* storaged_t */
storaged_t::storaged_t(void) {
    if (access(MMC_DISK_STATS_PATH, R_OK) < 0 && access(SDA_DISK_STATS_PATH, R_OK) < 0) {
        mConfig.diskstats_available = false;
    } else {
        mConfig.diskstats_available = true;
    }

    mConfig.proc_uid_io_available = (access(UID_IO_STATS_PATH, R_OK) == 0);

    mConfig.periodic_chores_interval_unit =
        property_get_int32("ro.storaged.event.interval", DEFAULT_PERIODIC_CHORES_INTERVAL_UNIT);

    mConfig.event_time_check_usec =
        property_get_int32("ro.storaged.event.perf_check", 0);

    mConfig.periodic_chores_interval_disk_stats_publish =
        property_get_int32("ro.storaged.disk_stats_pub", DEFAULT_PERIODIC_CHORES_INTERVAL_DISK_STATS_PUBLISH);

    mConfig.periodic_chores_interval_emmc_info_publish =
        property_get_int32("ro.storaged.emmc_info_pub", DEFAULT_PERIODIC_CHORES_INTERVAL_EMMC_INFO_PUBLISH);

    mConfig.periodic_chores_interval_uid_io =
        property_get_int32("ro.storaged.uid_io.interval", DEFAULT_PERIODIC_CHORES_INTERVAL_UID_IO);

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

    if (info && mTimer &&
        (mTimer % mConfig.periodic_chores_interval_emmc_info_publish) == 0) {
        info->update();
        info->publish();
    }

    if (mConfig.proc_uid_io_available && mTimer &&
            (mTimer % mConfig.periodic_chores_interval_uid_io) == 0) {
         mUidm.report();
    }

    mTimer += mConfig.periodic_chores_interval_unit;
}

void storaged_t::event_checked(void) {
    struct timespec start_ts, end_ts;
    bool check_time = true;

    if (mConfig.event_time_check_usec &&
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_ts) < 0) {
        check_time = false;
        static time_t state_a;
        IF_ALOG_RATELIMIT_LOCAL(300, &state_a) {
            PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
        }
    }

    event();

    if (mConfig.event_time_check_usec && check_time) {
        if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end_ts) < 0) {
            static time_t state_b;
            IF_ALOG_RATELIMIT_LOCAL(300, &state_b) {
                PLOG_TO(SYSTEM, ERROR) << "clock_gettime() failed";
            }
            return;
        }
        int64_t cost = (end_ts.tv_sec - start_ts.tv_sec) * SEC_TO_USEC +
                       (end_ts.tv_nsec - start_ts.tv_nsec) / USEC_TO_NSEC;
        if (cost > mConfig.event_time_check_usec) {
            LOG_TO(SYSTEM, ERROR)
                << "event loop spent " << cost << " usec, threshold "
                << mConfig.event_time_check_usec << " usec";
        }
    }
}
